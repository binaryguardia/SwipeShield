// Package envoy implements the Envoy External Processor (ext_proc) gRPC
// sidecar. When SwipeShield is deployed inside an Istio service mesh, the
// data-plane sidecar streams request headers and bodies to this server; it
// maps them onto the gateway inspection pipeline and replies with an allow /
// block verdict that Envoy enforces in the data plane. No proxying happens
// here — the sidecar is purely a decision engine.
package envoy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/binaryguardia/swipeshield/internal/decision"
	"github.com/binaryguardia/swipeshield/internal/proxy"
)

// evaluator runs the gateway pipeline for one synthetic request. It is an
// interface so tests can drive the sidecar without a full gateway.
type evaluator interface {
	Evaluate(r *http.Request, body []byte) (decision.Verdict, error)
}

// Server is the ext_proc gRPC service.
type Server struct {
	extproc.UnimplementedExternalProcessorServer
	gw evaluator
}

// NewServer wraps a gateway (or any evaluator) as an ext_proc server.
func NewServer(gw evaluator) *Server {
	return &Server{gw: gw}
}

// streamState accumulates a single request's fragments across the
// request_headers / request_body messages on one gRPC stream.
type streamState struct {
	r      *http.Request
	body   []byte
	closed bool // verdict already sent for this request
	onBody bool // last processed message was request_body
}

// Process implements envoy.service.ext_proc.v3.ExternalProcessor. It handles
// the inbound (request) direction: request_headers then buffered
// request_body. Envoy processes the stream sequentially, so a non-terminal
// headers message gets a bare CONTINUE and evaluation happens once on the
// terminal (EndOfStream) message. Response messages pass through untouched.
func (s *Server) Process(stream extproc.ExternalProcessor_ProcessServer) error {
	st := &streamState{}
	for {
		req, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch {
		case req.GetRequestHeaders() != nil:
			st.onBody = false
			if st.r == nil {
				st.r = buildRequest(req.GetRequestHeaders())
			}
			if !req.GetRequestHeaders().GetEndOfStream() {
				if err := s.send(stream, continueResponse()); err != nil {
					return err
				}
				continue
			}
			if err := s.decide(stream, st); err != nil {
				return err
			}
		case req.GetRequestBody() != nil:
			st.onBody = true
			st.body = append(st.body, req.GetRequestBody().GetBody()...)
			if !req.GetRequestBody().GetEndOfStream() {
				continue
			}
			if err := s.decide(stream, st); err != nil {
				return err
			}
		default:
			// Response-direction or trailer messages: nothing to inspect.
			continue
		}
	}
}

// decide runs the pipeline and streams the verdict back to the data plane.
func (s *Server) decide(stream extproc.ExternalProcessor_ProcessServer, st *streamState) error {
	if st.closed {
		return nil
	}
	st.closed = true

	if st.r == nil {
		return s.send(stream, blockResponse(http.StatusBadRequest, "missing request headers"))
	}
	verdict, err := s.gw.Evaluate(st.r, st.body)
	if err != nil {
		log.Error().Err(err).Msg("ext_proc evaluation failed")
		return s.send(stream, blockResponse(http.StatusInternalServerError, "inspection failure"))
	}
	switch verdict.Decision {
	case decision.Block, decision.Challenge:
		statusCode := verdict.StatusCode
		if statusCode == 0 {
			statusCode = http.StatusForbidden
		}
		return s.send(stream, blockResponse(statusCode, reasonText(verdict)))
	default:
		if st.onBody {
			return s.send(stream, allowBodyResponse(verdict))
		}
		return s.send(stream, allowResponse(verdict))
	}
}

func (s *Server) send(stream extproc.ExternalProcessor_ProcessServer, resp *extproc.ProcessingResponse) error {
	if err := stream.Send(resp); err != nil {
		return status.Errorf(codes.Aborted, "send verdict: %v", err)
	}
	return nil
}

// allowResponse tells Envoy to continue; the request carries the verdict in a
// header so downstream filters/observability can see it.
func allowResponse(verdict decision.Verdict) *extproc.ProcessingResponse {
	return &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extproc.HeadersResponse{
				Response: allowCommon(verdict),
			},
		},
	}
}

// allowBodyResponse is allowResponse, but wrapped as the request_body variant
// Envoy expects in reply to a request_body message.
func allowBodyResponse(verdict decision.Verdict) *extproc.ProcessingResponse {
	return &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_RequestBody{
			RequestBody: &extproc.BodyResponse{
				Response: allowCommon(verdict),
			},
		},
	}
}

// allowCommon builds the CommonResponse that lets Envoy continue and stamps
// the verdict header on the request.
func allowCommon(verdict decision.Verdict) *extproc.CommonResponse {
	mutation := &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:      "x-swipeshield-verdict",
			RawValue: []byte(string(verdict.Decision)),
		},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
	return &extproc.CommonResponse{
		Status:         extproc.CommonResponse_CONTINUE,
		HeaderMutation: &extproc.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{mutation}},
	}
}

// continueResponse acknowledges a non-terminal headers message so Envoy
// proceeds to send the buffered body.
func continueResponse() *extproc.ProcessingResponse {
	return &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extproc.HeadersResponse{
				Response: &extproc.CommonResponse{Status: extproc.CommonResponse_CONTINUE},
			},
		},
	}
}

// blockResponse instructs Envoy to answer locally with the given status.
func blockResponse(statusCode int, details string) *extproc.ProcessingResponse {
	code := typev3.StatusCode_OK
	if c, ok := statusCodes[statusCode]; ok {
		code = c
	}
	return &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &extproc.ImmediateResponse{
				Status:  &typev3.HttpStatus{Code: code},
				Details: details,
			},
		},
	}
}

// statusCodes maps HTTP codes to Envoy's enum for the common verdicts.
var statusCodes = map[int]typev3.StatusCode{
	http.StatusBadRequest:            typev3.StatusCode_BadRequest,
	http.StatusForbidden:             typev3.StatusCode_Forbidden,
	http.StatusRequestEntityTooLarge: typev3.StatusCode_PayloadTooLarge,
	http.StatusTooManyRequests:       typev3.StatusCode_TooManyRequests,
	http.StatusInternalServerError:   typev3.StatusCode_InternalServerError,
}

// reasonText folds the top verdict reasons into a short human string.
func reasonText(verdict decision.Verdict) string {
	if len(verdict.Reasons) == 0 {
		return "blocked by SwipeShield"
	}
	r := verdict.Reasons[0]
	return fmt.Sprintf("%s: %s (rule %s)", r.Module, r.Message, r.RuleID)
}

// buildRequest converts ext_proc header maps into an http.Request suitable for
// the gateway pipeline. Envoy lower-cases pseudo-header names; we translate
// :method, :path, :authority, :scheme.
func buildRequest(h *extproc.HttpHeaders) *http.Request {
	if h == nil || h.GetHeaders() == nil {
		return nil
	}
	r := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Path: "/"},
		ProtoMajor: 1,
		ProtoMinor: 1,
		Proto:      "HTTP/1.1",
		Header:     make(http.Header),
	}
	for _, hv := range h.GetHeaders().GetHeaders() {
		key := strings.ToLower(hv.GetKey())
		val := hv.GetValue()
		if val == "" {
			val = string(hv.GetRawValue())
		}
		switch key {
		case ":method":
			r.Method = val
		case ":path":
			r.URL.Path = val
			if i := strings.IndexByte(val, '?'); i >= 0 {
				r.URL.Path = val[:i]
				r.URL.RawQuery = val[i+1:]
			}
		case ":authority", "host":
			r.Host = val
		default:
			if !strings.HasPrefix(key, ":") {
				r.Header.Add(hv.GetKey(), val)
			}
		}
	}
	return r
}

// ListenAndServe starts the ext_proc gRPC server on addr and blocks until the
// listener fails or ctx is cancelled.
func (s *Server) ListenAndServe(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	gs := grpc.NewServer()
	extproc.RegisterExternalProcessorServer(gs, s)
	log.Info().Str("addr", addr).Msg("ext_proc sidecar listening")
	return gs.Serve(lis)
}

// Compile-time assertions that the server satisfies the interfaces.
var (
	_ extproc.ExternalProcessorServer = (*Server)(nil)
	_ evaluator                       = (*proxy.Gateway)(nil)
)
