package envoy

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/binaryguardia/swipeshield/internal/decision"
)

type fakeGW struct {
	verdict   decision.Verdict
	err       error
	gotPath   string
	gotBody   []byte
	gotHost   string
	gotMethod string
}

func (f *fakeGW) Evaluate(r *http.Request, body []byte) (decision.Verdict, error) {
	f.gotPath = r.URL.Path
	f.gotBody = append([]byte(nil), body...)
	f.gotHost = r.Host
	f.gotMethod = r.Method
	return f.verdict, f.err
}

func startServer(t *testing.T, gw evaluator) (extproc.ExternalProcessorClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	extproc.RegisterExternalProcessorServer(gs, NewServer(gw))
	go func() { _ = gs.Serve(lis) }()

	cc, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := extproc.NewExternalProcessorClient(cc)
	return client, func() { cc.Close(); gs.Stop() }
}

func sendHeaders(stream extproc.ExternalProcessor_ProcessClient, eos bool) {
	_ = stream.Send(&extproc.ProcessingRequest{
		Request: &extproc.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extproc.HttpHeaders{
				EndOfStream: eos,
				Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
					{Key: ":method", Value: "POST"},
					{Key: ":path", Value: "/api/login"},
					{Key: ":authority", Value: "shop.example.com"},
					{Key: "content-type", Value: "application/json"},
				}},
			},
		},
	})
}

func sendBody(stream extproc.ExternalProcessor_ProcessClient, data []byte, eos bool) {
	_ = stream.Send(&extproc.ProcessingRequest{
		Request: &extproc.ProcessingRequest_RequestBody{
			RequestBody: &extproc.HttpBody{Body: data, EndOfStream: eos},
		},
	})
}

func recv(stream extproc.ExternalProcessor_ProcessClient) (*extproc.ProcessingResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ch := make(chan *extproc.ProcessingResponse, 1)
	errCh := make(chan error, 1)
	go func() {
		r, err := stream.Recv()
		if err != nil {
			errCh <- err
			return
		}
		ch <- r
	}()
	select {
	case r := <-ch:
		return r, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestAllowRequest(t *testing.T) {
	gw := &fakeGW{verdict: decision.Verdict{Decision: decision.Allow}}
	client, done := startServer(t, gw)
	defer done()

	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	sendHeaders(stream, true)

	resp, err := recv(stream)
	if err != nil {
		t.Fatal(err)
	}
	hr := resp.GetRequestHeaders()
	if hr == nil || hr.GetResponse() == nil {
		t.Fatalf("expected headers continue response, got %v", resp.Response)
	}
	if hr.GetResponse().GetStatus() != extproc.CommonResponse_CONTINUE {
		t.Fatalf("expected CONTINUE, got %v", hr.GetResponse().GetStatus())
	}
	set := hr.GetResponse().GetHeaderMutation().GetSetHeaders()
	if len(set) == 0 || set[0].GetHeader().GetKey() != "x-swipeshield-verdict" {
		t.Fatalf("expected verdict header mutation, got %v", set)
	}
	if gw.gotHost != "shop.example.com" || gw.gotMethod != "POST" || gw.gotPath != "/api/login" {
		t.Fatalf("request mapping wrong: %s %s %s", gw.gotMethod, gw.gotPath, gw.gotHost)
	}
}

func TestBlockRequestOnHeaders(t *testing.T) {
	gw := &fakeGW{verdict: decision.Verdict{Decision: decision.Block, StatusCode: http.StatusForbidden,
		Reasons: []decision.Reason{{Module: "rules", RuleID: "CRS-920110", Message: "protocol attack"}}}}
	client, done := startServer(t, gw)
	defer done()

	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("open process stream: %v", err)
	}
	sendHeaders(stream, true)

	resp, err := recv(stream)
	if err != nil {
		t.Fatal(err)
	}
	ir := resp.GetImmediateResponse()
	if ir == nil {
		t.Fatalf("expected immediate response, got %v", resp.Response)
	}
	if ir.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("expected 403, got %v", ir.GetStatus().GetCode())
	}
	if ir.GetDetails() == "" {
		t.Fatal("expected block details")
	}
}

func TestBodyBufferedEvaluation(t *testing.T) {
	gw := &fakeGW{verdict: decision.Verdict{Decision: decision.Block, StatusCode: http.StatusBadRequest}}
	client, done := startServer(t, gw)
	defer done()

	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("open process stream: %v", err)
	}
	// Headers arrive with EndOfStream=false, then body in two chunks.
	sendHeaders(stream, false)
	sendBody(stream, []byte(`{"a":"s`), false)
	sendBody(stream, []byte(`ql injection"}`), true)

	resp, err := recv(stream)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetImmediateResponse() == nil {
		t.Fatalf("expected block, got %v", resp.Response)
	}
	want := `{"a":"sql injection"}`
	if string(gw.gotBody) != want {
		t.Fatalf("body reassembly wrong: got %q want %q", gw.gotBody, want)
	}
}

func TestEvaluationErrorFailsClosed(t *testing.T) {
	gw := &fakeGW{err: io.ErrUnexpectedEOF}
	client, done := startServer(t, gw)
	defer done()

	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("open process stream: %v", err)
	}
	sendHeaders(stream, true)

	resp, err := recv(stream)
	if err != nil {
		t.Fatal(err)
	}
	ir := resp.GetImmediateResponse()
	if ir == nil || ir.GetStatus().GetCode() != typev3.StatusCode_InternalServerError {
		t.Fatalf("expected 500 fail-closed, got %v", resp.Response)
	}
}

func TestBlockVerdictStatusCodePassedThrough(t *testing.T) {
	// The gateway resolves hosts; the sidecar must faithfully translate any
	// block verdict (e.g. Gateway.Evaluate's 400 "no site configured" for an
	// unknown host) into an ImmediateResponse with the same code.
	gw := &fakeGW{verdict: decision.Verdict{Decision: decision.Block, StatusCode: http.StatusBadRequest}}
	client, done := startServer(t, gw)
	defer done()

	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("open process stream: %v", err)
	}
	_ = stream.Send(&extproc.ProcessingRequest{
		Request: &extproc.ProcessingRequest_RequestHeaders{
			RequestHeaders: &extproc.HttpHeaders{
				EndOfStream: true,
				Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
					{Key: ":method", Value: "GET"},
					{Key: ":path", Value: "/"},
					{Key: ":authority", Value: "not-configured.example.com"},
				}},
			},
		},
	})
	resp, err := recv(stream)
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetImmediateResponse() == nil || resp.GetImmediateResponse().GetStatus().GetCode() != typev3.StatusCode_BadRequest {
		t.Fatalf("expected 400 passed through, got %v", resp.Response)
	}
}

func TestResponseDirectionIgnored(t *testing.T) {
	gw := &fakeGW{verdict: decision.Verdict{Decision: decision.Allow}}
	client, done := startServer(t, gw)
	defer done()

	stream, err := client.Process(context.Background())
	if err != nil {
		t.Fatalf("open process stream: %v", err)
	}
	// A response_headers message must not trigger evaluation or a reply.
	_ = stream.Send(&extproc.ProcessingRequest{
		Request: &extproc.ProcessingRequest_ResponseHeaders{
			ResponseHeaders: &extproc.HttpHeaders{EndOfStream: true},
		},
	})
	_ = stream.CloseSend()

	if gw.gotPath != "" {
		t.Fatal("response-direction message must not be evaluated")
	}
}
