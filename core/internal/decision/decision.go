// Package decision defines the shared inspection context and the verdict
// aggregation layer. Every module (rules, rate limit, fingerprint, bots,
// parsers, ML, LLM) contributes Reasons; the Engine folds them into a single
// Allow / Block / Challenge decision with full explainability.
package decision

import (
	"net/http"

	"github.com/binaryguardia/sentinelwaf/internal/config"
)

// Action mirrors config.Action for verdicts.
type Action string

const (
	Allow     Action = "allow"
	Block     Action = "block"
	Challenge Action = "challenge"
	Log       Action = "log"
)

// Reason is one explainable signal contributing to a verdict.
type Reason struct {
	Module  string         `json:"module"`
	RuleID  string         `json:"rule_id,omitempty"`
	Message string         `json:"message"`
	Score   float64        `json:"score,omitempty"`  // 0..1 severity/confidence
	Status  int            `json:"status,omitempty"` // suggested HTTP status
	Data    map[string]any `json:"data,omitempty"`
}

// Verdict is the final decision for a request.
type Verdict struct {
	Decision   Action   `json:"decision"`
	StatusCode int      `json:"status_code"`
	Reasons    []Reason `json:"reasons"`
	Body       string   `json:"body,omitempty"` // optional block/challenge body
}

// HighestSeverity folds reasons and returns the most severe action.
func HighestSeverity(reasons []Reason, defaultAction Action) Verdict {
	v := Verdict{Decision: defaultAction, StatusCode: http.StatusOK}
	if defaultAction == Block {
		v.StatusCode = http.StatusForbidden
	}
	for _, r := range reasons {
		switch r.Module {
		case "graphql", "grpc", "websocket":
			// protocol violations default to block unless a reason says log
		}
		if r.Status != 0 {
			v.StatusCode = r.Status
		}
	}
	return v
}

// InspectContext carries everything a module needs to inspect one request.
type InspectContext struct {
	Request  *http.Request
	Site     *config.Site
	ClientIP string
	APIKey   string
	Host     string
	Path     string
	Method   string
	Body     []byte // size-limited, already buffered for inspection

	Protocol string // rest | graphql | grpc | websocket | sse

	// Transport is the front-end transport the request arrived on.
	Transport string // h1 | h2 | h3
	// ZeroRTT is true when the request was sent as QUIC 0-RTT early data.
	// 0-RTT requests are replayable (no replay protection in early data).
	ZeroRTT bool

	// Protocol-aware snapshot data (populated by parsers).
	GraphQL *GraphQLInfo
	GRPC    *GRPCInfo
	WS      *WSInfo

	// Fingerprint data.
	JA3           string
	JA4           string
	H2Fingerprint string

	// Scoring.
	BotScore float64
	MLScore  float64
	LLMScore float64

	// Outcome accumulation.
	Reasons []Reason

	// Status is the final HTTP status sent to the client (set by the proxy).
	Status int
}

// GraphQLInfo holds parsed GraphQL query telemetry.
type GraphQLInfo struct {
	OperationName string
	Depth         int
	Complexity    int
	AliasCount    int
	Introspection bool
	Query         string
}

// GRPCInfo holds parsed protobuf message telemetry.
type GRPCInfo struct {
	ServiceName string
	MethodName  string
	Fields      []GRPCField
}

// GRPCField is one parsed protobuf field.
type GRPCField struct {
	FieldNumber int
	Name        string
	WireType    int
	Value       any
}

// WSInfo holds WebSocket connection/message telemetry.
type WSInfo struct {
	MessageCount int
	CurrentMsg   string
	FrameType    int // 1=text 2=binary
}

// AddReason appends an explainable reason.
func (c *InspectContext) AddReason(r Reason) { c.Reasons = append(c.Reasons, r) }

// Fired reports whether a module produced any reason.
func (c *InspectContext) Fired(module string) bool {
	for _, r := range c.Reasons {
		if r.Module == module {
			return true
		}
	}
	return false
}

// Allowed returns true if no block/challenge reasons are present.
func (c *InspectContext) Allowed() bool {
	for _, r := range c.Reasons {
		if r.Module != "log" {
			if r.Status >= 400 {
				return false
			}
		}
	}
	return true
}
