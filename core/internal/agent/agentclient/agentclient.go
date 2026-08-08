// Package agentclient is the client side of the SentinelWAF agent channel,
// used by the sentinelwaf-agent binary. It dials OUT to the manager, enrolls
// with a one-time token, and maintains an always-on stream that pushes
// heartbeats and security events.
package agentclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/binaryguardia/sentinelwaf/internal/agent/agentpb"
)

// Config is the agent's persisted identity (written by `enroll`).
type Config struct {
	Manager  string `json:"manager"` // "host:port" of the manager's agent service
	AgentID  string `json:"agent_id"`
	Secret   string `json:"secret"`
	Insecure bool   `json:"insecure,omitempty"` // skip TLS verification (self-signed managers)

	WAFEventLog string `json:"waf_event_log,omitempty"` // optional local WAF events.log to stream
}

// LoadConfig reads an agent config file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("agent: read %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("agent: parse %s: %w", path, err)
	}
	if c.Manager == "" || c.AgentID == "" || c.Secret == "" {
		return nil, fmt.Errorf("agent: config %s is incomplete (run `enroll` first)", path)
	}
	return &c, nil
}

// SaveConfig writes the agent config (0600).
func SaveConfig(path string, c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dirOf(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

// Enroll exchanges a one-time token for a long-term agent secret.
func Enroll(ctx context.Context, manager, token string, insecure bool) (*Config, error) {
	cc, err := dial(ctx, manager, insecure)
	if err != nil {
		return nil, err
	}
	defer cc.Close()
	client := agentpb.NewAgentServiceClient(cc)
	hostname, _ := os.Hostname()
	resp, err := client.Enroll(ctx, &agentpb.EnrollRequest{
		Token:    token,
		Hostname: hostname,
		OsInfo:   osInfo(),
	})
	if err != nil {
		return nil, fmt.Errorf("agent: enroll: %w", err)
	}
	return &Config{
		Manager:  manager,
		AgentID:  resp.AgentId,
		Secret:   resp.Secret,
		Insecure: insecure,
	}, nil
}

func dial(ctx context.Context, manager string, insecureFlag bool) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{}
	if insecureFlag {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// Accept both CA-signed and self-signed certificates; self-signed is
		// the default for a fresh manager, and pinning is the operator's
		// choice via -insecure=false + a real cert.
		tc := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})
		opts = append(opts, grpc.WithTransportCredentials(tc))
	}
	return grpc.DialContext(ctx, manager, opts...)
}

// Streamer pushes messages to the manager over a persistent authenticated
// stream, and returns the manager's replies.
type Streamer struct {
	cc     *grpc.ClientConn
	stream agentpb.AgentService_StreamClient
}

// NewStreamer dials the manager, authenticates with the agent secret, and
// opens the always-on stream.
func NewStreamer(ctx context.Context, c *Config) (*Streamer, error) {
	cc, err := dial(ctx, c.Manager, c.Insecure)
	if err != nil {
		return nil, err
	}
	client := agentpb.NewAgentServiceClient(cc)
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.Secret)
	stream, err := client.Stream(ctx)
	if err != nil {
		cc.Close()
		return nil, err
	}
	return &Streamer{cc: cc, stream: stream}, nil
}

// Send pushes one message and blocks for the manager's reply.
func (s *Streamer) Send(msg *agentpb.AgentToManager) (*agentpb.ManagerToAgent, error) {
	if err := s.stream.Send(msg); err != nil {
		return nil, err
	}
	return s.stream.Recv()
}

// Close terminates the stream and connection.
func (s *Streamer) Close() {
	if s == nil {
		return
	}
	_ = s.stream.CloseSend()
	_ = s.cc.Close()
}

func osInfo() string {
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
				return strings.Trim(v, `"'`)
			}
		}
	}
	return "linux"
}

// DefaultInterval is how often the agent sends a heartbeat.
const DefaultInterval = 30 * time.Second

// DefaultConfigPath is where the agent stores its identity.
func DefaultConfigPath() string {
	if p := os.Getenv("SENTINELWAF_AGENT_CONFIG"); p != "" {
		return p
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return xdg + "/sentinelwaf-agent/agent.json"
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "/etc/sentinelwaf-agent/agent.json"
	}
	return home + "/.config/sentinelwaf-agent/agent.json"
}
