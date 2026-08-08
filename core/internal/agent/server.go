// Package agent implements the manager side of the SwipeShield agent channel:
// a TLS gRPC service agents on monitored servers dial out to. It handles
// one-time enrollment (token → long-term secret) and the always-on stream of
// heartbeats and security events that back the dashboard's live view.
package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/binaryguardia/swipeshield/internal/agent/agentpb"
	"github.com/binaryguardia/swipeshield/internal/store"
)

// Server is the manager-side gRPC service for agents.
type Server struct {
	agentpb.UnimplementedAgentServiceServer

	store *store.Store

	// enrollment limiter: per-client-IP attempts, coarse and purely
	// anti-brute-force (the token itself is 256-bit random).
	mu          sync.Mutex
	attempts    map[string][]time.Time
	maxAttempts int
	window      time.Duration
}

// NewServer returns an agent service backed by the given store.
func NewServer(s *store.Store) *Server {
	return &Server{
		store:       s,
		attempts:    map[string][]time.Time{},
		maxAttempts: 20,
		window:      time.Hour,
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("agent: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func clientIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		if h, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
			return h
		}
		return p.Addr.String()
	}
	return ""
}

// Enroll validates a one-time token, issues the agent a long-term secret, and
// records liveness. Tokens are single-use and time-limited.
func (s *Server) Enroll(ctx context.Context, req *agentpb.EnrollRequest) (*agentpb.EnrollResponse, error) {
	ip := clientIP(ctx)
	if !s.allowEnrollAttempt(ip) {
		return nil, status.Errorf(codes.ResourceExhausted, "too many enrollment attempts; try again later")
	}
	if req.Token == "" {
		return nil, status.Errorf(codes.InvalidArgument, "token required")
	}
	agentID, err := s.store.ConsumeEnrollToken(req.Token)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "enrollment failed")
	}
	secret := randHex(32)
	if err := s.store.EnrollAgent(agentID, secret); err != nil {
		return nil, status.Errorf(codes.Internal, "store: %v", err)
	}
	_ = s.store.Touch(agentID, ip, req.Hostname, req.OsInfo)
	return &agentpb.EnrollResponse{AgentId: agentID, Secret: secret, Status: "online"}, nil
}

func (s *Server) allowEnrollAttempt(ip string) bool {
	if ip == "" {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now.Add(-s.window)
	keep := s.attempts[ip][:0]
	for _, t := range s.attempts[ip] {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= s.maxAttempts {
		s.attempts[ip] = keep
		return false
	}
	s.attempts[ip] = append(keep, now)
	return true
}

// authSecret extracts the agent's long-term secret from the metadata
// "authorization: Bearer <secret>".
func authSecret(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("missing metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return "", errors.New("missing authorization")
	}
	parts := strings.Fields(vals[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", errors.New("malformed authorization")
	}
	return parts[1], nil
}

// Stream handles the always-on agent channel: heartbeats update liveness,
// security events are persisted for the dashboard, and the agent is marked
// offline when the connection drops.
func (s *Server) Stream(stream agentpb.AgentService_StreamServer) error {
	secret, err := authSecret(stream.Context())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "missing or malformed credentials")
	}
	agentID, err := s.store.AgentIDBySecret(secret)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "unknown agent secret")
	}
	ip := clientIP(stream.Context())
	defer func() {
		_ = s.store.SetStatus(agentID, "offline")
	}()
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch m := msg.Msg.(type) {
		case *agentpb.AgentToManager_Heartbeat:
			hb := m.Heartbeat
			_ = s.store.Touch(agentID, ip, hb.Hostname, hb.OsInfo)
		case *agentpb.AgentToManager_Event:
			if err := s.store.AddEvent(agentID, m.Event.Type, json.RawMessage(m.Event.Payload)); err != nil {
				// Persisting one event must not kill the stream.
				_ = s.store.AddEvent(agentID, "store_error", map[string]string{"error": err.Error()})
			}
		}
		if err := stream.Send(&agentpb.ManagerToAgent{Command: "ack"}); err != nil {
			return err
		}
	}
}

// NewServerTLSFromFile loads a TLS server credential pair.
func credsFromFile(certFile, keyFile string) (credentials.TransportCredentials, error) {
	return credentials.NewServerTLSFromFile(certFile, keyFile)
}

// ServerAPI exposes the raw gRPC server for embedding (used by ListenAndServe
// and by tests).
type ServerAPI interface {
	RegisterService(*grpc.ServiceDesc, any)
}

// NewGRPCServer builds a configured grpc.Server serving the agent service.
func NewGRPCServer(s *Server, creds credentials.TransportCredentials) *grpc.Server {
	opts := []grpc.ServerOption{}
	if creds != nil {
		opts = append(opts, grpc.Creds(creds))
	}
	gs := grpc.NewServer(opts...)
	agentpb.RegisterAgentServiceServer(gs, s)
	return gs
}

// ListenAndServe starts the agent gRPC service on addr. When certFile and
// keyFile are non-empty, the listener is served over TLS.
func ListenAndServe(addr, certFile, keyFile string, s *Server) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	var creds credentials.TransportCredentials
	if certFile != "" && keyFile != "" {
		creds, err = credsFromFile(certFile, keyFile)
		if err != nil {
			return err
		}
	}
	return NewGRPCServer(s, creds).Serve(ln)
}
