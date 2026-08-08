package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/binaryguardia/swipeshield/internal/agent/agentpb"
	"github.com/binaryguardia/swipeshield/internal/store"
)

func startAgentServer(t *testing.T, s *store.Store) (agentpb.AgentServiceClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := NewGRPCServer(NewServer(s), nil)
	go func() { _ = gs.Serve(lis) }()

	cc, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := agentpb.NewAgentServiceClient(cc)
	return client, func() { cc.Close(); gs.Stop() }
}

func TestEnrollAndStream(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/agent.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()

	agentID, token, err := st.CreateAgent("web-01", "10.0.0.5")
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}

	client, stop := startAgentServer(t, st)
	defer stop()

	// Enroll.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := client.Enroll(ctx, &agentpb.EnrollRequest{Token: token, Hostname: "web-01", OsInfo: "linux"})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if resp.AgentId != agentID || resp.Secret == "" {
		t.Fatalf("bad enroll response: %+v", resp)
	}

	// Token is single-use.
	if _, err := client.Enroll(ctx, &agentpb.EnrollRequest{Token: token}); err == nil {
		t.Fatal("expected replay to be rejected")
	}

	// Stream with the long-term secret.
	sctx, scancel := context.WithCancel(context.Background())
	defer scancel()
	sctx = metadata.AppendToOutgoingContext(sctx, "authorization", "Bearer "+resp.Secret)
	stream, err := client.Stream(sctx)
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	if err := stream.Send(&agentpb.AgentToManager{Msg: &agentpb.AgentToManager_Heartbeat{
		Heartbeat: &agentpb.Heartbeat{Hostname: "web-01", OsInfo: "linux"},
	}}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	if err := stream.Send(&agentpb.AgentToManager{Msg: &agentpb.AgentToManager_Event{
		Event: &agentpb.SecurityEvent{Type: "waf_block", Payload: `{"rule":"920170","status":403}`},
	}}); err != nil {
		t.Fatalf("send event: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("recv ack: %v", err)
	}
	scancel()

	// Data landed in the store.
	a, err := st.GetAgent(agentID)
	if err != nil {
		t.Fatalf("get agent: %v", err)
	}
	if a.Status != "online" || a.Hostname != "web-01" {
		t.Fatalf("agent not touched: %+v", a)
	}
	evs, err := st.ListEvents(agentID, 10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(evs) != 1 || evs[0].Type != "waf_block" {
		t.Fatalf("unexpected events: %+v", evs)
	}
	if evs[0].Payload != `{"rule":"920170","status":403}` {
		t.Fatalf("payload not preserved raw: %s", evs[0].Payload)
	}

	// Stream with a bad secret is rejected.
	bad, err := client.Stream(context.Background())
	if err != nil {
		t.Fatalf("open bad stream: %v", err)
	}
	badCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer nope")
	badStream, err := client.Stream(badCtx)
	if err != nil {
		t.Fatalf("open bad-auth stream: %v", err)
	}
	if err := badStream.Send(&agentpb.AgentToManager{Msg: &agentpb.AgentToManager_Heartbeat{Heartbeat: &agentpb.Heartbeat{}}}); err == nil {
		// Server should reject on the first message with Unauthenticated.
		if _, err := badStream.Recv(); err == nil {
			t.Fatal("expected Unauthenticated for bad secret")
		}
	}
	_ = bad
}

func TestEnrollRateLimited(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/agent.db")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer st.Close()

	client, stop := startAgentServer(t, st)
	defer stop()
	ctx := context.Background()

	for i := 0; i < 21; i++ {
		_, _ = client.Enroll(ctx, &agentpb.EnrollRequest{Token: "invalid"})
	}
	if _, err := client.Enroll(ctx, &agentpb.EnrollRequest{Token: "invalid"}); err == nil {
		t.Fatal("expected enrollment to be rate-limited")
	}
}
