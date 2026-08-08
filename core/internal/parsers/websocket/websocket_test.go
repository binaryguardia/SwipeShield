package websocket

import (
	"context"
	"net/http"
	"testing"

	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/ratelimit"
	"github.com/binaryguardia/swipeshield/internal/ruleengine"
)

func testInspector(t *testing.T) *Inspector {
	t.Helper()
	eng := ruleengine.New()
	if err := eng.SetCRSToggles(ruleengine.CRSToggles{SQLi: true, XSS: true, RCE: true, PathTraversal: true, LFI: true, Protocol: true}); err != nil {
		t.Fatal(err)
	}
	lim := ratelimit.NewLimiter(ratelimit.NewMemoryBackend())
	cfg := &config.WebSocketConfig{Enabled: true, MaxMessagesPerMin: 5, MaxMessageBytes: 1024}
	return NewInspector(eng, lim, cfg)
}

func TestIsUpgrade(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	if !IsUpgrade(r) {
		t.Fatal("upgrade request not detected")
	}
	r2 := &http.Request{Header: http.Header{}}
	r2.Header.Set("Connection", "keep-alive")
	if IsUpgrade(r2) {
		t.Fatal("non-upgrade request misdetected")
	}
}

func TestInspectAllowsBenignMessage(t *testing.T) {
	insp := testInspector(t)
	reasons, ok := insp.InspectMessage(context.Background(), "10.0.0.1", "", []byte(`{"type":"chat","msg":"hello everyone"}`), OpText)
	if !ok {
		t.Fatalf("benign message rejected: %+v", reasons)
	}
}

func TestInspectBlocksSQLiMessage(t *testing.T) {
	insp := testInspector(t)
	reasons, ok := insp.InspectMessage(context.Background(), "10.0.0.1", "", []byte(`{"type":"search","q":"' OR 1=1 --"}`), OpText)
	if ok {
		t.Fatalf("malicious message allowed: %+v", reasons)
	}
	if len(reasons) == 0 {
		t.Fatal("no reasons returned")
	}
}

func TestInspectRateLimitPerMessage(t *testing.T) {
	insp := testInspector(t)
	for i := 0; i < 5; i++ {
		if _, ok := insp.InspectMessage(context.Background(), "10.0.0.2", "", []byte("ping"), OpText); !ok {
			t.Fatalf("message %d rejected unexpectedly", i+1)
		}
	}
	reasons, ok := insp.InspectMessage(context.Background(), "10.0.0.2", "", []byte("ping"), OpText)
	if ok {
		t.Fatalf("rate-limit message allowed: %+v", reasons)
	}
}

func TestInspectBlocksOversizeMessage(t *testing.T) {
	insp := testInspector(t)
	big := make([]byte, 2048)
	reasons, ok := insp.InspectMessage(context.Background(), "10.0.0.3", "", big, OpBinary)
	if ok {
		t.Fatalf("oversize binary message allowed: %+v", reasons)
	}
	if reasons[0].Status != 1008 {
		t.Fatalf("expected policy-violation status 1008, got %d", reasons[0].Status)
	}
}
