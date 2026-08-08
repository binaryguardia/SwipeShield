package store

import (
	"testing"
	"time"
)

func TestCreateEnrollStream(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	id, token, err := s.CreateAgent("web-01", "10.0.0.5")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if id == "" || token == "" {
		t.Fatal("expected id and token")
	}

	// Replay is rejected.
	if _, err := s.ConsumeEnrollToken(token); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if _, err := s.ConsumeEnrollToken(token); err == nil {
		t.Fatal("expected replay to be rejected")
	}

	secret := "long-term-secret"
	if err := s.EnrollAgent(id, secret); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	got, err := s.AgentIDBySecret(secret)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if got != id {
		t.Fatalf("auth mismatch: %s != %s", got, id)
	}
	if _, err := s.AgentIDBySecret("wrong"); err == nil {
		t.Fatal("expected auth failure for wrong secret")
	}

	if err := s.Touch(id, "10.0.0.5", "web-01", "linux"); err != nil {
		t.Fatalf("touch: %v", err)
	}
	a, err := s.GetAgent(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if a.Status != "online" || a.Hostname != "web-01" {
		t.Fatalf("unexpected agent: %+v", a)
	}

	// Wrong token shape.
	otherID, _, err := s.CreateAgent("web-02", "10.0.0.6")
	if err != nil {
		t.Fatalf("create 2: %v", err)
	}
	if err := s.AddEvent(otherID, "heartbeat", map[string]any{"n": 1}); err != nil {
		t.Fatalf("add event: %v", err)
	}
	evs, err := s.ListAllEvents(10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(evs) != 1 || evs[0].Type != "heartbeat" {
		t.Fatalf("unexpected events: %+v", evs)
	}

	if err := s.DeleteAgent(otherID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetAgent(otherID); err == nil {
		t.Fatal("expected agent gone after delete")
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	s, err := Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	// Directly insert an already-expired token.
	if _, err := s.db.Exec(`INSERT INTO enroll_tokens (token_hash,agent_id,expires_at,used) VALUES (?,?,?,0)`,
		hash("tok"), "a1", time.Now().Add(-time.Hour).Unix(), 0); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.ConsumeEnrollToken("tok"); err == nil {
		t.Fatal("expected expired token to be rejected")
	}
}
