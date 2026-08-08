// Package store provides the persistent SQLite-backed data layer for the
// SentinelWAF manager: enrolled agents, one-time enrollment tokens, and the
// security events agents stream home. It uses a pure-Go SQLite driver
// (modernc.org/sqlite) so the manager runs with zero CGO/database server
// dependencies — important for the .deb / AppImage single-binary installs.
//
// Nothing in this package is on the request-inspection path; it only backs
// the management API and the agent service.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS agents (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL DEFAULT '',
	ip          TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL DEFAULT 'pending',
	hostname    TEXT NOT NULL DEFAULT '',
	os_info     TEXT NOT NULL DEFAULT '',
	secret_hash TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	last_seen   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS enroll_tokens (
	token_hash TEXT PRIMARY KEY,
	agent_id   TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	used       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_enroll_tokens_agent ON enroll_tokens(agent_id);
CREATE TABLE IF NOT EXISTS agent_events (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	agent_id TEXT NOT NULL,
	ts       INTEGER NOT NULL,
	type     TEXT NOT NULL,
	payload  TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_agent_events_agent_ts ON agent_events(agent_id, ts DESC);
`

// Agent is one monitored server.
type Agent struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Status    string `json:"status"` // pending | online | offline
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
	CreatedAt int64  `json:"created_at"`
	LastSeen  int64  `json:"last_seen,omitempty"`
}

// Event is one security event streamed home by an agent.
type Event struct {
	ID      int64  `json:"id"`
	AgentID string `json:"agent_id"`
	TS      int64  `json:"ts"`
	Type    string `json:"type"`
	Payload string `json:"payload"` // JSON object
}

// Store wraps the SQLite connection.
type Store struct {
	db *sql.DB
	mu sync.Mutex // serializes writes; cheap and avoids contention surprises
}

// Open opens (creating if needed) the SQLite database at path.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("store: create dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: pragma: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("store: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// CreateAgent registers a server to be monitored and returns a one-time
// enrollment token the agent must present. The token is stored hashed.
func (s *Store) CreateAgent(name, ip string) (id, token string, err error) {
	id = randHex(12)
	token = randHex(32)
	now := time.Now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO agents (id,name,ip,status,created_at) VALUES (?,?,?,'pending',?)`,
		id, name, ip, now); err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(`INSERT INTO enroll_tokens (token_hash,agent_id,expires_at,used) VALUES (?,?,?,0)`,
		hash(token), id, now+int64(24*time.Hour/time.Second)); err != nil {
		return "", "", err
	}
	return id, token, tx.Commit()
}

// ConsumeEnrollToken validates a one-time enrollment token and atomically
// marks it used, returning the agent ID it was issued for.
func (s *Store) ConsumeEnrollToken(token string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var agentID string
	var expiresAt int64
	var used int
	err = tx.QueryRow(`SELECT agent_id, expires_at, used FROM enroll_tokens WHERE token_hash=?`,
		hash(token)).Scan(&agentID, &expiresAt, &used)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("store: invalid enrollment token")
	}
	if err != nil {
		return "", err
	}
	if used != 0 {
		return "", fmt.Errorf("store: enrollment token already used")
	}
	if time.Now().Unix() > expiresAt {
		return "", fmt.Errorf("store: enrollment token expired")
	}
	if _, err := tx.Exec(`UPDATE enroll_tokens SET used=1 WHERE token_hash=?`, hash(token)); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return agentID, nil
}

// EnrollAgent records the long-term agent secret (returned to the agent after
// enrollment) and marks the agent pending-enrollment-complete (online).
func (s *Store) EnrollAgent(agentID, secret string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE agents SET secret_hash=?, status='online', last_seen=? WHERE id=?`,
		hash(secret), time.Now().Unix(), agentID)
	return err
}

// AgentIDBySecret returns the agent ID matching a long-term secret, or an
// error. Used to authenticate the streaming connection.
func (s *Store) AgentIDBySecret(secret string) (string, error) {
	var id string
	err := s.db.QueryRow(`SELECT id FROM agents WHERE secret_hash=?`, hash(secret)).Scan(&id)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("store: unknown agent secret")
	}
	return id, err
}

// Touch updates agent liveness and identity details.
func (s *Store) Touch(agentID, ip, hostname, osInfo string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE agents SET last_seen=?, status='online', hostname=?, os_info=?, ip=? WHERE id=?`,
		time.Now().Unix(), hostname, osInfo, ip, agentID)
	return err
}

// SetStatus flips an agent's liveness state.
func (s *Store) SetStatus(agentID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`UPDATE agents SET status=? WHERE id=?`, status, agentID)
	return err
}

// GetAgent returns one agent by ID.
func (s *Store) GetAgent(id string) (*Agent, error) {
	var a Agent
	err := s.db.QueryRow(`SELECT id,name,ip,status,hostname,os_info,created_at,last_seen FROM agents WHERE id=?`,
		id).Scan(&a.ID, &a.Name, &a.IP, &a.Status, &a.Hostname, &a.OS, &a.CreatedAt, &a.LastSeen)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("store: agent %q not found", id)
	}
	return &a, err
}

// ListAgents returns all agents, most recently seen first.
func (s *Store) ListAgents() ([]Agent, error) {
	rows, err := s.db.Query(`SELECT id,name,ip,status,hostname,os_info,created_at,last_seen FROM agents ORDER BY last_seen DESC, created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(&a.ID, &a.Name, &a.IP, &a.Status, &a.Hostname, &a.OS, &a.CreatedAt, &a.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAgent removes an agent and its tokens and events.
func (s *Store) DeleteAgent(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM enroll_tokens WHERE agent_id=?`,
		`DELETE FROM agent_events WHERE agent_id=?`,
		`DELETE FROM agents WHERE id=?`,
	} {
		if _, err := tx.Exec(q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// AddEvent records a security event from an agent. payload is JSON-serialized.
func (s *Store) AddEvent(agentID, typ string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO agent_events (agent_id,ts,type,payload) VALUES (?,?,?,?)`,
		agentID, time.Now().UnixMilli(), typ, string(b))
	return err
}

// ListEvents returns the most recent events for an agent.
func (s *Store) ListEvents(agentID string, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id,agent_id,ts,type,payload FROM agent_events WHERE agent_id=? ORDER BY ts DESC, id DESC LIMIT ?`,
		agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// ListAllEvents returns the most recent events across all agents.
func (s *Store) ListAllEvents(limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id,agent_id,ts,type,payload FROM agent_events ORDER BY ts DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]Event, error) {
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.AgentID, &e.TS, &e.Type, &e.Payload); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
