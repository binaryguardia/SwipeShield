package mgmtapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// --- Fingerprint blocklist ---

type blocklistEntry struct {
	JA4     string `json:"ja4"`
	AddedAt string `json:"added_at,omitempty"`
	Note    string `json:"note,omitempty"`
}

func (s *Server) handleListBlocklist(w http.ResponseWriter, r *http.Request) {
	cfg := s.opts.Backend.Config()
	out := make([]blocklistEntry, 0, len(cfg.Fingerprint.Blocklist))
	for _, h := range cfg.Fingerprint.Blocklist {
		out = append(out, blocklistEntry{JA4: h})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAddBlocklist(w http.ResponseWriter, r *http.Request) {
	var in struct {
		JA4  string `json:"ja4"`
		Note string `json:"note"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return
	}
	h := strings.ToLower(strings.TrimSpace(in.JA4))
	if !validJA4(h) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JA4 hash (expected 32 hex chars)"})
		return
	}
	cfg := s.opts.Backend.Config()
	for _, existing := range cfg.Fingerprint.Blocklist {
		if existing == h {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "already blocked"})
			return
		}
	}
	cfg.Fingerprint.Blocklist = append(cfg.Fingerprint.Blocklist, h)
	if err := s.apply(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, blocklistEntry{JA4: h, AddedAt: time.Now().UTC().Format(time.RFC3339), Note: in.Note})
}

func (s *Server) handleDeleteBlocklist(w http.ResponseWriter, r *http.Request) {
	h := strings.ToLower(strings.TrimSpace(r.PathValue("ja4")))
	cfg := s.opts.Backend.Config()
	kept := cfg.Fingerprint.Blocklist[:0]
	found := false
	for _, existing := range cfg.Fingerprint.Blocklist {
		if existing == h {
			found = true
			continue
		}
		kept = append(kept, existing)
	}
	cfg.Fingerprint.Blocklist = kept
	if !found {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not blocked"})
		return
	}
	if err := s.apply(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validJA4(h string) bool {
	if len(h) != 32 {
		return false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// --- Metrics ---

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.opts.Backend.Stats())
}

// --- Live event stream (SSE) ---

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing token"})
		return
	}
	if _, err := verifyJWT(s.opts.JWTSecret, token); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid token"})
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "streaming unsupported"})
		return
	}
	sub, unsub := s.opts.Backend.SubscribeEvents()
	defer unsub()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()
	enc := json.NewEncoder(w)
	for {
		select {
		case e, ok := <-sub:
			if !ok {
				return
			}
			_, _ = w.Write([]byte("event: audit\n"))
			_, _ = w.Write([]byte("data: "))
			_ = enc.Encode(e)
			_, _ = w.Write([]byte("\n"))
			flusher.Flush()
		case <-heartbeat.C:
			_, _ = w.Write([]byte(": keepalive\n\n"))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
