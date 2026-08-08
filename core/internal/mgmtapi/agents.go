package mgmtapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/binaryguardia/sentinelwaf/internal/store"
)

// agentStore returns the backing store or nil.
func (s *Server) agentStore() *store.Store { return s.opts.Store }

// handleListAgents returns the agent registry (name, ip, status, last-seen).
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	if s.agentStore() == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent store not configured"})
		return
	}
	agents, err := s.agentStore().ListAgents()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

type createAgentRequest struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
}

// handleCreateAgent registers a server to monitor ("add by IP") and returns a
// single-use enrollment token plus the exact command to run on that server.
func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	st := s.agentStore()
	if st == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent store not configured"})
		return
	}
	var req createAgentRequest
	if err := readJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Name == "" {
		req.Name = req.IP
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name or ip is required"})
		return
	}
	id, token, err := st.CreateAgent(req.Name, req.IP)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a, err := st.GetAgent(id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"agent":          a,
		"token":          token,
		"enroll_command": s.enrollCommand(r, token),
	})
}

// enrollCommand renders the one-liner to run on the monitored server. The
// manager host is taken from the request's Host header (the dashboard's
// origin), so it works whether the operator reaches the UI by IP or domain.
func (s *Server) enrollCommand(r *http.Request, token string) string {
	host := r.Host
	if i := indexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	port := s.opts.AgentPort
	if port == "" {
		port = "9443"
	}
	return "sentinelwaf-agent enroll -m " + host + ":" + port + " -t " + token
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// handleDeleteAgent removes a monitored server.
func (s *Server) handleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	st := s.agentStore()
	if st == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent store not configured"})
		return
	}
	id := r.PathValue("id")
	if err := st.DeleteAgent(id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAgentEvents returns the most recent events streamed by an agent.
func (s *Server) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	st := s.agentStore()
	if st == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent store not configured"})
		return
	}
	id := r.PathValue("id")
	if _, err := st.GetAgent(id); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	events, err := st.ListEvents(id, limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var out []json.RawMessage
	for _, e := range events {
		out = append(out, json.RawMessage(e.Payload))
	}
	writeJSON(w, http.StatusOK, out)
}
