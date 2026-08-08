package mgmtapi

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/ruleengine"
)

// siteDTO is the dashboard-facing site shape.
type siteDTO struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Host       string   `json:"host"`
	Domains    []string `json:"domains"`
	Upstream   string   `json:"upstream"`
	PathPrefix string   `json:"path_prefix"`
	Status     string   `json:"status"`
}

// siteInput is the create/update body.
type siteInput struct {
	Name       string `json:"name"`
	Host       string `json:"host"`
	Upstream   string `json:"upstream"`
	PathPrefix string `json:"path_prefix"`
	Status     string `json:"status"`
}

func toSiteDTO(s *config.Site) siteDTO {
	host := ""
	if len(s.Domains) > 0 {
		host = s.Domains[0]
	}
	status := s.Status
	if status == "" {
		status = "enabled"
	}
	return siteDTO{
		ID: s.ID, Name: s.Name, Host: host, Domains: s.Domains,
		Upstream: s.Backend, PathPrefix: s.PathPrefix, Status: status,
	}
}

// ruleDTO is the dashboard-facing custom-rule shape.
type ruleDTO struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Status   int    `json:"status"`
	Source   string `json:"source"`
}

func toRuleDTO(r *ruleengine.Rule, source string) ruleDTO {
	return ruleDTO{
		ID: r.ID, Name: r.Name, Message: r.Description,
		Severity: r.Severity, Action: string(r.Action), Status: r.Status,
		Source: source,
	}
}

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	cfg := s.opts.Backend.Config()
	st := cfg.SiteByID(r.PathValue("id"))
	if st == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "site not found"})
		return
	}
	out := []ruleDTO{}
	for _, p := range st.CustomRules {
		rules, err := ruleengine.LoadRules(p)
		if err != nil {
			continue // a broken rule file is reported on reload, not here
		}
		for _, rl := range rules {
			out = append(out, toRuleDTO(rl, p))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateRules(w http.ResponseWriter, r *http.Request) {
	var in struct {
		YAML string `json:"yaml"`
	}
	if err := readJSON(w, r, &in); err != nil {
		return
	}
	rules, err := ruleengine.ParseRules([]byte(in.YAML))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	cfg := s.opts.Backend.Config()
	st := cfg.SiteByID(r.PathValue("id"))
	if st == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "site not found"})
		return
	}
	known := map[string]bool{}
	for _, rl := range rules {
		if known[rl.ID] {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("duplicate rule id %q", rl.ID)})
			return
		}
		known[rl.ID] = true
	}
	var added []ruleDTO
	for _, rl := range rules {
		path := filepath.Join(s.opts.RulesDir, ruleFilename(st.ID, rl.ID))
		if err := os.MkdirAll(s.opts.RulesDir, 0o755); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		data := marshalRuleYAML(rl)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		if !contains(st.CustomRules, path) {
			st.CustomRules = append(st.CustomRules, path)
		}
		added = append(added, toRuleDTO(rl, path))
	}
	if err := s.apply(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	resp := map[string]any{"added": added, "rules": added}
	if len(added) == 1 {
		resp["rule"] = added[0]
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	cfg := s.opts.Backend.Config()
	st := cfg.SiteByID(r.PathValue("id"))
	if st == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "site not found"})
		return
	}
	ruleID := r.PathValue("rule_id")
	kept := st.CustomRules[:0]
	removed := false
	for _, p := range st.CustomRules {
		if rulePathMatches(st.ID, ruleID, p) {
			removed = true
			// Only delete managed files under our rules dir.
			if filepath.Dir(p) == s.opts.RulesDir {
				_ = os.Remove(p)
			}
			continue
		}
		kept = append(kept, p)
	}
	st.CustomRules = kept
	if !removed {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "rule not found"})
		return
	}
	if err := s.apply(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rulePathMatches reports whether a rule file path carries the given rule id
// (by managed filename or by parsing its contents).
func rulePathMatches(siteID, ruleID, path string) bool {
	if filepath.Base(path) == ruleFilename(siteID, ruleID) {
		return true
	}
	rules, err := ruleengine.LoadRules(path)
	if err != nil {
		return false
	}
	for _, rl := range rules {
		if rl.ID == ruleID {
			return true
		}
	}
	return false
}

func ruleFilename(siteID, ruleID string) string {
	return sanitize(siteID) + "-" + sanitize(ruleID) + ".yaml"
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		default:
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "rule"
	}
	return b.String()
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func marshalRuleYAML(rl *ruleengine.Rule) []byte {
	// Marshal as a single-element list to match ParseRules' shape.
	b, err := yaml.Marshal([]*ruleengine.Rule{rl})
	if err != nil {
		return []byte{}
	}
	return b
}

func randID(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
