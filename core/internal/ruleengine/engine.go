// Package ruleengine evaluates requests against OWASP CRS-compatible
// signature rules (via Coraza) and the custom YAML rule DSL, and merges
// custom DSL matches with Coraza transaction results into a uniform Match.
package ruleengine

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// Phase indicates which request stage a rule fires on.
type Phase string

const (
	PhaseRequest  Phase = "request"
	PhaseResponse Phase = "response"
)

// Action is a rule action.
type Action string

const (
	ActionBlock     Action = "block"
	ActionChallenge Action = "challenge"
	ActionLog       Action = "log"
	ActionAllow     Action = "allow"
)

// Match is a single rule hit explaining a verdict.
type Match struct {
	RuleID      string         `json:"rule_id"`
	Name        string         `json:"name,omitempty"`
	Message     string         `json:"message"`
	Severity    string         `json:"severity,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Action      Action         `json:"action"`
	Phase       Phase          `json:"phase"`
	Engine      string         `json:"engine"` // "crs" | "custom" | "native"
	Data        map[string]any `json:"data,omitempty"`
	MatchedData string         `json:"matched_data,omitempty"`
}

// Engine evaluates requests against all loaded rule sources.
type Engine struct {
	mu       sync.RWMutex
	waf      coraza.WAF
	rules    []*Rule // custom DSL rules
	enabled  CRSToggles
	failMode string // "closed" | "open"
}

// CRSToggles enables/disables CRS rule classes.
type CRSToggles struct {
	SQLi          bool
	XSS           bool
	RCE           bool
	PathTraversal bool
	LFI           bool
	Protocol      bool
}

// New creates an empty rule engine with default fail mode.
func New() *Engine {
	return &Engine{failMode: "closed"}
}

// SetFailMode sets module fail behavior ("closed"|"open").
func (e *Engine) SetFailMode(m string) { e.mu.Lock(); e.failMode = m; e.mu.Unlock() }

// SetCRSToggles updates which CRS classes are active and rebuilds the engine.
func (e *Engine) SetCRSToggles(t CRSToggles) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enabled = t
	return e.rebuildLocked()
}

// SetCustomRules replaces the custom DSL rule set and rebuilds.
func (e *Engine) SetCustomRules(rules []*Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
	return e.rebuildLocked()
}

// rebuildLocked recompiles the Coraza WAF with the CRS SecLang directives
// corresponding to the active toggles.
func (e *Engine) rebuildLocked() error {
	cfg := coraza.NewWAFConfig().WithDirectives(crsDirectivesFor(e.enabled))
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return fmt.Errorf("ruleengine: build WAF: %w", err)
	}
	e.waf = waf
	return nil
}

// LoadCRSFile loads additional SecLang rules from a file (e.g. full CRS).
func (e *Engine) LoadCRSFile(path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.waf == nil {
		if err := e.rebuildLocked(); err != nil {
			return err
		}
	}
	cfg := coraza.NewWAFConfig().WithDirectivesFromFile(path)
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		return fmt.Errorf("ruleengine: load %s: %w", path, err)
	}
	e.waf = waf
	return nil
}

// MatchResult aggregates all matches from an evaluation.
type MatchResult struct {
	Matches []Match
	// Blocked is true when any match has Action block (or a request
	// interruption was signalled by Coraza).
	Blocked    bool
	Challenged bool
	Err        error
}

// Evaluate runs the rule engine against a request snapshot. uri/method are
// the request URI and method; headers and body are the inspected surfaces.
// It never panics and never blocks indefinitely.
func (e *Engine) Evaluate(req *http.Request, body []byte) MatchResult {
	var res MatchResult
	e.mu.RLock()
	waf := e.waf
	rules := e.rules
	failMode := e.failMode
	e.mu.RUnlock()

	if waf == nil {
		return res
	}

	done := make(chan MatchResult, 1)
	go func() {
		done <- e.evaluateLocked(waf, rules, failMode, req, body)
	}()

	select {
	case res = <-done:
	case <-time.After(2 * time.Second):
		res = MatchResult{Err: fmt.Errorf("ruleengine: evaluation timeout")}
		if failMode == "closed" {
			res.Matches = append(res.Matches, Match{
				RuleID: "ENGINE-TIMEOUT", Engine: "native", Action: ActionBlock,
				Message:  "rule engine timed out; fail-closed",
				Severity: "CRITICAL",
			})
			res.Blocked = true
		}
	}
	for i := range res.Matches {
		switch res.Matches[i].Action {
		case ActionBlock:
			res.Blocked = true
		case ActionChallenge:
			res.Challenged = true
		}
	}
	return res
}

func (e *Engine) evaluateLocked(waf coraza.WAF, rules []*Rule, failMode string, req *http.Request, body []byte) MatchResult {
	var res MatchResult

	tx := waf.NewTransaction()
	defer tx.Close()

	tx.ProcessConnection(clientIP(req), 0, "", 0)
	uri := "/"
	if req.URL != nil {
		uri = req.URL.RequestURI()
	}
	if uri == "" {
		uri = "/"
	}
	proto := req.Proto
	if proto == "" {
		// Synthetic requests (WS messages, SSE lines, gRPC field synthesis)
		// carry no protocol string; default it or CRS's HTTP-version rule
		// fires on every message.
		proto = "HTTP/1.1"
	}
	tx.ProcessURI(uri, req.Method, proto)
	for k, vs := range req.Header {
		for _, v := range vs {
			tx.AddRequestHeader(k, v)
		}
	}
	tx.ProcessRequestHeaders()
	if len(body) > 0 {
		if it, _, err := tx.WriteRequestBody(body); err == nil && it != nil {
			res = mergeInterruption(res, it)
		}
	}
	if it, _ := tx.ProcessRequestBody(); it != nil {
		res = mergeInterruption(res, it)
	}

	// Merge all matched rules (disruptive and non-disruptive) for full
	// explainability of the verdict.
	for _, mr := range tx.MatchedRules() {
		sev := mr.Rule().Severity().String()
		action := ActionBlock
		if it := tx.Interruption(); it != nil {
			switch it.Action {
			case "allow":
				action = ActionAllow
			case "challenge", "redirect":
				action = ActionChallenge
			}
		} else if mr.Disruptive() {
			action = ActionLog
		}
		m := Match{
			RuleID:   "CRS-" + strconv.Itoa(mr.Rule().ID()),
			Message:  mr.Message(),
			Action:   action,
			Engine:   "crs",
			Severity: sev,
			Data:     map[string]any{"data": mr.Data()},
		}
		if len(mr.MatchedDatas()) > 0 {
			m.MatchedData = truncate(mr.MatchedDatas()[0].Value(), 256)
		}
		res.Matches = append(res.Matches, m)
	}

	// Custom DSL rules.
	for _, r := range rules {
		if r.Phase != PhaseRequest {
			continue
		}
		if m, ok := r.Evaluate(req, body); ok {
			res.Matches = append(res.Matches, *m)
		}
	}

	// Native raw-body patterns (XSS / SQLi / RCE) — Coraza's REQUEST_BODY
	// collection is not populated through the raw tx API, so CRS rules that
	// target ARGS would otherwise miss JSON / GraphQL / text bodies.
	// Multipart bodies are skipped: Coraza parses them into ARGS (and files)
	// where the CRS rules apply correctly, and the raw scan would otherwise
	// false-positive on legitimate `";` boundary/header separators.
	if !strings.HasPrefix(strings.ToLower(req.Header.Get("Content-Type")), "multipart/") {
		res.Matches = append(res.Matches, e.enabled.evaluateNativeBody(body)...)
	}

	// Native URI traversal scan — covers percent-encoded traversal vectors the
	// raw-URI CRS rule cannot see.
	path := ""
	if req.URL != nil {
		path = req.URL.Path
	}
	res.Matches = append(res.Matches, e.enabled.evaluateNativeURI(uri, path)...)
	return res
}

func mergeInterruption(res MatchResult, it *types.Interruption) MatchResult {
	if it == nil {
		return res
	}
	m := Match{
		RuleID:   "CRS-" + strconv.Itoa(it.RuleID),
		Message:  "Request blocked by CRS rule",
		Action:   ActionBlock,
		Engine:   "crs",
		Severity: "CRITICAL",
		Data:     map[string]any{"status": it.Status, "action": it.Action, "data": it.Data},
	}
	res.Matches = append(res.Matches, m)
	return res
}

func clientIP(r *http.Request) string {
	if r.RemoteAddr != "" {
		if i := strings.LastIndexByte(r.RemoteAddr, ':'); i >= 0 {
			return r.RemoteAddr[:i]
		}
	}
	return "0.0.0.0"
}
