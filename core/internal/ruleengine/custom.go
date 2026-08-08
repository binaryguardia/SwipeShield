package ruleengine

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Operator selects how a rule's value is matched against a target.
type Operator string

const (
	OpRegex    Operator = "regex"
	OpContains Operator = "contains"
	OpEq       Operator = "eq"
	OpPrefix   Operator = "prefix"
	OpSuffix   Operator = "suffix"
)

// Target selects which request surface a rule inspects.
type Target string

const (
	TargetURI    Target = "request_uri"
	TargetPath   Target = "path"
	TargetQuery  Target = "query"
	TargetMethod Target = "method"
	TargetBody   Target = "body"
	TargetHost   Target = "host"
	TargetHeader Target = "header" // requires field: header name
	TargetCookie Target = "cookie" // requires field: cookie name
	TargetArg    Target = "arg"    // requires field: parameter name
	TargetIP     Target = "client_ip"
)

// Rule is a single custom YAML rule.
type Rule struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description,omitempty"`
	Phase       Phase    `yaml:"phase" json:"phase"`
	Severity    string   `yaml:"severity" json:"severity"`
	Tags        []string `yaml:"tags" json:"tags,omitempty"`
	Action      Action   `yaml:"action" json:"action"`
	Status      int      `yaml:"status" json:"status"`
	Target      Target   `yaml:"target" json:"target"`
	Field       string   `yaml:"field,omitempty" json:"field,omitempty"`
	Operator    Operator `yaml:"operator" json:"operator"`
	Value       string   `yaml:"value" json:"value"`

	re *regexp.Regexp
}

// Evaluate tests the rule against a request. It returns a Match when the
// rule fires.
func (r *Rule) Evaluate(req *http.Request, body []byte) (*Match, bool) {
	if r == nil || r.Phase != PhaseRequest {
		return nil, false
	}
	got, ok := r.matchTarget(req, body)
	if !ok {
		return nil, false
	}
	return &Match{
		RuleID:      r.ID,
		Name:        r.Name,
		Message:     r.Description,
		Severity:    r.Severity,
		Tags:        r.Tags,
		Action:      r.Action,
		Phase:       r.Phase,
		Engine:      "custom",
		Data:        map[string]any{"target": string(r.Target), "field": r.Field},
		MatchedData: truncate(got, 256),
	}, true
}

func (r *Rule) matchTarget(req *http.Request, body []byte) (string, bool) {
	values := r.targetValues(req, body)
	for _, v := range values {
		if r.opMatch(v) {
			return v, true
		}
	}
	return "", false
}

func (r *Rule) targetValues(req *http.Request, body []byte) []string {
	switch r.Target {
	case TargetURI:
		return []string{req.URL.RequestURI()}
	case TargetPath:
		return []string{req.URL.Path}
	case TargetQuery:
		return []string{req.URL.RawQuery}
	case TargetMethod:
		return []string{req.Method}
	case TargetHost:
		return []string{req.Host}
	case TargetBody:
		return []string{string(body)}
	case TargetHeader:
		if r.Field == "" {
			return nil
		}
		vs, ok := req.Header[http.CanonicalHeaderKey(r.Field)]
		if !ok {
			return nil
		}
		return vs
	case TargetCookie:
		if r.Field == "" {
			return nil
		}
		c, err := req.Cookie(r.Field)
		if err != nil {
			return nil
		}
		return []string{c.Value}
	case TargetArg:
		if r.Field == "" {
			return nil
		}
		if v := req.URL.Query().Get(r.Field); v != "" {
			return []string{v}
		}
		// Form body lookup (best effort).
		if len(body) > 0 {
			ct := req.Header.Get("Content-Type")
			if strings.Contains(strings.ToLower(ct), "x-www-form-urlencoded") {
				if err := req.ParseForm(); err == nil {
					if v := req.Form.Get(r.Field); v != "" {
						return []string{v}
					}
				}
			}
		}
		return nil
	case TargetIP:
		return []string{clientIP(req)}
	}
	return nil
}

func (r *Rule) opMatch(v string) bool {
	switch r.Operator {
	case OpRegex, "":
		if r.re != nil {
			return r.re.MatchString(v)
		}
		return false
	case OpContains:
		return strings.Contains(v, r.Value)
	case OpEq:
		return v == r.Value
	case OpPrefix:
		return strings.HasPrefix(v, r.Value)
	case OpSuffix:
		return strings.HasSuffix(v, r.Value)
	}
	return false
}

// LoadRules reads a YAML or JSON rule file and validates it.
func LoadRules(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rules, err := ParseRules(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rules, nil
}

// ParseRules parses and validates rule definitions from raw bytes.
func ParseRules(data []byte) ([]*Rule, error) {
	var rules []*Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		// Fall back to JSON for programmatic configs.
		if jerr := json.Unmarshal(data, &rules); jerr != nil {
			return nil, fmt.Errorf("invalid rule file: %w", err)
		}
	}
	if err := validateRules(rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func validateRules(rules []*Rule) error {
	seen := map[string]bool{}
	for i, r := range rules {
		if r == nil {
			return fmt.Errorf("rule %d: empty rule", i)
		}
		if r.ID == "" {
			return fmt.Errorf("rule %d: missing id", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("rule %q: duplicate id", r.ID)
		}
		seen[r.ID] = true
		if r.Phase != PhaseRequest && r.Phase != PhaseResponse {
			return fmt.Errorf("rule %q: invalid phase %q", r.ID, r.Phase)
		}
		switch r.Action {
		case ActionBlock, ActionChallenge, ActionLog, ActionAllow:
		default:
			return fmt.Errorf("rule %q: invalid action %q", r.ID, r.Action)
		}
		if r.Operator == "" {
			r.Operator = OpRegex
		}
		switch r.Operator {
		case OpRegex, OpContains, OpEq, OpPrefix, OpSuffix:
		default:
			return fmt.Errorf("rule %q: invalid operator %q", r.ID, r.Operator)
		}
		if r.Operator == OpRegex {
			re, err := regexp.Compile(r.Value)
			if err != nil {
				return fmt.Errorf("rule %q: invalid regex %q: %w", r.ID, r.Value, err)
			}
			r.re = re
		}
		if r.Status == 0 {
			r.Status = 403
		}
		if r.Severity == "" {
			r.Severity = "MEDIUM"
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
