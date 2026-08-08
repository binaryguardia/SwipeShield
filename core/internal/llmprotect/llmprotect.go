// Package llmprotect inspects inbound requests headed to operator-flagged
// AI/LLM backends for prompt-injection, system-prompt-exfiltration and
// jailbreak patterns. It is pattern/heuristic-based (fast, explainable,
// synchronous), scoped strictly to inbound request inspection — it does not
// evaluate LLM output, which stays the application's responsibility.
package llmprotect

import (
	"regexp"
	"strings"

	"github.com/binaryguardia/swipeshield/internal/config"
	"github.com/binaryguardia/swipeshield/internal/decision"
)

// pattern is one detection rule.
type pattern struct {
	ID      string
	Message string
	Regex   *regexp.Regexp
	Score   float64
}

// Detector evaluates request bodies against prompt-attack patterns.
type Detector struct {
	patterns []pattern
	failMode config.FailMode
	maxBody  int
}

// NewDetector builds a detector with the built-in pattern set.
func NewDetector(failMode config.FailMode, maxBody int) *Detector {
	if failMode == "" {
		failMode = config.FailOpen
	}
	if maxBody <= 0 {
		maxBody = 1 << 20
	}
	d := &Detector{failMode: failMode, maxBody: maxBody}
	d.patterns = []pattern{
		{ID: "LLM-001", Message: "ignore-previous-instructions injection", Score: 0.95, Regex: regexp.MustCompile(`(?i)\b(ignore|forget|disregard|overlook)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|messages?|context)\b`)},
		{ID: "LLM-002", Message: "system-prompt exfiltration attempt", Score: 0.9, Regex: regexp.MustCompile(`(?i)\b(reveal|show|print|output|display|leak|expose|dump|echo)\s+(your|the|its)\s+(system\s+)?(prompt|instructions?|messages?|initial)\b`)},
		{ID: "LLM-003", Message: "role-inversion jailbreak", Score: 0.85, Regex: regexp.MustCompile(`(?i)\byou\s+are\s+(now|no longer)\b|\bact\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored|developer)\b|\bdan\b|\bdo\s+anything\s+now\b|\bdeveloper\s+mode\b`)},
		{ID: "LLM-004", Message: "secret-key exfiltration attempt", Score: 0.9, Regex: regexp.MustCompile(`(?i)\b(what|show|reveal|print)\s+(is|are)\s+your\s+(secret|api|openai|private|internal)\s+(key|token|credential)s?\b|\b(authorization|bearer)\s+token\b`)},
		{ID: "LLM-005", Message: "dangerous-content unlock attempt", Score: 0.8, Regex: regexp.MustCompile(`(?i)\b(ignore|bypass|disable|remove)\s+(the|your)?\s*(safety|ethical|moral|guideline|policy|filter|guardrail)s?\b`)},
		{ID: "LLM-006", Message: "delimiter-injection bypass", Score: 0.75, Regex: regexp.MustCompile(`(?i)(\]\]\s*[<{]|<<[A-Z]+>>|<\|[a-z_]+\|>|</?system_prompt>)`)},
		{ID: "LLM-007", Message: "excessive payload (agentic abuse)", Score: 0.4, Regex: nil},
	}
	return d
}

// Inspect returns reasons for any detected prompt-attack patterns in body.
func (d *Detector) Inspect(body []byte) []decision.Reason {
	var reasons []decision.Reason
	text := string(body)
	for _, p := range d.patterns {
		if p.Regex == nil {
			if len(body) > d.maxBody {
				reasons = append(reasons, decision.Reason{
					Module:  "llm",
					RuleID:  p.ID,
					Message: p.Message,
					Score:   p.Score,
				})
			}
			continue
		}
		if p.Regex.MatchString(text) {
			reasons = append(reasons, decision.Reason{
				Module:  "llm",
				RuleID:  p.ID,
				Message: p.Message,
				Score:   p.Score,
			})
		}
	}
	return reasons
}

// IsLLMRoute reports whether a path is flagged as an AI backend.
func IsLLMRoute(path string, routes []string) bool {
	for _, r := range routes {
		if r == path || strings.HasPrefix(path, r) {
			return true
		}
	}
	return false
}
