// Example SentinelWAF WASM plugin written in Go, compiled to WASI.
//
// The host sends a PluginRequest (JSON) on stdin and reads a PluginResponse
// (JSON) on stdout. This plugin blocks requests whose body contains a
// signature of a shell command, and flags "password" fields in JSON bodies.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type PluginRequest struct {
	Method   string            `json:"method"`
	Path     string            `json:"path"`
	Query    string            `json:"query"`
	Host     string            `json:"host"`
	ClientIP string            `json:"client_ip"`
	Protocol string            `json:"protocol"`
	Headers  map[string]string `json:"headers"`
	Body     string            `json:"body"`
	SiteID   string            `json:"site_id"`
}

type PluginVerdict struct {
	RuleID  string  `json:"rule_id"`
	Message string  `json:"message"`
	Action  string  `json:"action"`
	Score   float64 `json:"score"`
}

type PluginResponse struct {
	Verdicts []PluginVerdict `json:"verdicts"`
}

var cmdRe = regexp.MustCompile(`(?i)(?:;|\||&&)\s*(?:id|whoami|cat|ls|rm|wget|curl|bash|sh)\b`)

func main() {
	in, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read stdin: %v", err)
		os.Exit(1)
	}
	var req PluginRequest
	if err := json.Unmarshal(in, &req); err != nil {
		fmt.Fprintf(os.Stderr, "bad request: %v", err)
		os.Exit(1)
	}

	var resp PluginResponse
	if cmdRe.MatchString(req.Body) {
		resp.Verdicts = append(resp.Verdicts, PluginVerdict{
			RuleID:  "WASM-EX-001",
			Message: "shell command injection signature in body",
			Action:  "block",
			Score:   0.9,
		})
	}
	if strings.Contains(req.Body, `"password"`) {
		resp.Verdicts = append(resp.Verdicts, PluginVerdict{
			RuleID:  "WASM-EX-002",
			Message: "request contains a password field (flagged for review)",
			Action:  "log",
			Score:   0.4,
		})
	}
	if req.Path == "/admin" && !strings.HasPrefix(req.Headers["Cookie"], "session=admin") {
		resp.Verdicts = append(resp.Verdicts, PluginVerdict{
			RuleID:  "WASM-EX-003",
			Message: "admin path without admin session",
			Action:  "challenge",
			Score:   0.7,
		})
	}
	out, _ := json.Marshal(resp)
	os.Stdout.Write(out)
}
