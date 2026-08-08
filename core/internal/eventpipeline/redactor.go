package eventpipeline

import (
	"bytes"
	"encoding/json"
	"strings"
)

// Redactor strips sensitive fields and truncates request bodies before they
// reach any sink. It is applied to event bodies only — never to the
// inspected request itself (rule engines run on the original data).
type Redactor struct {
	fields  []string
	trunc   int
	special map[string]string
}

// NewRedactor builds a redactor for the given sensitive field names.
func NewRedactor(fields []string, trunc int) *Redactor {
	if trunc <= 0 {
		trunc = 2048
	}
	// Authorization, cookies and credentials are always redacted regardless
	// of config — never negotiate on these.
	always := []string{"authorization", "cookie", "set-cookie", "x-api-key", "apikey", "password", "passwd", "secret", "token", "access_token", "refresh_token", "jwt", "credential", "x-auth-token", "client-secret"}
	r := &Redactor{fields: append(fields, always...), trunc: trunc}
	r.special = map[string]string{
		"authorization": "[REDACTED]",
		"cookie":        "[REDACTED]",
		"set-cookie":    "[REDACTED]",
		"x-api-key":     "[REDACTED]",
		"apikey":        "[REDACTED]",
		"api-key":       "[REDACTED]",
		"password":      "[REDACTED]",
		"passwd":        "[REDACTED]",
		"secret":        "[REDACTED]",
		"token":         "[REDACTED]",
		"access_token":  "[REDACTED]",
		"refresh_token": "[REDACTED]",
		"jwt":           "[REDACTED]",
		"credential":    "[REDACTED]",
		"x-auth-token":  "[REDACTED]",
		"client-secret": "[REDACTED]",
	}
	return r
}

// RedactBody truncates and strips sensitive keys from a body string. JSON
// bodies get field-level redaction; other bodies are truncated only.
func (r *Redactor) RedactBody(body string) string {
	if len(body) > r.trunc {
		body = body[:r.trunc] + "...(truncated)"
	}
	if !isJSONish(body) {
		return body
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return body
	}
	r.redactMap(m)
	out, err := json.Marshal(m)
	if err != nil {
		return body
	}
	return string(out)
}

func (r *Redactor) redactMap(m map[string]any) {
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			r.redactMap(sub)
			continue
		}
		if sub, ok := v.([]any); ok {
			r.redactSlice(sub)
			continue
		}
		if r.isSensitive(k) {
			m[k] = r.special[strings.ToLower(k)]
		}
	}
}

func (r *Redactor) redactSlice(s []any) {
	for _, v := range s {
		if sub, ok := v.(map[string]any); ok {
			r.redactMap(sub)
		}
	}
}

func (r *Redactor) isSensitive(k string) bool {
	lk := strings.ToLower(k)
	if v, ok := r.special[lk]; ok {
		_ = v
		return true
	}
	for _, f := range r.fields {
		if strings.EqualFold(k, f) {
			return true
		}
	}
	return false
}

func isJSONish(b string) bool {
	b = strings.TrimSpace(b)
	return bytes.HasPrefix([]byte(b), []byte("{")) || bytes.HasPrefix([]byte(b), []byte("["))
}
