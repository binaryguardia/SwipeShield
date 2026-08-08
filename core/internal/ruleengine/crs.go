package ruleengine

import (
	"fmt"
	"regexp"
	"strings"
)

// crsDirectivesFor returns Coraza SecLang directives enabling the requested
// OWASP CRS rule classes. Rule IDs follow the OWASP CRS 4.x numbering
// convention (920 protocol, 930 LFI, 931 path traversal, 932 RCE, 941 XSS,
// 942 SQLi). This embedded set is CRS-derived; the full corpus can be loaded
// from disk via Engine.LoadCRSFile.
func crsDirectivesFor(t CRSToggles) string {
	var sb strings.Builder
	sb.WriteString("SecRuleEngine On\n")
	sb.WriteString("SecRequestBodyAccess On\n")
	sb.WriteString("SecRequestBodyLimit 4194304\n")
	sb.WriteString("SecRequestBodyNoFilesLimit 1048576\n")
	sb.WriteString("SecResponseBodyAccess Off\n")
	sb.WriteString("SecDefaultAction \"phase:2,pass,log\"\n")
	sb.WriteString("SecAuditEngine Off\n")

	if t.Protocol {
		sb.WriteString(protocolRules)
	}
	if t.PathTraversal {
		sb.WriteString(pathTraversalRules)
	}
	if t.LFI {
		sb.WriteString(lfiRules)
	}
	if t.RCE {
		sb.WriteString(rceRules)
	}
	if t.XSS {
		sb.WriteString(xssRules)
	}
	if t.SQLi {
		sb.WriteString(sqliRules)
	}
	return sb.String()
}

// action maps a toggle to the standard SecLang deny action used by CRS.
const crsDeny = "deny,status:403,log,tag:'CRS'"

var protocolRules = strings.Join([]string{
	`SecRule REQUEST_METHOD "!@rx ^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|TRACE)$" "id:920100,` + crsDeny + `,msg:'Invalid HTTP Request Line'",logdata:'%{MATCHED_VAR}'"`,
	`SecRule REQUEST_PROTOCOL "!@rx ^HTTP/\d(?:\.\d)?$" "id:920110,` + crsDeny + `,msg:'Invalid HTTP version'"`,
	`SecRule REQUEST_METHOD "@rx ^CONNECT$" "id:920160,` + crsDeny + `,msg:'Method CONNECT is not allowed'"`,
	`SecRule REQUEST_URI "@rx (?:\.\./|\.\.\\)" "id:920280,` + crsDeny + `,msg:'Request has an invalid range header'"`,
	`SecRule REQUEST_HEADERS:Content-Length "!@rx ^\s*(\d+)\s*$" "id:920170,` + crsDeny + `,msg:'Invalid Content-Length header'"`,
	`SecRule REQUEST_HEADERS_NAMES "@rx (?:\x00|\n|\r)" "id:920180,` + crsDeny + `,msg:'Invalid character in request header name'"`,
	`SecRule REQUEST_HEADERS "@rx (?:\x00|[\n\r])" "id:920181,` + crsDeny + `,msg:'Invalid character in request header'"`,
	`SecRule REQUEST_URI "@rx [\x00-\x08\x0b\x0c\x0e-\x1f\x7f]" "id:920270,` + crsDeny + `,msg:'Invalid character in request'"`,
}, "\n")

var pathTraversalRules = strings.Join([]string{
	`SecRule REQUEST_URI_RAW|ARGS "@rx (?:\.\./|\.\.\\)+" "id:931130,` + crsDeny + `,msg:'Possible Remote File Inclusion (RFI) Attack'"`,
	`SecRule REQUEST_URI_RAW|ARGS "@rx (?:^|[\?&])(?:file|path|dir|url|uri)=.*(?:\.\.%2f|%2e%2e)" "id:931150,` + crsDeny + `,msg:'Path traversal attempt'"`,
	`SecRule REQUEST_URI_RAW|ARGS "@rx /(?:etc|boot|home|root|proc)/" "id:930120,` + crsDeny + `,msg:'OS File Access Attempt'"`,
}, "\n")

var lfiRules = strings.Join([]string{
	`SecRule REQUEST_URI_RAW|ARGS "@rx (?:file|path|include|require)(?:\.php)?=.*\.(?:php|inc|conf|ini|log|txt|env)" "id:930110,` + crsDeny + `,msg:'Possible Local File Inclusion'",logdata:'%{MATCHED_VAR}'"`,
	`SecRule ARGS "@rx (?:php|data|file|expect|zip|phar)://" "id:930121,` + crsDeny + `,msg:'PHP/Stream wrapper used'"`,
}, "\n")

var rceRules = strings.Join([]string{
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?:;|&&|\|\|)\s*(?:id|whoami|cat|ls|pwd|uname|wget|curl|nc|bash|sh|perl|python|ruby|php|nmap|sqlmap|ping)\b" "id:932160,` + crsDeny + `,msg:'Remote Command Execution: Unix Command Injection'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?:cmd|command|exec|run)=.*(?:cmd\.exe|powershell|wmic|netstat|ipconfig|whoami)" "id:932170,` + crsDeny + `,msg:'Remote Command Execution: Windows Command Injection'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?:\(\)\s*\{|\{:[^}]+\}|java|javac|groovy|jshell|eval\s*\()" "id:932180,` + crsDeny + `,msg:'RCE injection attempt (shell metacharacters)'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?:\\\\x[0-9a-f]{2}|\\\\[0-7]{3}){2,}" "id:932185,` + crsDeny + `,msg:'Escaped byte sequence in RCE attempt'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?:system|passthru|exec|shell_exec|proc_open|popen|pcntl_exec|assert)\s*\(" "id:932200,` + crsDeny + `,msg:'RCE PHP function call'"`,
}, "\n")

var xssRules = strings.Join([]string{
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:<script[\s>]|<\/script>|javascript:)" "id:941100,` + crsDeny + `,msg:'XSS Attack Detected via libinjection'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:on(?:load|error|click|mouseover|focus|blur|submit|keydown|keyup|change)\s*=)" "id:941110,` + crsDeny + `,msg:'XSS Filter - Category 1: Script Tag Vector'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:<svg|iframe|object|embed|video|audio|math)[\s/>]" "id:941140,` + crsDeny + `,msg:'XSS Attack Detected - Object/Embed/Script'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:alert|prompt|confirm)\s*\(" "id:941160,` + crsDeny + `,msg:'NoScript XSS InjectionChecker'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:%3c(?:script|svg|iframe)|%3e)" "id:941170,` + crsDeny + `,msg:'XSS - HTML encoded attack'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:document\.cookie|window\.location|\.innerHTML|document\.location)" "id:941190,` + crsDeny + `,msg:'XSS using HTML/JS mutation'"`,
}, "\n")

var sqliRules = strings.Join([]string{
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:'|\")\s*(?:--|#|;)" "id:942100,` + crsDeny + `,msg:'SQL Injection Attack detected via libinjection'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:union\s+(?:all\s+|distinct\s+)?select|select\s+.*\s+from\s+)" "id:942120,` + crsDeny + `,msg:'SQL Injection Attack Detected via libinjection'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:sleep\s*\(|\bwaitfor\s+delay\b|benchmark\s*\()" "id:942160,` + crsDeny + `,msg:'Detects blind sqli tests using sleep() or benchmark()'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:information_schema|sys\.|pg_catalog|sqlite_master)" "id:942200,` + crsDeny + `,msg:'Detects MySQL comment / space obfuscated injection'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:1\s*=\s*1|1\s*=\s*2|\sor\s+.*=\s*|and\s+.*=\s*)" "id:942230,` + crsDeny + `,msg:'Detects conditional SQL injection attempts'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|create\s+table|alter\s+table)" "id:942251,` + crsDeny + `,msg:'Detects MySQL in-band SQL injection attacks'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:;)\s*(?:drop|delete|insert|update|select|union|alter)\s" "id:942270,` + crsDeny + `,msg:'Basic SQL injection'"`,
	`SecRule ARGS|REQUEST_URI_RAW "@rx (?i)(?:\\\\x[0-9a-f]{2}|%27|%22|%u0027|%u0022)" "id:942300,` + crsDeny + `,msg:'Detects MySQL comment / space obfuscated injection and backtick termination'"`,
}, "\n")

// Describe returns a human-readable list of the active CRS classes.
func (t CRSToggles) Describe() []string {
	var out []string
	if t.Protocol {
		out = append(out, "920-protocol")
	}
	if t.PathTraversal {
		out = append(out, "931/930-path-traversal")
	}
	if t.LFI {
		out = append(out, "930-lfi")
	}
	if t.RCE {
		out = append(out, "932-rce")
	}
	if t.XSS {
		out = append(out, "941-xss")
	}
	if t.SQLi {
		out = append(out, "942-sqli")
	}
	return out
}

// nativeBodyRule is a Go-side raw-body pattern. It exists because Coraza's
// REQUEST_BODY collection is not populated through the raw transaction API,
// so CRS-style rules that target ARGS miss raw bodies (JSON, GraphQL, text).
// Patterns are RE2 (Go regexp) per RULES.md.
type nativeBodyRule struct {
	ID      string
	Message string
	Re      *regexp.Regexp
}

var nativeXSS = []*nativeBodyRule{
	{ID: "NATIVE-941100", Message: "XSS in raw request body", Re: regexp.MustCompile(`(?i)<(?:script|svg|iframe|object|embed)[\s/>]|</?script|javascript:`)},
	{ID: "NATIVE-941110", Message: "XSS event-handler vector", Re: regexp.MustCompile(`(?i)on(?:load|error|click|mouseover|focus|blur|submit|change|keydown|keyup)\s*=`)},
}

var nativeSQLi = []*nativeBodyRule{
	{ID: "NATIVE-942100", Message: "SQLi quote-terminator", Re: regexp.MustCompile(`(?i)['"]\s*(?:--|#|;|/\*)`)},
	{ID: "NATIVE-942120", Message: "SQLi union select", Re: regexp.MustCompile(`(?i)union\s+(?:all\s+|distinct\s+)?select\b`)},
	{ID: "NATIVE-942160", Message: "SQLi time-based", Re: regexp.MustCompile(`(?i)sleep\s*\(|\bwaitfor\s+delay\b|benchmark\s*\(`)},
	{ID: "NATIVE-942200", Message: "SQLi metadata tables", Re: regexp.MustCompile(`(?i)information_schema|pg_catalog|sqlite_master|sys\.tables`)},
	{ID: "NATIVE-942230", Message: "SQLi conditional", Re: regexp.MustCompile(`(?i)\b1\s*=\s*[12]\b|\bor\s+['\"]|' or '|\b(?:and|or)\s+.*=\s*`)},
}

var nativeRCE = []*nativeBodyRule{
	{ID: "NATIVE-932200", Message: "RCE function call", Re: regexp.MustCompile(`(?i)\b(?:system|passthru|shell_exec|exec|proc_open|popen|eval|assert)\s*\(`)},
	{ID: "NATIVE-932160", Message: "RCE command chaining", Re: regexp.MustCompile(`(?i)(?:;|&&|\|\|)\s*(?:id|whoami|cat\s+|ls\s|rm\s|curl\s|wget\s|nc\s|bash\s|sh\s|python|perl|php|nmap|sqlmap)\b`)},
	{ID: "NATIVE-932180", Message: "RCE shell metacharacters", Re: regexp.MustCompile(`(?:\$\(|\$\{|\$\x60|` + "`" + `[^` + "`" + `]+` + "`" + `)`)},
}

// nativeTraversalRaw matches path-traversal vectors that survive URL escaping
// (single- and double-encoded slashes / dots), which the REQUEST_URI CRS rule
// misses because ProcessURI receives the raw, escaped request target.
var nativeTraversalRaw = regexp.MustCompile(`(?i)(?:%2e%2e[%2f\\]|%252e%252e%252f|\.\.%2f|\.\.%5c|\.\.%252f|%2e\.%2f|\.%2e%2f|%00)`)
var nativeTraversalDecoded = regexp.MustCompile(`(?:\.\.[/\\])`)

// evaluateNativeURI scans both the raw (escaped) request target and the
// decoded path for traversal sequences. Any hit blocks.
func (t CRSToggles) evaluateNativeURI(rawURI, decodedPath string) []Match {
	if !t.PathTraversal {
		return nil
	}
	var out []Match
	for _, m := range []struct {
		id, msg string
		re      *regexp.Regexp
		s       string
	}{
		{"NATIVE-920280", "Encoded path traversal", nativeTraversalRaw, rawURI},
		{"NATIVE-920281", "Path traversal", nativeTraversalDecoded, decodedPath},
	} {
		if m.re.MatchString(m.s) {
			out = append(out, Match{
				RuleID: m.id, Message: m.msg, Action: ActionBlock,
				Phase: PhaseRequest, Engine: "native", Severity: "CRITICAL",
				MatchedData: truncate(matchedSubstr(m.re, m.s), 128),
			})
		}
	}
	return out
}

// evaluateNativeBody scans the raw request body with native patterns.
// It returns matches with the block action; the caller appends them.
func (t CRSToggles) evaluateNativeBody(body []byte) []Match {
	if len(body) == 0 {
		return nil
	}
	var rules []*nativeBodyRule
	if t.XSS {
		rules = append(rules, nativeXSS...)
	}
	if t.SQLi {
		rules = append(rules, nativeSQLi...)
	}
	if t.RCE {
		rules = append(rules, nativeRCE...)
	}
	var out []Match
	s := string(body)
	for _, r := range rules {
		if r.Re.MatchString(s) {
			out = append(out, Match{
				RuleID: r.ID, Message: r.Message, Action: ActionBlock,
				Phase: PhaseRequest, Engine: "native", Severity: "CRITICAL",
				MatchedData: truncate(matchedSubstr(r.Re, s), 128),
			})
		}
	}
	return out
}

func matchedSubstr(re *regexp.Regexp, s string) string {
	loc := re.FindStringIndex(s)
	if loc == nil {
		return ""
	}
	return s[loc[0]:loc[1]]
}

var _ = fmt.Sprintf
