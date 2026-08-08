// Package graphql parses GraphQL queries into a real AST and computes the
// telemetry SentinelWAF enforces on: query depth, complexity/cost,
// alias/batching attacks, and introspection probes. It deliberately uses a
// full parser (vektah/gqlparser) rather than string matching — string regex
// on GraphQL is exactly what a 2026 WAF must not do.
package graphql

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/binaryguardia/sentinelwaf/internal/config"
	"github.com/binaryguardia/sentinelwaf/internal/decision"
)

// Report is the outcome of one GraphQL inspection.
type Report struct {
	Info decision.GraphQLInfo `json:"info"`
	// Issues are human-readable violations detected (depth bomb, batching,
	// introspection, complexity, malformed).
	Issues []string `json:"issues"`
	// Malformed is true when the query could not be parsed at all.
	Malformed bool `json:"malformed"`
}

// Request is the normalized GraphQL request payload.
type Request struct {
	Query         string
	OperationName string
}

// ExtractQuery pulls the GraphQL query from an HTTP body or query string.
// It supports the standard application/json envelope, raw
// application/graphql bodies, and ?query= GET parameters.
func ExtractQuery(body []byte, queryParam string, contentType string) (Request, error) {
	if strings.Contains(strings.ToLower(contentType), "graphql") && !strings.Contains(strings.ToLower(contentType), "json") {
		return Request{Query: strings.TrimSpace(string(body))}, nil
	}
	trimmed := strings.TrimSpace(string(body))
	if strings.HasPrefix(trimmed, "{") {
		var env struct {
			Query         string `json:"query"`
			OperationName string `json:"operationName"`
		}
		if err := json.Unmarshal(body, &env); err != nil {
			return Request{}, err
		}
		return Request{Query: env.Query, OperationName: env.OperationName}, nil
	}
	if queryParam != "" {
		return Request{Query: queryParam}, nil
	}
	if trimmed != "" {
		return Request{Query: trimmed}, nil
	}
	return Request{}, fmt.Errorf("no query present")
}

// Inspect parses and scores a GraphQL query against the site policy.
// A query that fails to parse is reported as Malformed — the caller decides
// whether that means block (default per RULES.md) or log.
func Inspect(req Request, cfg *config.GraphQLConfig) Report {
	var rep Report
	rep.Info.Query = truncate(req.Query, 2048)
	rep.Info.OperationName = req.OperationName

	if strings.TrimSpace(req.Query) == "" {
		rep.Malformed = true
		rep.Issues = append(rep.Issues, "empty query")
		return rep
	}

	doc, err := parser.ParseQuery(&ast.Source{Input: req.Query})
	if err != nil {
		rep.Malformed = true
		rep.Issues = append(rep.Issues, "malformed query: "+firstErr(err))
		return rep
	}

	// Batching attack: multiple operations in one request.
	if len(doc.Operations) > 1 {
		rep.Issues = append(rep.Issues, fmt.Sprintf("batching: %d operations in one request", len(doc.Operations)))
	}

	for _, op := range doc.Operations {
		if op.Name != "" {
			rep.Info.OperationName = op.Name
		}
		depth, complexity, aliases, introspection := walk(op.SelectionSet, 0)
		if depth > rep.Info.Depth {
			rep.Info.Depth = depth
		}
		rep.Info.Complexity += complexity
		rep.Info.AliasCount += aliases
		if introspection {
			rep.Info.Introspection = true
		}
	}

	if cfg != nil {
		if cfg.MaxDepth > 0 && rep.Info.Depth > cfg.MaxDepth {
			rep.Issues = append(rep.Issues, fmt.Sprintf("depth bomb: depth %d exceeds limit %d", rep.Info.Depth, cfg.MaxDepth))
		}
		if cfg.MaxComplexity > 0 && rep.Info.Complexity > cfg.MaxComplexity {
			rep.Issues = append(rep.Issues, fmt.Sprintf("complexity: cost %d exceeds limit %d", rep.Info.Complexity, cfg.MaxComplexity))
		}
		if cfg.BlockIntrospection && rep.Info.Introspection {
			rep.Issues = append(rep.Issues, "introspection query")
		}
		if cfg.BlockBatching && len(doc.Operations) > 1 {
			rep.Issues = append(rep.Issues, "batching attack blocked")
		}
		if cfg.MaxAliases > 0 && rep.Info.AliasCount > cfg.MaxAliases {
			rep.Issues = append(rep.Issues, fmt.Sprintf("alias abuse: %d aliases exceeds limit %d", rep.Info.AliasCount, cfg.MaxAliases))
		}
	}
	return rep
}

// walk computes depth, complexity, alias count and introspection flag for a
// selection set. Complexity is a per-field additive cost model where a field
// costs 1 plus the cost of its children.
func walk(ss ast.SelectionSet, level int) (depth, complexity, aliases int, introspection bool) {
	if len(ss) == 0 {
		return level, 0, 0, false
	}
	depth = level
	for _, sel := range ss {
		switch s := sel.(type) {
		case *ast.Field:
			if s.Alias != "" && s.Alias != s.Name {
				aliases++ // explicit alias (response-name rewrite) = amplification signal
			}
			if s.Name == "__schema" || s.Name == "__type" || s.Name == "__typename" {
				introspection = true
			}
			cd, cc, ca, ci := walk(s.SelectionSet, level+1)
			if cd > depth {
				depth = cd
			}
			complexity += 1 + cc
			aliases += ca
			introspection = introspection || ci
		case *ast.InlineFragment:
			cd, cc, ca, ci := walk(s.SelectionSet, level)
			if cd > depth {
				depth = cd
			}
			complexity += cc
			aliases += ca
			introspection = introspection || ci
		case *ast.FragmentSpread:
			// Fragment definitions are walked separately; depth counted as
			// a single step to avoid double counting.
			complexity++
		}
	}
	return depth, complexity, aliases, introspection
}

func firstErr(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
