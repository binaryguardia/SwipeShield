package graphql

import (
	"fmt"
	"strings"
	"testing"

	"github.com/binaryguardia/swipeshield/internal/config"
)

func gqlCfg() *config.GraphQLConfig {
	return &config.GraphQLConfig{
		Enabled: true, MaxDepth: 4, MaxComplexity: 50,
		BlockIntrospection: true, BlockBatching: true, MaxAliases: 5,
	}
}

func TestGraphQLDepthBomb(t *testing.T) {
	q := "{ a { b { c { d { e { f { g } } } } } } }"
	rep := Inspect(Request{Query: q}, gqlCfg())
	if rep.Malformed {
		t.Fatalf("not malformed: %+v", rep.Issues)
	}
	if rep.Info.Depth != 7 {
		t.Fatalf("depth = %d, want 7", rep.Info.Depth)
	}
	if !hasIssue(rep.Issues, "depth bomb") {
		t.Fatalf("depth bomb not flagged: %+v", rep.Issues)
	}
}

func TestGraphQLBatching(t *testing.T) {
	q := "query A { user(id: 1) { name } } query B { post(id: 2) { title } }"
	rep := Inspect(Request{Query: q}, gqlCfg())
	if !hasIssue(rep.Issues, "batching") {
		t.Fatalf("batching not flagged: %+v", rep.Issues)
	}
	if !hasIssue(rep.Issues, "batching attack blocked") {
		t.Fatalf("block flag missing: %+v", rep.Issues)
	}
}

func TestGraphQLIntrospection(t *testing.T) {
	q := `query { __schema { types { name } } }`
	rep := Inspect(Request{Query: q}, gqlCfg())
	if !rep.Info.Introspection {
		t.Fatal("introspection not detected")
	}
	if !hasIssue(rep.Issues, "introspection") {
		t.Fatalf("introspection not flagged: %+v", rep.Issues)
	}
}

func TestGraphQLComplexity(t *testing.T) {
	// A single parent with 60 children exceeds MaxComplexity 50 while
	// staying shallow (cost model: 1 + sum of children).
	var fields strings.Builder
	for i := 0; i < 60; i++ {
		fields.WriteString(" f" + fmt.Sprintf("%d", i))
	}
	q := "{ a {" + fields.String() + " } }"
	rep := Inspect(Request{Query: q}, gqlCfg())
	if rep.Info.Complexity <= 50 {
		t.Fatalf("complexity %d should exceed 50", rep.Info.Complexity)
	}
	if !hasIssue(rep.Issues, "complexity") {
		t.Fatalf("complexity not flagged: %+v", rep.Issues)
	}
}

func TestGraphQLAliasAbuse(t *testing.T) {
	q := `{ a0: user { name } a1: user { name } a2: user { name } a3: user { name } a4: user { name } a5: user { name } a6: user { name } }`
	rep := Inspect(Request{Query: q}, gqlCfg())
	if !hasIssue(rep.Issues, "alias") {
		t.Fatalf("alias abuse not flagged: %+v", rep.Issues)
	}
}

func TestGraphQLMalformed(t *testing.T) {
	rep := Inspect(Request{Query: "{ this is not valid gql"}, gqlCfg())
	if !rep.Malformed {
		t.Fatalf("malformed query not flagged: %+v", rep.Issues)
	}
}

func TestGraphQLBenignQueryPasses(t *testing.T) {
	q := `query GetUser($id: ID!) { user(id: $id) { id name } }`
	rep := Inspect(Request{Query: q, OperationName: "GetUser"}, gqlCfg())
	if rep.Malformed {
		t.Fatalf("benign query marked malformed: %+v", rep.Issues)
	}
	if len(rep.Issues) != 0 {
		t.Fatalf("benign query flagged: %+v", rep.Issues)
	}
	if rep.Info.OperationName != "GetUser" {
		t.Fatalf("op name = %q", rep.Info.OperationName)
	}
	if rep.Info.Depth > 4 {
		t.Fatalf("benign depth too high: %d", rep.Info.Depth)
	}
	if rep.Info.AliasCount > 5 {
		t.Fatalf("benign field count too high: %d", rep.Info.AliasCount)
	}
}

func TestGraphQLSimpleQueryPasses(t *testing.T) {
	rep := Inspect(Request{Query: `{ hello }`}, gqlCfg())
	if rep.Malformed || len(rep.Issues) != 0 {
		t.Fatalf("simple query flagged: %+v", rep.Issues)
	}
}

func hasIssue(issues []string, sub string) bool {
	for _, s := range issues {
		if len(s) >= len(sub) && indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
