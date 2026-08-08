// Package telemetry defines the shared metrics snapshot types used by the
// proxy (producer) and the Management API / dashboard (consumer). Keeping
// the structs here avoids an import cycle between proxy and mgmtapi.
package telemetry

import (
	"sync/atomic"
)

// Stats is a point-in-time snapshot of gateway activity. All counters are
// monotonic since process start.
type Stats struct {
	Sites      int               `json:"sites"`
	Requests   uint64            `json:"requests_total"`
	Blocked    uint64            `json:"blocked_total"`
	Challenged uint64            `json:"challenged_total"`
	ByProtocol map[string]uint64 `json:"by_protocol"`
	GraphQL    GraphQLStats      `json:"graphql"`
}

// GraphQLStats tracks parsed-query telemetry.
type GraphQLStats struct {
	Requests uint64 `json:"requests"`
	MaxDepth uint64 `json:"max_depth"`
	MaxCost  uint64 `json:"max_cost"`
}

// Collector accumulates request metrics with lock-free atomic counters.
type Collector struct {
	requests   atomic.Uint64
	blocked    atomic.Uint64
	challenged atomic.Uint64
	protocol   [5]atomic.Uint64 // rest, graphql, grpc, websocket, sse
	gqlReq     atomic.Uint64
	gqlMaxDep  atomic.Uint64
	gqlMaxCost atomic.Uint64
}

// Protocol order used by the fixed-size protocol counter array.
var protocolIndex = map[string]int{
	"rest": 0, "graphql": 1, "grpc": 2, "websocket": 3, "sse": 4,
}

// AddRequest records one request in the given protocol bucket.
func (c *Collector) AddRequest(protocol string) {
	c.requests.Add(1)
	if i, ok := protocolIndex[protocol]; ok {
		c.protocol[i].Add(1)
	}
}

// AddBlocked records a blocked request.
func (c *Collector) AddBlocked() { c.blocked.Add(1) }

// AddChallenged records a challenge response.
func (c *Collector) AddChallenged() { c.challenged.Add(1) }

// AddGraphQL records parsed-query telemetry, tracking running maxima.
func (c *Collector) AddGraphQL(depth, cost uint64) {
	c.gqlReq.Add(1)
	for {
		cur := c.gqlMaxDep.Load()
		if depth <= cur || c.gqlMaxDep.CompareAndSwap(cur, depth) {
			break
		}
	}
	for {
		cur := c.gqlMaxCost.Load()
		if cost <= cur || c.gqlMaxCost.CompareAndSwap(cur, cost) {
			break
		}
	}
}

// Snapshot returns the current stats.
func (c *Collector) Snapshot() Stats {
	return Stats{
		Requests:   c.requests.Load(),
		Blocked:    c.blocked.Load(),
		Challenged: c.challenged.Load(),
		ByProtocol: map[string]uint64{
			"rest": c.protocol[0].Load(), "graphql": c.protocol[1].Load(),
			"grpc": c.protocol[2].Load(), "websocket": c.protocol[3].Load(),
			"sse": c.protocol[4].Load(),
		},
		GraphQL: GraphQLStats{
			Requests: c.gqlReq.Load(),
			MaxDepth: c.gqlMaxDep.Load(),
			MaxCost:  c.gqlMaxCost.Load(),
		},
	}
}
