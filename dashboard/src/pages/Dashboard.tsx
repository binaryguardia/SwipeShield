import { useEffect, useState } from "react"
import { api, type Metrics } from "../api"
import StatCard from "../components/StatCard"
import EventFeed from "../components/EventFeed"

export default function Dashboard() {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .metrics()
      .then(setMetrics)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load metrics"))
  }, [])

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Overview</h1>
          <p className="text-sm text-slate-500">Live traffic and protection statistics</p>
        </div>
        {error && <span className="text-sm text-red-400">{error}</span>}
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
        <StatCard label="Sites" value={metrics?.sites ?? "—"} accent="cyan" />
        <StatCard label="Requests" value={metrics?.requests_total ?? "—"} accent="slate" />
        <StatCard label="Blocked" value={metrics?.blocked_total ?? "—"} accent="red" />
        <StatCard label="REST" value={metrics?.by_protocol.rest ?? "—"} accent="green" />
        <StatCard label="GraphQL" value={metrics?.by_protocol.graphql ?? "—"} accent="amber" />
        <StatCard label="gRPC" value={metrics?.by_protocol.grpc ?? "—"} accent="slate" />
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="WebSocket" value={metrics?.by_protocol.websocket ?? "—"} accent="slate" />
        <StatCard label="SSE" value={metrics?.by_protocol.sse ?? "—"} accent="slate" />
        <StatCard label="GraphQL requests" value={metrics?.graphql.requests ?? "—"} accent="amber" />
        <StatCard
          label="Max depth / cost"
          value={metrics ? `${metrics.graphql.max_depth} / ${metrics.graphql.max_cost}` : "—"}
          accent="amber"
        />
      </div>

      <section>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">
          Live events
        </h2>
        <EventFeed />
      </section>
    </div>
  )
}
