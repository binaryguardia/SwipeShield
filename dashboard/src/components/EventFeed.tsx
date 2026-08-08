import { useEffect, useState } from "react"
import { API_BASE, getToken, type Event } from "../api"

const actionStyles: Record<Event["action"], string> = {
  block: "bg-red-500/10 text-red-400 ring-red-500/30",
  challenge: "bg-amber-500/10 text-amber-400 ring-amber-500/30",
  log: "bg-slate-500/10 text-slate-400 ring-slate-500/30",
  allow: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/30",
}

function formatTime(ts: string): string {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return ts
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
}

export default function EventFeed() {
  const [events, setEvents] = useState<Event[]>([])

  useEffect(() => {
    const token = getToken() ?? ""
    const url = `${API_BASE}/events?token=${encodeURIComponent(token)}`
    const es = new EventSource(url)

    const onMessage = (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data as string) as Event
        if (data && typeof data.action === "string") {
          setEvents((prev) => [data, ...prev].slice(0, 30))
        }
      } catch {
        /* ignore malformed frames */
      }
    }

    es.onmessage = onMessage
    return () => es.close()
  }, [])

  if (events.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-8 text-center text-sm text-slate-500">
        Waiting for events...
      </div>
    )
  }

  return (
    <div className="overflow-hidden rounded-lg border border-slate-800">
      <div className="max-h-96 divide-y divide-slate-800 overflow-y-auto bg-slate-900/40">
        {events.map((ev, i) => (
          <div
            key={`${ev.ts}-${i}`}
            className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5 text-sm"
          >
            <span className="font-mono text-xs text-slate-500">{formatTime(ev.ts)}</span>
            <span className="font-mono text-xs text-slate-400">{ev.site_id || "global"}</span>
            <span className="font-mono text-xs text-slate-400">{ev.client_ip}</span>
            <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-xs uppercase text-slate-400">
              {ev.protocol}
            </span>
            <span
              className={`rounded px-1.5 py-0.5 font-mono text-xs font-semibold uppercase ring-1 ${
                actionStyles[ev.action] ?? actionStyles.log
              }`}
            >
              {ev.action}
            </span>
            <span className="text-xs text-slate-500">{ev.reason}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
