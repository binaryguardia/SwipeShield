const accents = {
  cyan: { border: "border-cyan-500/30", text: "text-cyan-400" },
  green: { border: "border-emerald-500/30", text: "text-emerald-400" },
  red: { border: "border-red-500/30", text: "text-red-400" },
  amber: { border: "border-amber-500/30", text: "text-amber-400" },
  slate: { border: "border-slate-700", text: "text-slate-200" },
} as const

interface StatCardProps {
  label: string
  value: string | number
  accent?: keyof typeof accents
  sub?: string
}

export default function StatCard({ label, value, accent = "slate", sub }: StatCardProps) {
  const a = accents[accent]
  return (
    <div className={`rounded-lg border bg-slate-900/60 p-4 ${a.border}`}>
      <div className="text-xs font-medium uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`mt-2 truncate font-mono text-2xl font-semibold ${a.text}`}>{value}</div>
      {sub && <div className="mt-1 truncate text-xs text-slate-500">{sub}</div>}
    </div>
  )
}
