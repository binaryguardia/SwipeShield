import { useCallback, useEffect, useState, type FormEvent } from "react"
import { api, type BlocklistEntry } from "../api"

const inputCls =
  "w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 outline-none transition-colors focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/20"

export default function Fingerprints() {
  const [entries, setEntries] = useState<BlocklistEntry[]>([])
  const [ja4, setJa4] = useState("")
  const [note, setNote] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    api
      .listBlocklist()
      .then(setEntries)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load blocklist"))
  }, [])

  useEffect(load, [load])

  async function handleAdd(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.addBlocklist(ja4, note)
      setJa4("")
      setNote("")
      load()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add fingerprint")
    } finally {
      setBusy(false)
    }
  }

  async function handleRemove(ja4Hash: string) {
    if (!window.confirm(`Remove JA4 ${ja4Hash} from the blocklist?`)) return
    setError(null)
    try {
      await api.deleteBlocklist(ja4Hash)
      load()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove fingerprint")
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-slate-100">JA4 Fingerprint Blocklist</h1>
        <p className="text-sm text-slate-500">TLS client fingerprints blocked at the edge</p>
      </div>

      {error && (
        <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      <form
        onSubmit={handleAdd}
        className="grid gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-6 sm:grid-cols-[1fr_2fr_auto] sm:items-end"
      >
        <div>
          <label htmlFor="ja4" className="mb-1.5 block text-sm font-medium text-slate-300">
            JA4 hash
          </label>
          <input
            id="ja4"
            value={ja4}
            onChange={(e) => setJa4(e.target.value)}
            required
            placeholder="t13d1517h2_8daaf6152771_b9b8a5aaf23e"
            className={`${inputCls} font-mono text-xs`}
          />
        </div>
        <div>
          <label htmlFor="ja4-note" className="mb-1.5 block text-sm font-medium text-slate-300">
            Note
          </label>
          <input
            id="ja4-note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Reason for blocking"
            className={inputCls}
          />
        </div>
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-cyan-500 px-4 py-2 text-sm font-semibold text-slate-950 transition-colors hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {busy ? "Adding..." : "Add"}
        </button>
      </form>

      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900/80 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-3 font-medium">JA4</th>
              <th className="px-4 py-3 font-medium">Added</th>
              <th className="px-4 py-3 font-medium">Note</th>
              <th className="px-4 py-3 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {entries.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-8 text-center text-slate-500">
                  Blocklist is empty.
                </td>
              </tr>
            )}
            {entries.map((entry) => (
              <tr key={entry.ja4} className="transition-colors hover:bg-slate-800/30">
                <td className="px-4 py-3 font-mono text-xs text-cyan-300">{entry.ja4}</td>
                <td className="px-4 py-3 font-mono text-xs text-slate-500">{entry.added_at}</td>
                <td className="px-4 py-3 text-slate-400">{entry.note}</td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => handleRemove(entry.ja4)}
                    className="rounded px-2 py-1 text-xs text-red-400 transition-colors hover:bg-red-500/10"
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
