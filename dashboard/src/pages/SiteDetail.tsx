import { useCallback, useEffect, useState, type FormEvent } from "react"
import { Link, useParams } from "react-router-dom"
import { api, type Rule, type Site } from "../api"

const inputCls =
  "w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 outline-none transition-colors focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/20"

const actionStyles: Record<string, string> = {
  block: "bg-red-500/10 text-red-400 ring-red-500/30",
  challenge: "bg-amber-500/10 text-amber-400 ring-amber-500/30",
  log: "bg-slate-500/10 text-slate-400 ring-slate-500/30",
  allow: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/30",
}

const severityStyles: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-amber-400",
  low: "text-slate-400",
}

const ruleStatusStyles: Record<string, string> = {
  active: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/30",
  enabled: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/30",
  disabled: "bg-slate-500/10 text-slate-400 ring-slate-500/30",
}

export default function SiteDetail() {
  const { id = "" } = useParams()
  const [site, setSite] = useState<Site | null>(null)
  const [rules, setRules] = useState<Rule[]>([])
  const [yaml, setYaml] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [saved, setSaved] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const loadSite = useCallback(() => {
    if (!id) return
    api
      .listSites()
      .then((sites) => {
        const found = sites.find((s) => s.id === id)
        if (found) setSite(found)
        else setError("Site not found")
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load site"))
  }, [id])

  const loadRules = useCallback(() => {
    if (!id) return
    api
      .listRules(id)
      .then(setRules)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load rules"))
  }, [id])

  useEffect(() => {
    setError(null)
    loadSite()
    loadRules()
  }, [loadSite, loadRules])

  async function saveSite(e: FormEvent) {
    e.preventDefault()
    if (!site) return
    setBusy(true)
    setError(null)
    setSaved(null)
    try {
      const { site: updated } = await api.updateSite(site.id, {
        host: site.host,
        upstream: site.upstream,
        path_prefix: site.path_prefix,
        status: site.status,
      })
      setSite(updated)
      setSaved("Site updated")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update site")
    } finally {
      setBusy(false)
    }
  }

  async function saveRule(e: FormEvent) {
    e.preventDefault()
    if (!id) return
    setBusy(true)
    setError(null)
    setSaved(null)
    try {
      await api.createRule(id, yaml)
      setYaml("")
      setSaved("Rule added")
      loadRules()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add rule")
    } finally {
      setBusy(false)
    }
  }

  async function removeRule(ruleId: string) {
    if (!id) return
    if (!window.confirm("Delete this rule?")) return
    setError(null)
    setSaved(null)
    try {
      await api.deleteRule(id, ruleId)
      loadRules()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete rule")
    }
  }

  if (!site && !error) {
    return <div className="text-sm text-slate-500">Loading site...</div>
  }

  return (
    <div className="space-y-8">
      <div>
        <Link to="/sites" className="text-sm text-slate-500 transition-colors hover:text-slate-300">
          &larr; Back to sites
        </Link>
        <h1 className="mt-2 font-mono text-xl font-semibold text-slate-100">
          {site?.host ?? "Site"}
        </h1>
      </div>

      {error && (
        <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}
      {saved && (
        <div className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-400">
          {saved}
        </div>
      )}

      {site && (
        <form
          onSubmit={saveSite}
          className="space-y-4 rounded-lg border border-slate-800 bg-slate-900/60 p-6"
        >
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            Site configuration
          </h2>
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-300">Host</label>
              <input
                value={site.host}
                onChange={(e) => setSite({ ...site, host: e.target.value })}
                className={inputCls}
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-300">Upstream</label>
              <input
                value={site.upstream}
                onChange={(e) => setSite({ ...site, upstream: e.target.value })}
                className={inputCls}
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-300">Path prefix</label>
              <input
                value={site.path_prefix}
                onChange={(e) => setSite({ ...site, path_prefix: e.target.value })}
                className={inputCls}
              />
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium text-slate-300">Status</label>
              <select
                value={site.status}
                onChange={(e) => setSite({ ...site, status: e.target.value })}
                className={inputCls}
              >
                <option value="enabled">enabled</option>
                <option value="disabled">disabled</option>
              </select>
            </div>
          </div>
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={busy}
              className="rounded-md bg-cyan-500 px-3 py-1.5 text-sm font-semibold text-slate-950 transition-colors hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {busy ? "Saving..." : "Save site"}
            </button>
          </div>
        </form>
      )}

      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">
            Custom rules
          </h2>
          <span className="text-xs text-slate-500">
            {rules.length} rule{rules.length === 1 ? "" : "s"}
          </span>
        </div>

        <form onSubmit={saveRule} className="space-y-3 rounded-lg border border-slate-800 bg-slate-900/60 p-6">
          <label htmlFor="rule-yaml" className="mb-1.5 block text-sm font-medium text-slate-300">
            Rule definition (YAML)
          </label>
          <textarea
            id="rule-yaml"
            value={yaml}
            onChange={(e) => setYaml(e.target.value)}
            rows={8}
            spellCheck={false}
            placeholder={
              "name: block-sqli\nmatch:\n  header: User-Agent\n  contains: sqlmap\naction: block"
            }
            className={`${inputCls} resize-y font-mono text-xs`}
          />
          <div className="flex justify-end">
            <button
              type="submit"
              disabled={busy}
              className="rounded-md bg-cyan-500 px-3 py-1.5 text-sm font-semibold text-slate-950 transition-colors hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {busy ? "Saving..." : "Add rule"}
            </button>
          </div>
        </form>

        <div className="overflow-x-auto rounded-lg border border-slate-800">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-900/80 text-xs uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-4 py-3 font-medium">Message</th>
                <th className="px-4 py-3 font-medium">Severity</th>
                <th className="px-4 py-3 font-medium">Action</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Source</th>
                <th className="px-4 py-3 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 bg-slate-900/40">
              {rules.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                    No custom rules for this site.
                  </td>
                </tr>
              )}
              {rules.map((rule) => (
                <tr key={rule.id} className="transition-colors hover:bg-slate-800/30">
                  <td className="px-4 py-3 text-slate-300">{rule.message}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`font-mono text-xs font-semibold uppercase ${
                        severityStyles[rule.severity] ?? severityStyles.medium
                      }`}
                    >
                      {rule.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium uppercase ring-1 ${
                        actionStyles[rule.action] ?? actionStyles.log
                      }`}
                    >
                      {rule.action}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium capitalize ring-1 ${
                        ruleStatusStyles[rule.status] ?? ruleStatusStyles.disabled
                      }`}
                    >
                      {rule.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-500">{rule.source}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => removeRule(rule.id)}
                      className="rounded px-2 py-1 text-xs text-red-400 transition-colors hover:bg-red-500/10"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
