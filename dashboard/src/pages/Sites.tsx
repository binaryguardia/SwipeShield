import {
  useCallback,
  useEffect,
  useState,
  type ChangeEvent,
  type FormEvent,
  type ReactNode,
} from "react"
import { Link } from "react-router-dom"
import { api, type Site } from "../api"

const inputCls =
  "w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 outline-none transition-colors focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/20"

const statusStyles: Record<string, string> = {
  enabled: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/30",
  active: "bg-emerald-500/10 text-emerald-400 ring-emerald-500/30",
  disabled: "bg-slate-500/10 text-slate-400 ring-slate-500/30",
}

interface SiteFormState {
  host: string
  upstream: string
  path_prefix: string
  status: string
}

interface ModalProps {
  title: string
  onClose: () => void
  children: ReactNode
}

function Modal({ title, onClose, children }: ModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        className="w-full max-w-md rounded-lg border border-slate-700 bg-slate-900 p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-base font-semibold text-slate-100">{title}</h2>
          <button
            onClick={onClose}
            className="rounded p-1 text-slate-500 transition-colors hover:bg-slate-800 hover:text-slate-300"
            aria-label="Close"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6 6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}

interface FieldProps {
  label: string
  hint?: string
  children: ReactNode
}

function Field({ label, hint, children }: FieldProps) {
  return (
    <div>
      <label className="mb-1.5 block text-sm font-medium text-slate-300">{label}</label>
      {children}
      {hint && <p className="mt-1 text-xs text-slate-600">{hint}</p>}
    </div>
  )
}

interface SiteFormProps {
  initial: SiteFormState
  showStatus: boolean
  submitLabel: string
  busy: boolean
  onSubmit: (form: SiteFormState) => void
  onCancel: () => void
}

function SiteForm({ initial, showStatus, submitLabel, busy, onSubmit, onCancel }: SiteFormProps) {
  const [form, setForm] = useState<SiteFormState>(initial)
  const set =
    (key: keyof SiteFormState) => (e: ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
      setForm((f) => ({ ...f, [key]: e.target.value }))

  function handleSubmit(e: FormEvent) {
    e.preventDefault()
    onSubmit(form)
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <Field label="Host" hint="e.g. api.example.com">
        <input value={form.host} onChange={set("host")} required placeholder="api.example.com" className={inputCls} />
      </Field>
      <Field label="Upstream" hint="e.g. http://127.0.0.1:9000">
        <input
          value={form.upstream}
          onChange={set("upstream")}
          required
          placeholder="http://127.0.0.1:9000"
          className={inputCls}
        />
      </Field>
      <Field label="Path prefix">
        <input value={form.path_prefix} onChange={set("path_prefix")} placeholder="/" className={inputCls} />
      </Field>
      {showStatus && (
        <Field label="Status">
          <select value={form.status} onChange={set("status")} className={inputCls}>
            <option value="enabled">enabled</option>
            <option value="disabled">disabled</option>
          </select>
        </Field>
      )}
      <div className="flex justify-end gap-2 pt-2">
        <button
          type="button"
          onClick={onCancel}
          className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition-colors hover:bg-slate-800"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-cyan-500 px-3 py-1.5 text-sm font-semibold text-slate-950 transition-colors hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {busy ? "Saving..." : submitLabel}
        </button>
      </div>
    </form>
  )
}

const newSiteForm: SiteFormState = { host: "", upstream: "", path_prefix: "/", status: "enabled" }

export default function Sites() {
  const [sites, setSites] = useState<Site[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing] = useState<Site | null>(null)
  const [deleting, setDeleting] = useState<Site | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    api
      .listSites()
      .then(setSites)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load sites"))
  }, [])

  useEffect(load, [load])

  function closeModals() {
    setShowCreate(false)
    setEditing(null)
    setDeleting(null)
  }

  async function createSite(form: SiteFormState) {
    setBusy(true)
    setError(null)
    try {
      await api.createSite({ host: form.host, upstream: form.upstream, path_prefix: form.path_prefix })
      closeModals()
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create site")
    } finally {
      setBusy(false)
    }
  }

  async function updateSite(form: SiteFormState) {
    if (!editing) return
    setBusy(true)
    setError(null)
    try {
      await api.updateSite(editing.id, {
        host: form.host,
        upstream: form.upstream,
        path_prefix: form.path_prefix,
        status: form.status,
      })
      closeModals()
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to update site")
    } finally {
      setBusy(false)
    }
  }

  async function deleteSite() {
    if (!deleting) return
    setBusy(true)
    setError(null)
    try {
      await api.deleteSite(deleting.id)
      closeModals()
      load()
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete site")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-slate-100">Sites</h1>
          <p className="text-sm text-slate-500">Managed origin sites and their status</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="rounded-md bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 transition-colors hover:bg-cyan-400"
        >
          Add site
        </button>
      </div>

      {error && (
        <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      <div className="overflow-x-auto rounded-lg border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900/80 text-xs uppercase tracking-wider text-slate-500">
            <tr>
              <th className="px-4 py-3 font-medium">Host</th>
              <th className="px-4 py-3 font-medium">Upstream</th>
              <th className="px-4 py-3 font-medium">Path prefix</th>
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 text-right font-medium">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 bg-slate-900/40">
            {!sites && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                  Loading...
                </td>
              </tr>
            )}
            {sites?.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                  No sites configured.
                </td>
              </tr>
            )}
            {sites?.map((site) => (
              <tr key={site.id} className="transition-colors hover:bg-slate-800/30">
                <td className="px-4 py-3">
                  <Link
                    to={`/sites/${site.id}`}
                    className="font-mono text-cyan-300 hover:text-cyan-200 hover:underline"
                  >
                    {site.host}
                  </Link>
                </td>
                <td className="px-4 py-3 font-mono text-slate-300">{site.upstream}</td>
                <td className="px-4 py-3 font-mono text-slate-400">{site.path_prefix}</td>
                <td className="px-4 py-3">
                  <span
                    className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium capitalize ring-1 ${
                      statusStyles[site.status] ?? statusStyles.disabled
                    }`}
                  >
                    {site.status}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex justify-end gap-2">
                    <Link
                      to={`/sites/${site.id}`}
                      className="rounded px-2 py-1 text-xs text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-200"
                    >
                      Details
                    </Link>
                    <button
                      onClick={() => setEditing(site)}
                      className="rounded px-2 py-1 text-xs text-slate-400 transition-colors hover:bg-slate-800 hover:text-slate-200"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => setDeleting(site)}
                      className="rounded px-2 py-1 text-xs text-red-400 transition-colors hover:bg-red-500/10"
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {(showCreate || editing) && (
        <Modal title={showCreate ? "Add site" : "Edit site"} onClose={closeModals}>
          <SiteForm
            key={editing ? editing.id : "new"}
            initial={editing ?? newSiteForm}
            showStatus={Boolean(editing)}
            submitLabel={showCreate ? "Create" : "Save changes"}
            busy={busy}
            onSubmit={showCreate ? createSite : updateSite}
            onCancel={closeModals}
          />
        </Modal>
      )}

      {deleting && (
        <Modal title="Delete site" onClose={closeModals}>
          <div className="space-y-4">
            <p className="text-sm text-slate-400">
              Delete <span className="font-mono text-slate-200">{deleting.host}</span>? This cannot be
              undone.
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={closeModals}
                className="rounded-md border border-slate-700 px-3 py-1.5 text-sm text-slate-300 transition-colors hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={deleteSite}
                disabled={busy}
                className="rounded-md bg-red-500 px-3 py-1.5 text-sm font-semibold text-white transition-colors hover:bg-red-400 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {busy ? "Deleting..." : "Delete"}
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
