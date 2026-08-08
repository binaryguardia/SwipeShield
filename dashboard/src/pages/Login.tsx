import { useState, type FormEvent } from "react"
import { useLocation, useNavigate } from "react-router-dom"
import { useAuth } from "../auth"

const inputCls =
  "w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder-slate-600 outline-none transition-colors focus:border-cyan-500/60 focus:ring-2 focus:ring-cyan-500/20"

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const from = (location.state as { from?: string } | null)?.from ?? "/"

  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setBusy(true)
    try {
      await login(username, password)
      navigate(from, { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed")
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3">
          <img
            src="/logo.jpeg"
            alt="SwipeShield"
            className="h-12 w-12 rounded-xl object-cover ring-1 ring-cyan-500/40"
          />
          <div className="text-center">
            <h1 className="font-mono text-lg font-semibold text-slate-100">SwipeShield</h1>
            <p className="text-sm text-slate-500">Management Console</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border border-slate-800 bg-slate-900/60 p-6">
          <div>
            <label htmlFor="username" className="mb-1.5 block text-sm font-medium text-slate-300">
              Username
            </label>
            <input
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
              placeholder="admin"
              className={inputCls}
            />
          </div>
          <div>
            <label htmlFor="password" className="mb-1.5 block text-sm font-medium text-slate-300">
              Password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              placeholder="password"
              className={inputCls}
            />
          </div>

          {error && (
            <div className="rounded-md border border-red-500/40 bg-red-500/10 px-3 py-2 text-sm text-red-400">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-md bg-cyan-500 px-3 py-2 text-sm font-semibold text-slate-950 transition-colors hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {busy ? "Signing in..." : "Sign in"}
          </button>
        </form>

        <p className="mt-4 text-center font-mono text-xs text-slate-600">
          API base: {import.meta.env.VITE_API_BASE || "/api/v1"}
        </p>
      </div>
    </div>
  )
}
