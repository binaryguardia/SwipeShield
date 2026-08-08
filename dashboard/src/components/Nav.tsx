import { Link, NavLink } from "react-router-dom"
import { useAuth } from "../auth"

const links = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/sites", label: "Sites", end: false },
  { to: "/fingerprint", label: "Fingerprints", end: false },
]

export default function Nav() {
  const { logout } = useAuth()

  return (
    <header className="sticky top-0 z-40 border-b border-slate-800 bg-slate-950/80 backdrop-blur">
      <div className="mx-auto flex h-14 w-full max-w-6xl items-center justify-between px-4">
        <div className="flex items-center gap-8">
          <Link to="/" className="flex items-center gap-2.5">
            <span className="flex h-7 w-7 items-center justify-center rounded-md bg-cyan-500/15 font-mono text-xs font-bold text-cyan-400 ring-1 ring-cyan-500/40">
              SW
            </span>
            <span className="font-mono text-sm font-semibold tracking-wide text-slate-100">
              SentinelWAF
            </span>
          </Link>
          <nav className="flex items-center gap-1">
            {links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.end}
                className={({ isActive }) =>
                  isActive
                    ? "rounded-md bg-slate-800 px-3 py-1.5 text-sm font-medium text-cyan-300"
                    : "rounded-md px-3 py-1.5 text-sm font-medium text-slate-400 transition-colors hover:bg-slate-800/60 hover:text-slate-200"
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
        </div>
        <button
          onClick={logout}
          className="rounded-md border border-slate-700 px-3 py-1.5 text-sm font-medium text-slate-300 transition-colors hover:border-red-500/50 hover:text-red-400"
        >
          Logout
        </button>
      </div>
    </header>
  )
}
