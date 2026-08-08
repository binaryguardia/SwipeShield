export interface Site {
  id: string
  host: string
  upstream: string
  path_prefix: string
  status: string
}

export interface Rule {
  id: string
  message: string
  severity: string
  action: string
  status: string
  source: string
}

export interface BlocklistEntry {
  ja4: string
  added_at: string
  note: string
}

export interface Metrics {
  sites: number
  requests_total: number
  blocked_total: number
  by_protocol: {
    rest: number
    graphql: number
    grpc: number
    websocket: number
    sse: number
  }
  graphql: {
    requests: number
    max_depth: number
    max_cost: number
  }
}

export interface Event {
  ts: string
  site_id: string
  client_ip: string
  action: "allow" | "block" | "challenge" | "log"
  protocol: string
  reason: string
}

export const API_BASE: string = (import.meta.env.VITE_API_BASE as string | undefined) || "/api/v1"

const TOKEN_KEY = "sentinelwaf_token"

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

let unauthorizedHandler: (() => void) | null = null

export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

interface RequestOptions extends RequestInit {
  json?: unknown
}

async function request<T>(path: string, init: RequestOptions = {}): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {}
  const body: BodyInit | null | undefined = init.json !== undefined ? JSON.stringify(init.json) : init.body
  if (init.json !== undefined) headers["Content-Type"] = "application/json"
  if (token) headers["Authorization"] = `Bearer ${token}`

  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}`, { ...init, body, headers })
  } catch {
    throw new ApiError(0, "Network error: unable to reach the SentinelWAF API")
  }

  if (res.status === 401) {
    clearToken()
    unauthorizedHandler?.()
    throw new ApiError(401, "Unauthorized")
  }
  if (res.status === 204) return undefined as T
  if (!res.ok) {
    let message = `Request failed (${res.status})`
    try {
      const data = await res.json()
      if (data && typeof data.message === "string") message = data.message
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message)
  }
  return (await res.json()) as T
}

export const api = {
  login(username: string, password: string): Promise<{ token: string }> {
    return request("/auth/login", { method: "POST", json: { username, password } })
  },
  listSites(): Promise<Site[]> {
    return request("/sites")
  },
  createSite(data: { host: string; upstream: string; path_prefix: string }): Promise<{ site: Site }> {
    return request("/sites", { method: "POST", json: data })
  },
  updateSite(
    id: string,
    data: { host: string; upstream: string; path_prefix: string; status: string },
  ): Promise<{ site: Site }> {
    return request(`/sites/${encodeURIComponent(id)}`, { method: "PUT", json: data })
  },
  deleteSite(id: string): Promise<void> {
    return request(`/sites/${encodeURIComponent(id)}`, { method: "DELETE" })
  },
  listRules(siteId: string): Promise<Rule[]> {
    return request(`/sites/${encodeURIComponent(siteId)}/rules`)
  },
  createRule(siteId: string, yaml: string): Promise<{ rule: Rule }> {
    return request(`/sites/${encodeURIComponent(siteId)}/rules`, { method: "POST", json: { yaml } })
  },
  deleteRule(siteId: string, ruleId: string): Promise<void> {
    return request(`/sites/${encodeURIComponent(siteId)}/rules/${encodeURIComponent(ruleId)}`, { method: "DELETE" })
  },
  listBlocklist(): Promise<BlocklistEntry[]> {
    return request("/fingerprint/blocklist")
  },
  addBlocklist(ja4: string, note: string): Promise<unknown> {
    return request("/fingerprint/blocklist", { method: "POST", json: { ja4, note } })
  },
  deleteBlocklist(ja4: string): Promise<void> {
    return request(`/fingerprint/blocklist/${encodeURIComponent(ja4)}`, { method: "DELETE" })
  },
  metrics(): Promise<Metrics> {
    return request("/metrics")
  },
}
