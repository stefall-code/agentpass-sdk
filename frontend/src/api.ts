import type { Session, DashboardData, AuditEvent, Agent, Document } from "./types";

function parseErrorMessage(data: unknown): string {
  if (typeof data === "object" && data !== null && "detail" in data) {
    return String((data as { detail: unknown }).detail);
  }
  if (typeof data === "string") return data;
  return "Unknown error";
}

export function makeHeaders(session: Session | null, useAuth = true, extra: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = { ...extra };
  if (useAuth && session?.token) {
    headers.Authorization = `Bearer ${session.token}`;
  }
  return headers;
}

export async function request<T = unknown>(path: string, options: RequestInit & { headers?: Record<string, string> } = {}): Promise<T> {
  const response = await fetch(path, {
    method: options.method || "GET",
    headers: options.headers || {},
    body: options.body,
  });
  const contentType = response.headers.get("content-type") || "";
  const data: unknown = contentType.includes("application/json") ? await response.json() : await response.text();

  if (!response.ok) {
    throw { status: response.status, data, message: parseErrorMessage(data) };
  }
  return data as T;
}

export async function authRequest<T = unknown>(path: string, session: Session | null, options: RequestInit & { headers?: Record<string, string> } = {}): Promise<T> {
  if (!session?.token) throw new Error("当前没有可用 token，请先登录。");
  try {
    return await request<T>(path, { ...options, headers: makeHeaders(session, true, options.headers || {}) });
  } catch (error: unknown) {
    const err = error as { status?: number };
    if (err?.status === 401 && session?.refreshToken) {
      try {
        const refreshed = await refreshToken(session.refreshToken);
        session.token = refreshed.access_token;
        session.refreshToken = refreshed.refresh_token;
        session.expiresAt = refreshed.expires_at;
        return await request<T>(path, { ...options, headers: makeHeaders(session, true, options.headers || {}) });
      } catch {
        throw new Error("会话已过期且刷新失败，请重新登录。");
      }
    }
    if (err?.status === 401) throw new Error("会话已过期，请重新登录。");
    throw error;
  }
}

interface LoginResponse { access_token: string; refresh_token: string; token_type: string; expires_at: string; jti: string; usage_limit: number; bound_ip: string | null; }
interface RefreshResponse { access_token: string; refresh_token: string; expires_at: string; }

export async function loginAgent(agentId: string, apiKey: string, options: { boundIp?: string | null; expiresInMinutes?: number; usageLimit?: number } = {}): Promise<LoginResponse> {
  return await request<LoginResponse>("/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      agent_id: agentId, api_key: apiKey,
      bound_ip: options.boundIp || null,
      expires_in_minutes: Number(options.expiresInMinutes || 60),
      usage_limit: Number(options.usageLimit || 30),
    }),
  });
}

export async function batchLogin(adminAgentId: string, adminApiKey: string, agents: Array<{ agentId: string; apiKey: string; boundIp?: string; expiresInMinutes?: number; usageLimit?: number }>): Promise<{ results: LoginResponse[] }> {
  return await request("/login/batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      admin_agent_id: adminAgentId, admin_api_key: adminApiKey,
      agents: agents.map((a) => ({
        agent_id: a.agentId, api_key: a.apiKey, bound_ip: a.boundIp || null,
        expires_in_minutes: Number(a.expiresInMinutes || 60), usage_limit: Number(a.usageLimit || 30),
      })),
    }),
  });
}

export async function registerAgent(payload: Record<string, unknown>): Promise<Agent> {
  return await request<Agent>("/register", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  });
}

export async function getAgentInfo(session: Session): Promise<Agent> { return await authRequest<Agent>("/me", session); }
export async function introspectToken(session: Session): Promise<unknown> { return await authRequest("/auth/introspect", session); }
export async function revokeToken(session: Session): Promise<unknown> { return await authRequest("/auth/revoke", session, { method: "POST" }); }
export async function refreshToken(token: string): Promise<RefreshResponse> {
  return await request<RefreshResponse>("/auth/refresh", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: token }),
  });
}

export async function readDocument(docId: string, session: Session): Promise<Document> {
  return await authRequest<Document>(`/resource/docs/${docId}`, session);
}

export async function writeDocument(docId: string, payload: { content: string; sensitivity: string }, session: Session): Promise<Document> {
  return await authRequest<Document>(`/resource/docs/${docId}`, session, {
    method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  });
}

export async function executeTask(payload: { task_name: string; resource: string; parameters?: Record<string, unknown> }, session: Session): Promise<unknown> {
  return await authRequest("/tasks/execute", session, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  });
}

export async function callIntegration(payload: { service_name: string; payload: Record<string, unknown> }, session: Session): Promise<unknown> {
  return await authRequest("/integrations/call", session, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  });
}

export async function getOverview(): Promise<unknown> { return await request("/api/overview"); }
export async function getHealth(): Promise<unknown> { return await request("/healthz"); }
export async function getDashboard(session: Session): Promise<DashboardData> { return await authRequest<DashboardData>("/admin/dashboard", session); }
export async function getAgents(session: Session): Promise<Agent[]> { return await authRequest<Agent[]>("/admin/agents", session); }

export async function updateAgentStatus(agentId: string, payload: { status: string; reason?: string }, session: Session): Promise<unknown> {
  return await authRequest(`/admin/agents/${agentId}/status`, session, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  });
}

export async function deleteAgent(agentId: string, session: Session): Promise<unknown> {
  return await authRequest(`/admin/agents/${agentId}`, session, { method: "DELETE" });
}

export async function updateAgent(agentId: string, payload: Record<string, unknown>, session: Session): Promise<unknown> {
  return await authRequest(`/admin/agents/${agentId}`, session, {
    method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
  });
}

export async function getAuditLogs(params: Record<string, string | number | undefined>, session: Session): Promise<AuditEvent[]> {
  const filtered = Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ""));
  const qs = new URLSearchParams(filtered as Record<string, string>).toString();
  return await authRequest<AuditEvent[]>(`/admin/audit/logs?${qs}`, session);
}

export async function exportAuditLogs(format: string, params: Record<string, string | number | undefined>, session: Session): Promise<void> {
  const filtered = Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ""));
  (filtered as Record<string, string>).format = format;
  const qs = new URLSearchParams(filtered as Record<string, string>).toString();
  const response = await fetch(`/admin/audit/export?${qs}`, { headers: makeHeaders(session, true) });
  if (!response.ok) throw new Error("Export failed");
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `audit_logs.${format}`;
  a.click();
  URL.revokeObjectURL(url);
}

export async function resetDemo(session: Session): Promise<unknown> {
  return await authRequest("/admin/demo/reset", session, { method: "POST" });
}
