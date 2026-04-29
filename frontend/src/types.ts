export interface Agent {
  agent_id: string;
  name: string;
  role: string;
  status: string;
  status_reason?: string;
  attributes: Record<string, unknown>;
  api_key?: string;
  created_at?: string;
  updated_at?: string;
  last_login_at?: string;
}

export interface TokenInfo {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_at: string;
  jti: string;
  usage_limit: number;
  bound_ip: string | null;
}

export interface Document {
  doc_id: string;
  content?: string;
  sensitivity: string;
  updated_by?: string;
  updated_at?: string;
}

export interface AuditEvent {
  id?: number;
  agent_id: string | null;
  action: string;
  resource: string;
  decision: "allow" | "deny";
  reason: string;
  ip_address?: string | null;
  token_id?: string | null;
  created_at?: string;
  context?: Record<string, unknown>;
}

export interface PolicyDecision {
  allowed: boolean;
  reason: string;
}

export interface Session {
  agentId: string;
  agentName: string;
  role: string;
  apiKey: string;
  token: string;
  refreshToken: string;
  expiresAt: string;
}

export interface SystemSnapshot {
  agents: { total: number; by_role: Record<string, number>; by_status: Record<string, number> };
  tokens: { total: number; active: number; inactive: number };
  documents: { total: number; by_sensitivity: Record<string, number> };
}

export interface AuditSummary {
  total: number;
  allow: number;
  deny: number;
  top_actions: Array<{ action: string; count: number }>;
  recent_denials: AuditEvent[];
}

export interface DashboardData {
  snapshot: SystemSnapshot;
  audit: AuditSummary;
  role_permissions: Record<string, string[]>;
  demo_agents: Array<{ agent_id: string; name: string; role: string }>;
  policy_notes: string[];
}

export interface TestResult {
  name: string;
  passed: boolean;
  detail: string;
  duration?: number;
}
