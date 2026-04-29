import { Signal, effect } from "./signals";
import type { Session, AuditEvent } from "./types";

const STORAGE_KEY = "agent-security-console-state-v4";

interface TimelineEntry {
  time: string;
  title: string;
  detail: string;
  tone: "success" | "warning" | "danger" | "info";
}

interface TestResultEntry {
  passed: number;
  failed: number;
  timestamp: string;
  [key: string]: unknown;
}

export const sessions = Signal<Record<string, Session>>({});
export const activeSessionId = Signal<string | null>(null);
export const scenarioTimeline = Signal<TimelineEntry[]>([]);
export const apiResponse = Signal<string>("");
export const testResults = Signal<Record<string, TestResultEntry>>({});
export const overview = Signal<unknown>(null);
export const dashboard = Signal<unknown>(null);

export function saveState(): void {
  const persisted = {
    activeSessionId: activeSessionId.value,
    sessions: Object.fromEntries(
      Object.entries(sessions.value).map(([key, value]) => [
        key,
        {
          agentId: value.agentId,
          label: value.label ?? value.agentName ?? key,
          apiKey: value.apiKey,
          token: value.token || "",
          refreshToken: value.refreshToken || "",
          tokenType: value.tokenType || "Bearer",
          expiresAt: value.expiresAt || null,
          jti: value.jti || null,
          usageLimit: value.usageLimit || null,
          roleHint: value.roleHint || null,
          source: value.source || "custom",
          profile: value.profile || null,
          tokenMeta: value.tokenMeta || null,
        },
      ])
    ),
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));
}

export function restoreState(): void {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return;
  try {
    const parsed = JSON.parse(raw);
    activeSessionId.value = parsed.activeSessionId || null;
    sessions.value = parsed.sessions || {};
  } catch {
    localStorage.removeItem(STORAGE_KEY);
  }
}

export function getOrderedSessionIds(knownPresets?: Record<string, unknown>): string[] {
  const known = Object.keys(knownPresets || {});
  const custom = Object.keys(sessions.value).filter((id) => !known.includes(id));
  return [...known, ...custom.filter((id) => sessions.value[id])].filter(
    (id, index, array) => array.indexOf(id) === index
  );
}

export function getSession(agentId?: string | null): Session | null {
  const id = agentId ?? activeSessionId.value;
  if (!id) return null;
  return sessions.value[id] || null;
}

export function getActiveSession(): Session | null {
  return getSession();
}

export function getAdminSession(): Session | null {
  const active = getActiveSession();
  if ((active as Record<string, unknown>)?.profile && typeof active!.profile === "object" && (active!.profile as Record<string, unknown>)?.role === "admin" && active!.token) return active;
  return Object.values(sessions.value).find(
    (s) => typeof s.profile === "object" && (s.profile as Record<string, unknown>)?.role === "admin" && s.token
  ) || null;
}

export function upsertSession(partial: Partial<Session> & { agentId: string }): void {
  const current = sessions.value[partial.agentId] || ({} as Session);
  sessions.value = {
    ...sessions.value,
    [partial.agentId]: { ...current, ...partial } as Session,
  };
  if (!activeSessionId.value) activeSessionId.value = partial.agentId;
  saveState();
}

export function clearSessionToken(agentId: string): void {
  const session = sessions.value[agentId];
  if (!session) return;
  sessions.value = {
    ...sessions.value,
    [agentId]: { ...session, token: "", refreshToken: "", jti: null, expiresAt: null, usageLimit: null, tokenMeta: null },
  };
  saveState();
}

export function setActiveSession(agentId: string): void {
  if (!sessions.value[agentId]) return;
  activeSessionId.value = agentId;
  saveState();
}

export function addTimelineEntry(title: string, detail: string, tone: TimelineEntry["tone"] = "success"): void {
  const entry: TimelineEntry = {
    time: new Date().toLocaleTimeString("zh-CN", { hour12: false }),
    title, detail, tone,
  };
  scenarioTimeline.value = [entry, ...scenarioTimeline.value].slice(0, 40);
}

export function clearTimeline(): void { scenarioTimeline.value = []; }

export function resetState(): void {
  sessions.value = {};
  activeSessionId.value = null;
  scenarioTimeline.value = [];
  apiResponse.value = "";
  testResults.value = {};
  overview.value = null;
  dashboard.value = null;
  localStorage.removeItem(STORAGE_KEY);
}

export function setTestResult(scenarioId: string, result: TestResultEntry): void {
  testResults.value = {
    ...testResults.value,
    [scenarioId]: { ...result, timestamp: new Date().toLocaleTimeString("zh-CN", { hour12: false }) },
  };
}

export function getTestSummary(): { total: number; passed: number; failed: number; scenarios: Record<string, TestResultEntry> } {
  let total = 0, passed = 0, failed = 0;
  for (const result of Object.values(testResults.value)) {
    total += result.passed + result.failed;
    passed += result.passed;
    failed += result.failed;
  }
  return { total, passed, failed, scenarios: testResults.value };
}

export function clearTestResults(): void { testResults.value = {}; }
