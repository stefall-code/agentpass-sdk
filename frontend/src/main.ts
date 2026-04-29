import { restoreState, saveState, sessions, activeSessionId, scenarioTimeline, addTimelineEntry } from "./state";
import { getOverview } from "./api";
import { escapeHtml, pretty } from "./utils";

let ws: WebSocket | null = null;

function initTheme(): void {
  const toggle = document.getElementById("themeToggle") as HTMLInputElement | null;
  if (!toggle) return;

  const saved = localStorage.getItem("agent-console-theme");
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const isDark = saved === "dark" || (!saved && prefersDark);

  if (isDark) {
    document.documentElement.setAttribute("data-theme", "dark");
    toggle.checked = true;
  }

  toggle.addEventListener("change", () => {
    const dark = toggle.checked;
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    localStorage.setItem("agent-console-theme", dark ? "dark" : "light");
  });
}

function initWebSocket(): void {
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${protocol}//${location.host}/ws/audit`;
  ws = new WebSocket(url);
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      addTimelineEntry(
        `[WS] ${data.action}`,
        `${data.agent_id || "?"} → ${data.resource}: ${data.decision}`,
        data.decision === "allow" ? "success" : "danger"
      );
    } catch { /* ignore */ }
  };
  ws.onclose = () => { setTimeout(initWebSocket, 3000); };
}

function initTabs(): void {
  document.querySelectorAll(".tab-bar").forEach((bar) => {
    bar.addEventListener("click", (e) => {
      const target = e.target as HTMLElement;
      if (!target.classList.contains("tab-btn")) return;
      const tabId = target.dataset.tab;
      if (!tabId) return;
      bar.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      target.classList.add("active");
      const panel = bar.parentElement;
      if (!panel) return;
      panel.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));
      const pane = panel.querySelector(`#${tabId}`);
      if (pane) pane.classList.add("active");
    });
  });
}

function initApp(): void {
  initTheme();
  initWebSocket();
  initTabs();
  restoreState();

  const loginAllBtn = document.getElementById("loginAllBtn");
  if (loginAllBtn) {
    loginAllBtn.addEventListener("click", async () => {
      try {
        const data = await getOverview();
        console.log("Overview loaded:", data);
      } catch (err) {
        console.error("Failed to load overview:", err);
      }
    });
  }

  console.log("Agent Security Console v1.3 initialized");
}

document.addEventListener("DOMContentLoaded", initApp);

export { initApp };
