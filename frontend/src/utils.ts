export function nowTime(): string {
  return new Date().toLocaleTimeString("zh-CN", { hour12: false });
}

export function deepClone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value));
}

export function parseErrorMessage(data: unknown): string {
  if (typeof data === "string") return data;
  if (!data) return "Unknown error";
  if (typeof data === "object" && "detail" in data) return String((data as { detail: unknown }).detail);
  return JSON.stringify(data);
}

export function escapeHtml(value: unknown): string {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function pretty(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value, null, 2);
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function generateId(prefix = ""): string {
  return `${prefix}${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
}
