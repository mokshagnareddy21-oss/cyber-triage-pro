/**
 * REST transport.
 *
 * When `VITE_API_URL` is set the app talks to the Express backend and every
 * number on screen comes from a real Jev/Gemini call. When it is not set — the
 * Freebuff preview, or a reviewer who has not deployed the API yet — the app
 * runs the identical decision core in the browser against deterministic DEMO
 * FIXTURES, and says so in the top bar. Nothing is ever presented as a live
 * model result unless a live model produced it.
 */

const RAW_BASE = import.meta.env.VITE_API_URL as string | undefined;

export const API_BASE = RAW_BASE ? RAW_BASE.replace(/\/+$/, "") : null;

export type ApiMode = "backend" | "local";

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status = 0) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

const TOKEN_KEY = "cybersentinel.token";

export function getAuthToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setAuthToken(token: string | null): void {
  try {
    if (token) window.localStorage.setItem(TOKEN_KEY, token);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable — session simply will not persist */
  }
}

function timeoutSignal(ms: number): AbortSignal | undefined {
  if (typeof AbortController === "undefined") return undefined;
  const controller = new AbortController();
  window.setTimeout(() => controller.abort(), ms);
  return controller.signal;
}

export async function apiFetch<T>(
  path: string,
  init: RequestInit & { timeoutMs?: number } = {},
): Promise<T> {
  if (!API_BASE) throw new ApiError("No backend configured (VITE_API_URL is unset).");
  const { timeoutMs = 8000, headers, ...rest } = init;
  const token = getAuthToken();
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...rest,
      signal: timeoutSignal(timeoutMs),
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(headers ?? {}),
      },
    });
  } catch (error) {
    throw new ApiError(
      error instanceof Error ? error.message : "Network request failed",
      0,
    );
  }

  const text = await response.text();
  let payload: unknown = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { message: text };
    }
  }

  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && "error" in payload
        ? String((payload as { error: unknown }).error)
        : `Request failed with status ${response.status}`;
    throw new ApiError(message, response.status);
  }

  return payload as T;
}

/** True when the configured backend answers `/api/health` quickly. */
export async function probeBackend(timeoutMs = 2500): Promise<boolean> {
  if (!API_BASE) return false;
  try {
    const response = await fetch(`${API_BASE}/api/health`, {
      signal: timeoutSignal(timeoutMs),
    });
    return response.ok;
  } catch {
    return false;
  }
}
