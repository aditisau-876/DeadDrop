import { clearAccessToken, getAccessToken } from "../auth/authStorage";

const configuredBase = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api";
const API_BASE = configuredBase.replace(/\/+$/, "");

function endpoint(path: string): string {
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  if (API_BASE.endsWith("/api") && cleanPath.startsWith("/api/")) {
    return `${API_BASE}${cleanPath.slice(4)}`;
  }
  return `${API_BASE}${cleanPath}`;
}

export async function authApiRequest<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }

  const token = getAccessToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);

  let response: Response;
  try {
    response = await fetch(endpoint(path), { ...options, headers });
  } catch {
    throw new Error(
      "Cannot connect to the DeadDrop backend. Check that the backend is running and VITE_API_BASE_URL is correct.",
    );
  }

  const payload = await response.json().catch(() => null) as
    | { detail?: unknown }
    | null;

  if (response.status === 401) {
    clearAccessToken();
  }

  if (!response.ok) {
    const detail = payload?.detail;
    const message = typeof detail === "string"
      ? detail
      : detail !== undefined
        ? JSON.stringify(detail)
        : `Request failed (${response.status}).`;
    throw new Error(message);
  }

  return payload as T;
}
