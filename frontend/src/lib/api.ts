
const API_BASE_URL =
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

export async function apiRequest<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(
    `${API_BASE_URL}${path}`,
    {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    },
  );

  const responseText = await response.text();

  let body: unknown;

  try {
    body = responseText ? JSON.parse(responseText) : null;
  } catch {
    body = responseText;
  }

  if (!response.ok) {
    let message = `Request failed (${response.status}).`;

    if (
      typeof body === "object" &&
      body !== null &&
      "detail" in body
    ) {
      const detail = (body as { detail: unknown }).detail;

      message =
        typeof detail === "string"
          ? detail
          : JSON.stringify(detail);
    }

    throw new Error(message);
  }

  return body as T;
}
