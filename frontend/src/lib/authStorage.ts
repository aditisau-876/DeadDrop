
const AUTH_TOKEN_KEY = "deaddrop_access_token";

/**
 * Retrieve the authentication token from session storage.
 */
export function getStoredToken(): string | null {
  try {
    return sessionStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return null;
  }
}

/**
 * Save the authentication token for the current browser session.
 */
export function setStoredToken(token: string): void {
  if (!token || typeof token !== "string") {
    throw new Error("A valid authentication token is required.");
  }

  try {
    sessionStorage.setItem(AUTH_TOKEN_KEY, token);
  } catch {
    throw new Error("Unable to store the authentication token.");
  }
}

/**
 * Remove the authentication token during logout.
 */
export function clearStoredToken(): void {
  try {
    sessionStorage.removeItem(AUTH_TOKEN_KEY);
  } catch {
    // Ignore storage errors during logout.
  }
}

/**
 * Check whether an authentication token exists.
 */
export function hasStoredToken(): boolean {
  return Boolean(getStoredToken());
}
