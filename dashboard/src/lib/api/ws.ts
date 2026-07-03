// Shared client helpers for the authenticated dashboard WebSocket.
//
// The browser connects to the SAME-ORIGIN endpoint `/api/ws` (served by the
// custom Node server in `server.js`), never straight to the backend :8080.
// That endpoint validates the `ghost-session` JWT on the HTTP upgrade before
// relaying to the loopback backend, so the WS is gated by the same session as
// every REST call.

/**
 * Same-origin WebSocket URL. Preserves `wss:` on HTTPS pages and inherits the
 * page host/port, so it works over the SSH tunnel (`localhost:3000`) and any
 * reverse proxy without extra config.
 */
export function getWsUrl(): string {
  if (typeof window !== "undefined") {
    const { protocol, host } = window.location;
    const wsProto = protocol === "https:" ? "wss:" : "ws:";
    return `${wsProto}//${host}/api/ws`;
  }
  return "ws://localhost:3000/api/ws";
}

let redirecting = false;

/**
 * Probe whether the session is actually dead. A failed WS handshake cannot
 * expose its HTTP status to the browser (the spec hides it), so when a socket
 * closes without ever opening we ask the auth layer directly: POST
 * `/api/auth/refresh` returns 401 iff the `ghost-session` cookie is missing or
 * expired (and slides it otherwise). Returns true only on a definite 401 — a
 * network error is treated as "not an auth problem" so a transiently-down
 * backend doesn't bounce the operator to /login.
 */
export async function isSessionExpired(): Promise<boolean> {
  try {
    const res = await fetch("/api/auth/refresh", {
      method: "POST",
      cache: "no-store",
    });
    return res.status === 401;
  } catch {
    return false;
  }
}

/** Redirect to the login page once, preserving the current path for return. */
export function redirectToLogin(): void {
  if (redirecting || typeof window === "undefined") return;
  redirecting = true;
  const here = window.location.pathname + window.location.search;
  const target =
    here && here !== "/"
      ? `/login?redirect=${encodeURIComponent(here)}`
      : "/login";
  window.location.assign(target);
}
