import { NextRequest, NextResponse } from "next/server";
import {
  resolveJwtSecret,
  resolveTtlSecs,
  signSession,
  timingSafeEqualStr,
} from "@/lib/jwt";
import { BACKEND_URL, internalAuthHeaders } from "@/lib/internal-auth";

// ---------------------------------------------------------------------------
// Per-client login rate limiting (Finding 8)
// ---------------------------------------------------------------------------
// In-memory fixed-window limiter: at most MAX_ATTEMPTS within WINDOW_MS per
// client before further attempts are rejected with 429. An in-memory Map is
// sufficient for a single-node, SSH-tunnel-only dashboard (one process, no
// horizontal scaling). A successful login clears the client's counter.
//
// We key on the REAL TCP peer address, which `server.js` stamps into the
// trusted `x-ghost-peer-addr` header (deleting any client-supplied value first,
// so it cannot be spoofed). Next does not expose `request.ip` under our custom
// server, so without this every request would collapse into one global bucket —
// letting any LAN client lock out the real operator with five wrong passwords.
// We do NOT key on X-Forwarded-For: it is client-spoofable. When no peer
// address is available, we fall back to a single global bucket, which still
// throttles brute force (just coarsely) for the loopback/tunnel norm.
// ---------------------------------------------------------------------------

const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes

interface Bucket {
  count: number;
  resetAt: number;
}

const attempts = new Map<string, Bucket>();

function clientKey(request: NextRequest): string {
  // The real socket peer address, stamped by server.js as a trusted header
  // (client-supplied copies are stripped there). Falls back to `request.ip`
  // for any runtime that does populate it, then to a global bucket.
  const peer = request.headers.get("x-ghost-peer-addr");
  if (peer && peer.length > 0) return peer;
  const ip = (request as unknown as { ip?: string }).ip;
  return ip && ip.length > 0 ? ip : "global";
}

/** Returns the bucket after recording one attempt, or null if over the limit. */
function recordAttempt(key: string): { limited: boolean; retryAfterSecs: number } {
  const now = Date.now();
  const existing = attempts.get(key);

  if (!existing || now >= existing.resetAt) {
    attempts.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return { limited: false, retryAfterSecs: 0 };
  }

  if (existing.count >= MAX_ATTEMPTS) {
    return {
      limited: true,
      retryAfterSecs: Math.max(1, Math.ceil((existing.resetAt - now) / 1000)),
    };
  }

  existing.count += 1;
  return { limited: false, retryAfterSecs: 0 };
}

function clearAttempts(key: string): void {
  attempts.delete(key);
}

// Opportunistic cleanup so the Map can't grow unbounded across many keys.
function sweepExpired(now: number): void {
  for (const [key, bucket] of attempts) {
    if (now >= bucket.resetAt) attempts.delete(key);
  }
}

// ---------------------------------------------------------------------------
// Failed-login alert signal (cross-layer: dashboard -> ghost-pool)
// ---------------------------------------------------------------------------
// Dashboard password auth lives here in the Next.js layer, not in ghost-pool.
// To surface a brute-force attempt as an operator alert, we count CONSECUTIVE
// failed password checks in-process and, when the streak first crosses
// FAILED_LOGIN_ALERT_THRESHOLD within FAILED_LOGIN_WINDOW_MS, signal ghost-pool
// to dispatch a `FailedLogin` alert. The signal carries ONLY the attempt count
// (never the attempted password). We edge-trigger (the `alerted` flag) so a
// single burst pages once; a successful login clears the streak.
// ---------------------------------------------------------------------------

const FAILED_LOGIN_ALERT_THRESHOLD = 5;
const FAILED_LOGIN_WINDOW_MS = 10 * 60 * 1000; // 10 minutes

interface FailStreak {
  count: number;
  resetAt: number;
  alerted: boolean;
}

const failedLogins = new Map<string, FailStreak>();

/** Record one failed login; report the streak count and whether to alert now. */
function recordFailedLogin(key: string): { count: number; shouldAlert: boolean } {
  const now = Date.now();
  const existing = failedLogins.get(key);

  if (!existing || now >= existing.resetAt) {
    failedLogins.set(key, { count: 1, resetAt: now + FAILED_LOGIN_WINDOW_MS, alerted: false });
    return { count: 1, shouldAlert: false };
  }

  existing.count += 1;
  if (existing.count >= FAILED_LOGIN_ALERT_THRESHOLD && !existing.alerted) {
    existing.alerted = true; // edge: only the first crossing fires.
    return { count: existing.count, shouldAlert: true };
  }
  return { count: existing.count, shouldAlert: false };
}

function clearFailedLogins(key: string): void {
  failedLogins.delete(key);
}

/**
 * Signal ghost-pool to dispatch a `FailedLogin` alert. Runs pre-session (no
 * operator cookie exists on a failed login), so it cannot use the authenticated
 * dashboard proxy; it signs the call directly with the shared internal-auth
 * secret (the same HMAC the proxy uses). No-ops when INTERNAL_AUTH_KEY is
 * unset. Never sends or logs the attempted password.
 */
async function signalFailedLoginBurst(attempts: number): Promise<void> {
  const body = JSON.stringify({
    attempts,
    window_secs: Math.floor(FAILED_LOGIN_WINDOW_MS / 1000),
  });
  const authHeaders = internalAuthHeaders(body);
  if (!("X-Ghost-Signature" in authHeaders)) {
    // No signing key configured — we cannot authenticate the signal, so skip it
    // rather than send an unauthenticated (and rejected) request.
    return;
  }
  const url = new URL("/api/v1/alerts/internal/failed-login", BACKEND_URL);
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    await fetch(url.toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json", ...authHeaders },
      body,
      signal: controller.signal,
    });
    clearTimeout(timeout);
  } catch {
    // Best-effort: a failed-login alert must never break the login response.
  }
}

export async function POST(request: NextRequest) {
  const key = clientKey(request);
  sweepExpired(Date.now());

  const { limited, retryAfterSecs } = recordAttempt(key);
  if (limited) {
    return NextResponse.json(
      { error: "Too many login attempts. Try again later." },
      { status: 429, headers: { "Retry-After": String(retryAfterSecs) } },
    );
  }

  const { password } = await request.json();
  const dashboardPassword = process.env.DASHBOARD_PASSWORD;

  if (!dashboardPassword) {
    return NextResponse.json({ error: "No password configured" }, { status: 500 });
  }

  if (!timingSafeEqualStr(password ?? "", dashboardPassword)) {
    // Track the consecutive-failure streak and, on crossing the threshold,
    // signal ghost-pool to raise a `FailedLogin` operator alert. Awaited (a
    // fast loopback call, guarded by a timeout) so the signal completes before
    // the response returns; it never carries or logs the attempted password.
    const { count, shouldAlert } = recordFailedLogin(key);
    if (shouldAlert) {
      await signalFailedLoginBurst(count);
    }
    return NextResponse.json({ error: "Invalid password" }, { status: 401 });
  }

  const secret = await resolveJwtSecret();
  if (!secret) {
    return NextResponse.json({ error: "No signing secret configured" }, { status: 500 });
  }

  // Successful auth — reset this client's attempt counter so a legitimate
  // operator isn't throttled by their own earlier typos, and clear the
  // failed-login streak so an occasional typo never accumulates toward an alert.
  clearAttempts(key);
  clearFailedLogins(key);

  const ttl = resolveTtlSecs();
  const token = await signSession("operator", secret, ttl);

  const response = NextResponse.json({ ok: true, expires_in: ttl });
  // `secure` is gated on HTTPS. Under the SSH-tunnel-only model the dashboard
  // is served over localhost HTTP, so the cookie is intentionally allowed on a
  // non-TLS connection — it never traverses an untrusted network (the SSH
  // tunnel provides the transport encryption). httpOnly + sameSite still apply.
  response.cookies.set("ghost-session", token, {
    httpOnly: true,
    secure: request.nextUrl.protocol === "https:",
    sameSite: "lax",
    path: "/",
    maxAge: ttl,
  });
  return response;
}
