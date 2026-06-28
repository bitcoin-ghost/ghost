import { NextRequest, NextResponse } from "next/server";
import {
  resolveJwtSecret,
  resolveTtlSecs,
  signSession,
  timingSafeEqualStr,
} from "@/lib/jwt";

// ---------------------------------------------------------------------------
// Per-client login rate limiting (Finding 8)
// ---------------------------------------------------------------------------
// In-memory fixed-window limiter: at most MAX_ATTEMPTS within WINDOW_MS per
// client before further attempts are rejected with 429. An in-memory Map is
// sufficient for a single-node, SSH-tunnel-only dashboard (one process, no
// horizontal scaling). A successful login clears the client's counter.
//
// We key on the connection IP when the runtime exposes it. We do NOT key on
// X-Forwarded-For: it is client-spoofable, so trusting it would let an
// attacker rotate the header to dodge the limit. When no trustworthy IP is
// available (the tunnel-only norm, where every request originates from
// 127.0.0.1), all attempts share a single global bucket — which is exactly
// the throttle we want for a single-operator dashboard.
// ---------------------------------------------------------------------------

const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes

interface Bucket {
  count: number;
  resetAt: number;
}

const attempts = new Map<string, Bucket>();

function clientKey(request: NextRequest): string {
  // `ip` is populated by some Next.js runtimes/hosts; it is the connection
  // address, not a client-supplied header, so it is safe to key on.
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
    return NextResponse.json({ error: "Invalid password" }, { status: 401 });
  }

  const secret = await resolveJwtSecret();
  if (!secret) {
    return NextResponse.json({ error: "No signing secret configured" }, { status: 500 });
  }

  // Successful auth — reset this client's attempt counter so a legitimate
  // operator isn't throttled by their own earlier typos.
  clearAttempts(key);

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
