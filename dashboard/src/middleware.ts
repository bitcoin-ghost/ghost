import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { resolveJwtSecret, verifySession } from "@/lib/jwt";

// ---------------------------------------------------------------------------
// SSH-tunnel-only access model
// ---------------------------------------------------------------------------
// The dashboard is reachable ONLY over an SSH tunnel:
//
//     ssh -L 3000:localhost:3000 ghost-vmN
//
// There is no remote/LAN access mode. The deployment binds the dashboard to
// 127.0.0.1, but this middleware does NOT rely on that — it fails closed even
// if the server is mis-bound to 0.0.0.0. A valid JWT session gates EVERY route
// (pages, the node API proxy, and the ghost-pay proxy) so the backend can never
// be reached unauthenticated.
//
// We deliberately do NOT consult `X-Forwarded-For` or the `Host` header for any
// auth decision: both are client-spoofable, and the previous "localhost bypass"
// they powered let a direct connection to a mis-bound dashboard skip auth
// entirely. Auth is the JWT cookie and nothing else.
// ---------------------------------------------------------------------------

// Paths that must remain reachable without a session: the login page, its
// supporting auth API (login/logout/refresh), and Next.js static assets.
const PUBLIC_PREFIXES = ["/login", "/api/auth/"];

// Paths owned ENTIRELY by the custom Node server (`server.js`), never by Next —
// this middleware must not touch them.
//
// `/api/ws` is the authenticated WebSocket relay. A real handshake is an HTTP
// `upgrade` event that `server.js` intercepts and authorises itself (same JWT),
// so it never reaches this middleware. But a NON-upgrade request to the very
// same path — an intermediary/SSH-tunnel/proxy that strips the `Upgrade`
// header, or a browser reconnect quirk — DOES fall through to Next and lands
// here. Because `/api/ws` is not a Next route, the middleware would treat it as
// a protected page/API and, when the cookie is absent-or-lapsed, run
// `denyAccess`, whose 401 response carries a `Set-Cookie` that DELETES
// `ghost-session`. That turns a transient blip into a hard logout — and on the
// always-on Home screen, whose socket reconnects continuously, it fires
// repeatedly, ejecting a working operator to /login.
//
// The relay owns its own auth, so leave `/api/ws` strictly alone here. This is
// NOT an auth hole: a genuine handshake is still gated by `server.js`, and a
// non-upgrade GET to `/api/ws` matches no route and 404s (it proxies nothing).
const RELAY_OWNED_PREFIXES = ["/api/ws"];

const SECURITY_HEADERS = {
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};

function addSecurityHeaders(response: NextResponse): NextResponse {
  for (const [key, value] of Object.entries(SECURITY_HEADERS)) {
    response.headers.set(key, value);
  }
  return response;
}

function isStaticAsset(pathname: string): boolean {
  return (
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon") ||
    pathname.endsWith(".svg") ||
    pathname.endsWith(".ico")
  );
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Public, unauthenticated paths: login flow + Next.js internals/static.
  if (PUBLIC_PREFIXES.some((p) => pathname.startsWith(p)) || isStaticAsset(pathname)) {
    return NextResponse.next();
  }

  // Relay-owned paths (the WebSocket relay): pass through untouched so the
  // middleware can never clear `ghost-session` on a stray `/api/ws` request.
  // `server.js` authenticates the actual upgrade; see RELAY_OWNED_PREFIXES.
  if (
    RELAY_OWNED_PREFIXES.some(
      (p) => pathname === p || pathname.startsWith(`${p}/`),
    )
  ) {
    return NextResponse.next();
  }

  // Everything else — pages AND the API proxies — requires a valid session.
  const token = request.cookies.get("ghost-session")?.value;
  const secret = token ? await resolveJwtSecret() : null;
  const payload = secret ? await verifySession(token!, secret) : null;

  if (!payload) {
    // Fail closed. A missing password (no resolvable secret) means no one can
    // authenticate — that is a deliberate locked state, not an open door.
    return denyAccess(request, pathname);
  }

  return addSecurityHeaders(NextResponse.next());
}

/**
 * Reject an unauthenticated request. API calls (the node proxy + ghost-pay
 * proxy) get a 401 JSON body so the client's fetch layer surfaces a real
 * auth error instead of silently receiving the login HTML. Page navigations
 * are redirected to the login screen.
 */
function denyAccess(request: NextRequest, pathname: string): NextResponse {
  if (pathname.startsWith("/api/")) {
    const response = NextResponse.json(
      { error: "Authentication required" },
      { status: 401 },
    );
    response.cookies.delete("ghost-session");
    return addSecurityHeaders(response);
  }
  return redirectToLogin(request, pathname);
}

function redirectToLogin(request: NextRequest, pathname: string): NextResponse {
  const loginUrl = new URL("/login", request.url);
  if (pathname !== "/") {
    loginUrl.searchParams.set("redirect", pathname);
  }
  const response = NextResponse.redirect(loginUrl);
  // Clear a stale/expired cookie so the next request doesn't retrigger the same path.
  response.cookies.delete("ghost-session");
  return addSecurityHeaders(response);
}

export const config = {
  // `geo/geoip.bin` is a large static binary served from /public; exclude it so
  // the middleware never runs for it and it is delivered directly (same treatment
  // as `_next/static`). This is the asset only — the `/geo` PAGE is still matched
  // and stays behind the JWT session gate.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|geo/geoip\\.bin).*)"],
};
