import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { resolveJwtSecret, verifySession } from "@/lib/jwt";

const PUBLIC_PATHS = ["/login", "/api/auth/login", "/api/auth/logout"];

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

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow public paths
  if (PUBLIC_PATHS.some((p) => pathname.startsWith(p))) {
    return NextResponse.next();
  }

  // Allow static files and Next.js internals
  if (
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon") ||
    pathname.endsWith(".svg") ||
    pathname.endsWith(".ico")
  ) {
    return NextResponse.next();
  }

  // Check if request is from localhost — skip auth
  const forwardedFor = request.headers.get("x-forwarded-for");
  const ip = forwardedFor?.split(",")[0]?.trim() || "";
  const isLocalhost =
    ip === "127.0.0.1" ||
    ip === "::1" ||
    ip === "localhost" ||
    ip === "" || // Direct access (no proxy)
    request.headers.get("host")?.startsWith("localhost");

  if (isLocalhost) {
    return addSecurityHeaders(NextResponse.next());
  }

  // Remote access — password-gated dashboard.
  // Fail CLOSED: if no DASHBOARD_PASSWORD is configured we cannot authenticate a
  // remote caller, so deny rather than serve unauthenticated. Localhost is
  // handled above and is unaffected; remote access only works once the operator
  // sets a password.
  const dashboardPassword = process.env.DASHBOARD_PASSWORD;
  if (!dashboardPassword) {
    return redirectToLogin(request, pathname);
  }

  const token = request.cookies.get("ghost-session")?.value;
  if (!token) {
    return redirectToLogin(request, pathname);
  }

  const secret = await resolveJwtSecret();
  if (!secret) {
    // Server misconfig — fail closed.
    return redirectToLogin(request, pathname);
  }

  const payload = await verifySession(token, secret);
  if (!payload) {
    return redirectToLogin(request, pathname);
  }

  return addSecurityHeaders(NextResponse.next());
}

function redirectToLogin(request: NextRequest, pathname: string): NextResponse {
  const loginUrl = new URL("/login", request.url);
  if (pathname !== "/") {
    loginUrl.searchParams.set("redirect", pathname);
  }
  const response = NextResponse.redirect(loginUrl);
  // Clear a stale/expired cookie so the next request doesn't retrigger the same path.
  response.cookies.delete("ghost-session");
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
