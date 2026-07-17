import { NextRequest, NextResponse } from "next/server";
import { BACKEND_URL, signInternalRequest } from "@/lib/internal-auth";

// Upper bound on how long a single proxied backend request may take. Without
// it, a hung or slow backend holds the Next request (and its client socket)
// open indefinitely — a connection-exhaustion vector when the dashboard is
// LAN-exposed. Generous enough for any loopback admin op (backup export, etc.).
const BACKEND_TIMEOUT_MS = 30_000;

function isMutating(method: string): boolean {
  return method !== "GET" && method !== "HEAD";
}

async function proxyRequest(request: NextRequest, params: Promise<{ path: string[] }>) {
  const { path } = await params;
  const backendPath = "/" + path.join("/");
  const url = new URL(backendPath, BACKEND_URL);

  // Preserve query parameters
  request.nextUrl.searchParams.forEach((value, key) => {
    url.searchParams.set(key, value);
  });

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  let body: string | undefined;

  if (isMutating(request.method)) {
    body = await request.text();

    // Sign mutating requests with HMAC. The backend's internal router requires
    // this signature for every mutation (and fails closed without it), so a
    // mutation we cannot sign would be rejected downstream anyway — refuse it
    // here, fail-closed, rather than forward an unauthenticated write and
    // surface a confusing backend 401 to the operator.
    const { signature, timestamp } = signInternalRequest(body);
    if (!signature) {
      return NextResponse.json(
        {
          error:
            "Dashboard is not configured to authenticate node writes (INTERNAL_AUTH_KEY unset). Mutation refused.",
        },
        { status: 503 },
      );
    }
    headers["X-Ghost-Signature"] = signature;
    headers["X-Ghost-Timestamp"] = timestamp;
  } else {
    // Sign GET requests to internal endpoints too (empty body). Reads are not
    // gated on the signature (they hit public/loopback-exempt routes), so a
    // missing key only downgrades the rate-limit tier — GETs still pass.
    const { signature, timestamp } = signInternalRequest("");
    if (signature) {
      headers["X-Ghost-Signature"] = signature;
      headers["X-Ghost-Timestamp"] = timestamp;
    }
  }

  const abort = new AbortController();
  const timeout = setTimeout(() => abort.abort(), BACKEND_TIMEOUT_MS);
  try {
    const response = await fetch(url.toString(), {
      method: request.method,
      headers,
      body,
      signal: abort.signal,
    });

    const contentType = response.headers.get("Content-Type") || "application/json";

    // Binary payloads (e.g. a backup download) must NOT be round-tripped through
    // `.text()` — that would decode the bytes as UTF-8 and corrupt the file.
    // Pass them through as an ArrayBuffer, preserving the attachment headers.
    const isBinary = !contentType.includes("json") && !contentType.startsWith("text/");
    if (isBinary) {
      const buffer = await response.arrayBuffer();
      const outHeaders: Record<string, string> = { "Content-Type": contentType };
      const disposition = response.headers.get("Content-Disposition");
      if (disposition) outHeaders["Content-Disposition"] = disposition;
      const length = response.headers.get("Content-Length");
      if (length) outHeaders["Content-Length"] = length;
      return new NextResponse(buffer, {
        status: response.status,
        headers: outHeaders,
      });
    }

    const responseData = await response.text();

    return new NextResponse(responseData, {
      status: response.status,
      headers: {
        "Content-Type": contentType,
      },
    });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      return NextResponse.json(
        { error: "Backend timed out" },
        { status: 504 },
      );
    }
    return NextResponse.json(
      { error: `Backend unavailable: ${error instanceof Error ? error.message : "unknown"}` },
      { status: 502 },
    );
  } finally {
    clearTimeout(timeout);
  }
}

export async function GET(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(request, context.params);
}

export async function POST(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(request, context.params);
}

export async function PUT(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(request, context.params);
}

export async function DELETE(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(request, context.params);
}
