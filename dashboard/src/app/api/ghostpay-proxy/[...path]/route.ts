import { NextRequest, NextResponse } from "next/server";
import { createHmac } from "crypto";

const GHOST_PAY_URL = process.env.GHOST_PAY_URL;
if (!GHOST_PAY_URL) {
  console.error("GHOST_PAY_URL environment variable is required");
}

// Bound every ghost-pay backend request so a hung backend can't hold the Next
// request open indefinitely (see the main proxy for the rationale).
const BACKEND_TIMEOUT_MS = 30_000;

function signRequest(body: string): { signature: string; timestamp: string } {
  const key = process.env.INTERNAL_AUTH_KEY;
  if (!key) {
    return { signature: "", timestamp: "" };
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const keyBytes = Buffer.from(key, "hex");

  // Match Rust HMAC: HMAC-SHA256(secret, timestamp_le_bytes || body)
  const hmac = createHmac("sha256", keyBytes);
  const timestampBuf = Buffer.alloc(8);
  timestampBuf.writeBigUInt64LE(BigInt(timestamp));
  hmac.update(timestampBuf);
  hmac.update(body);
  const signature = hmac.digest("hex");

  return { signature, timestamp: timestamp.toString() };
}

async function proxyRequest(request: NextRequest, params: Promise<{ path: string[] }>) {
  const { path } = await params;
  const backendPath = "/" + path.join("/");
  const url = new URL(backendPath, GHOST_PAY_URL);

  // Preserve query parameters
  request.nextUrl.searchParams.forEach((value, key) => {
    url.searchParams.set(key, value);
  });

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  let body: string | undefined;

  if (request.method !== "GET" && request.method !== "HEAD") {
    body = await request.text();

    // Sign mutating requests with HMAC. Fail closed if we cannot: a ghost-pay
    // mutation the backend can't authenticate would be rejected anyway, so
    // refuse it here rather than forward an unauthenticated write.
    const { signature, timestamp } = signRequest(body);
    if (!signature) {
      return NextResponse.json(
        {
          error:
            "Dashboard is not configured to authenticate ghost-pay writes (INTERNAL_AUTH_KEY unset). Mutation refused.",
        },
        { status: 503 },
      );
    }
    headers["X-Ghost-Signature"] = signature;
    headers["X-Ghost-Timestamp"] = timestamp;
  } else {
    // Sign GET requests to internal endpoints too (empty body)
    const { signature, timestamp } = signRequest("");
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

    const responseData = await response.text();

    return new NextResponse(responseData, {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("Content-Type") || "application/json",
      },
    });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      return NextResponse.json({ error: "Backend timed out" }, { status: 504 });
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
