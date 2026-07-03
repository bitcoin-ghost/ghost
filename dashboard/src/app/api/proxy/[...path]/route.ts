import { NextRequest, NextResponse } from "next/server";
import { createHmac } from "crypto";

// The node's local API is always reachable on loopback:8080. Default to it so a
// fresh install works with no configuration; honour NEXT_PUBLIC_API_URL when set.
const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8080";

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
  const url = new URL(backendPath, BACKEND_URL);

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

    // Sign mutating requests with HMAC if key is configured
    const { signature, timestamp } = signRequest(body);
    if (signature) {
      headers["X-Ghost-Signature"] = signature;
      headers["X-Ghost-Timestamp"] = timestamp;
    }
  } else {
    // Sign GET requests to internal endpoints too (empty body)
    const { signature, timestamp } = signRequest("");
    if (signature) {
      headers["X-Ghost-Signature"] = signature;
      headers["X-Ghost-Timestamp"] = timestamp;
    }
  }

  try {
    const response = await fetch(url.toString(), {
      method: request.method,
      headers,
      body,
    });

    const responseData = await response.text();

    return new NextResponse(responseData, {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("Content-Type") || "application/json",
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: `Backend unavailable: ${error instanceof Error ? error.message : "unknown"}` },
      { status: 502 },
    );
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
