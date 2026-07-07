import { NextRequest, NextResponse } from "next/server";
import { BACKEND_URL, signInternalRequest } from "@/lib/internal-auth";

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
    const { signature, timestamp } = signInternalRequest(body);
    if (signature) {
      headers["X-Ghost-Signature"] = signature;
      headers["X-Ghost-Timestamp"] = timestamp;
    }
  } else {
    // Sign GET requests to internal endpoints too (empty body)
    const { signature, timestamp } = signInternalRequest("");
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
