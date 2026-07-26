import { NextRequest, NextResponse } from "next/server";
import { createHmac } from "crypto";
import { request as httpsRequest } from "node:https";
import { request as httpRequest } from "node:http";

const GHOST_PAY_URL = process.env.GHOST_PAY_URL;
if (!GHOST_PAY_URL) {
  console.error("GHOST_PAY_URL environment variable is required");
}

// Bound every ghost-pay backend request so a hung backend can't hold the Next
// request open indefinitely (see the main proxy for the rationale).
const BACKEND_TIMEOUT_MS = 30_000;

function isLoopbackHost(hostname: string): boolean {
  return hostname === "127.0.0.1" || hostname === "::1" || hostname === "localhost";
}

// ghost-pay authenticates with HMAC-SHA256(api_secret, decimal_timestamp ‖ body)
// where the secret is `GHOST_PAY_API_SECRET` used as RAW UTF-8 bytes (NOT
// hex-decoded) and the timestamp is its decimal string. This is a DIFFERENT
// construction and a DIFFERENT secret from the pool proxy (which hex-decodes its
// key and uses an 8-byte little-endian timestamp), so the ghost-pay proxy signs
// on its own. Returns empty strings when no secret is configured.
function signGhostPayRequest(body: string): { signature: string; timestamp: string } {
  const key = process.env.GHOST_PAY_API_SECRET;
  if (!key) {
    return { signature: "", timestamp: "" };
  }
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const mac = createHmac("sha256", Buffer.from(key, "utf8"));
  mac.update(timestamp);
  mac.update(body);
  return { signature: mac.digest("hex"), timestamp };
}

interface BackendResponse {
  status: number;
  contentType: string;
  body: string;
}

// Forward via node:https/http rather than fetch so we can accept ghost-pay's
// self-signed, identity-derived cert on loopback (`rejectUnauthorized: false`)
// WITHOUT relaxing TLS verification anywhere else. Verification is only skipped
// for an HTTPS loopback target — never for a remote host.
function forwardToBackend(
  url: URL,
  method: string,
  headers: Record<string, string>,
  body: string | undefined,
): Promise<BackendResponse> {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const reqFn = isHttps ? httpsRequest : httpRequest;
    const req = reqFn(
      url,
      {
        method,
        headers,
        rejectUnauthorized: !(isHttps && isLoopbackHost(url.hostname)),
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const ct = res.headers["content-type"];
          resolve({
            status: res.statusCode ?? 502,
            contentType: (Array.isArray(ct) ? ct[0] : ct) || "application/json",
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );
    req.setTimeout(BACKEND_TIMEOUT_MS, () => {
      req.destroy(Object.assign(new Error("Backend timed out"), { code: "ETIMEDOUT" }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
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
    const { signature, timestamp } = signGhostPayRequest(body);
    if (!signature) {
      return NextResponse.json(
        {
          error:
            "Dashboard is not configured to authenticate ghost-pay writes (GHOST_PAY_API_SECRET unset). Mutation refused.",
        },
        { status: 503 },
      );
    }
    headers["X-Ghost-Signature"] = signature;
    headers["X-Ghost-Timestamp"] = timestamp;
  } else {
    // Sign GET requests too (empty body) — ghost-pay's auth guard covers reads.
    const { signature, timestamp } = signGhostPayRequest("");
    if (signature) {
      headers["X-Ghost-Signature"] = signature;
      headers["X-Ghost-Timestamp"] = timestamp;
    }
  }

  try {
    const res = await forwardToBackend(url, request.method, headers, body);
    return new NextResponse(res.body, {
      status: res.status,
      headers: { "Content-Type": res.contentType },
    });
  } catch (error) {
    const code = (error as { code?: string })?.code;
    if (code === "ETIMEDOUT") {
      return NextResponse.json({ error: "Backend timed out" }, { status: 504 });
    }
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
