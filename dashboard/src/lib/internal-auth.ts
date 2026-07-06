import { createHmac } from "crypto";

// The node's local API is always reachable on loopback:8080. Default to it so a
// fresh install works with no configuration; honour NEXT_PUBLIC_API_URL when set.
export const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8080";

export interface InternalSignature {
  signature: string;
  timestamp: string;
}

// Sign a request body for the node's internal (mesh-authenticated) endpoints.
//
// Matches the Rust `InternalAuth` scheme in `ghost-verification`:
//   HMAC-SHA256(secret, timestamp_le_bytes(8) || body)
// where `secret` is the hex-decoded `INTERNAL_AUTH_KEY` and `timestamp` is the
// current Unix time in seconds. Returns empty strings when no key is configured,
// so callers can detect that and skip the signed call.
export function signInternalRequest(body: string): InternalSignature {
  const key = process.env.INTERNAL_AUTH_KEY;
  if (!key) {
    return { signature: "", timestamp: "" };
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const keyBytes = Buffer.from(key, "hex");

  const hmac = createHmac("sha256", keyBytes);
  const timestampBuf = Buffer.alloc(8);
  timestampBuf.writeBigUInt64LE(BigInt(timestamp));
  hmac.update(timestampBuf);
  hmac.update(body);
  const signature = hmac.digest("hex");

  return { signature, timestamp: timestamp.toString() };
}

// Build the internal-auth headers for a signed request body, or an empty object
// when no signing key is configured.
export function internalAuthHeaders(body: string): Record<string, string> {
  const { signature, timestamp } = signInternalRequest(body);
  if (!signature) {
    return {};
  }
  return {
    "X-Ghost-Signature": signature,
    "X-Ghost-Timestamp": timestamp,
  };
}
