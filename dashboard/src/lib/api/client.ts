// Ghost Node API Client - Base utilities
//
// All API calls go through Next.js API proxy routes (/api/proxy/...)
// which handle HMAC signing for internal endpoints server-side.

import { getWsUrl } from "./ws";

const FETCH_TIMEOUT = 5000;

/// Get the API base URL for proxied requests
function getProxyBase(): string {
  if (typeof window !== "undefined") {
    return window.location.origin;
  }
  return "http://localhost:3000";
}

// Legacy exports for compatibility
export function getApiBase(): string {
  return getProxyBase();
}

export const API_BASE =
  typeof window !== "undefined" ? getProxyBase() : "http://localhost:3000";

export async function fetchWithTimeout(
  url: string,
  options?: RequestInit,
  timeout = FETCH_TIMEOUT,
): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
    });
    return response;
  } finally {
    clearTimeout(timeoutId);
  }
}

// No-op auth token — auth is handled server-side by the proxy
export async function getAuthToken(): Promise<string | null> {
  return null;
}

export async function fetchApi<T>(
  endpoint: string,
  options?: RequestInit,
): Promise<T> {
  // Route through the proxy: /api/v1/foo -> /api/proxy/api/v1/foo
  const proxyUrl = `${getProxyBase()}/api/proxy${endpoint}`;

  const response = await fetchWithTimeout(proxyUrl, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ error: "Unknown error" }));
    throw new Error(error.error || `API error: ${response.status}`);
  }

  return response.json();
}

export async function fetchApiWithFormData<T>(
  endpoint: string,
  formData: FormData,
  timeout = FETCH_TIMEOUT,
): Promise<T> {
  const proxyUrl = `${getProxyBase()}/api/proxy${endpoint}`;

  const response = await fetchWithTimeout(
    proxyUrl,
    {
      method: "POST",
      body: formData,
    },
    timeout,
  );

  if (!response.ok) {
    const error = await response
      .json()
      .catch(() => ({ error: "Unknown error" }));
    throw new Error(error.error || `API error: ${response.status}`);
  }

  return response.json();
}

// WebSocket connection — routed through the same-origin, JWT-authenticated
// `/api/ws` relay (see server.js), NOT straight to the backend :8080.
export function createWebSocket(): WebSocket | null {
  if (typeof window === "undefined") return null;
  return new WebSocket(getWsUrl());
}
