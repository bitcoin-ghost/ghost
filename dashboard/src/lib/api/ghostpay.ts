// Ghost Pay API endpoints
import { fetchApi, fetchWithTimeout } from './client';
import type {
  GhostPayStatus,
  WraithSessionsResponse,
  WraithStats,
  WraithSession,
  GhostLocksResponse,
  GhostLock,
  PaymentsResponse,
  SettlementResponse,
  SettlementStatus,
  GhostPayPayoutHistoryResponse,
  PayoutHistoryTimeFilter,
} from '@/types/api';

// The Ghost ID (and other key material) is served by the ghost-pay backend,
// reached through the dedicated ghostpay-proxy route which signs the request.
function getGhostPayProxyBase(): string {
  if (typeof window !== 'undefined') {
    return window.location.origin;
  }
  return 'http://localhost:3000';
}

async function fetchGhostPay<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const proxyUrl = `${getGhostPayProxyBase()}/api/ghostpay-proxy${endpoint}`;

  const response = await fetchWithTimeout(proxyUrl, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const err = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(err.error || `API error: ${response.status}`);
  }

  return response.json();
}

// Node Ghost ID (the node's single derived L2 receive address).
export interface GhostIdResponse {
  ghost_id: string;
}

export async function getGhostId(): Promise<GhostIdResponse> {
  return fetchGhostPay<GhostIdResponse>('/api/v1/keys/ghost-id');
}

// === Ghost Glyph ===========================================================
// A glyph is a 16x16 grid of palette indices (0..25), 256 bytes total. The
// backend keys uniqueness on SHA256("GhostGlyphBitmap/v1" || pixels) — we must
// compute the IDENTICAL hash here so the availability check matches what the
// claim will register. Mirrors crates/ghost-glyph/src/glyph.rs.

export const GLYPH_GRID = 16;
export const GLYPH_PIXELS = GLYPH_GRID * GLYPH_GRID; // 256
export const GLYPH_PALETTE_SIZE = 26;

const GLYPH_BITMAP_DOMAIN = 'GhostGlyphBitmap/v1';

export interface GlyphInfo {
  ghost_id: string;
  pixels: number[];
  bitmap_hash: string;
  commitment: string;
  funding_txid: string | null;
  registered_at: number | null;
  status: string; // "pending" | "registered" (backend never returns "none" here)
}

export interface GlyphClaimResult {
  commitment: string;
  bitmap_hash: string;
  status: string;
}

export interface GlyphAvailability {
  available: boolean;
}

/**
 * Compute the bitmap uniqueness hash exactly as the Rust backend does:
 * SHA256(domain-bytes || 256 pixel-bytes), hex-encoded. Uses Web Crypto so it
 * runs in the browser without a dependency.
 */
export async function computeBitmapHash(pixels: number[]): Promise<string> {
  if (pixels.length !== GLYPH_PIXELS) {
    throw new Error(`Expected ${GLYPH_PIXELS} pixels, got ${pixels.length}`);
  }
  const domain = new TextEncoder().encode(GLYPH_BITMAP_DOMAIN);
  const buf = new Uint8Array(domain.length + GLYPH_PIXELS);
  buf.set(domain, 0);
  for (let i = 0; i < GLYPH_PIXELS; i++) {
    const v = pixels[i];
    if (!Number.isInteger(v) || v < 0 || v >= GLYPH_PALETTE_SIZE) {
      throw new Error(`Invalid pixel value at index ${i}`);
    }
    buf[domain.length + i] = v;
  }
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Fetch the glyph registered to a ghost_id. Returns null when none exists (404). */
export async function getGlyph(ghostId: string): Promise<GlyphInfo | null> {
  try {
    return await fetchGhostPay<GlyphInfo>(`/api/v1/glyph/${encodeURIComponent(ghostId)}`);
  } catch (e) {
    // 404 ("Glyph not found") is the expected "not yet designed" path.
    if (e instanceof Error && /not found/i.test(e.message)) return null;
    throw e;
  }
}

/** Check whether a bitmap design is unclaimed, by its computed bitmap hash. */
export async function checkGlyphAvailability(pixels: number[]): Promise<boolean> {
  const hash = await computeBitmapHash(pixels);
  const r = await fetchGhostPay<GlyphAvailability>(
    `/api/v1/glyph/check/${encodeURIComponent(hash)}`,
  );
  return r.available;
}

/** Submit a glyph claim for a ghost_id (pending until its lock funds). */
export async function claimGlyph(ghostId: string, pixels: number[]): Promise<GlyphClaimResult> {
  return fetchGhostPay<GlyphClaimResult>('/api/v1/glyph/claim', {
    method: 'POST',
    body: JSON.stringify({ ghost_id: ghostId, pixels }),
  });
}

// Ghost Pay Status
export async function getGhostPayStatus(): Promise<GhostPayStatus> {
  return fetchApi<GhostPayStatus>('/api/v1/ghostpay/status');
}

// Wraith
export async function getWraithSessions(): Promise<WraithSessionsResponse> {
  return fetchApi<WraithSessionsResponse>('/api/v1/wraith/sessions');
}

export async function getWraithSession(sessionId: string): Promise<WraithSession> {
  return fetchApi<WraithSession>(`/api/v1/wraith/session/${sessionId}`);
}

export async function joinWraithSession(sessionId: string, lockId: string): Promise<{ success: boolean; message: string }> {
  return fetchApi<{ success: boolean; message: string }>(`/api/v1/wraith/sessions/${sessionId}/join`, {
    method: 'POST',
    body: JSON.stringify({ lock_id: lockId }),
  });
}

// Ghost Locks
export async function getGhostLocks(): Promise<GhostLocksResponse> {
  return fetchApi<GhostLocksResponse>('/api/v1/locks');
}

export async function getGhostLock(lockId: string): Promise<GhostLock> {
  return fetchApi<GhostLock>(`/api/v1/locks/${lockId}`);
}

export async function requestLockSettlement(lockId: string): Promise<{ success: boolean; message: string }> {
  return fetchApi<{ success: boolean; message: string }>(`/api/v1/locks/${lockId}/settlement`, {
    method: 'POST',
  });
}

export async function useLockInMix(lockId: string, sessionId: string): Promise<{ success: boolean; message: string }> {
  return fetchApi<{ success: boolean; message: string }>(`/api/v1/locks/${lockId}/mix`, {
    method: 'POST',
    body: JSON.stringify({ session_id: sessionId }),
  });
}

// Payments
export async function getPayments(limit?: number, offset?: number): Promise<PaymentsResponse> {
  const params = new URLSearchParams();
  if (limit) params.set('limit', limit.toString());
  if (offset) params.set('offset', offset.toString());
  const query = params.toString();
  return fetchApi<PaymentsResponse>(`/api/v1/payments${query ? `?${query}` : ''}`);
}

// Settlement
export async function getSettlement(): Promise<SettlementResponse> {
  return fetchApi<SettlementResponse>('/api/v1/settlement/status');
}

// Wraith Stats (aggregate stats, not wallet-specific)
export async function getWraithStats(): Promise<WraithStats> {
  try {
    // Try to get from wraith sessions and compute stats
    const sessions = await fetchApi<WraithSessionsResponse>('/api/v1/wraith/sessions');
    return {
      total_sessions: sessions.stats?.total_sessions ?? sessions.sessions?.length ?? 0,
      active_sessions: sessions.stats?.active_sessions ?? sessions.sessions?.filter(s => s.status === 'Filling' || s.status === 'Full').length ?? 0,
      sessions_completed: sessions.stats?.sessions_completed ?? sessions.sessions?.filter(s => s.status === 'Complete').length ?? 0,
      sessions_expired: sessions.stats?.sessions_expired ?? sessions.sessions?.filter(s => s.status === 'Expired').length ?? 0,
      total_participants: sessions.sessions?.reduce((sum, s) => sum + (s.participant_count ?? 0), 0) ?? 0,
      avg_fill_rate: sessions.sessions?.length > 0
        ? sessions.sessions.reduce((sum, s) => sum + (s.fill_percentage ?? 0), 0) / sessions.sessions.length / 100
        : 0,
      your_participations: sessions.stats?.your_participations ?? 0,
      your_completed: sessions.stats?.your_completed ?? 0,
    };
  } catch (e) {
    // Don't fail silently — a fetch error here previously rendered as all-zeros,
    // indistinguishable from "no activity". Log so operators can diagnose.
    console.error("getWraithStats: failed to fetch wraith sessions", e);
    return {
      total_sessions: 0,
      active_sessions: 0,
      sessions_completed: 0,
      sessions_expired: 0,
      total_participants: 0,
      avg_fill_rate: 0,
      your_participations: 0,
      your_completed: 0,
    };
  }
}

// Settlement Status (node-level settlement service status)
export async function getSettlementStatus(): Promise<SettlementStatus> {
  try {
    const settlement = await fetchApi<SettlementResponse>('/api/v1/settlement/status');
    return {
      l1_available: settlement.stats?.l1_connected ?? false,
      l1_height: settlement.stats?.l1_height ?? 0,
      active_count: settlement.stats?.active_batches ?? 0,
      pending_count: settlement.stats?.pending_batches ?? 0,
      batches_24h: settlement.stats?.confirmed_24h ?? 0,
      total_settled_24h: settlement.stats?.total_settled_24h ?? 0,
      current_epoch: settlement.stats?.current_epoch ?? 0,
      avg_batch_size: (settlement.batches?.length ?? 0) > 0
        ? settlement.batches!.reduce((sum, b) => sum + b.participant_count, 0) / settlement.batches!.length
        : 0,
    };
  } catch (e) {
    // See getWraithStats — log instead of silently returning all-zeros.
    console.error("getSettlementStatus: failed to fetch settlement status", e);
    return {
      l1_available: false,
      l1_height: 0,
      active_count: 0,
      pending_count: 0,
      batches_24h: 0,
      total_settled_24h: 0,
      current_epoch: 0,
      avg_batch_size: 0,
    };
  }
}

// GhostPay Payout History (for Ghost-Pay page)
export async function getGhostPayPayoutHistory(
  timeFilter: PayoutHistoryTimeFilter = '7d'
): Promise<GhostPayPayoutHistoryResponse> {
  return fetchApi<GhostPayPayoutHistoryResponse>(
    `/api/v1/ghostpay/payout-history?time_filter=${timeFilter}`
  );
}

