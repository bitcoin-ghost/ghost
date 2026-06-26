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
      avg_completion_time_secs: 180, // Placeholder
      your_participations: sessions.stats?.your_participations ?? 0,
      your_completed: sessions.stats?.your_completed ?? 0,
    };
  } catch {
    return {
      total_sessions: 0,
      active_sessions: 0,
      sessions_completed: 0,
      sessions_expired: 0,
      total_participants: 0,
      avg_fill_rate: 0,
      avg_completion_time_secs: 0,
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
      avg_confirmation_time_mins: 30, // Placeholder
    };
  } catch {
    return {
      l1_available: false,
      l1_height: 0,
      active_count: 0,
      pending_count: 0,
      batches_24h: 0,
      total_settled_24h: 0,
      current_epoch: 0,
      avg_batch_size: 0,
      avg_confirmation_time_mins: 0,
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

// Lock reconciliation (settle lock to L1)
export async function reconcileLock(lockId: string, config: {
  destination_address: string;
  settlement_class?: 'standard' | 'batched';
}): Promise<{ success: boolean; withdrawal_id?: number; message: string }> {
  return fetchApi(`/api/v1/locks/${lockId}/reconcile`, {
    method: 'POST',
    body: JSON.stringify(config),
  });
}

// ---------------------------------------------------------------------------
// Pay-node write routes
//
// The L2 payment-send and read-only ghost-id routes live on the ghost-pay
// node (port 8800), reached through the dashboard's `/api/ghostpay-proxy`
// route (which HMAC-signs the request). This is a DIFFERENT backend from the
// read-only `/api/proxy` (ghost-pool, port 8080) used by the getters above,
// so these functions must go through their own proxy base — mirroring the
// helper in `glyph.ts`.
// ---------------------------------------------------------------------------

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
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `API error: ${response.status}`);
  }

  return response.json();
}

export interface GhostIdInfo {
  ghost_id: string;
  scan_pubkey: string;
  spend_pubkey: string;
}

// Read the node's Ghost ID (derived from the operator's keys).
// GET /api/v1/keys/ghost-id  (ghost-pay, read-only)
export async function getGhostId(): Promise<GhostIdInfo> {
  return fetchGhostPay<GhostIdInfo>('/api/v1/keys/ghost-id');
}

export interface SendL2PaymentResponse {
  success: boolean;
  error?: string;
  payment_id?: string;
  sender?: string;
  recipient?: string;
  amount_sats?: number;
  memo?: string | null;
  status?: string;
  proof_required?: boolean;
  message?: string;
  // Returned on the "insufficient balance" business failure.
  available_sats?: number;
  requested_sats?: number;
}

// Send an L2 instant payment.
//
// POST /api/v1/payments/send  (ghost-pay, port 8800 via the ghostpay-proxy).
// This is a ONE-SHOT call — the L2 transfer is recorded immediately; there
// is no prepare→submit handshake (an off-chain transfer produces no on-chain
// tx and needs no per-payment sighash). The handler returns HTTP 200 with
// `{ success: false, error }` for business failures (insufficient balance,
// zero amount, missing recipient/keys), so callers must check `success`.
//
// `sender_ghost_id` identifies the paying wallet; the dashboard supplies the
// node's own Ghost ID (read via `getGhostId`) since the operator pays from
// their node's Ghost Pay balance.
export async function sendL2Payment(config: {
  sender_ghost_id: string;
  recipient: string;
  amount_sats: number;
  memo?: string;
}): Promise<SendL2PaymentResponse> {
  return fetchGhostPay<SendL2PaymentResponse>('/api/v1/payments/send', {
    method: 'POST',
    body: JSON.stringify({
      sender_ghost_id: config.sender_ghost_id,
      recipient: config.recipient,
      amount_sats: config.amount_sats,
      memo: config.memo,
    }),
  });
}
