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

// ---------------------------------------------------------------------------
// Pay-node write routes
//
// Lock creation, lock reconciliation, L2 payment send and the read-only
// ghost-id all live on the ghost-pay node (port 8800), reached through the
// dashboard's `/api/ghostpay-proxy` route (which HMAC-signs the request).
// This is a DIFFERENT backend from the read-only `/api/proxy` (ghost-pool,
// port 8080) used by the getters above, so these functions must go through
// their own proxy base — mirroring `glyph.ts`.
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

/** Denomination tiers accepted by ghost-pay's `Denomination::from_sats`. */
export type LockDenomination = 'micro' | 'tiny' | 'small' | 'medium' | 'large';

/** Timelock tiers accepted by ghost-pay's lock creation route. */
export type TimelockTier = 'short' | 'standard' | 'long';

/** Settlement classes accepted by ghost-pay's `reconcile_lock` handler. */
export type SettlementClass = 'express' | 'standard' | 'economy';

const DENOMINATION_SATS: Record<LockDenomination, number> = {
  micro: 10_000,
  tiny: 100_000,
  small: 1_000_000,
  medium: 10_000_000,
  large: 100_000_000,
};

/** Lock summary returned in the `lock` field of the create-lock response. */
export interface CreatedLockInfo {
  id: string;
  state?: string;
  amount_sats: number;
  denomination?: string;
  timelock_tier?: string;
  address: string;
  creation_height?: number;
}

export interface CreateLockResponse {
  success: boolean;
  lock: CreatedLockInfo;
}

// Create a Ghost Lock on the pay node.
// POST /api/v1/locks/create  (ghost-pay)
export async function createLock(config: {
  denomination: LockDenomination;
  timelock_tier: TimelockTier;
}): Promise<CreateLockResponse> {
  return fetchGhostPay<CreateLockResponse>('/api/v1/locks/create', {
    method: 'POST',
    body: JSON.stringify({
      amount_sats: DENOMINATION_SATS[config.denomination],
      timelock_tier: config.timelock_tier,
    }),
  });
}

export interface ReconcileLockResponse {
  success: boolean;
  error?: string;
  withdrawal_id?: number;
  lock_id?: string;
  settlement_amount?: number;
  fee_sats?: number;
  settlement_class?: string;
  destination_address?: string;
  message?: string;
}

// Reconcile (settle) a Ghost Lock to an L1 address.
// POST /api/v1/locks/:id/reconcile  (ghost-pay)
export async function reconcileLock(lockId: string, config: {
  destination_address: string;
  settlement_class?: SettlementClass;
}): Promise<ReconcileLockResponse> {
  return fetchGhostPay<ReconcileLockResponse>(`/api/v1/locks/${lockId}/reconcile`, {
    method: 'POST',
    body: JSON.stringify({
      destination_address: config.destination_address,
      settlement_class: config.settlement_class ?? 'standard',
    }),
  });
}

export interface SendL2PaymentResponse {
  success: boolean;
  payment_id?: string;
  message?: string;
}

// Send an L2 instant payment.
// POST /api/v1/payments/send  (ghost-pay)
export async function sendL2Payment(config: {
  recipient: string;
  amount_sats: number;
  memo?: string;
}): Promise<SendL2PaymentResponse> {
  return fetchGhostPay<SendL2PaymentResponse>('/api/v1/payments/send', {
    method: 'POST',
    body: JSON.stringify(config),
  });
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
