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
  L2FeeDistributionContext,
  L2TreeState,
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

// L2 fee-distribution context — treasury pool + Ghost Pay nodes sharing L2 fees.
export async function getL2FeeDistributionContext(): Promise<L2FeeDistributionContext> {
  return fetchApi<L2FeeDistributionContext>('/api/v1/l2/fee-distribution-context');
}

// L2 commitment-tree state (root, checkpoint, finalization counts).
export async function getL2TreeState(): Promise<L2TreeState> {
  return fetchApi<L2TreeState>('/api/v1/l2/tree-state');
}

// GhostPay Payout History (for Ghost-Pay page)
export async function getGhostPayPayoutHistory(
  timeFilter: PayoutHistoryTimeFilter = '7d'
): Promise<GhostPayPayoutHistoryResponse> {
  return fetchApi<GhostPayPayoutHistoryResponse>(
    `/api/v1/ghostpay/payout-history?time_filter=${timeFilter}`
  );
}

