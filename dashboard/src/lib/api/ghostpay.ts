// Ghost Pay API endpoints
import { fetchApi, fetchWithTimeout } from './client';
import type {
  GhostPayStatus,
  WraithSessionsResponse,
  WraithStats,
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

// Ghost Locks
export async function getGhostLock(lockId: string): Promise<GhostLock> {
  return fetchApi<GhostLock>(`/api/v1/locks/${lockId}`);
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

// Wraith Stats (node-level aggregate mixing stats, not wallet-specific).
// The backend returns the aggregate counts at the TOP LEVEL of the response
// (total_sessions, active_sessions, sessions_completed, …); prefer those real
// fields, then a nested `stats` object, then a count derived from the live
// session list as a last resort.
export async function getWraithStats(): Promise<WraithStats> {
  // Let fetch errors propagate so React Query exposes `isError`. Swallowing them
  // into all-zeros here makes a backend outage indistinguishable from genuine
  // "no activity"; the consuming page renders an explicit "unavailable" state.
  const sessions = await fetchApi<WraithSessionsResponse>('/api/v1/wraith/sessions');
  const list = sessions.sessions ?? [];
  return {
    total_sessions: sessions.total_sessions ?? sessions.total ?? sessions.stats?.total_sessions ?? list.length,
    active_sessions: sessions.active_sessions ?? sessions.active ?? sessions.stats?.active_sessions ?? list.filter(s => s.status === 'Filling' || s.status === 'Full').length,
    sessions_completed: sessions.sessions_completed ?? sessions.stats?.sessions_completed ?? list.filter(s => s.status === 'Complete').length,
    sessions_expired: sessions.sessions_expired ?? sessions.stats?.sessions_expired ?? list.filter(s => s.status === 'Expired').length,
    total_participants: sessions.total_participants ?? sessions.stats?.total_participants ?? list.reduce((sum, s) => sum + (s.participant_count ?? 0), 0),
    avg_fill_rate: list.length > 0
      ? list.reduce((sum, s) => sum + (s.fill_percentage ?? 0), 0) / list.length / 100
      : 0,
    your_participations: sessions.stats?.your_participations ?? 0,
    your_completed: sessions.stats?.your_completed ?? 0,
  };
}

// Settlement Status (node-level settlement service status).
//
// The live `/settlement/status` endpoint returns a FLAT shape:
//   { status, pending_settlements, pending_count, batches_24h,
//     last_settlement, total_settled_sats }
// There is no nested `stats` object or `batches` array, so we read the real
// flat fields directly. The previous nested-shape mapping silently produced
// all-zeros against the real backend (Settlement Quick-Stats always showed 0).
export async function getSettlementStatus(): Promise<SettlementStatus> {
  // Let fetch errors propagate (see getWraithStats) rather than masking a
  // backend outage as an all-zeros "idle" status.
  const settlement = await fetchApi<SettlementResponse>('/api/v1/settlement/status');
  return {
    status: settlement.status ?? 'idle',
    pending_count: settlement.pending_count ?? settlement.pending_settlements ?? 0,
    batches_24h: settlement.batches_24h ?? 0,
    total_settled_sats: settlement.total_settled_sats ?? 0,
  };
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

