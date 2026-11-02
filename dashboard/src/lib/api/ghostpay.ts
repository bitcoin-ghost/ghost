// Ghost Pay API endpoints
import { fetchApi, fetchWithTimeout } from './client';
import type {
  GhostPayStatus,
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

/// Error that preserves the backend's response body.
///
/// ghost-pay answers failures with a structured payload (`reason`, `remedy`), not an
/// `error` string. Collapsing that to `API error: <status>` threw the useful half away and
/// left the UI showing a bare status code — which is what #404 was reporting.
export class GhostPayApiError extends Error {
  readonly status: number;
  readonly body: Record<string, unknown>;

  constructor(status: number, body: Record<string, unknown>) {
    const detail =
      (typeof body.reason === 'string' && body.reason) ||
      (typeof body.error === 'string' && body.error) ||
      `API error: ${status}`;
    super(detail);
    this.name = 'GhostPayApiError';
    this.status = status;
    this.body = body;
  }

  /// The operator-facing next step, when the backend supplied one.
  get remedy(): string | null {
    return typeof this.body.remedy === 'string' ? this.body.remedy : null;
  }
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
    const body = await response.json().catch(() => ({}));
    throw new GhostPayApiError(response.status, body as Record<string, unknown>);
  }

  return response.json();
}

// Node Ghost ID (the node's single derived L2 receive address).
//
// `generated: false` is a legitimate state, not a failure: a node that has never had a
// keypair created answers 404 with that body. It is surfaced as data so the wizard can offer
// to generate one, rather than as an exception the UI can only render as red text.
export interface GhostIdResponse {
  generated: boolean;
  ghost_id: string | null;
  scan_pubkey?: string;
  spend_pubkey?: string;
  identity_kind?: string;
  reason?: string;
  remedy?: string;
}

export async function getGhostId(): Promise<GhostIdResponse> {
  try {
    return await fetchGhostPay<GhostIdResponse>('/api/v1/keys/ghost-id');
  } catch (err) {
    // Only the specific "no keypair yet" 404 is a state; anything else is a real error.
    if (err instanceof GhostPayApiError && err.status === 404 && err.body.generated === false) {
      return err.body as unknown as GhostIdResponse;
    }
    throw err;
  }
}

/// Create the node's ghost-pay keypair. Mutating, so the proxy HMAC-signs it.
export async function generateGhostKeys(): Promise<GhostIdResponse> {
  return fetchGhostPay<GhostIdResponse>('/api/v1/keys/generate', { method: 'POST' });
}

// Ghost Pay Status
export async function getGhostPayStatus(): Promise<GhostPayStatus> {
  return fetchApi<GhostPayStatus>('/api/v1/ghostpay/status');
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

// Settlement Status (node-level settlement service status).
//
// The live `/settlement/status` endpoint returns a FLAT shape:
//   { status, pending_settlements, pending_count, batches_24h,
//     last_settlement, total_settled_sats }
// There is no nested `stats` object or `batches` array, so we read the real
// flat fields directly. The previous nested-shape mapping silently produced
// all-zeros against the real backend (Settlement Quick-Stats always showed 0).
export async function getSettlementStatus(): Promise<SettlementStatus> {
  // Let fetch errors propagate so React Query exposes `isError`, rather than masking a
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

