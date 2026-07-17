// Rewards API endpoints
import { fetchApi } from './client';
import type {
  RewardsCurrent,
  RewardsHistory,
  RewardsFullResponse,
  NodePayoutEntry,
  PayoutHistoryTimeFilter,
} from '@/types/api';

export async function getRewardsCurrent(): Promise<RewardsCurrent> {
  return fetchApi<RewardsCurrent>('/api/v1/rewards/current');
}

export async function getRewardsHistory(): Promise<RewardsHistory> {
  return fetchApi<RewardsHistory>('/api/v1/rewards/history');
}

export async function getRewardsFull(): Promise<RewardsFullResponse> {
  const data = await fetchApi<RewardsFullResponse & { pending_payout_sats?: number }>('/api/v1/rewards/full');
  // Backend may return pending_payout_sats instead of pending_rewards_sats
  if (data.pending_rewards_sats === undefined && data.pending_payout_sats !== undefined) {
    data.pending_rewards_sats = data.pending_payout_sats;
  }
  return data;
}

// Node Payout History (for Rewards page - only THIS node's payments)
export async function getNodePayoutHistory(
  timeFilter: PayoutHistoryTimeFilter = '7d',
  payoutType?: string
): Promise<NodePayoutEntry[]> {
  const params = new URLSearchParams({ time_filter: timeFilter });
  if (payoutType) params.set('payout_type', payoutType);
  // The /api/v1/rewards/node-history endpoint wraps the entries in
  // `{ history, total }` (same payload as getNodeBalances) — it does NOT return
  // a bare array. Unwrap here so every caller receives the array it is typed to
  // get. Stay tolerant of a bare-array response in case the endpoint changes.
  const res = await fetchApi<NodePayoutEntry[] | { history?: NodePayoutEntry[] }>(
    `/api/v1/rewards/node-history?${params.toString()}`,
  );
  return Array.isArray(res) ? res : res?.history ?? [];
}

// Node Payout EVENTS — individual per-round credit events (not the running
// balance ledger). Backed by the `payouts` table via the
// /api/v1/rewards/node-payout-events endpoint. Available only once the node
// binary that serves it is deployed; callers fall back to the balance ledger
// when it is absent (older node → this request 404s/throws).
export interface NodePayoutEvent {
  round_id: number;
  recipient_id: string;
  amount_sats: number;
  txid: string | null;
  status: string;
  created_at: number;
  confirmed_at: number | null;
  is_self: boolean;
}

export interface NodePayoutEventsResponse {
  events: NodePayoutEvent[];
  total: number;
}

export async function getNodePayoutEvents(
  timeFilter: PayoutHistoryTimeFilter = '7d',
): Promise<NodePayoutEventsResponse> {
  return fetchApi<NodePayoutEventsResponse>(
    `/api/v1/rewards/node-payout-events?time_filter=${timeFilter}`,
  );
}

// Node Balance Accounts — all nodes with their reward balances
export interface NodeBalanceEntry {
  node_id: string;
  balance_sats: number;
  last_credited_round: number;
  total_credits_sats: number;
  total_withdrawals_sats: number;
  is_self: boolean;
  created_at: number;
  updated_at: number;
}

export interface NodeBalancesResponse {
  history: NodeBalanceEntry[];
  total: number;
}

export async function getNodeBalances(): Promise<NodeBalancesResponse> {
  return fetchApi<NodeBalancesResponse>('/api/v1/rewards/node-history');
}

// CSV export helper (client-side)
export function exportRewardsToCSV(payouts: Array<{ timestamp: number; amount_btc: number; txid: string; block_height: number }>): void {
  const headers = ['Date', 'Amount (BTC)', 'TxID', 'Block Height'];
  const rows = payouts.map((p) => [
    new Date(p.timestamp * 1000).toISOString(),
    p.amount_btc.toFixed(8),
    p.txid,
    p.block_height.toString(),
  ]);

  const csv = [headers, ...rows].map((row) => row.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);

  const a = document.createElement('a');
  a.href = url;
  a.download = `ghost-node-rewards-${new Date().toISOString().split('T')[0]}.csv`;
  a.click();

  URL.revokeObjectURL(url);
}
