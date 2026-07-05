// Reaper observability — cumulative counters from the pool's block-template
// reaper, read from ghost-pool via `/api/v1/reaper/status`.
import { fetchApi } from "./client";

// Per-DeadCodeType hit counters. Keys mirror ghost-pool's `DeadCodeType`
// variants; a single reaped transaction can trip more than one, so the sum of
// `by_type` may exceed `txs_reaped`.
export interface ReaperByType {
  inscription_envelope: number;
  drop_stuffing: number;
  unreachable_code: number;
  fake_pubkey: number;
  fake_pubkey_curve_point: number;
  annex_present: number;
  oversized_op_return: number;
  dust_flood: number;
  excess_witness_data: number;
  excess_stack_items: number;
  legacy_scriptsig_data: number;
}

export interface ReaperStats {
  txs_evaluated: number;
  txs_reaped: number;
  txs_accepted: number;
  // Total virtual bytes of dead weight stripped from block templates.
  dead_bytes_total: number;
  last_reaped_unix: number | null;
  // Per-block snapshot: the most-recently-built template's reaped tx count +
  // dead bytes. last_block_unix is null until the first template is built,
  // which distinguishes "0 reaped this block" from "no block yet".
  last_block_reaped: number;
  last_block_dead_bytes: number;
  last_block_unix: number | null;
  by_type: ReaperByType;
}

/**
 * Fetch the cumulative reaper counters. Returns `null` (rather than throwing)
 * when ghost-pool hasn't wired the observability callback yet, or on any
 * transport error, so callers can degrade to a "no counters yet" state.
 *
 * Routed through `fetchApi` so the HMAC-signed internal request actually
 * reaches ghost-pool; a bare `fetch` hits the Next server and 404s.
 */
export async function getReaperStatus(): Promise<ReaperStats | null> {
  try {
    const data = await fetchApi<unknown>("/api/v1/reaper/status");
    return data && typeof data === "object" && "txs_evaluated" in data
      ? (data as ReaperStats)
      : null;
  } catch {
    return null;
  }
}
