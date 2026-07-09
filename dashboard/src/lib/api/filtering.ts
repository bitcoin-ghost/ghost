// Filtering activity — cumulative per-stage rejection counts, read from the node
// via `/api/v1/filtering/activity`.
import { fetchApi } from "./client";
import type { FilteringActivity } from "@/types/api";

/**
 * Fetch the cumulative filtering-activity counters. Returns `null` (rather than
 * throwing) when the endpoint is absent — it is added in a separate rollout, so
 * older nodes 404 — or on any transport error, so callers can degrade to a
 * "no rejections yet" state instead of crashing.
 *
 * Routed through `fetchApi` so the HMAC-signed internal request actually reaches
 * the node; a bare `fetch` hits the Next server and 404s.
 */
export async function getFilteringActivity(): Promise<FilteringActivity | null> {
  try {
    const data = await fetchApi<unknown>("/api/v1/filtering/activity");
    return data && typeof data === "object" && "stage1_mempool" in data
      ? (data as FilteringActivity)
      : null;
  } catch {
    return null;
  }
}
