// Capability self-check — per-capability prerequisite probes computed by
// ghost-pool's background loop and read from `/api/v1/system/self-check`.
//
// For every capability the node CLAIMS in its config, the node probes whether
// the prerequisite is actually satisfied (e.g. `public_mining` requires the
// SV1 stratum port to be listening). When a claim's prerequisite is missing the
// operator is silently NOT earning that capability's shares, so the dashboard
// surfaces it as a warning banner.
import { fetchApi } from "./client";

export interface CapabilityCheck {
  // True iff the node's config asks for this capability.
  claimed: boolean;
  // True iff the prerequisite probe passes right now.
  passed: boolean;
  // Human-readable failure reason (null when passing / not claimed).
  reason: string | null;
  // Unix timestamp of the most recent probe.
  last_checked_unix: number;
}

export interface SelfCheckState {
  public_mining: CapabilityCheck;
  archive: CapabilityCheck;
  ghost_pay: CapabilityCheck;
  reaper: CapabilityCheck;
}

/**
 * Fetch the self-check snapshot. Returns `null` (rather than throwing) when the
 * backend hasn't wired the provider yet (older deploy — the endpoint serves
 * JSON `null`), when the endpoint is absent (404 → older backend without the
 * route at all), or on any transport error. Callers treat `null` as "nothing
 * to warn about", so the frontend is safe to ship before the backend bounce.
 */
export async function getSelfCheck(): Promise<SelfCheckState | null> {
  try {
    const data = await fetchApi<unknown>("/api/v1/system/self-check");
    return data && typeof data === "object" && "public_mining" in data
      ? (data as SelfCheckState)
      : null;
  } catch {
    return null;
  }
}

// A single failing capability, flattened for banner rendering.
export interface SelfCheckFailure {
  capability: keyof SelfCheckState;
  reason: string;
}

// Extract the capabilities that are CLAIMED but whose prerequisite is missing.
// Empty array when the snapshot is null or everything claimed is passing.
export function selfCheckFailures(
  state: SelfCheckState | null | undefined,
): SelfCheckFailure[] {
  if (!state) return [];
  const caps: (keyof SelfCheckState)[] = [
    "public_mining",
    "archive",
    "ghost_pay",
    "reaper",
  ];
  return caps
    .filter((c) => state[c]?.claimed && !state[c]?.passed)
    .map((c) => ({
      capability: c,
      reason: state[c]?.reason ?? "prerequisite not satisfied",
    }));
}
