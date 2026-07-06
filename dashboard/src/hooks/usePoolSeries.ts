'use client';

import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useMiningStatus, usePoolStatus, miningKeys, networkKeys } from '@/hooks/queries';
import type { MiningStatus, PoolStatus } from '@/types/api';

/**
 * Session-scoped rolling time-series for the Node Pool page.
 *
 * The node API exposes only *current* pool values (hashrate, miner count,
 * share tallies) — there is no historical time-series endpoint. So the graphs
 * are driven from a client-side rolling buffer: every time the mining-status
 * query refetches (~5s) we append the latest reading. The buffer lives for the
 * session only (it resets on reload) and is labelled "live (session)" in the UI.
 *
 * Accumulation is driven by subscribing to the react-query cache (an external
 * system) and appending in the subscription callback — the idiomatic pattern
 * for syncing external updates into state.
 *
 * Backend follow-up: persisting these series server-side (e.g. 1-minute
 * roll-ups of pool hashrate / miner count / accept-rate) would let the charts
 * survive reloads and show longer windows than a single session.
 */

export interface SeriesPoint {
  t: number;
  v: number;
}

export interface PoolSeries {
  /** Mesh (whole Ghost pool) hashrate, in H/s. */
  meshHashrate: SeriesPoint[];
  /** This node's local hashrate, in H/s. */
  nodeHashrate: SeriesPoint[];
  /** Connected miners across the mesh. */
  miners: SeriesPoint[];
  /** Share accept-rate, 0–100. */
  acceptRate: SeriesPoint[];
  /** Number of samples collected this session. */
  sampleCount: number;
}

const MAX_POINTS = 240; // ~20 min at a 5s poll

export function usePoolSeries(): PoolSeries {
  // Keep the underlying queries active (and shared via the react-query cache)
  // so there is always fresh data to sample.
  useMiningStatus();
  usePoolStatus();

  const queryClient = useQueryClient();
  const [series, setSeries] = useState<PoolSeries>({
    meshHashrate: [],
    nodeHashrate: [],
    miners: [],
    acceptRate: [],
    sampleCount: 0,
  });

  // Dedupe: only append once per distinct refetch tick.
  const lastTickRef = useRef<number>(0);

  useEffect(() => {
    const cache = queryClient.getQueryCache();

    const sample = () => {
      const state = queryClient.getQueryState<MiningStatus>(miningKeys.status());
      const status = state?.data;
      const updatedAt = state?.dataUpdatedAt ?? 0;
      if (!status || updatedAt === 0 || updatedAt === lastTickRef.current) return;
      lastTickRef.current = updatedAt;

      const pool = queryClient.getQueryData<PoolStatus>(networkKeys.pool());
      const t = Math.floor(updatedAt / 1000);

      const meshTh = status.hashrate_th ?? status.total_hashrate ?? 0;
      const nodeTh = status.local_hashrate_th ?? 0;
      const miners =
        status.mesh_active_miners ??
        pool?.miner_count ??
        status.connected_miners ??
        status.active_miners ??
        0;
      const submitted = status.shares_submitted ?? 0;
      const accepted = status.shares_accepted ?? 0;
      const acceptRate = submitted > 0 ? (accepted / submitted) * 100 : 100;

      const push = (arr: SeriesPoint[], v: number): SeriesPoint[] => {
        const next = [...arr, { t, v }];
        return next.length > MAX_POINTS ? next.slice(next.length - MAX_POINTS) : next;
      };

      setSeries((prev) => ({
        meshHashrate: push(prev.meshHashrate, meshTh * 1e12),
        nodeHashrate: push(prev.nodeHashrate, nodeTh * 1e12),
        miners: push(prev.miners, miners),
        acceptRate: push(prev.acceptRate, acceptRate),
        sampleCount: prev.sampleCount + 1,
      }));
    };

    // Seed with whatever is already cached, then follow cache updates.
    sample();
    const unsubscribe = cache.subscribe(sample);
    return unsubscribe;
  }, [queryClient]);

  return series;
}
