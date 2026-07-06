'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import {
  useMiningStatus,
  usePoolStatus,
  usePoolSeriesHistory,
  miningKeys,
  networkKeys,
} from '@/hooks/queries';
import type { MiningStatus, PoolStatus } from '@/types/api';

/**
 * Rolling time-series for the Node Pool page.
 *
 * Preferred source is the backend `GET /api/v1/pool/series` endpoint, a
 * server-side ring sampled every 30s (survives reloads, covers up to 24h). When
 * that ring is still empty (fresh node / just-restarted) the hook falls back to
 * a client-side session buffer: every time the mining-status query refetches
 * (~5s) we append the latest reading. Session accumulation is driven by
 * subscribing to the react-query cache (an external system) — the idiomatic
 * pattern for syncing external updates into state.
 *
 * Share accept-rate has no backend series (the node exposes cumulative counters,
 * not a rate history) so that chart is always session-derived.
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
  /** Share accept-rate, 0–100 (always session-derived). */
  acceptRate: SeriesPoint[];
  /** Number of samples collected this session (session buffer). */
  sampleCount: number;
  /** True when the hashrate/miner charts are backed by server-side history. */
  serverBacked: boolean;
}

const MAX_POINTS = 240; // ~20 min at a 5s poll

interface SessionSeries {
  meshHashrate: SeriesPoint[];
  nodeHashrate: SeriesPoint[];
  miners: SeriesPoint[];
  acceptRate: SeriesPoint[];
  sampleCount: number;
}

export function usePoolSeries(): PoolSeries {
  // Keep the underlying queries active (and shared via the react-query cache)
  // so there is always fresh data to sample.
  useMiningStatus();
  usePoolStatus();
  // Server-side history (1h window). Falls back silently to the session buffer
  // when the endpoint is empty or unavailable on older nodes.
  const { data: history } = usePoolSeriesHistory('1h');

  const queryClient = useQueryClient();
  const [session, setSession] = useState<SessionSeries>({
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

      setSession((prev) => ({
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

  // Merge: prefer the server ring for hashrate/miner charts once it has enough
  // points to draw a meaningful line; otherwise use the session buffer. Chart
  // values are H/s (TH/s * 1e12) to match the session buffer's units.
  return useMemo<PoolSeries>(() => {
    const samples = history?.samples ?? [];
    const serverBacked = samples.length >= 2;
    if (serverBacked) {
      return {
        meshHashrate: samples.map((s) => ({ t: s.t, v: s.mesh_hashrate_th * 1e12 })),
        nodeHashrate: samples.map((s) => ({ t: s.t, v: s.local_hashrate_th * 1e12 })),
        miners: samples.map((s) => ({ t: s.t, v: s.miners })),
        // No backend accept-rate series — keep the session-derived one.
        acceptRate: session.acceptRate,
        sampleCount: session.sampleCount,
        serverBacked: true,
      };
    }
    return { ...session, serverBacked: false };
  }, [history, session]);
}
