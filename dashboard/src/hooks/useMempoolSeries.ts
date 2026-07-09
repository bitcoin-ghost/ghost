'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { usePoolSeriesHistory } from '@/hooks/queries';
import type { SeriesPoint } from '@/hooks/usePoolSeries';

/**
 * Rolling time-series of this node's mempool transaction count, for the Mempool
 * page graph + tiles.
 *
 * It mirrors {@link usePoolSeries}: the preferred source is the backend
 * `GET /api/v1/pool/series` ring (sampled every 30s, up to 24h, survives
 * reloads), which now carries a per-sample `mempool_txs` (getmempoolinfo.size)
 * and `block_txs` (block-template tx count). When that ring is empty — or is an
 * older node whose samples predate those fields — the hook falls back to a
 * client-side session buffer keyed on the mempool page's own `/buds/mempool`
 * query (`total` = getmempoolinfo.size): every time that query refetches we
 * append the latest reading. Session accumulation is driven by subscribing to
 * the react-query cache (an external system), the same idiomatic pattern
 * usePoolSeries uses.
 *
 * There is no session source for the block-template tx count (the buds/mempool
 * RPC view doesn't expose it), so `blockTxs` / `latestBlockTxs` are populated
 * only from the server ring and stay `[]` / `null` until it has samples.
 */

export interface MempoolSeries {
  /** Mempool transaction count over time (server ring, else session buffer). */
  mempoolTxs: SeriesPoint[];
  /** Block-template transaction count over time (server ring only). */
  blockTxs: SeriesPoint[];
  /** Most recent mempool tx count from the series (null until any sample). */
  latestMempoolTxs: number | null;
  /** Most recent block-template tx count from the server ring (null until any). */
  latestBlockTxs: number | null;
  /** Number of samples collected this session (session buffer). */
  sampleCount: number;
  /** True when the mempool-txs chart is backed by server-side history. */
  serverBacked: boolean;
}

// The mempool page's buds/mempool query key + the field the graph tracks.
const BUDS_MEMPOOL_KEY = ['buds-mempool'] as const;
const MAX_POINTS = 240; // ~1h at the 15s buds/mempool poll

interface BudsMempoolSample {
  total?: number; // getmempoolinfo.size
}

interface SessionSeries {
  mempoolTxs: SeriesPoint[];
  sampleCount: number;
}

export function useMempoolSeries(): MempoolSeries {
  // Server-side history (1h window). Falls back silently to the session buffer
  // when the endpoint is empty, unavailable, or predates the mempool fields.
  const { data: history } = usePoolSeriesHistory('1h');

  const queryClient = useQueryClient();
  const [session, setSession] = useState<SessionSeries>({ mempoolTxs: [], sampleCount: 0 });

  // Dedupe: only append once per distinct refetch tick.
  const lastTickRef = useRef<number>(0);

  useEffect(() => {
    const cache = queryClient.getQueryCache();

    const sample = () => {
      const state = queryClient.getQueryState<BudsMempoolSample>(BUDS_MEMPOOL_KEY);
      const data = state?.data;
      const updatedAt = state?.dataUpdatedAt ?? 0;
      if (!data || updatedAt === 0 || updatedAt === lastTickRef.current) return;
      const total = data.total;
      if (total === undefined || total === null) return;
      lastTickRef.current = updatedAt;

      const t = Math.floor(updatedAt / 1000);
      setSession((prev) => {
        const next = [...prev.mempoolTxs, { t, v: total }];
        return {
          mempoolTxs: next.length > MAX_POINTS ? next.slice(next.length - MAX_POINTS) : next,
          sampleCount: prev.sampleCount + 1,
        };
      });
    };

    // Seed with whatever is already cached, then follow cache updates.
    sample();
    const unsubscribe = cache.subscribe(sample);
    return unsubscribe;
  }, [queryClient]);

  return useMemo<MempoolSeries>(() => {
    const samples = history?.samples ?? [];
    // The mempool/block fields are optional; only samples that carry them count.
    const withMempool = samples.filter((s) => s.mempool_txs != null);
    const withBlock = samples.filter((s) => s.block_txs != null);
    const latestBlockTxs = withBlock.length ? withBlock[withBlock.length - 1].block_txs! : null;
    const blockTxs = withBlock.map((s) => ({ t: s.t, v: s.block_txs! }));

    // Prefer the server ring once it has ≥2 mempool points to draw a line.
    const serverBacked = withMempool.length >= 2;
    if (serverBacked) {
      const mempoolTxs = withMempool.map((s) => ({ t: s.t, v: s.mempool_txs! }));
      return {
        mempoolTxs,
        blockTxs,
        latestMempoolTxs: mempoolTxs[mempoolTxs.length - 1].v,
        latestBlockTxs,
        sampleCount: session.sampleCount,
        serverBacked: true,
      };
    }

    return {
      mempoolTxs: session.mempoolTxs,
      blockTxs,
      latestMempoolTxs: session.mempoolTxs.length
        ? session.mempoolTxs[session.mempoolTxs.length - 1].v
        : null,
      latestBlockTxs,
      sampleCount: session.sampleCount,
      serverBacked: false,
    };
  }, [history, session]);
}
