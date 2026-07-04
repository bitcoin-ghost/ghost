'use client';

import { useEffect, useRef } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useWebSocket } from './useWebSocket';
import { nodeKeys } from './queries/useNodeQueries';
import { useNodeStore } from '@/stores';
import type { NodeEvent } from '@/types/api';

/**
 * WebSocket → React Query bridge.
 * Mount once in the dashboard layout. Pushes real-time events
 * directly into the React Query cache so pages get instant updates.
 */
export function useRealtimeSync() {
  const queryClient = useQueryClient();
  const setNodeStatus = useNodeStore((s) => s.setNodeStatus);
  const setShares = useNodeStore((s) => s.setShares);
  const setConnected = useNodeStore((s) => s.setConnected);
  const connectedRef = useRef(false);

  const { connectionState, isConnected } = useWebSocket({
    onStatusChange: (event) => {
      const data = (event as NodeEvent & { type: 'StatusChange' }).data;
      if (data) {
        queryClient.setQueryData(nodeKeys.status(), data);
        setNodeStatus(data);
      }
    },
    onSharesUpdate: (event) => {
      const data = (event as NodeEvent & { type: 'SharesUpdate' }).data;
      if (data) {
        // The pushed payload carries CLAIMED capabilities. Writing it straight
        // into the cache would overwrite the verified merge getShares() performs
        // (see lib/api/node.ts), re-showing archive-on / 15-15. Invalidate so the
        // query refetches the verified view instead of trusting the raw push.
        queryClient.invalidateQueries({ queryKey: nodeKeys.shares() });
        queryClient.invalidateQueries({ queryKey: nodeKeys.health() });
        setShares(data);
      }
    },
    onConfigChange: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] });
      queryClient.invalidateQueries({ queryKey: nodeKeys.status() });
    },
    onHealthChange: () => {
      queryClient.invalidateQueries({ queryKey: nodeKeys.health() });
      queryClient.invalidateQueries({ queryKey: ['watchdog'] });
    },
  });

  useEffect(() => {
    if (isConnected !== connectedRef.current) {
      connectedRef.current = isConnected;
      setConnected(isConnected);
    }
  }, [isConnected, setConnected]);

  return { connectionState, isConnected };
}
