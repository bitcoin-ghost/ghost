"use client";

import { useState, useEffect, useCallback } from "react";
import type {
  NodeInfo,
  NodeStatus,
  SharesInfo,
  NodeConfig,
  NodeEvent,
  TreasuryStatus,
  GhostPayStatus,
} from "@/types/api";
import * as api from "@/lib/api";

export function useNodeInfo() {
  const [data, setData] = useState<NodeInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    api.getNodeInfo()
      .then((newData) => {
        setData(newData);
        setError(null);
      })
      .catch(setError)
      .finally(() => setLoading(false));
  }, []);

  return { data, loading, error };
}

export function useNodeStatus() {
  const [data, setData] = useState<NodeStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const refresh = useCallback(() => {
    setLoading(true);
    api.getNodeStatus()
      .then((newData) => {
        setData(newData);
        setError(null);
      })
      .catch((err) => {
        setError(err);
        // Keep previous data on error so UI doesn't blank out
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    // Schedule refresh as microtask to avoid synchronous setState in effect
    queueMicrotask(refresh);
    const interval = setInterval(refresh, 10000);
    return () => clearInterval(interval);
  }, [refresh]);

  return { data, loading, error, refresh };
}

export function useShares() {
  const [data, setData] = useState<SharesInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    api.getShares()
      .then((newData) => {
        setData(newData);
        setError(null);
      })
      .catch(setError)
      .finally(() => setLoading(false));
  }, []);

  return { data, loading, error };
}

export function useConfig() {
  const [data, setData] = useState<NodeConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const refresh = useCallback(() => {
    api.getConfig()
      .then((newData) => {
        setData(newData);
        setError(null);
      })
      .catch(setError)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    queueMicrotask(refresh);
  }, [refresh]);

  const setGhostMode = useCallback(async (enabled: boolean) => {
    const newConfig = await api.setGhostMode(enabled);
    setData(newConfig);
    return newConfig;
  }, []);

  const setArchiveMode = useCallback(async (enabled: boolean) => {
    // The archive POST returns a status envelope (not a full NodeConfig) — it
    // persists to pool.toml and restarts ghostd. Reload the authoritative config
    // afterwards rather than storing the envelope.
    const result = await api.setArchiveMode(enabled);
    refresh();
    return result;
  }, [refresh]);

  return { data, loading, error, refresh, setGhostMode, setArchiveMode };
}

export function useTreasury() {
  const [data, setData] = useState<TreasuryStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const refresh = useCallback(() => {
    api.getTreasury()
      .then((newData) => {
        setData(newData);
        setError(null);
      })
      .catch((err) => {
        setError(err);
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    queueMicrotask(refresh);
    const interval = setInterval(refresh, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, [refresh]);

  return { data, loading, error, refresh };
}

export function useGhostPayStatus() {
  const [data, setData] = useState<GhostPayStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const refresh = useCallback(() => {
    api.getGhostPayStatus()
      .then((newData) => {
        setData(newData);
        setError(null);
      })
      .catch((err) => {
        setError(err);
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    queueMicrotask(refresh);
    const interval = setInterval(refresh, 10000);
    return () => clearInterval(interval);
  }, [refresh]);

  return { data, loading, error, refresh };
}

export function useWebSocket(onEvent: (event: NodeEvent) => void) {
  useEffect(() => {
    const ws = api.createWebSocket();
    if (!ws) return;

    ws.onmessage = (event) => {
      try {
        const nodeEvent = JSON.parse(event.data) as NodeEvent;
        onEvent(nodeEvent);
      } catch (e) {
        console.error("Failed to parse WebSocket message:", e);
      }
    };

    ws.onerror = (error) => {
      console.error("WebSocket error:", error);
    };

    return () => {
      ws.close();
    };
  }, [onEvent]);
}
