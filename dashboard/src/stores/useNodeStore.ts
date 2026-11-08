import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import type { NodeInfo, NodeStatus } from '@/types/api';

interface NodeState {
  // Core node data
  nodeInfo: NodeInfo | null;
  nodeStatus: NodeStatus | null;

  // Connection state
  isConnected: boolean;
  lastSyncTime: number | null;

  // Actions
  setNodeInfo: (info: NodeInfo) => void;
  setNodeStatus: (status: NodeStatus) => void;
  setConnected: (connected: boolean) => void;
  reset: () => void;
}

const initialState = {
  nodeInfo: null,
  nodeStatus: null,
  isConnected: false,
  lastSyncTime: null,
};

export const useNodeStore = create<NodeState>()(
  subscribeWithSelector((set) => ({
    ...initialState,

    setNodeInfo: (nodeInfo) => set({ nodeInfo }),

    setNodeStatus: (nodeStatus) => set({
      nodeStatus,
      lastSyncTime: Date.now()
    }),

    setConnected: (isConnected) => set({ isConnected }),

    reset: () => set(initialState),
  }))
);

// Selectors for performance
export const selectNodeInfo = (state: NodeState) => state.nodeInfo;
export const selectNodeStatus = (state: NodeState) => state.nodeStatus;
export const selectIsConnected = (state: NodeState) => state.isConnected;
