import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  getConfig,
  getFullConfig,
  setGhostMode,
  setGhostModeLocalEgress,
  setTor,
  setArchiveMode,
  setReaper,
  getReaper,
  type ReaperSettings,
  getDaemonSettings,
  setDaemonSettings,
  type DaemonSettings,
  setPolicyProfile,
  type PolicyProfileType,
  setBlockPriority,
  type BlockPriorityType,
  setOperatorWindow,
  getL2PruningStatus,
  setGhostPayPayoutAddress,
  configureHaze,
  configureShroud,
  restartNode,
  setGhostPay,
  setWraith,
  setMiningPayoutAddress,
  setPoolName,
  setPublicMiningConfig,
} from '@/lib/api/config';
import { nodeKeys } from './useNodeQueries';

export const configKeys = {
  all: ['config'] as const,
  basic: () => [...configKeys.all, 'basic'] as const,
  full: () => [...configKeys.all, 'full'] as const,
};

export function useConfig() {
  return useQuery({
    queryKey: configKeys.basic(),
    queryFn: getConfig,
    staleTime: 30_000,
  });
}

export function useFullConfig() {
  return useQuery({
    queryKey: configKeys.full(),
    queryFn: getFullConfig,
    staleTime: 30_000,
  });
}

export function useSetGhostMode() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (enabled: boolean) => setGhostMode(enabled),
    onSuccess: () => {
      // The toggle binds to node status (status.ghost_mode), so refresh both
      // the config and node status caches to keep the control in sync.
      queryClient.invalidateQueries({ queryKey: configKeys.all });
      queryClient.invalidateQueries({ queryKey: nodeKeys.status() });
    },
  });
}

export function useSetGhostModeLocalEgress() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (enabled: boolean) => setGhostModeLocalEgress(enabled),
    onSuccess: () => {
      // The toggle state is surfaced on node status (ghost_mode_local_egress),
      // so refresh both config and status caches.
      queryClient.invalidateQueries({ queryKey: configKeys.all });
      queryClient.invalidateQueries({ queryKey: nodeKeys.status() });
    },
  });
}

export function useSetTor() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (enabled: boolean) => setTor(enabled),
    onSuccess: () => {
      // Config changed and the live Tor state (node status) will flip once
      // ghostd finishes restarting — refresh both.
      queryClient.invalidateQueries({ queryKey: configKeys.all });
      queryClient.invalidateQueries({ queryKey: nodeKeys.status() });
    },
  });
}

export function useSetArchiveMode() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (enabled: boolean) => setArchiveMode(enabled),
    onSuccess: () => {
      // The toggle binds to node status (status.archive_mode), so refresh both
      // the config and node status caches to keep the control in sync.
      queryClient.invalidateQueries({ queryKey: configKeys.all });
      queryClient.invalidateQueries({ queryKey: nodeKeys.status() });
    },
  });
}

export function useReaperConfig() {
  return useQuery({
    queryKey: [...configKeys.all, 'reaper'] as const,
    queryFn: getReaper,
  });
}

export function useSetReaper() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (input: ReaperSettings | boolean) => setReaper(input),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

export function useDaemonSettings() {
  return useQuery({
    queryKey: [...configKeys.all, 'daemon'] as const,
    queryFn: getDaemonSettings,
    staleTime: 30_000,
  });
}

export function useSetDaemonSettings() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (settings: DaemonSettings) => setDaemonSettings(settings),
    onSuccess: () => {
      // Config changed; the live daemon state flips once ghostd finishes
      // restarting — refresh both the config views and node status.
      queryClient.invalidateQueries({ queryKey: configKeys.all });
      queryClient.invalidateQueries({ queryKey: nodeKeys.status() });
    },
  });
}

// The REAL tier-policy lever (pool.toml [policy].profile), persisted to disk and
// applied via a graceful restart. This is what the mempool/block-template
// filtering actually keys off — the old cosmetic mempool/template "profiles"
// were removed. Used by the setup/onboarding wizards.
export function useSetPolicyProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profile: PolicyProfileType) => setPolicyProfile(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

// Block-priority lever (pool.toml [pool].block_priority). Writing it persists to
// pool.toml and triggers a graceful restart so the new template ORDERING is
// resolved at startup. `max_fee` maximises revenue; `payments_first` seats BUDS
// financial txs (T0/T1) ahead of data txs (T2/T3), forgoing some fee income.
export function useSetBlockPriority() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (blockPriority: BlockPriorityType) => setBlockPriority(blockPriority),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

// Pruning configuration
export const pruningKeys = {
  all: ['pruning'] as const,
  l2: () => [...pruningKeys.all, 'l2'] as const,
};

export function useL2PruningStatus() {
  return useQuery({
    queryKey: pruningKeys.l2(),
    queryFn: getL2PruningStatus,
    staleTime: 60_000,
  });
}

export function useSetOperatorWindow() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (blocks: number) => setOperatorWindow(blocks),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

// Payout Address Settings
export function useSetGhostPayPayoutAddress() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (address: string | null) => setGhostPayPayoutAddress(address),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
      // Also invalidate mining status which may include payout info
      queryClient.invalidateQueries({ queryKey: ['mining', 'status'] });
    },
  });
}

// Wizard mutation hooks

import { hazeKeys } from './useHazeQueries';
import { shroudKeys } from './useShroudQueries';

export function useConfigureHaze() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (mode: 'standard' | 'hazed' | 'full_archive') => configureHaze(mode),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: hazeKeys.all });
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

export function useConfigureShroud() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (config: { enabled: boolean }) =>
      configureShroud(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: shroudKeys.all });
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

export function useRestartNode() {
  return useMutation({
    mutationFn: () => restartNode(),
  });
}

export function useSetGhostPay() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (enabled: boolean) => setGhostPay(enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

export function useSetWraith() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (enabled: boolean) => setWraith(enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
      // The real wraith_enabled value is surfaced by the ghostpay status.
      queryClient.invalidateQueries({ queryKey: ['ghostpay'] });
    },
  });
}

export function useSetMiningPayoutAddress() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (address: string) => setMiningPayoutAddress(address),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
      queryClient.invalidateQueries({ queryKey: ['mining'] });
    },
  });
}

export function useSetPoolName() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (name: string | null) => setPoolName(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
      queryClient.invalidateQueries({ queryKey: ['mining'] });
    },
  });
}

export function useSetPublicMiningConfig() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (enabled: boolean) => setPublicMiningConfig(enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

// Re-export types for convenience
export type { DaemonSettings };
