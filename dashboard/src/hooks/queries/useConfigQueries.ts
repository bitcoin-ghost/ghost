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
  setMempoolProfile,
  setTemplateProfile,
  getMempoolProfiles,
  saveMempoolProfile,
  deleteMempoolProfile,
  activateMempoolProfile,
  getTemplateProfiles,
  saveTemplateProfile,
  deleteTemplateProfile,
  activateTemplateProfile,
  setPruneProfile,
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
  type CustomMempoolProfile,
  type CustomTemplateProfile,
} from '@/lib/api/config';
import type { MempoolProfile, TemplateProfile, PruneProfile } from '@/types/api';
import { nodeKeys } from './useNodeQueries';

export const configKeys = {
  all: ['config'] as const,
  basic: () => [...configKeys.all, 'basic'] as const,
  full: () => [...configKeys.all, 'full'] as const,
  mempoolProfiles: () => [...configKeys.all, 'mempool-profiles'] as const,
  templateProfiles: () => [...configKeys.all, 'template-profiles'] as const,
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
      queryClient.invalidateQueries({ queryKey: configKeys.all });
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
      queryClient.invalidateQueries({ queryKey: configKeys.all });
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

export function useSetMempoolProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profile: MempoolProfile) => setMempoolProfile(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

export function useSetTemplateProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profile: TemplateProfile) => setTemplateProfile(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

// Custom Mempool Profiles
export function useMempoolProfiles() {
  return useQuery({
    queryKey: configKeys.mempoolProfiles(),
    queryFn: getMempoolProfiles,
    staleTime: 60_000,
  });
}

export function useSaveMempoolProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profile: CustomMempoolProfile) => saveMempoolProfile(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.mempoolProfiles() });
    },
  });
}

export function useDeleteMempoolProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (name: string) => deleteMempoolProfile(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.mempoolProfiles() });
    },
  });
}

export function useActivateMempoolProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (name: string) => activateMempoolProfile(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
  });
}

// Custom Template Profiles
export function useTemplateProfiles() {
  return useQuery({
    queryKey: configKeys.templateProfiles(),
    queryFn: getTemplateProfiles,
    staleTime: 60_000,
  });
}

export function useSaveTemplateProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profile: CustomTemplateProfile) => saveTemplateProfile(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.templateProfiles() });
    },
  });
}

export function useDeleteTemplateProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (name: string) => deleteTemplateProfile(name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.templateProfiles() });
    },
  });
}

export function useActivateTemplateProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (name: string) => activateTemplateProfile(name),
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

export function useSetPruneProfile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (profile: PruneProfile) => setPruneProfile(profile),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: configKeys.all });
    },
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
export type { CustomMempoolProfile, CustomTemplateProfile, DaemonSettings };
