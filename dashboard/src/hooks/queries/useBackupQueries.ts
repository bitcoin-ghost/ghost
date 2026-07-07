import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  createBackup,
  verifyBackup,
  importBackup,
  getBackupHistory,
  deleteBackup,
} from '@/lib/api/backup';

export const backupKeys = {
  all: ['backup'] as const,
  history: () => [...backupKeys.all, 'history'] as const,
};

export function useBackupHistory() {
  return useQuery({
    queryKey: backupKeys.history(),
    queryFn: getBackupHistory,
    refetchInterval: false,
  });
}

export function useCreateBackup() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: () => createBackup(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: backupKeys.history() });
    },
  });
}

export function useVerifyBackup() {
  return useMutation({
    mutationFn: ({ file }: { file: File }) => verifyBackup(file),
  });
}

export function useImportBackup() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ file }: { file: File }) => importBackup(file),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: backupKeys.all });
    },
  });
}

export function useDeleteBackup() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (filename: string) => deleteBackup(filename),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: backupKeys.history() });
    },
  });
}
