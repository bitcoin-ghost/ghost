import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getBackupSchedule,
  setBackupSchedule,
  type BackupSchedule,
} from "@/lib/api/backupSchedule";

export const backupScheduleKeys = {
  all: ["backupSchedule"] as const,
  config: () => [...backupScheduleKeys.all, "config"] as const,
};

export function useBackupSchedule() {
  return useQuery({
    queryKey: backupScheduleKeys.config(),
    queryFn: getBackupSchedule,
    staleTime: 30_000,
  });
}

export function useSetBackupSchedule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (config: BackupSchedule) => setBackupSchedule(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: backupScheduleKeys.all });
    },
  });
}
