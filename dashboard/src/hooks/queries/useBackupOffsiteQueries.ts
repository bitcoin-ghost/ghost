import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getBackupOffsite,
  postBackupOffsite,
  type OffsiteAction,
} from "@/lib/api/backupOffsite";

export const backupOffsiteKeys = {
  all: ["backupOffsite"] as const,
  state: () => [...backupOffsiteKeys.all, "state"] as const,
};

// Nightly database backups + the optional off-node destination (#1016). Default OFF.
export function useBackupOffsite() {
  return useQuery({
    queryKey: backupOffsiteKeys.state(),
    queryFn: getBackupOffsite,
    staleTime: 30_000,
  });
}

export function useBackupOffsiteAction() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (body: OffsiteAction) => postBackupOffsite(body),
    onSuccess: (res) => {
      if (res.state) queryClient.setQueryData(backupOffsiteKeys.state(), res.state);
      queryClient.invalidateQueries({ queryKey: backupOffsiteKeys.all });
    },
  });
}
