import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getAlerts,
  setAlerts,
  sendTestAlert,
  type AlertsConfig,
} from "@/lib/api/alerts";

export const alertsKeys = {
  all: ["alerts"] as const,
  config: () => [...alertsKeys.all, "config"] as const,
};

export function useAlertsConfig() {
  return useQuery({
    queryKey: alertsKeys.config(),
    queryFn: getAlerts,
    staleTime: 30_000,
  });
}

export function useSetAlerts() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (config: AlertsConfig) => setAlerts(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: alertsKeys.all });
    },
  });
}

export function useSendTestAlert() {
  return useMutation({
    mutationFn: () => sendTestAlert(),
  });
}
