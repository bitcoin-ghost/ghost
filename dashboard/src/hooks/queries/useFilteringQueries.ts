import { useQuery } from "@tanstack/react-query";
import { getFilteringActivity } from "@/lib/api/filtering";

export const filteringKeys = {
  all: ["filtering-activity"] as const,
};

export function useFilteringActivity(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: filteringKeys.all,
    queryFn: getFilteringActivity,
    refetchInterval: options?.refetchInterval ?? 15_000,
  });
}
