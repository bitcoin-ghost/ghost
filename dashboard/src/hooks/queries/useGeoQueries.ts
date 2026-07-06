import { useQuery } from "@tanstack/react-query";
import { loadGeoDb, type GeoDb } from "@/lib/geo/geoip";

export const geoKeys = {
  all: ["geo"] as const,
  db: () => [...geoKeys.all, "db"] as const,
};

/**
 * Load the bundled offline GeoIP database once and cache it forever. The
 * ~185 KB asset is fetched from same-origin `public/geo/geoip.bin`, decoded in
 * the browser, and never refetched (it is static). Resolution is synchronous
 * against the returned {@link GeoDb}.
 */
export function useGeoDb() {
  return useQuery<GeoDb>({
    queryKey: geoKeys.db(),
    queryFn: () => loadGeoDb(),
    staleTime: Infinity,
    gcTime: Infinity,
    retry: 1,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
}
