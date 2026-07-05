/**
 * Offline IP → geographic region resolution.
 *
 * The dashboard runs under a strict, offline CSP posture: no external map
 * tiles, no CDN, and no third-party geolocation API calls are permitted. That
 * rules out the usual "look the IP up in a GeoIP web service" approach and any
 * bundled city-level GeoIP database (those are megabytes).
 *
 * What we CAN do offline, cheaply and deterministically, is map an address to
 * the Regional Internet Registry (RIR) that administers its block. The IANA
 * IPv4 /8 registry is a small, stable, authoritative table — one entry per
 * first octet — so it costs almost nothing to bundle. RIR granularity is
 * continent-scale, not country- or city-level: an address resolves to one of
 * five service regions (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC). Private,
 * loopback, and reserved ranges are detected and never plotted.
 *
 * LIMITATION (surfaced in the UI): locations are approximate, region-level
 * placements at each RIR's service-area centroid — not precise coordinates.
 * Sharpening this to country/city would require an external GeoIP data source,
 * which the offline posture forbids.
 */

export type Rir = "ARIN" | "RIPE" | "APNIC" | "LACNIC" | "AFRINIC";

export type LocationKind =
  | "public" // routable, resolved to an RIR region
  | "private" // RFC1918 LAN
  | "cgnat" // RFC6598 carrier-grade NAT (100.64/10)
  | "loopback" // 127/8
  | "linklocal" // 169.254/16
  | "reserved" // 0/8, multicast, future-use, broadcast
  | "unknown"; // unparseable / unmapped

export interface ResolvedLocation {
  kind: LocationKind;
  /** Human label for the resolved region, e.g. "Europe / M.East (RIPE)". */
  label: string;
  /** The administering RIR, when kind === "public". */
  rir?: Rir;
  /** Centroid latitude of the RIR service region (present only when plottable). */
  lat?: number;
  /** Centroid longitude of the RIR service region (present only when plottable). */
  lon?: number;
  /** Whether this location has coordinates and should be drawn on the map. */
  plottable: boolean;
}

/** Representative service-area centroid + label for each RIR. */
const RIR_REGION: Record<Rir, { label: string; lat: number; lon: number }> = {
  ARIN: { label: "North America (ARIN)", lat: 40, lon: -100 },
  RIPE: { label: "Europe / M.East (RIPE)", lat: 50, lon: 15 },
  APNIC: { label: "Asia-Pacific (APNIC)", lat: 18, lon: 105 },
  LACNIC: { label: "Latin America (LACNIC)", lat: -15, lon: -60 },
  AFRINIC: { label: "Africa (AFRINIC)", lat: 2, lon: 21 },
};

/**
 * IANA IPv4 /8 → RIR map, indexed by first octet. Built from range tuples for
 * readability. Entries left null are unmapped; special-use blocks
 * (private/loopback/reserved) are handled separately below, before this table
 * is consulted.
 *
 * This is the standard /8-granularity approximation of the IANA registry. A
 * handful of legacy /8s are sub-divided across RIRs at finer than /8; each such
 * block is attributed to its dominant registry. Region-level accuracy makes
 * that approximation immaterial to where the dot lands.
 */
function buildOctetTable(): (Rir | null)[] {
  const table: (Rir | null)[] = new Array(256).fill(null);
  const assign = (rir: Rir, ...spans: (number | [number, number])[]) => {
    for (const span of spans) {
      const [start, end] = Array.isArray(span) ? span : [span, span];
      for (let o = start; o <= end; o++) table[o] = rir;
    }
  };

  assign(
    "ARIN",
    [3, 9], [11, 13], [15, 24], 26, [28, 30], [32, 35], 38, 40, 44, 45, 47, 48, 50, 52,
    54, 55, 56, [63, 76], [96, 100], 104, 107, 108, [128, 132], [134, 140], [142, 144],
    [146, 149], 152, [155, 162], [164, 170], [172, 174], 184, 192, 198, 199, [204, 209],
    [214, 216],
  );
  assign(
    "RIPE",
    2, 5, 25, 31, 37, 46, 51, 53, 57, 62, [77, 95], 109, 141, 145, 151, 176, 178, 185,
    188, [193, 195], 212, 213, 217,
  );
  assign(
    "APNIC",
    1, 14, 27, 36, 39, 42, 43, 49, [58, 61], 101, 103, 106, [110, 126], 133, 150, 153,
    163, 171, 175, 180, 182, 183, 202, 203, 210, 211, [218, 223],
  );
  assign("AFRINIC", 41, 102, 105, 154, 196, 197);
  assign("LACNIC", 177, 179, 181, 186, 187, 189, 190, 191, 200, 201);

  return table;
}

const OCTET_TABLE = buildOctetTable();

function parseIPv4(ip: string): number[] | null {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const octets = [m[1], m[2], m[3], m[4]].map((s) => Number(s));
  if (octets.some((o) => o < 0 || o > 255)) return null;
  return octets;
}

/** Strip a trailing `:port` and surrounding brackets so we resolve the host. */
function extractHost(addressOrIp: string): string {
  let host = addressOrIp.trim();
  // Bracketed IPv6 with optional port: [2a00::1]:8555
  const bracket = host.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracket) return bracket[1];
  // IPv4 (or hostname) with a single trailing :port
  if ((host.match(/:/g) || []).length === 1) host = host.split(":")[0];
  return host;
}

function locateIPv6(host: string): ResolvedLocation {
  const h = host.toLowerCase();
  if (h === "::1") return special("loopback", "Loopback (::1)");
  if (h.startsWith("fe80")) return special("linklocal", "Link-local (IPv6)");
  if (h.startsWith("fc") || h.startsWith("fd")) return special("private", "Unique-local (IPv6)");
  // Coarse RIR mapping from the leading hextet of the global-unicast 2000::/3
  // block. Enough to place a dot on the right continent; honest about no more.
  const first = h.split(":")[0];
  const val = parseInt(first, 16);
  let rir: Rir | null = null;
  if (!Number.isNaN(val)) {
    if (val >= 0x2a00 && val <= 0x2aff) rir = "RIPE";
    else if (val >= 0x2400 && val <= 0x24ff) rir = "APNIC";
    else if (val >= 0x2c00 && val <= 0x2cff) rir = "AFRINIC";
    else if (val >= 0x2800 && val <= 0x28ff) rir = "LACNIC";
    else if ((val >= 0x2600 && val <= 0x26ff) || val === 0x2620) rir = "ARIN";
  }
  if (rir) return fromRir(rir);
  return special("unknown", "Unknown (IPv6)");
}

function fromRir(rir: Rir): ResolvedLocation {
  const region = RIR_REGION[rir];
  return {
    kind: "public",
    label: region.label,
    rir,
    lat: region.lat,
    lon: region.lon,
    plottable: true,
  };
}

function special(kind: LocationKind, label: string): ResolvedLocation {
  return { kind, label, plottable: false };
}

/**
 * Resolve a peer address (bare IP or `host:port`, IPv4 or IPv6) to an
 * approximate, region-level location. Never makes a network call.
 */
export function resolveLocation(addressOrIp: string | undefined | null): ResolvedLocation {
  if (!addressOrIp) return special("unknown", "Unknown");
  const host = extractHost(addressOrIp);

  if (host.includes(":")) return locateIPv6(host);

  const octets = parseIPv4(host);
  if (!octets) return special("unknown", "Unknown");
  const [a, b] = octets;

  // Special-use IPv4 blocks (checked before the RIR table).
  if (a === 0) return special("reserved", "Reserved (0.0.0.0/8)");
  if (a === 10) return special("private", "Private LAN (10/8)");
  if (a === 127) return special("loopback", "Loopback (127/8)");
  if (a === 169 && b === 254) return special("linklocal", "Link-local (169.254/16)");
  if (a === 172 && b >= 16 && b <= 31) return special("private", "Private LAN (172.16/12)");
  if (a === 192 && b === 168) return special("private", "Private LAN (192.168/16)");
  if (a === 100 && b >= 64 && b <= 127) return special("cgnat", "Carrier NAT (100.64/10)");
  if (a >= 224 && a <= 239) return special("reserved", "Multicast (224/4)");
  if (a >= 240) return special("reserved", "Reserved (240/4)");

  const rir = OCTET_TABLE[a];
  if (rir) return fromRir(rir);
  return special("unknown", "Unmapped block");
}

/**
 * Deterministic small offset (in degrees) so several peers in the same RIR
 * region don't stack on one pixel. Seeded by the address string, so a peer
 * always lands in the same spot. Bounded to roughly +/-9 degrees.
 */
export function jitterFor(seed: string): { dLat: number; dLon: number } {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const a = (h >>> 0) % 1000;
  const b = ((h >>> 10) >>> 0) % 1000;
  return {
    dLat: (a / 1000 - 0.5) * 12,
    dLon: (b / 1000 - 0.5) * 18,
  };
}
