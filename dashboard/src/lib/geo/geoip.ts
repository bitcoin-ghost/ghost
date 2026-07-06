/**
 * Offline IP -> country resolution.
 *
 * The dashboard runs under a strict, offline CSP posture: no external map
 * tiles, no CDN, and no third-party geolocation API calls are permitted. So
 * instead of an online GeoIP lookup we ship a small, self-contained IP ->
 * country table (`public/geo/geoip.bin`, ~185 KB gzipped) that is fetched once
 * from the SAME ORIGIN and searched entirely in the browser. This upgrades the
 * old continent-scale RIR placement to genuine country-level accuracy while
 * still making zero third-party requests.
 *
 * The table is derived from the DB-IP Lite country database (CC-BY 4.0); see
 * `scripts/gen-geoip.py` for the build. Private, loopback, CGNAT, link-local
 * and reserved addresses are detected locally and never plotted.
 *
 * `geoip.bin` is gzip-compressed and decoded with the browser's native
 * `DecompressionStream` (no dependency, no network). If the DB cannot be loaded
 * the resolver degrades gracefully: special-use ranges are still classified and
 * public addresses fall back to "unresolved" (listed, not plotted).
 */

import { COUNTRIES, type CountryMeta } from "./countries";

export type GeoKind =
  | "public" // routable, resolved to a country
  | "unresolved" // routable but not found in the offline table
  | "private" // RFC1918 LAN
  | "cgnat" // RFC6598 carrier-grade NAT (100.64/10)
  | "loopback" // 127/8, ::1
  | "linklocal" // 169.254/16, fe80::/10
  | "reserved" // 0/8, multicast, future-use
  | "unknown"; // unparseable

export interface GeoResult {
  kind: GeoKind;
  /** Human label, e.g. "Germany" or "Private LAN (10/8)". */
  label: string;
  /** Country name, present when kind === "public". */
  name?: string;
  /** ISO 3166-1 alpha-2 code, present when kind === "public". */
  code?: string;
  /** ISO 3166-1 numeric code (matches world-110m feature ids). */
  num?: number;
  /** Continental region grouping, present when resolved. */
  region?: string;
  /** Centroid latitude, present and non-null only when plottable. */
  lat?: number;
  /** Centroid longitude, present and non-null only when plottable. */
  lon?: number;
  /** Whether this address has coordinates and should be drawn on the map. */
  plottable: boolean;
}

const UNKNOWN_CC = 0xff;
const GEOIP_URL = "/geo/geoip.bin";

/** Strip a trailing `:port` and surrounding brackets to get the bare host. */
export function extractHost(addressOrIp: string): string {
  const host = addressOrIp.trim();
  const bracket = host.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracket) return bracket[1];
  // IPv4 (or hostname) with a single trailing :port
  if ((host.match(/:/g) || []).length === 1) return host.split(":")[0];
  return host;
}

function parseIPv4(host: string): number | null {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  let v = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    v = v * 256 + o;
  }
  return v >>> 0;
}

/** Expand an IPv6 address to its top 32 bits (first two hextets) as a uint32. */
function ipv6Top32(host: string): number | null {
  const h = host.toLowerCase();
  if (!/^[0-9a-f:]+$/.test(h)) return null;
  const halves = h.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  const parts =
    halves.length === 2
      ? [...head, ...new Array(missing).fill("0"), ...tail]
      : head;
  if (parts.length !== 8) return null;
  const h0 = parseInt(parts[0] || "0", 16);
  const h1 = parseInt(parts[1] || "0", 16);
  if (Number.isNaN(h0) || Number.isNaN(h1)) return null;
  return ((h0 << 16) | h1) >>> 0;
}

function special(kind: GeoKind, label: string): GeoResult {
  return { kind, label, plottable: false };
}

function fromCountry(meta: CountryMeta): GeoResult {
  const plottable = meta.lat != null && meta.lon != null;
  return {
    kind: "public",
    label: meta.name,
    name: meta.name,
    code: meta.code,
    num: meta.num,
    region: meta.region,
    lat: plottable ? (meta.lat as number) : undefined,
    lon: plottable ? (meta.lon as number) : undefined,
    plottable,
  };
}

interface Section {
  starts: Uint32Array;
  cc: Uint8Array;
}

/** Greatest index whose start <= key; -1 if key precedes the first start. */
function findRange(sec: Section, key: number): number {
  const { starts } = sec;
  let lo = 0;
  let hi = starts.length - 1;
  let ans = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    if (starts[mid] <= key) {
      ans = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return ans;
}

/**
 * A loaded offline GeoIP database. Resolution is synchronous once loaded.
 */
export class GeoDb {
  private constructor(
    private readonly v4: Section,
    private readonly v6: Section,
  ) {}

  /** The number of country records the table can resolve to. */
  static readonly countryCount = COUNTRIES.length;

  private countryOf(sec: Section, key: number): GeoResult {
    const i = findRange(sec, key);
    if (i < 0) return special("unresolved", "Unresolved");
    const idx = sec.cc[i];
    if (idx === UNKNOWN_CC || idx >= COUNTRIES.length) {
      return special("unresolved", "Unresolved");
    }
    return fromCountry(COUNTRIES[idx]);
  }

  /** Resolve a bare IP or `host:port` (IPv4 or IPv6) to a country, offline. */
  resolve(addressOrIp: string | null | undefined): GeoResult {
    if (!addressOrIp) return special("unknown", "Unknown");
    const host = extractHost(addressOrIp);

    if (host.includes(":")) {
      // IPv6 special-use ranges first.
      const h = host.toLowerCase();
      if (h === "::1") return special("loopback", "Loopback (::1)");
      if (h === "::") return special("reserved", "Unspecified (::)");
      if (h.startsWith("fe80")) return special("linklocal", "Link-local (fe80::/10)");
      if (h.startsWith("fc") || h.startsWith("fd"))
        return special("private", "Unique-local (fc00::/7)");
      const top = ipv6Top32(host);
      if (top == null) return special("unknown", "Unknown (IPv6)");
      return this.countryOf(this.v6, top);
    }

    const v = parseIPv4(host);
    if (v == null) return special("unknown", "Unknown");
    const a = v >>> 24;
    const b = (v >>> 16) & 0xff;

    // IPv4 special-use blocks (checked before the country table).
    if (a === 0) return special("reserved", "Reserved (0.0.0.0/8)");
    if (a === 10) return special("private", "Private LAN (10/8)");
    if (a === 127) return special("loopback", "Loopback (127/8)");
    if (a === 169 && b === 254) return special("linklocal", "Link-local (169.254/16)");
    if (a === 172 && b >= 16 && b <= 31) return special("private", "Private LAN (172.16/12)");
    if (a === 192 && b === 168) return special("private", "Private LAN (192.168/16)");
    if (a === 100 && b >= 64 && b <= 127) return special("cgnat", "Carrier NAT (100.64/10)");
    if (a >= 224 && a <= 239) return special("reserved", "Multicast (224/4)");
    if (a >= 240) return special("reserved", "Reserved (240/4)");

    return this.countryOf(this.v4, v);
  }

  /** Fetch and decode `geoip.bin`. Throws if the asset is unavailable. */
  static async load(signal?: AbortSignal): Promise<GeoDb> {
    const res = await fetch(GEOIP_URL, { signal });
    if (!res.ok || !res.body) throw new Error(`geoip.bin ${res.status}`);
    let buf: ArrayBuffer;
    if (typeof DecompressionStream !== "undefined") {
      const stream = res.body.pipeThrough(new DecompressionStream("gzip"));
      buf = await new Response(stream).arrayBuffer();
    } else {
      // No native gunzip: the asset ships gzipped, so we cannot decode it.
      throw new Error("DecompressionStream unavailable");
    }
    return GeoDb.parse(new Uint8Array(buf));
  }

  private static parse(bytes: Uint8Array): GeoDb {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (bytes[0] !== 0x47 || bytes[1] !== 0x45 || bytes[2] !== 0x4f || bytes[3] !== 0x31) {
      throw new Error("geoip.bin: bad magic");
    }
    // byte 4 = version, byte 5 = country count (both validated implicitly)
    const n4 = dv.getUint32(6, true);
    const l4 = dv.getUint32(10, true);
    const n6 = dv.getUint32(14, true);
    const l6 = dv.getUint32(18, true);
    let o = 22;

    const readStarts = (n: number): Uint32Array => {
      const starts = new Uint32Array(n);
      let prev = 0;
      for (let i = 0; i < n; i++) {
        let shift = 0;
        let val = 0;
        let byte: number;
        do {
          byte = bytes[o++];
          val += (byte & 0x7f) * 2 ** shift;
          shift += 7;
        } while (byte & 0x80);
        prev = (prev + val) >>> 0;
        starts[i] = prev;
      }
      return starts;
    };
    const readCc = (n: number): Uint8Array => {
      const cc = bytes.subarray(o, o + n);
      o += n;
      return cc;
    };

    const v4Starts = readStarts(n4);
    const v4Cc = readCc(n4);
    const v6Starts = readStarts(n6);
    const v6Cc = readCc(n6);
    void l4;
    void l6;
    return new GeoDb(
      { starts: v4Starts, cc: v4Cc },
      { starts: v6Starts, cc: v6Cc },
    );
  }
}

/** Module-level singleton so the ~185 KB asset is fetched at most once. */
let dbPromise: Promise<GeoDb> | null = null;

export function loadGeoDb(): Promise<GeoDb> {
  if (!dbPromise) {
    dbPromise = GeoDb.load().catch((err) => {
      dbPromise = null; // allow a retry on transient failure
      throw err;
    });
  }
  return dbPromise;
}

/** The regional-indicator emoji flag for an ISO 3166-1 alpha-2 code. */
export function flagEmoji(code: string): string {
  if (!/^[A-Za-z]{2}$/.test(code)) return "";
  const A = 0x1f1e6;
  const cc = code.toUpperCase();
  return String.fromCodePoint(A + cc.charCodeAt(0) - 65, A + cc.charCodeAt(1) - 65);
}
