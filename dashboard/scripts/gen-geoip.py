#!/usr/bin/env python3
"""Generate the bundled offline GeoIP dataset for the dashboard Geo page.

The dashboard runs under a strict, offline CSP posture: no external map tiles,
no CDN, and no third-party geolocation API calls. To plot peers at country
granularity we therefore ship a small, self-contained IP -> country table that
is fetched once from same-origin `public/geo/geoip.bin` and searched entirely
in the browser.

This script rebuilds three artefacts from public-domain / permissively-licensed
upstream data:

  public/geo/geoip.bin         packed, gzipped IPv4 + IPv6 -> country table
  src/lib/geo/countries.ts     country metadata, positionally indexed to geoip.bin
  src/lib/geo/world-110m.json  Natural Earth 110m world basemap (copied verbatim)

Data sources (all bundled offline, none fetched at runtime):
  - DB-IP Lite country database   (CC-BY 4.0)     -> IP ranges
  - mledoze/countries             (ODbL)          -> names, ISO numeric, centroids
  - Natural Earth via world-atlas (public domain) -> world-110m.json basemap

Run from the `dashboard/` directory:

  python3 scripts/gen-geoip.py \
      --v4 dbip-country-ipv4-num.csv \
      --v6 dbip-country-ipv6-num.csv \
      --countries mledoze-countries.json \
      --world world-atlas-countries-110m.json

Upstream files (fetch once, offline thereafter):
  https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-country/dbip-country-ipv4-num.csv
  https://cdn.jsdelivr.net/npm/@ip-location-db/dbip-country/dbip-country-ipv6-num.csv
  https://cdn.jsdelivr.net/gh/mledoze/countries@master/countries.json
  https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json

Binary format of geoip.bin (little-endian, gzip-compressed as a whole):

  magic   'GEO1'          4 bytes
  version u8              = 1
  ccCount u8              number of country records (indices 0..ccCount-1)
  n4      u32             IPv4 range-boundary count
  len4    u32             byte length of the IPv4 delta-varint start stream
  n6      u32             IPv6 (/32-prefix) range-boundary count
  len6    u32             byte length of the IPv6 delta-varint start stream
  <IPv4 starts>  n4 LEB128 deltas of absolute range-start addresses (u32)
  <IPv4 cc>      n4 bytes  country index (0xFF = unknown / gap)
  <IPv6 starts>  n6 LEB128 deltas of top-32-bit prefixes
  <IPv6 cc>      n6 bytes  country index (0xFF = unknown / gap)

Country index 0xFF is reserved for "unknown" and never indexes COUNTRIES.
"""

from __future__ import annotations

import argparse
import gzip
import json
import struct

UNKNOWN = 0xFF
# Absorb IPv4 fragments smaller than this many addresses (i.e. finer than /24)
# into their neighbouring range. DB-IP is /24-aligned for real allocations, so
# this only merges sub-/24 routing noise while preserving country accuracy for
# every genuine allocation (e.g. 1.1.1.0/24 stays AU, not its /22 neighbour).
V4_ABSORB = 256


def load_v4(path: str) -> list[tuple[int, int, str]]:
    rows = []
    with open(path) as f:
        for line in f:
            s, e, cc = line.rstrip("\n").split(",")
            rows.append((int(s), int(e), cc))
    merged: list[list] = []
    for s, e, cc in rows:
        size = e - s + 1
        if merged and size < V4_ABSORB and merged[-1][1] + 1 == s:
            merged[-1][1] = e  # absorb sub-/24 sliver into previous country
            continue
        if merged and merged[-1][2] == cc and merged[-1][1] + 1 == s:
            merged[-1][1] = e
            continue
        merged.append([s, e, cc])
    out: list[tuple[int, int, str]] = []
    for s, e, cc in merged:
        if out and out[-1][2] == cc and out[-1][1] + 1 == s:
            out[-1] = (out[-1][0], e, cc)
        else:
            out.append((s, e, cc))
    return out


def load_v6(path: str) -> list[tuple[int, int, str]]:
    # Country granularity for IPv6 lives at the top 32 bits (RIRs allocate
    # /12-/32 to LIRs per country), so reduce each range to its /32-prefix span
    # and keep the dominant country per prefix.
    pref: dict[int, dict[str, int]] = {}
    with open(path) as f:
        for line in f:
            s, e, cc = line.rstrip("\n").split(",")
            s, e = int(s), int(e)
            p0, p1 = s >> 96, e >> 96
            if p1 - p0 > 70000:  # guard against absurd spans
                p1 = p0
            for p in range(p0, p1 + 1):
                d = pref.setdefault(p, {})
                d[cc] = d.get(cc, 0) + 1
    out: list[tuple[int, int, str]] = []
    for p in sorted(pref):
        dom = max(pref[p], key=pref[p].get)
        if out and out[-1][1] + 1 == p and out[-1][2] == dom:
            out[-1] = (out[-1][0], p, dom)
        else:
            out.append((p, p, dom))
    return out


def varint(n: int) -> bytes:
    o = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        o.append(b | (0x80 if n else 0))
        if not n:
            return bytes(o)


def pack(ranges, cc_index) -> tuple[int, bytes, bytes]:
    starts: list[int] = []
    ccs: list[int] = []
    prev = -1
    for s, e, cc in ranges:
        if s > prev + 1:  # gap sentinel before this range
            starts.append(prev + 1)
            ccs.append(UNKNOWN)
        starts.append(s)
        ccs.append(cc_index[cc])
        prev = e
    d = bytearray()
    p = 0
    for s in starts:
        d += varint(s - p)
        p = s
    return len(starts), bytes(d), bytes(ccs)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--v4", required=True)
    ap.add_argument("--v6", required=True)
    ap.add_argument("--countries", required=True, help="mledoze countries.json")
    ap.add_argument("--world", help="world-atlas countries-110m.json (copied verbatim)")
    ap.add_argument("--out-bin", default="public/geo/geoip.bin")
    ap.add_argument("--out-ts", default="src/lib/geo/countries.ts")
    ap.add_argument("--out-world", default="src/lib/geo/world-110m.json")
    args = ap.parse_args()

    meta: dict[str, dict] = {}
    for c in json.load(open(args.countries)):
        a2 = c.get("cca2")
        if not a2:
            continue
        ll = c.get("latlng") or [None, None]
        ccn3 = c.get("ccn3") or ""
        meta[a2] = {
            "name": c["name"]["common"],
            "num": int(ccn3) if ccn3.isdigit() else 0,
            "lat": ll[0],
            "lon": ll[1],
            "region": c.get("region") or "",
        }

    v4 = load_v4(args.v4)
    v6 = load_v6(args.v6)

    cc_index: dict[str, int] = {}
    cc_order: list[str] = []

    def ci(cc: str) -> int:
        if cc not in cc_index:
            cc_index[cc] = len(cc_order)
            cc_order.append(cc)
        return cc_index[cc]

    for s, e, cc in v4:
        ci(cc)
    for s, e, cc in v6:
        ci(cc)
    if len(cc_order) >= UNKNOWN:
        raise SystemExit("too many country codes for a u8 index")

    n4, d4, c4 = pack(v4, cc_index)
    n6, d6, c6 = pack(v6, cc_index)

    head = b"GEO1" + struct.pack("<BB", 1, len(cc_order)) + struct.pack(
        "<IIII", n4, len(d4), n6, len(d6)
    )
    blob = head + d4 + c4 + d6 + c6
    gz = gzip.compress(blob, 9)
    with open(args.out_bin, "wb") as f:
        f.write(gz)

    lines = [
        "// AUTO-GENERATED by scripts/gen-geoip.py. Do not edit by hand.",
        "// Country metadata positionally indexed to match the country byte codes in",
        "// public/geo/geoip.bin. Sources: DB-IP Lite country DB (CC-BY 4.0),",
        "// mledoze/countries (ODbL), Natural Earth via world-atlas (public domain).",
        "",
        "export interface CountryMeta {",
        "  /** ISO 3166-1 alpha-2 code. */ code: string;",
        "  /** Common English name. */ name: string;",
        "  /** ISO 3166-1 numeric code (matches world-110m feature ids); 0 if unknown. */ num: number;",
        "  /** Representative centroid latitude, or null if not plottable. */ lat: number | null;",
        "  /** Representative centroid longitude, or null if not plottable. */ lon: number | null;",
        "  /** Continental region grouping. */ region: string;",
        "}",
        "",
        "/** Country records, positionally indexed by the byte codes stored in geoip.bin. */",
        "export const COUNTRIES: readonly CountryMeta[] = [",
    ]
    for cc in cc_order:
        m = meta.get(cc, {"name": cc, "num": 0, "lat": None, "lon": None, "region": ""})
        lat = "null" if m["lat"] is None else f"{m['lat']:.2f}"
        lon = "null" if m["lon"] is None else f"{m['lon']:.2f}"
        name = m["name"].replace("\\", "\\\\").replace('"', '\\"')
        lines.append(
            f'  {{ code: "{cc}", name: "{name}", num: {m["num"]}, '
            f"lat: {lat}, lon: {lon}, region: \"{m['region']}\" }},"
        )
    lines.append("];")
    lines.append("")
    with open(args.out_ts, "w") as f:
        f.write("\n".join(lines))

    if args.world:
        with open(args.world) as src, open(args.out_world, "w") as dst:
            dst.write(src.read())

    print(f"geoip.bin: {len(gz) / 1024:.1f} KB gz ({len(blob) / 1024:.1f} KB raw)")
    print(f"countries: {len(cc_order)}  v4 entries: {n4}  v6 entries: {n6}")


if __name__ == "__main__":
    main()
