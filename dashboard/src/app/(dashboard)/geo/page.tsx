"use client";

import { useMemo, useState } from "react";
import { Info } from "lucide-react";

import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { WorldMap, type MapPoint } from "@/components/geo/WorldMap";
import { usePeers, useGeoDb } from "@/hooks/queries";
import { flagEmoji, type GeoResult } from "@/lib/geo/geoip";
import type { PeerInfo } from "@/types/api";

const TOOLTIPS = {
  peers: "Mesh peers this node currently knows, from the network peers endpoint.",
  plotted: "Peers whose IP resolved to a country and are drawn on the map.",
  countries: "Distinct countries your plotted peers resolve to.",
  online: "Peers seen within the mesh freshness window (synced).",
};

interface Row {
  key: string;
  peer: PeerInfo;
  host: string;
  online: boolean;
  isSelf: boolean;
  geo: GeoResult;
}

function hostOf(address: string | undefined): string {
  if (!address) return "";
  const trimmed = address.trim();
  const bracket = trimmed.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracket) return bracket[1];
  if ((trimmed.match(/:/g) || []).length === 1) return trimmed.split(":")[0];
  return trimmed;
}

function toPoint(r: Row): MapPoint | null {
  if (!r.geo.plottable || r.geo.lat == null || r.geo.lon == null) return null;
  return {
    id: r.key,
    lat: r.geo.lat,
    lon: r.geo.lon,
    code: r.geo.code ?? "",
    name: r.geo.name ?? "",
    label: `${r.host || "peer"} — ${r.geo.name ?? "peer"}`,
    online: r.online,
    isSelf: r.isSelf,
    num: r.geo.num,
  };
}

export default function GeoPage() {
  const { data: peersData, isLoading: peersLoading } = usePeers();
  const { data: geoDb, isLoading: geoLoading, isError: geoError } = useGeoDb();
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const rows: Row[] = useMemo(() => {
    const peers = peersData?.peers ?? [];
    return peers.map((peer, i): Row => {
      const key = peer.node_id || peer.address || `peer-${i}`;
      const host = hostOf(peer.address);
      const geo: GeoResult = geoDb
        ? geoDb.resolve(peer.address)
        : { kind: "unknown", label: geoLoading ? "Resolving…" : "Unresolved", plottable: false };
      return {
        key,
        peer,
        host,
        online: Boolean(peer.synced),
        isSelf: Boolean(peer.is_self),
        geo,
      };
    });
  }, [peersData, geoDb, geoLoading]);

  const points = useMemo(
    () => rows.map(toPoint).filter((p): p is MapPoint => p !== null),
    [rows],
  );

  const self = useMemo(() => points.find((p) => p.isSelf) ?? null, [points]);

  const onlineCount = rows.filter((r) => r.online).length;
  const countryCount = useMemo(() => new Set(points.map((p) => p.code)).size, [points]);

  // Distinct-country counts per continental region, for the summary chips.
  const regionCounts = useMemo(() => {
    const perRegion = new Map<string, Set<string>>();
    rows.forEach((r) => {
      if (r.geo.plottable && r.geo.region && r.geo.code) {
        const set = perRegion.get(r.geo.region) ?? new Set<string>();
        set.add(r.geo.code);
        perRegion.set(r.geo.region, set);
      }
    });
    return [...perRegion.entries()]
      .map(([region, set]) => ({ region, count: set.size }))
      .sort((a, b) => b.count - a.count);
  }, [rows]);

  const loading = peersLoading || geoLoading;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="geo"
        title="Peer map."
        subtitle="Geographic spread of the mesh peers this node knows, resolved offline from peer IP addresses to country level."
      />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Peers" value={rows.length} tooltip={TOOLTIPS.peers} loading={peersLoading} />
        <StatCard label="Plotted" value={points.length} tooltip={TOOLTIPS.plotted} loading={loading} />
        <StatCard label="Countries" value={countryCount} tooltip={TOOLTIPS.countries} loading={loading} />
        <StatCard label="Online" value={`${onlineCount} / ${rows.length}`} tooltip={TOOLTIPS.online} loading={peersLoading} />
      </div>

      {/* Region chips */}
      {regionCounts.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          {regionCounts.map((r) => (
            <span
              key={r.region}
              style={{
                fontSize: "12px",
                color: "var(--dim)",
                background: "var(--surface)",
                border: "1px solid var(--rule)",
                borderRadius: "999px",
                padding: "3px 10px",
              }}
            >
              {r.region}
              <span style={{ color: "var(--fg)", marginLeft: 6, fontWeight: 500 }}>{r.count}</span>
            </span>
          ))}
        </div>
      )}

      {/* Resolution note */}
      <div
        className="flex items-start gap-3"
        style={{
          background: "var(--accent-weak)",
          border: "1px solid var(--rule)",
          borderRadius: "4px",
          padding: "12px 14px",
        }}
      >
        <Info size={16} strokeWidth={1.75} style={{ color: "var(--accent)", flexShrink: 0, marginTop: "1px" }} />
        <p style={{ color: "var(--dim)", fontSize: "13px", lineHeight: 1.5 }}>
          Locations are <strong style={{ color: "var(--fg)" }}>country-level</strong>, resolved entirely
          offline. The dashboard&apos;s CSP forbids external map tiles and geolocation lookups, so each peer IP
          is matched against a small bundled IP&#8209;to&#8209;country table (DB&#8209;IP Lite, CC&#8209;BY 4.0)
          and drawn at that country&apos;s centroid on a bundled Natural&nbsp;Earth vector map. Private,
          loopback, carrier&#8209;NAT and reserved addresses are listed but not plotted. Per&#8209;peer ASN and
          direction would need those fields added to the peers endpoint.
          {geoError && (
            <>
              {" "}
              <strong style={{ color: "var(--red)" }}>The GeoIP dataset failed to load</strong>, so peers are
              listed without country placement.
            </>
          )}
        </p>
      </div>

      {/* Map */}
      <SectionErrorBoundary section="Peer Map">
        <Card>
          <CardHeader title="World map" subtitle={`${points.length} of ${rows.length} peers plotted`} />
          <WorldMap points={points} self={self} hoveredId={hoveredId} onHover={setHoveredId} />
          {/* Legend */}
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 mt-4" style={{ fontSize: "12px", color: "var(--dim)" }}>
            <span className="inline-flex items-center gap-2">
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--green)", display: "inline-block" }} />
              Online peer
            </span>
            <span className="inline-flex items-center gap-2">
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--red)", display: "inline-block" }} />
              Offline / stale
            </span>
            <span className="inline-flex items-center gap-2">
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--accent)", display: "inline-block" }} />
              This node
            </span>
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Peer list */}
      <SectionErrorBoundary section="Peer List">
        <Card>
          <CardHeader title="Peers" subtitle={`${rows.length} known`} />
          {rows.length === 0 ? (
            <p style={{ color: "var(--dim)", fontSize: "14px", padding: "8px 0" }}>
              {peersLoading ? "Loading peers…" : "No peers connected. Your node will discover peers automatically."}
            </p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px", minWidth: "520px" }}>
                <thead>
                  <tr style={{ textAlign: "left", color: "var(--dim)" }}>
                    <th style={{ padding: "8px 10px", fontWeight: 500 }}>Address</th>
                    <th style={{ padding: "8px 10px", fontWeight: 500 }}>Country</th>
                    <th style={{ padding: "8px 10px", fontWeight: 500 }}>Latency</th>
                    <th style={{ padding: "8px 10px", fontWeight: 500 }}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => {
                    const active = hoveredId === r.key;
                    const flag = r.geo.code ? flagEmoji(r.geo.code) : "";
                    const latency = r.peer.latency_ms;
                    return (
                      <tr
                        key={r.key}
                        onMouseEnter={() => setHoveredId(r.key)}
                        onMouseLeave={() => setHoveredId(null)}
                        style={{
                          borderTop: "1px solid var(--rule)",
                          background: active ? "var(--accent-weak)" : "transparent",
                        }}
                      >
                        <td style={{ padding: "8px 10px", fontFamily: "var(--font-mono)", color: "var(--fg)", whiteSpace: "nowrap" }}>
                          {r.host || "—"}
                          {r.isSelf && (
                            <span style={{ marginLeft: 8, color: "var(--accent)", fontSize: "11px" }}>this node</span>
                          )}
                        </td>
                        <td style={{ padding: "8px 10px", color: r.geo.plottable ? "var(--fg)" : "var(--dim)" }}>
                          {flag && <span style={{ marginRight: 6 }}>{flag}</span>}
                          {r.geo.plottable ? r.geo.name : r.geo.label}
                          {r.geo.plottable && r.geo.code && (
                            <span style={{ marginLeft: 6, color: "var(--fainter)", fontSize: "11px" }}>{r.geo.code}</span>
                          )}
                          {!r.geo.plottable && (
                            <span style={{ marginLeft: 8, color: "var(--fainter)", fontSize: "11px" }}>not plotted</span>
                          )}
                        </td>
                        <td style={{ padding: "8px 10px", color: "var(--dim)", fontVariantNumeric: "tabular-nums" }}>
                          {latency != null ? `${Math.round(latency)} ms` : "—"}
                        </td>
                        <td style={{ padding: "8px 10px" }}>
                          <StatusDot
                            status={r.online ? "online" : "warning"}
                            label={r.online ? "Online" : "Stale"}
                            size="sm"
                          />
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </SectionErrorBoundary>
    </div>
  );
}
