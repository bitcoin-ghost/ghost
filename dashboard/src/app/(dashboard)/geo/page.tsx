"use client";

import { useMemo, useState } from "react";
import { Info } from "lucide-react";

import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { WorldMap, type MapPoint } from "@/components/geo/WorldMap";
import { usePeers } from "@/hooks/queries";
import { resolveLocation, jitterFor } from "@/lib/geo/ipLocation";
import type { PeerInfo } from "@/types/api";

const TOOLTIPS = {
  peers: "Mesh peers this node currently knows, from the network peers endpoint.",
  plotted: "Peers whose address resolved to a routable region and are drawn on the map.",
  regions: "Distinct Regional Internet Registry regions your peers resolve to.",
  online: "Peers seen within the mesh freshness window (synced).",
};

interface Row {
  key: string;
  peer: PeerInfo;
  host: string;
  online: boolean;
  isSelf: boolean;
  locationLabel: string;
  plottable: boolean;
  point?: MapPoint;
}

function hostOf(address: string | undefined): string {
  if (!address) return "";
  const trimmed = address.trim();
  const bracket = trimmed.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracket) return bracket[1];
  if ((trimmed.match(/:/g) || []).length === 1) return trimmed.split(":")[0];
  return trimmed;
}

export default function GeoPage() {
  const { data: peersData, isLoading } = usePeers();
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const rows: Row[] = useMemo(() => {
    const peers = peersData?.peers ?? [];
    return peers.map((peer, i): Row => {
      const key = peer.node_id || peer.address || `peer-${i}`;
      const host = hostOf(peer.address);
      const online = Boolean(peer.synced);
      const isSelf = Boolean(peer.is_self);
      const loc = resolveLocation(peer.address);

      let point: MapPoint | undefined;
      if (loc.plottable && loc.lat != null && loc.lon != null) {
        const { dLat, dLon } = jitterFor(host || key);
        point = {
          id: key,
          lat: Math.max(-85, Math.min(85, loc.lat + dLat)),
          lon: Math.max(-179, Math.min(179, loc.lon + dLon)),
          label: `${host || "peer"} — ${loc.label}`,
          online,
          isSelf,
        };
      }

      return {
        key,
        peer,
        host,
        online,
        isSelf,
        locationLabel: loc.label,
        plottable: loc.plottable,
        point,
      };
    });
  }, [peersData]);

  const points = useMemo(
    () => rows.map((r) => r.point).filter((p): p is MapPoint => Boolean(p)),
    [rows],
  );

  const plottedCount = points.length;
  const onlineCount = rows.filter((r) => r.online).length;
  const regionCount = useMemo(() => {
    const set = new Set<string>();
    rows.forEach((r) => {
      if (r.point) set.add(r.locationLabel);
    });
    return set.size;
  }, [rows]);

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="geo"
        title="Peer map."
        subtitle="Approximate geographic spread of the mesh peers this node knows, resolved offline from peer IP addresses."
      />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Peers" value={rows.length} tooltip={TOOLTIPS.peers} loading={isLoading} />
        <StatCard label="Plotted" value={plottedCount} tooltip={TOOLTIPS.plotted} loading={isLoading} />
        <StatCard label="Regions" value={regionCount} tooltip={TOOLTIPS.regions} loading={isLoading} />
        <StatCard label="Online" value={`${onlineCount} / ${rows.length}`} tooltip={TOOLTIPS.online} loading={isLoading} />
      </div>

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
          Locations are <strong style={{ color: "var(--fg)" }}>approximate, region-level</strong> placements. The
          dashboard&apos;s offline posture forbids external map tiles and geolocation lookups, so each peer IP is
          mapped locally via the IANA IPv4 registry to the Regional Internet Registry that administers its block
          (ARIN, RIPE, APNIC, LACNIC, AFRINIC) and drawn at that region&apos;s centroid. Private, loopback, and
          reserved addresses are listed but not plotted. Precise country/city geolocation would require a data
          source the offline posture does not allow.
        </p>
      </div>

      {/* Map */}
      <SectionErrorBoundary section="Peer Map">
        <Card>
          <CardHeader title="World map" subtitle={`${plottedCount} of ${rows.length} peers plotted`} />
          <WorldMap points={points} hoveredId={hoveredId} onHover={setHoveredId} />
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
              {isLoading ? "Loading peers…" : "No peers connected. Your node will discover peers automatically."}
            </p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                <thead>
                  <tr style={{ textAlign: "left", color: "var(--dim)" }}>
                    <th style={{ padding: "8px 10px", fontWeight: 500 }}>Address</th>
                    <th style={{ padding: "8px 10px", fontWeight: 500 }}>Resolved location</th>
                    <th style={{ padding: "8px 10px", fontWeight: 500 }}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => {
                    const active = hoveredId === r.key;
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
                        <td style={{ padding: "8px 10px", fontFamily: "var(--font-mono)", color: "var(--fg)" }}>
                          {r.host || "—"}
                          {r.isSelf && (
                            <span style={{ marginLeft: 8, color: "var(--accent)", fontSize: "11px" }}>this node</span>
                          )}
                        </td>
                        <td style={{ padding: "8px 10px", color: r.plottable ? "var(--fg)" : "var(--dim)" }}>
                          {r.locationLabel}
                          {!r.plottable && (
                            <span style={{ marginLeft: 8, color: "var(--fainter)", fontSize: "11px" }}>not plotted</span>
                          )}
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
