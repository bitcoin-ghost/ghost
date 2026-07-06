"use client";

import { useMemo, useState } from "react";
import { Info } from "lucide-react";

import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { StatusDot } from "@/components/ui/StatusDot";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { WorldMap, type MapPoint } from "@/components/geo/WorldMap";
import { useMeshNodes, useGeoDb } from "@/hooks/queries";
import { extractHost, flagEmoji, type GeoResult } from "@/lib/geo/geoip";
import type { MeshNode } from "@/lib/api/meshNodes";

const TOOLTIPS = {
  nodes: "Mesh nodes this node knows — self plus every connected peer, from the mesh-nodes endpoint.",
  plotted: "Nodes whose IP resolved to a country and are drawn on the map.",
  countries: "Distinct countries your plotted nodes resolve to.",
  online: "Nodes reporting healthy in the current mesh view.",
};

interface Row {
  key: string;
  node: MeshNode;
  host: string;
  online: boolean;
  isSelf: boolean;
  geo: GeoResult;
}

function toPoint(r: Row): MapPoint | null {
  if (!r.geo.plottable || r.geo.lat == null || r.geo.lon == null) return null;
  return {
    id: r.key,
    lat: r.geo.lat,
    lon: r.geo.lon,
    code: r.geo.code ?? "",
    name: r.geo.name ?? "",
    label: `${r.host || "node"} — ${r.geo.name ?? "node"}`,
    online: r.online,
    isSelf: r.isSelf,
    num: r.geo.num,
  };
}

export default function GeoPage() {
  const { data: meshData, isLoading: nodesLoading } = useMeshNodes();
  const { data: geoDb, isLoading: geoLoading, isError: geoError } = useGeoDb();
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const rows: Row[] = useMemo(() => {
    const nodes = meshData?.nodes ?? [];
    return nodes.map((node, i): Row => {
      const key = node.node_id || node.address || `node-${i}`;
      const host = extractHost(node.address);
      const geo: GeoResult = geoDb
        ? geoDb.resolve(node.address)
        : { kind: "unknown", label: geoLoading ? "Resolving…" : "Unresolved", plottable: false };
      return {
        key,
        node,
        host,
        online: Boolean(node.healthy),
        isSelf: Boolean(node.is_self),
        geo,
      };
    });
  }, [meshData, geoDb, geoLoading]);

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

  const loading = nodesLoading || geoLoading;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="geo"
        title="Node map."
        subtitle="Geographic spread of the mesh nodes this node knows, resolved offline from node IP addresses to country level."
      />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Nodes" value={rows.length} tooltip={TOOLTIPS.nodes} loading={nodesLoading} />
        <StatCard label="Plotted" value={points.length} tooltip={TOOLTIPS.plotted} loading={loading} />
        <StatCard label="Countries" value={countryCount} tooltip={TOOLTIPS.countries} loading={loading} />
        <StatCard label="Online" value={`${onlineCount} / ${rows.length}`} tooltip={TOOLTIPS.online} loading={nodesLoading} />
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

      {/* Map */}
      <SectionErrorBoundary section="Node Map">
        <Card>
          <CardHeader title="World map" subtitle={`${points.length} of ${rows.length} nodes plotted`} />
          <WorldMap points={points} self={self} hoveredId={hoveredId} onHover={setHoveredId} />
          {/* Legend */}
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 mt-4" style={{ fontSize: "12px", color: "var(--dim)" }}>
            <span className="inline-flex items-center gap-2">
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--green)", display: "inline-block" }} />
              Online node
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

      {/* Resolution note (below the map) */}
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
          offline. The dashboard&apos;s CSP forbids external map tiles and geolocation lookups, so each node IP
          is matched against a small bundled IP&#8209;to&#8209;country table (DB&#8209;IP Lite, CC&#8209;BY 4.0)
          and drawn at that country&apos;s centroid on a bundled Natural&nbsp;Earth vector map. Private,
          loopback, carrier&#8209;NAT and reserved addresses are listed but not plotted. This node is drawn in
          the accent colour; peers are green when healthy and red when stale.
          {geoError && (
            <>
              {" "}
              <strong style={{ color: "var(--red)" }}>The GeoIP dataset failed to load</strong>, so nodes are
              listed without country placement.
            </>
          )}
        </p>
      </div>

      {/* Node list */}
      <SectionErrorBoundary section="Node List">
        <Card>
          <CardHeader title="Nodes" subtitle={`${rows.length} known`} />
          {rows.length === 0 ? (
            <p style={{ color: "var(--dim)", fontSize: "14px", padding: "8px 0" }}>
              {nodesLoading ? "Loading nodes…" : "No mesh nodes connected. Your node will discover peers automatically."}
            </p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px", minWidth: "520px" }}>
                <thead>
                  <tr style={{ textAlign: "left", color: "var(--dim)" }}>
                    <th style={{ padding: "8px 10px", fontWeight: 500 }}>Address</th>
                    <th style={{ padding: "8px 10px", fontWeight: 500 }}>Country</th>
                    <th style={{ padding: "8px 10px", fontWeight: 500 }}>Role</th>
                    <th style={{ padding: "8px 10px", fontWeight: 500 }}>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => {
                    const active = hoveredId === r.key;
                    const flag = r.geo.code ? flagEmoji(r.geo.code) : "";
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
                        <td style={{ padding: "8px 10px", color: "var(--dim)" }}>
                          {r.node.elder ? (
                            <span style={{ color: "var(--accent)" }}>Elder</span>
                          ) : (
                            "Node"
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
