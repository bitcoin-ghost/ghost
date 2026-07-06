"use client";

import { useMemo } from "react";
import { geoNaturalEarth1, geoPath, geoGraticule10 } from "d3-geo";
import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import type { FeatureCollection, Geometry } from "geojson";

import worldRaw from "@/lib/geo/world-110m.json";

export interface MapPoint {
  id: string;
  lat: number;
  lon: number;
  /** ISO 3166-1 alpha-2 code. */
  code: string;
  /** Country name. */
  name: string;
  /** Tooltip label, e.g. "203.0.113.4 — Germany". */
  label: string;
  online: boolean;
  isSelf?: boolean;
  /** ISO 3166-1 numeric code, used to highlight the matching country polygon. */
  num?: number;
}

interface WorldMapProps {
  points: MapPoint[];
  /** Origin for the connection lines (this node), if its location is known. */
  self?: MapPoint | null;
  hoveredId?: string | null;
  onHover?: (id: string | null) => void;
}

// ── Static basemap geometry (computed once; the topology never changes) ──────
const WIDTH = 980;
const HEIGHT = 500;

const world = worldRaw as unknown as Topology;
const countries = feature(
  world,
  world.objects.countries as GeometryCollection,
) as FeatureCollection<Geometry, { name?: string }>;

// Fit the whole sphere into the frame so peer centroids project consistently.
const projection = geoNaturalEarth1().fitExtent(
  [
    [6, 6],
    [WIDTH - 6, HEIGHT - 6],
  ],
  { type: "Sphere" },
);
const pathGen = geoPath(projection);

const SPHERE_PATH = pathGen({ type: "Sphere" }) ?? "";
const GRATICULE_PATH = pathGen(geoGraticule10()) ?? "";
const COUNTRY_PATHS: { id: number; d: string }[] = countries.features.map((f) => ({
  id: Number(f.id),
  d: pathGen(f) ?? "",
}));

function project(lon: number, lat: number): [number, number] | null {
  const p = projection([lon, lat]);
  return p ? [p[0], p[1]] : null;
}

/** Deterministic small pixel offset so co-located peers do not fully overlap. */
function jitterPx(seed: string): [number, number] {
  let h = 2166136261;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  const a = ((h >>> 0) % 1000) / 1000 - 0.5;
  const b = (((h >>> 10) >>> 0) % 1000) / 1000 - 0.5;
  return [a * 14, b * 14];
}

interface Placed extends MapPoint {
  x: number;
  y: number;
}

/**
 * Vector world map (Natural Earth 110m) rendered as inline SVG with d3-geo.
 * All geometry is bundled — no tiles, no CDN, no runtime fetches — and every
 * colour is a theme CSS variable so it reads correctly in light and dark.
 * Peers plot at country centroids, with connection arcs from this node and
 * hover cross-highlighting shared with the peer list.
 */
export function WorldMap({ points, self, hoveredId, onHover }: WorldMapProps) {
  const placed = useMemo<Placed[]>(() => {
    return points
      .map((p): Placed | null => {
        const xy = project(p.lon, p.lat);
        if (!xy) return null;
        const [dx, dy] = jitterPx(p.id);
        return { ...p, x: xy[0] + dx, y: xy[1] + dy };
      })
      .filter((p): p is Placed => p !== null);
  }, [points]);

  const origin = useMemo<Placed | null>(() => {
    if (!self) return null;
    const xy = project(self.lon, self.lat);
    return xy ? { ...self, x: xy[0], y: xy[1] } : null;
  }, [self]);

  // Country numeric id under the hovered peer, for polygon highlight.
  const hoverNum = useMemo(() => {
    const hp = placed.find((p) => p.id === hoveredId);
    return hp?.num ?? null;
  }, [placed, hoveredId]);

  return (
    <div style={{ width: "100%", overflowX: "auto" }}>
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label="World map of peer locations"
        preserveAspectRatio="xMidYMid meet"
        style={{
          width: "100%",
          height: "auto",
          minWidth: "560px",
          display: "block",
          background: "var(--surface)",
          border: "1px solid var(--rule)",
          borderRadius: "4px",
        }}
      >
        {/* Ocean / sphere outline */}
        <path d={SPHERE_PATH} fill="var(--bg)" stroke="var(--rule)" strokeWidth={0.6} />

        {/* Graticule */}
        <path
          d={GRATICULE_PATH}
          fill="none"
          stroke="var(--rule)"
          strokeWidth={0.3}
          opacity={0.6}
        />

        {/* Countries */}
        <g stroke="var(--surface)" strokeWidth={0.4}>
          {COUNTRY_PATHS.map((c) => {
            const lit = hoverNum != null && c.id === hoverNum;
            return (
              <path
                key={c.id}
                d={c.d}
                fill={lit ? "var(--accent)" : "var(--rule-strong)"}
                opacity={lit ? 0.55 : 0.9}
              />
            );
          })}
        </g>

        {/* Connection arcs: this node → each peer */}
        {origin && (
          <g fill="none" strokeWidth={0.7}>
            {placed.map((p) => {
              if (p.isSelf) return null;
              const active = hoveredId === p.id;
              const mx = (origin.x + p.x) / 2;
              const my = (origin.y + p.y) / 2;
              // Bow the arc perpendicular to the chord for a gentle curve.
              const dx = p.x - origin.x;
              const dy = p.y - origin.y;
              const len = Math.hypot(dx, dy) || 1;
              const cx = mx - (dy / len) * len * 0.14;
              const cy = my + (dx / len) * len * 0.14;
              return (
                <path
                  key={`arc-${p.id}`}
                  d={`M${origin.x} ${origin.y} Q${cx} ${cy} ${p.x} ${p.y}`}
                  stroke="var(--accent)"
                  opacity={active ? 0.85 : 0.28}
                />
              );
            })}
          </g>
        )}

        {/* Peer markers */}
        <g>
          {placed.map((p) => {
            const active = hoveredId === p.id;
            const color = p.isSelf
              ? "var(--accent)"
              : p.online
                ? "var(--green)"
                : "var(--red)";
            return (
              <g
                key={p.id}
                onMouseEnter={() => onHover?.(p.id)}
                onMouseLeave={() => onHover?.(null)}
                style={{ cursor: "default" }}
              >
                <circle cx={p.x} cy={p.y} r={active ? 8 : 5} fill={color} opacity={0.18} />
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={active ? 3.4 : 2.4}
                  fill={color}
                  stroke="var(--surface)"
                  strokeWidth={0.6}
                />
                <title>{`${p.label}${p.isSelf ? " (this node)" : ""}`}</title>
              </g>
            );
          })}
        </g>
      </svg>
    </div>
  );
}
