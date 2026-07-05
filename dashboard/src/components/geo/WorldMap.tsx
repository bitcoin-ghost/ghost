"use client";

import { CONTINENTS, MAP_HEIGHT, MAP_WIDTH, project, ringToPath } from "@/lib/geo/worldMap";

export interface MapPoint {
  id: string;
  lat: number;
  lon: number;
  label: string;
  online: boolean;
  isSelf?: boolean;
}

interface WorldMapProps {
  points: MapPoint[];
  hoveredId?: string | null;
  onHover?: (id: string | null) => void;
}

// Graticule every 30° longitude / 30° latitude for a subtle sense of scale.
const LON_LINES = [-150, -120, -90, -60, -30, 0, 30, 60, 90, 120, 150];
const LAT_LINES = [-60, -30, 0, 30, 60];

/**
 * Inline SVG equirectangular world map. All geometry is bundled (no tiles, no
 * external requests) and every colour is a theme CSS variable so the map reads
 * correctly in both light and dark themes.
 */
export function WorldMap({ points, hoveredId, onHover }: WorldMapProps) {
  return (
    <div style={{ width: "100%", overflowX: "auto" }}>
      <svg
        viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}
        role="img"
        aria-label="World map of mesh peer locations"
        preserveAspectRatio="xMidYMid meet"
        style={{
          width: "100%",
          height: "auto",
          minWidth: "520px",
          display: "block",
          background: "var(--surface)",
          border: "1px solid var(--rule)",
          borderRadius: "4px",
        }}
      >
        {/* Graticule */}
        <g stroke="var(--rule)" strokeWidth={0.3} opacity={0.7}>
          {LON_LINES.map((lon) => {
            const [x] = project(lon, 0);
            return <line key={`lon-${lon}`} x1={x} y1={0} x2={x} y2={MAP_HEIGHT} />;
          })}
          {LAT_LINES.map((lat) => {
            const [, y] = project(0, lat);
            return <line key={`lat-${lat}`} x1={0} y1={y} x2={MAP_WIDTH} y2={y} />;
          })}
        </g>

        {/* Continents */}
        <g fill="var(--rule-strong)" stroke="var(--fainter)" strokeWidth={0.35} opacity={0.9}>
          {CONTINENTS.map((ring, i) => (
            <path key={`land-${i}`} d={ringToPath(ring)} />
          ))}
        </g>

        {/* Peer markers */}
        <g>
          {points.map((p) => {
            const [x, y] = project(p.lon, p.lat);
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
                {/* Halo */}
                <circle cx={x} cy={y} r={active ? 6 : 4} fill={color} opacity={0.18} />
                {/* Core dot */}
                <circle
                  cx={x}
                  cy={y}
                  r={active ? 2.6 : 2}
                  fill={color}
                  stroke="var(--surface)"
                  strokeWidth={0.5}
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
