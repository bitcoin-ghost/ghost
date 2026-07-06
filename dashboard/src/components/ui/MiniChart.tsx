'use client';

import { useEffect, useMemo, useRef, useState } from 'react';

/**
 * Lightweight, dependency-free inline-SVG charts for the dashboard.
 *
 * The dashboard ships no charting library (recharts/chart.js/d3 are all absent
 * from package.json) and runs under a strict CSP that forbids external scripts,
 * so these are hand-rolled SVG. They follow the dataviz house rules: a single
 * series carries no legend (the card title names it), marks are thin (2px line,
 * soft area fill), gridlines/axes are recessive, there is exactly one value
 * axis, and every plot has a hover crosshair + tooltip. Colours come from the
 * theme CSS variables so both light and dark render correctly.
 */

interface Point {
  /** Unix seconds. */
  t: number;
  /** Value at that time. */
  v: number;
}

// Measure a container's pixel width so the SVG maps hover coordinates to data
// indices correctly. A pure viewBox scale can't do that (mouse events are in
// CSS pixels), so we render at the measured width instead.
function useElementWidth<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [width, setWidth] = useState(0);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width ?? 0;
      setWidth(Math.floor(w));
    });
    ro.observe(el);
    setWidth(Math.floor(el.clientWidth));
    return () => ro.disconnect();
  }, []);
  return { ref, width };
}

interface TimeSeriesChartProps {
  data: Point[];
  /** CSS colour for the line/area (default: accent orange). */
  color?: string;
  height?: number;
  /** Minimum px per sample; when the series is wide the chart scrolls. */
  minPointWidth?: number;
  formatValue?: (v: number) => string;
  ariaLabel?: string;
}

const AXIS_LEFT = 52;
const AXIS_BOTTOM = 20;
const PAD_TOP = 10;
const PAD_RIGHT = 10;

function formatClock(t: number): string {
  const d = new Date(t * 1000);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function TimeSeriesChart({
  data,
  color = 'var(--accent)',
  height = 160,
  minPointWidth = 8,
  formatValue = (v) => v.toFixed(2),
  ariaLabel,
}: TimeSeriesChartProps) {
  const { ref, width } = useElementWidth<HTMLDivElement>();
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  // Desired inner plot width; grow past the container so it scrolls when there
  // are many samples, otherwise fill the container.
  const desiredInner = Math.max(0, data.length - 1) * minPointWidth;
  const containerInner = Math.max(0, width - AXIS_LEFT - PAD_RIGHT);
  const innerW = Math.max(containerInner, desiredInner);
  const svgWidth = innerW + AXIS_LEFT + PAD_RIGHT;
  const innerH = height - PAD_TOP - AXIS_BOTTOM;

  const { min, max } = useMemo(() => {
    if (data.length === 0) return { min: 0, max: 1 };
    let lo = Infinity;
    let hi = -Infinity;
    for (const p of data) {
      if (p.v < lo) lo = p.v;
      if (p.v > hi) hi = p.v;
    }
    if (lo === hi) {
      // Flat series: pad so the line sits mid-plot rather than on an edge.
      const pad = Math.abs(lo) > 0 ? Math.abs(lo) * 0.1 : 1;
      return { min: lo - pad, max: hi + pad };
    }
    const pad = (hi - lo) * 0.08;
    return { min: lo - pad, max: hi + pad };
  }, [data]);

  const x = (i: number) =>
    AXIS_LEFT + (data.length <= 1 ? innerW / 2 : (i / (data.length - 1)) * innerW);
  const y = (v: number) => PAD_TOP + innerH - ((v - min) / (max - min || 1)) * innerH;

  if (data.length < 2 || width === 0) {
    return (
      <div ref={ref} style={{ height }} className="flex items-center justify-center">
        <span style={{ color: 'var(--fainter)', fontSize: '12px' }}>
          {width === 0 ? '' : 'Collecting live samples…'}
        </span>
      </div>
    );
  }

  const linePath = data.map((p, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ');
  const areaPath = `${linePath} L${x(data.length - 1).toFixed(1)},${(PAD_TOP + innerH).toFixed(1)} L${x(0).toFixed(1)},${(PAD_TOP + innerH).toFixed(1)} Z`;

  // Three recessive gridlines with value labels.
  const ticks = [0, 0.5, 1].map((f) => min + (max - min) * (1 - f));
  const hovered = hoverIdx != null ? data[hoverIdx] : null;

  const gradId = `msc-${Math.round(min)}-${data.length}`;

  return (
    <div ref={ref} className="relative w-full" style={{ overflowX: innerW > containerInner ? 'auto' : 'visible' }}>
      <svg
        width={svgWidth}
        height={height}
        role="img"
        aria-label={ariaLabel}
        style={{ display: 'block' }}
        onMouseMove={(e) => {
          const rect = (e.currentTarget as SVGSVGElement).getBoundingClientRect();
          const mx = e.clientX - rect.left;
          const rel = (mx - AXIS_LEFT) / (innerW || 1);
          const idx = Math.round(rel * (data.length - 1));
          setHoverIdx(Math.max(0, Math.min(data.length - 1, idx)));
        }}
        onMouseLeave={() => setHoverIdx(null)}
      >
        <defs>
          <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.22" />
            <stop offset="100%" stopColor={color} stopOpacity="0.02" />
          </linearGradient>
        </defs>

        {/* Gridlines + y labels */}
        {ticks.map((tv, i) => {
          const gy = y(tv);
          return (
            <g key={i}>
              <line
                x1={AXIS_LEFT}
                y1={gy}
                x2={svgWidth - PAD_RIGHT}
                y2={gy}
                stroke="var(--rule)"
                strokeWidth={1}
              />
              <text
                x={AXIS_LEFT - 8}
                y={gy + 3}
                textAnchor="end"
                fontSize={10}
                fontFamily="var(--font-mono)"
                fill="var(--fainter)"
              >
                {formatValue(tv)}
              </text>
            </g>
          );
        })}

        {/* Area + line */}
        <path d={areaPath} fill={`url(#${gradId})`} stroke="none" />
        <path d={linePath} fill="none" stroke={color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />

        {/* Endpoint marker (rounded data-end) */}
        <circle cx={x(data.length - 1)} cy={y(data[data.length - 1].v)} r={3} fill={color} />

        {/* x-axis end labels */}
        <text x={AXIS_LEFT} y={height - 5} textAnchor="start" fontSize={10} fontFamily="var(--font-mono)" fill="var(--fainter)">
          {formatClock(data[0].t)}
        </text>
        <text x={svgWidth - PAD_RIGHT} y={height - 5} textAnchor="end" fontSize={10} fontFamily="var(--font-mono)" fill="var(--fainter)">
          {formatClock(data[data.length - 1].t)}
        </text>

        {/* Hover crosshair */}
        {hovered && (
          <g pointerEvents="none">
            <line x1={x(hoverIdx!)} y1={PAD_TOP} x2={x(hoverIdx!)} y2={PAD_TOP + innerH} stroke="var(--rule-strong)" strokeWidth={1} />
            <circle cx={x(hoverIdx!)} cy={y(hovered.v)} r={3.5} fill="var(--bg)" stroke={color} strokeWidth={2} />
          </g>
        )}
      </svg>

      {hovered && (
        <div
          className="pointer-events-none absolute z-10 rounded px-2 py-1"
          style={{
            left: Math.min(Math.max(x(hoverIdx!) - 40, 0), svgWidth - 92),
            top: 0,
            background: 'var(--surface)',
            border: '1px solid var(--rule-strong)',
            fontSize: '11px',
            whiteSpace: 'nowrap',
          }}
        >
          <span style={{ color: 'var(--fg)', fontWeight: 600 }}>{formatValue(hovered.v)}</span>
          <span style={{ color: 'var(--fainter)', marginLeft: 6, fontFamily: 'var(--font-mono)' }}>{formatClock(hovered.t)}</span>
        </div>
      )}
    </div>
  );
}

interface ProportionBarProps {
  /** Ordered segments; each rendered proportional to its value. */
  segments: { label: string; value: number; color: string }[];
  height?: number;
}

/**
 * A single horizontal proportion bar (accepted vs rejected shares). Segments are
 * separated by a 2px surface gap per the mark spec, and each carries a
 * label + value below so identity is never colour-alone.
 */
export function ProportionBar({ segments, height = 12 }: ProportionBarProps) {
  const total = segments.reduce((s, x) => s + Math.max(0, x.value), 0);
  return (
    <div>
      <div
        className="flex w-full overflow-hidden rounded"
        style={{ height, gap: '2px', background: 'var(--rule)' }}
      >
        {total > 0 ? (
          segments.map((s, i) => (
            <div
              key={i}
              style={{
                width: `${(Math.max(0, s.value) / total) * 100}%`,
                background: s.color,
              }}
              title={`${s.label}: ${s.value.toLocaleString()}`}
            />
          ))
        ) : (
          <div style={{ width: '100%', background: 'var(--rule)' }} />
        )}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
        {segments.map((s, i) => (
          <div key={i} className="flex items-center gap-1.5" style={{ fontSize: '12px' }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: s.color, display: 'inline-block' }} />
            <span style={{ color: 'var(--dim)' }}>{s.label}</span>
            <span style={{ color: 'var(--fg)', fontFamily: 'var(--font-mono)' }}>{s.value.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
