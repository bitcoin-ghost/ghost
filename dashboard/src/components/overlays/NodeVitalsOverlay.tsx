/**
 * Overlay: Node Vitals
 *
 * CONCEPT — a calm mission-control board for this node: block height ticking
 * up, a heartbeat pulse on each new block, current hashrate, the 5-4-3-2-1
 * capability ring, peer count, uptime, and a sync progress bar. Big, legible,
 * ambient — designed to be glanced at from across a room.
 *
 * IMPLEMENTER NOTES:
 *  - Keep the `export function NodeVitalsOverlay({ active }: OverlayProps)`
 *    signature exactly. Replace only the body of this file.
 *  - Honour `active`: run your rAF / animation loop and any polling ONLY while
 *    `active === true`; cancel the rAF and stop polling when it flips to false.
 *  - CSP-safe only: draw with <canvas> or inline SVG. No external assets.
 */
'use client';

import { useEffect, useRef } from 'react';
import type { OverlayProps } from './types';
import { useNodeStatus, useShares } from '@/hooks/queries/useNodeQueries';
import { useMiningStatus, useBestHash } from '@/hooks/queries/useMiningQueries';
import { formatHashrate, formatDuration } from '@/components/ui/DataTable';
import type { SharesInfo } from '@/types/api';

// Bitcoin orange — identical in both themes (--accent), so the canvas can use
// it directly without reading it back out of the DOM every frame.
const ACCENT_RGB = '247, 147, 26';

// The 5-4-3-2-1 capability ring, first arc (Archive, +5) to last (Elder, +1).
// `key` indexes SharesInfo's boolean capability flags.
const CAPS: { key: keyof SharesInfo; label: string; bonus: number }[] = [
  { key: 'archive_mode', label: 'ARCHIVE', bonus: 5 },
  { key: 'ghost_pay', label: 'GHOSTPAY', bonus: 4 },
  { key: 'public_mining', label: 'MINING', bonus: 3 },
  { key: 'reaper', label: 'REAPER', bonus: 2 },
  { key: 'elder', label: 'ELDER', bonus: 1 },
];

// Ring geometry (SVG userspace units; viewBox is 0 0 400 400).
const CENTER = 200;
const RING_R = 150;
const RING_STROKE = 13;
const SEG_SLOT = 100 / CAPS.length; // pathLength=100 → 20 units per capability
const SEG_GAP = 3; // units of gap between arcs
const SEG_VISIBLE = SEG_SLOT - SEG_GAP;
const LABEL_R = RING_R + 30;

interface Vitals {
  height: number; // node's synced height (the big ticking number)
  target: number; // chain tip height (== height once synced)
  isSyncing: boolean;
  syncPct: number;
  peers: number;
  miners: number;
  hashrateHs: number; // this node's local hashrate, in H/s
  uptimeSecs: number;
  bestDifficulty: number;
}

function fmtCompact(n: number): string {
  if (!isFinite(n) || n <= 0) return '—';
  if (n >= 1e12) return `${(n / 1e12).toFixed(2)}T`;
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(2)}K`;
  return Math.round(n).toLocaleString();
}

export function NodeVitalsOverlay({ active }: OverlayProps) {
  const { data: status, isLoading: statusLoading } = useNodeStatus();
  const { data: mining } = useMiningStatus();
  const { data: shares } = useShares();
  const { data: bestHash } = useBestHash();

  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);

  // Heartbeat: timestamps of recent block increments the canvas is animating.
  const beatsRef = useRef<number[]>([]);
  const prevHeightRef = useRef<number | null>(null);

  // ── Derive a single tidy vitals object (mirrors the Overview page logic). ──
  const blockHeight = status?.block_height ?? 0;
  const syncHeight = status?.sync_height ?? status?.block_height ?? 0;
  const isSyncing = status?.is_synced === false && syncHeight > 0 && blockHeight > 0;

  const v: Vitals = {
    height: syncHeight,
    target: blockHeight,
    isSyncing,
    syncPct: isSyncing ? Math.min(100, (syncHeight / blockHeight) * 100) : status?.is_synced ? 100 : 0,
    peers: status?.peer_count ?? 0,
    miners: mining?.connected_miners ?? mining?.local_connected_miners ?? 0,
    hashrateHs: (mining?.local_hashrate_th ?? 0) * 1e12,
    uptimeSecs: status?.uptime_seconds ?? status?.uptime_secs ?? 0,
    bestDifficulty:
      bestHash?.all_time?.difficulty ??
      bestHash?.best_difficulty ??
      bestHash?.last_24h?.difficulty ??
      0,
  };

  const uptimeQualified = shares?.uptime_qualified ?? true;
  const totalShares = shares?.total ?? 0;
  const maxShares = shares?.max_shares ?? 15;
  const hasStatus = !!status;

  // ── Heartbeat detection: a rising synced height registers a beat. ──
  useEffect(() => {
    const h = v.height;
    if (h <= 0) return;
    const prev = prevHeightRef.current;
    prevHeightRef.current = h;
    // Only pulse on a genuine forward tick (not the first data arrival, and not
    // a backward wobble), and only while this overlay is the active one. The
    // canvas reads these timestamps; the central number restarts its CSS beat
    // purely via its `key={v.height}` remount below — no state needed here.
    if (prev !== null && h > prev && active) {
      beatsRef.current.push(performance.now());
    }
  }, [v.height, active]);

  // ── Canvas: ambient breathing ring + emanating pulse on each new block. ──
  useEffect(() => {
    if (!active) return;
    const canvas = canvasRef.current;
    const wrap = wrapRef.current;
    if (!canvas || !wrap) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let raf = 0;
    let dpr = 1;

    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      const r = wrap.getBoundingClientRect();
      canvas.width = Math.max(1, Math.round(r.width * dpr));
      canvas.height = Math.max(1, Math.round(r.height * dpr));
    };
    resize();
    window.addEventListener('resize', resize);

    // Radius, in CSS px, of the medallion the pulses emanate from. Tracks the
    // rendered SVG ring (a fraction of the smaller side), clamped for big rooms.
    const medallionR = () => {
      const r = wrap.getBoundingClientRect();
      return Math.min(Math.min(r.width, r.height) * 0.32, 320);
    };

    const draw = (t: number) => {
      const w = canvas.width / dpr;
      const h = canvas.height / dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      const cx = w / 2;
      const cy = h / 2;
      const base = medallionR();

      // Ambient breathing ring — a very slow, quiet halo so the board feels
      // alive even between blocks.
      const breathe = 0.5 + 0.5 * Math.sin(t / 2600);
      ctx.beginPath();
      ctx.arc(cx, cy, base + 12 + breathe * 6, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(${ACCENT_RGB}, ${0.04 + breathe * 0.05})`;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Emanating pulses on each recent block. Rings expand and fade over ~1.8s.
      const LIFE = 1800;
      const beats = beatsRef.current;
      for (let i = beats.length - 1; i >= 0; i--) {
        const age = t - beats[i];
        if (age > LIFE || age < 0) {
          if (age > LIFE) beats.splice(i, 1);
          continue;
        }
        const p = age / LIFE; // 0 → 1
        const ease = 1 - Math.pow(1 - p, 3);
        const r = base + ease * (Math.min(w, h) * 0.42);
        const alpha = (1 - p) * 0.5;
        ctx.beginPath();
        ctx.arc(cx, cy, r, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(${ACCENT_RGB}, ${alpha})`;
        ctx.lineWidth = 2.5 * (1 - p) + 0.5;
        ctx.stroke();
      }

      raf = requestAnimationFrame(draw);
    };
    raf = requestAnimationFrame(draw);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
      ctx.setTransform(1, 0, 0, 1, 0, 0);
      ctx.clearRect(0, 0, canvas.width, canvas.height);
    };
  }, [active]);

  // ── Render ──────────────────────────────────────────────────────────────
  return (
    <div
      className="relative flex h-full w-full flex-col items-center justify-center select-none overflow-hidden"
      style={{ background: 'var(--bg)', color: 'var(--fg)', gap: 'clamp(20px, 4vh, 56px)' }}
    >
      <style>{keyframes}</style>

      {/* Eyebrow / status line */}
      <div
        className="flex items-center gap-3"
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '12px',
          textTransform: 'uppercase',
          letterSpacing: '0.24em',
          color: 'var(--dim)',
        }}
      >
        <span
          style={{
            width: 8,
            height: 8,
            borderRadius: 9999,
            background: v.isSyncing ? 'var(--accent)' : 'var(--green)',
            boxShadow: `0 0 12px 2px rgba(${ACCENT_RGB}, ${v.isSyncing ? 0.6 : 0})`,
            animation: active ? 'nv-blink 2.4s ease-in-out infinite' : undefined,
          }}
        />
        <span>Node Vitals</span>
        <span style={{ color: 'var(--fainter)' }}>·</span>
        <span style={{ color: v.isSyncing ? 'var(--accent)' : 'var(--dim)' }}>
          {!hasStatus ? 'Acquiring signal' : v.isSyncing ? 'Syncing' : 'Synced'}
        </span>
      </div>

      {/* Medallion: capability ring wrapping the big ticking block height. */}
      <div
        ref={wrapRef}
        className="relative flex items-center justify-center"
        style={{ width: 'min(74vh, 92vw, 620px)', aspectRatio: '1 / 1' }}
      >
        {/* Canvas heartbeat layer (behind the SVG ring). */}
        <canvas
          ref={canvasRef}
          className="absolute inset-0"
          style={{ width: '100%', height: '100%' }}
          aria-hidden
        />

        {/* Capability ring. */}
        <svg
          viewBox="0 0 400 400"
          className="absolute inset-0"
          style={{ width: '100%', height: '100%' }}
          aria-hidden
        >
          {/* faint full track */}
          <circle
            cx={CENTER}
            cy={CENTER}
            r={RING_R}
            fill="none"
            stroke="var(--rule)"
            strokeWidth={RING_STROKE}
            opacity={0.5}
          />
          <g transform={`rotate(-90 ${CENTER} ${CENTER})`}>
            {CAPS.map((cap, i) => {
              const qualified = !!shares?.[cap.key] && uptimeQualified;
              const claimed = !!shares?.[cap.key] && !uptimeQualified;
              const color = qualified
                ? `rgb(${ACCENT_RGB})`
                : claimed
                  ? 'var(--red)'
                  : 'var(--rule-strong)';
              return (
                <circle
                  key={cap.key}
                  cx={CENTER}
                  cy={CENTER}
                  r={RING_R}
                  fill="none"
                  stroke={color}
                  strokeWidth={RING_STROKE}
                  strokeLinecap="round"
                  pathLength={100}
                  strokeDasharray={`${SEG_VISIBLE} ${100 - SEG_VISIBLE}`}
                  strokeDashoffset={-(i * SEG_SLOT)}
                  style={{
                    filter: qualified
                      ? `drop-shadow(0 0 5px rgba(${ACCENT_RGB}, 0.7))`
                      : 'none',
                    transition: 'stroke 0.4s ease',
                    animation: qualified && active ? 'nv-arc 3.6s ease-in-out infinite' : undefined,
                    animationDelay: `${i * 0.24}s`,
                  }}
                />
              );
            })}
          </g>
        </svg>

        {/* Capability labels around the ring. */}
        <svg
          viewBox="0 0 400 400"
          className="absolute inset-0"
          style={{ width: '100%', height: '100%', overflow: 'visible' }}
          aria-hidden
        >
          {CAPS.map((cap, i) => {
            const frac = (i * SEG_SLOT + SEG_VISIBLE / 2) / 100;
            const ang = (-90 + frac * 360) * (Math.PI / 180);
            const x = CENTER + LABEL_R * Math.cos(ang);
            const y = CENTER + LABEL_R * Math.sin(ang);
            const qualified = !!shares?.[cap.key] && uptimeQualified;
            return (
              <g key={cap.key} transform={`translate(${x} ${y})`}>
                <text
                  textAnchor="middle"
                  dominantBaseline="middle"
                  y={-6}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 12,
                    letterSpacing: '0.12em',
                    fill: qualified ? 'var(--fg)' : 'var(--fainter)',
                  }}
                >
                  {cap.label}
                </text>
                <text
                  textAnchor="middle"
                  dominantBaseline="middle"
                  y={9}
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    fontWeight: 600,
                    fill: qualified ? `rgb(${ACCENT_RGB})` : 'var(--fainter)',
                  }}
                >
                  +{cap.bonus}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Centre readout. */}
        <div
          key={v.height}
          className="relative flex flex-col items-center justify-center text-center"
          style={{ animation: active ? 'nv-beat 1.6s ease-out' : undefined }}
        >
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(10px, 1.4vh, 13px)',
              textTransform: 'uppercase',
              letterSpacing: '0.28em',
              color: 'var(--dim)',
              marginBottom: 6,
            }}
          >
            Block Height
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(40px, 9vh, 108px)',
              fontWeight: 300,
              lineHeight: 1,
              letterSpacing: '-0.01em',
              fontVariantNumeric: 'tabular-nums',
              color: 'var(--fg)',
            }}
          >
            {hasStatus ? v.height.toLocaleString() : '—'}
          </div>
          {v.isSyncing && (
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: 'clamp(11px, 1.6vh, 14px)',
                color: 'var(--accent)',
                marginTop: 8,
              }}
            >
              / {v.target.toLocaleString()} · {v.syncPct.toFixed(1)}%
            </div>
          )}
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(11px, 1.6vh, 14px)',
              letterSpacing: '0.1em',
              color: uptimeQualified ? 'var(--dim)' : 'var(--red)',
              marginTop: 14,
            }}
          >
            {shares ? (
              <>
                <span style={{ color: uptimeQualified ? 'var(--fg)' : 'var(--red)', fontWeight: 600 }}>
                  {totalShares}
                </span>
                <span style={{ color: 'var(--fainter)' }}> / {maxShares} shares</span>
              </>
            ) : (
              <span style={{ color: 'var(--fainter)' }}>— / {maxShares} shares</span>
            )}
          </div>
          {shares && !uptimeQualified && (
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '10px',
                textTransform: 'uppercase',
                letterSpacing: '0.18em',
                color: 'var(--red)',
                marginTop: 4,
              }}
            >
              uptime below 95% · shares paused
            </div>
          )}
        </div>
      </div>

      {/* Vital stat tiles. */}
      <div
        className="flex flex-wrap items-stretch justify-center"
        style={{ gap: 'clamp(10px, 2vw, 28px)', maxWidth: '92vw' }}
      >
        <Stat label="Hashrate" value={v.hashrateHs > 0 ? formatHashrate(v.hashrateHs) : hasStatus ? '0 H/s' : '—'} />
        <Stat label="Miners" value={hasStatus ? String(v.miners) : '—'} />
        <Stat label="Peers" value={hasStatus ? String(v.peers) : '—'} />
        <Stat label="Uptime" value={v.uptimeSecs > 0 ? formatDuration(v.uptimeSecs) : hasStatus ? '0m' : '—'} />
        <Stat label="Best Share" value={fmtCompact(v.bestDifficulty)} />
      </div>

      {/* Sync progress bar. */}
      <div style={{ width: 'min(620px, 82vw)' }}>
        <div
          className="flex items-center justify-between"
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: '10px',
            textTransform: 'uppercase',
            letterSpacing: '0.2em',
            color: 'var(--dim)',
            marginBottom: 6,
          }}
        >
          <span>Chain Sync</span>
          <span style={{ color: v.isSyncing ? 'var(--accent)' : 'var(--green)' }}>
            {!hasStatus ? '—' : v.isSyncing ? `${v.syncPct.toFixed(1)}%` : 'Synced · 100%'}
          </span>
        </div>
        <div
          style={{
            height: 4,
            width: '100%',
            borderRadius: 9999,
            background: 'var(--rule)',
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              height: '100%',
              width: `${hasStatus ? v.syncPct : 0}%`,
              borderRadius: 9999,
              background: v.isSyncing ? `rgb(${ACCENT_RGB})` : 'var(--green)',
              boxShadow: `0 0 10px 0 rgba(${ACCENT_RGB}, ${v.isSyncing ? 0.5 : 0.25})`,
              transition: 'width 0.6s ease',
            }}
          />
        </div>
      </div>

      {/* Initial connecting state — only before any status has arrived. */}
      {statusLoading && !hasStatus && (
        <div
          style={{
            position: 'absolute',
            bottom: 'clamp(16px, 4vh, 40px)',
            fontFamily: 'var(--font-mono)',
            fontSize: '11px',
            letterSpacing: '0.2em',
            textTransform: 'uppercase',
            color: 'var(--fainter)',
          }}
        >
          connecting to node…
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div
      className="flex flex-col items-center"
      style={{
        minWidth: 'clamp(88px, 15vw, 150px)',
        padding: 'clamp(8px, 1.4vh, 16px) clamp(10px, 1.6vw, 22px)',
        borderRadius: 12,
        border: '1px solid var(--rule)',
        background: 'var(--surface)',
      }}
    >
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 'clamp(18px, 3vh, 30px)',
          fontWeight: 300,
          lineHeight: 1.1,
          fontVariantNumeric: 'tabular-nums',
          color: 'var(--fg)',
          whiteSpace: 'nowrap',
        }}
      >
        {value}
      </div>
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '10px',
          textTransform: 'uppercase',
          letterSpacing: '0.18em',
          color: 'var(--dim)',
          marginTop: 6,
        }}
      >
        {label}
      </div>
    </div>
  );
}

const keyframes = `
@keyframes nv-blink { 0%, 100% { opacity: 1 } 50% { opacity: 0.35 } }
@keyframes nv-beat {
  0% { transform: scale(1); }
  12% { transform: scale(1.035); }
  40% { transform: scale(1); }
}
@keyframes nv-arc { 0%, 100% { opacity: 1 } 50% { opacity: 0.72 } }
`;
