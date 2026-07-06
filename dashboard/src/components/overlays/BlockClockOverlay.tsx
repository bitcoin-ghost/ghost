/**
 * Overlay: Block Clock
 *
 * CONCEPT — a giant, ambient next-block countdown. The centrepiece is the clock
 * ring itself; everything else is quiet supporting detail.
 *
 * The ring fills with the chain's progress toward the ~10-minute average block
 * interval: elapsed time since the last L1 block versus that target. At its
 * centre a big, room-legible counter ticks up the time since the last block.
 * Block height, network difficulty and network hashrate sit underneath as calm
 * readouts. When a new block lands (the height increments between polls) the
 * whole clock gives a satisfying golden flash and the ring sweeps back to empty
 * for the fresh block.
 *
 * DATA NOTES (why this file was rewritten):
 *  - "Since last block" = `now - chain.tip_time`. `tip_time` is a unix SECONDS
 *    timestamp of the current chain tip (verified against the node: it matches
 *    the pool's `last_block_time`). This is the correct, honest L1 source — it
 *    can legitimately read tens of minutes on a low-hashrate chain where blocks
 *    are sparse, so a long value is "running long", NOT a bug.
 *  - The ring is driven ENTIRELY from that L1 elapsed vs a 10-min target. The
 *    old code filled it from `pool.estimated_time_to_block_secs` /
 *    `current_round_duration_secs`, which the node never emits (they exist only
 *    in the dashboard's TS types) — so the ring was permanently empty and the
 *    face read "no block-time estimate yet". The ring is now never dead: it
 *    shows real progress, a full breathing ring when a block runs long, and an
 *    indeterminate breathing spinner while we have no tip yet.
 *
 * IMPLEMENTER NOTES:
 *  - Keep the `export function BlockClockOverlay({ active }: OverlayProps)`
 *    signature exactly. Replace only the body of this file.
 *  - Honour `active`: the 1s tick that drives the counter/ring and the new-block
 *    pulse run ONLY while `active === true`, and all ambient motion (CSS
 *    keyframes scoped under `.bc-live`, SMIL sweep) is disabled when the overlay
 *    is off-screen or the viewer prefers reduced motion. Polling backs right off
 *    while parked.
 *  - CSP-safe only: inline SVG + one inline <style> of keyframes (same pattern
 *    the sibling NodeVitals overlay uses). No external assets, no injected
 *    remote stylesheets, no new deps.
 */
'use client';

import { useEffect, useRef, useState } from 'react';
import type { OverlayProps } from './types';
import {
  useBlockchainStatus,
  usePoolStatus,
  useBestHash,
  useMiningStatus,
} from '@/hooks/queries';

const DASH = '—';

// Bitcoin's long-run average inter-block time. The ring measures progress
// toward this; past it, the block is simply "running long" (Poisson — ~37% of
// blocks take longer than the mean), shown as a full, breathing ring.
const TARGET_BLOCK_SECS = 600;

function isNum(n: number | null | undefined): n is number {
  return typeof n === 'number' && Number.isFinite(n);
}

// Big clock face: H:MM:SS once we pass an hour, else M:SS. Room-legible.
function formatClock(totalSecs: number): string {
  const s = Math.max(0, Math.floor(totalSecs));
  const hh = Math.floor(s / 3600);
  const mm = Math.floor((s % 3600) / 60);
  const ss = s % 60;
  const pad = (n: number) => String(n).padStart(2, '0');
  if (hh > 0) return `${hh}:${pad(mm)}:${pad(ss)}`;
  return `${mm}:${pad(ss)}`;
}

function formatShort(totalSecs: number | null | undefined): string {
  if (!isNum(totalSecs) || totalSecs <= 0) return DASH;
  const s = Math.floor(totalSecs);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

// Mirrors `formatDifficulty` on the public pool page / pool.html.
function formatDifficulty(d: number | null | undefined): string {
  if (!isNum(d) || d <= 0) return DASH;
  if (d < 1e3) return d.toFixed(2);
  if (d < 1e6) return `${(d / 1e3).toFixed(2)}K`;
  if (d < 1e9) return `${(d / 1e6).toFixed(2)}M`;
  if (d < 1e12) return `${(d / 1e9).toFixed(2)}G`;
  if (d < 1e15) return `${(d / 1e12).toFixed(2)}T`;
  if (d < 1e18) return `${(d / 1e15).toFixed(2)}P`;
  return `${(d / 1e18).toFixed(2)}E`;
}

// network_hashrate is reported in H/s (same value the pool page feeds to its
// hashrate formatter).
function formatHashrate(hps: number | null | undefined): string {
  if (!isNum(hps) || hps <= 0) return DASH;
  const units = ['H/s', 'KH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s', 'ZH/s'];
  let v = hps;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i += 1;
  }
  return `${v.toFixed(2)} ${units[i]}`;
}

// ─── geometry ────────────────────────────────────────────────────────────────

const VB = 320; // viewBox size
const C = VB / 2; // centre
const R = 138; // ring radius
const CIRC = 2 * Math.PI * R;

function polar(angleDeg: number, radius: number): { x: number; y: number } {
  const rad = ((angleDeg - 90) * Math.PI) / 180; // 0° at 12 o'clock, clockwise
  return { x: C + radius * Math.cos(rad), y: C + radius * Math.sin(rad) };
}

// 60 clock ticks, longer/brighter every 5 (the "hours").
const TICKS = Array.from({ length: 60 }, (_, i) => {
  const major = i % 5 === 0;
  const outer = R + 14;
  const inner = major ? R + 4 : R + 9;
  const a = polar(i * 6, outer);
  const b = polar(i * 6, inner);
  return { a, b, major };
});

// Indeterminate "waiting" arc: a short bright segment we spin.
const SPIN_DASH = `${CIRC * 0.24} ${CIRC * 0.76}`;

// Ambient keyframes. Scoped under `.bc-live` so ALL motion stops the instant the
// overlay is parked or the viewer prefers reduced motion (the class is only
// applied while animating).
const keyframes = `
.bc-live .bc-breathe { animation: bc-breathe 4.6s ease-in-out infinite; }
.bc-live .bc-headglow { animation: bc-headglow 2.6s ease-in-out infinite; }
.bc-live .bc-corepulse { animation: bc-breathe 5.4s ease-in-out infinite; }
@keyframes bc-breathe { 0%, 100% { opacity: 0.28; } 50% { opacity: 0.62; } }
@keyframes bc-headglow { 0%, 100% { opacity: 0.4; } 50% { opacity: 0.95; } }
@media (prefers-reduced-motion: reduce) {
  .bc-live .bc-breathe,
  .bc-live .bc-headglow,
  .bc-live .bc-corepulse { animation: none; }
}
`;

// ─── overlay ─────────────────────────────────────────────────────────────────

export function BlockClockOverlay({ active }: OverlayProps) {
  // Poll at a calm cadence while on-screen; back right off when parked so we
  // are not doing background work for an overlay nobody is looking at.
  const poll = active ? 5_000 : 120_000;
  const { data: chain, isLoading: chainLoading } = useBlockchainStatus({
    refetchInterval: poll,
  });
  const { data: pool } = usePoolStatus({ refetchInterval: poll });
  const { data: best } = useBestHash({ refetchInterval: poll });
  const { data: mining } = useMiningStatus({ refetchInterval: poll });

  // Current chain height, used both as a readout and to detect new blocks.
  const heightNow =
    chain?.blocks ?? mining?.block_height ?? best?.block_height ?? null;

  // The interval below reads the latest height without re-subscribing on every
  // poll; a ref keeps it fresh (updating a ref is not a state write).
  const heightRef = useRef<number | null>(heightNow);
  useEffect(() => {
    heightRef.current = heightNow;
  });

  // Respect the viewer's motion preference; gates the ambient CSS + SMIL motion.
  const [reduced, setReduced] = useState(false);
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    const sync = () => setReduced(mq.matches);
    sync();
    mq.addEventListener?.('change', sync);
    return () => mq.removeEventListener?.('change', sync);
  }, []);

  // Single 1s clock that drives every live figure AND spots new blocks. Runs
  // ONLY while active; setState happens only inside the timer callback, never
  // synchronously in the effect body. `flashUntil` is the wall-clock instant
  // the new-block pulse should fade out by.
  const [now, setNow] = useState<number>(() => Date.now());
  const [flashUntil, setFlashUntil] = useState(0);
  const prevHeightRef = useRef<number | null>(null);
  useEffect(() => {
    if (!active) return;
    const tick = () => {
      setNow(Date.now());
      const h = heightRef.current;
      const prev = prevHeightRef.current;
      if (isNum(h)) {
        // Only celebrate a genuine forward step (never the first sighting).
        if (prev !== null && h > prev) setFlashUntil(Date.now() + 1600);
        prevHeightRef.current = h;
      }
    };
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [active]);

  const flash = active && now < flashUntil;
  const animate = active && !reduced;

  // ── derived live values ────────────────────────────────────────────────────

  // Time since the last block: ticks up from the chain tip timestamp (unix
  // seconds). This is the honest L1 source — long values are real, not a bug.
  const tipTime = isNum(chain?.tip_time) ? chain!.tip_time! : null;
  const tipSecs = tipTime !== null ? Math.max(0, now / 1000 - tipTime) : null;
  const hasTip = isNum(tipSecs);

  // Ring fill = progress toward the ~10-minute average, capped at 1. Past the
  // average the block is "running long" and the ring stays full (breathing).
  const rawProgress = hasTip ? tipSecs! / TARGET_BLOCK_SECS : 0;
  const progress = hasTip ? Math.min(1, rawProgress) : 0;
  const overdue = hasTip && rawProgress >= 1;
  const remainingSecs = hasTip ? Math.max(0, TARGET_BLOCK_SECS - tipSecs!) : null;
  const overSecs = hasTip ? Math.max(0, tipSecs! - TARGET_BLOCK_SECS) : null;

  const height = isNum(heightNow) ? heightNow : null;
  const difficulty =
    chain?.difficulty ?? mining?.difficulty ?? best?.best_difficulty ?? null;
  const netHashrate = best?.network_hashrate ?? null;
  const roundId = pool?.round_id ?? best?.round_id ?? mining?.round_id ?? null;

  const waiting = !hasTip && (chainLoading || height === null);

  // ── ring geometry ──────────────────────────────────────────────────────────

  const dashOffset = CIRC * (1 - progress);
  const head = polar(progress * 360, R); // glowing tip of the arc

  const accent = 'var(--accent)';
  const arcColor = flash ? 'var(--green)' : accent;

  return (
    <div
      className={`relative flex h-full w-full flex-col items-center justify-center select-none${
        animate ? ' bc-live' : ''
      }`}
      style={{
        background: 'var(--bg)',
        color: 'var(--fg)',
        fontFamily: 'var(--font-sans)',
        overflow: 'hidden',
        transition: 'transform 1200ms cubic-bezier(0.16, 1, 0.3, 1)',
        transform: flash ? 'scale(1.015)' : 'scale(1)',
        gap: 'clamp(24px, 4vh, 48px)',
      }}
    >
      <style>{keyframes}</style>

      {/* Full-bleed golden flash on a new block. Quick rise, slow fall. */}
      <div
        aria-hidden
        style={{
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          background:
            'radial-gradient(circle at 50% 42%, var(--accent-weak), transparent 62%)',
          opacity: flash ? 1 : 0,
          transition: flash ? 'opacity 140ms ease-out' : 'opacity 1200ms ease-out',
        }}
      />

      {/* Header eyebrow */}
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 'clamp(10px, 1.1vw, 13px)',
          textTransform: 'uppercase',
          letterSpacing: '0.28em',
          color: 'var(--fainter)',
          zIndex: 1,
        }}
      >
        Block Clock
      </div>

      {/* The clock itself */}
      <div
        style={{
          position: 'relative',
          width: 'clamp(260px, 58vmin, 560px)',
          aspectRatio: '1 / 1',
          zIndex: 1,
        }}
      >
        {/* Soft ambient halo behind the ring — always present, breathing so the
            face never reads as dead even at low progress. */}
        <div
          className="bc-breathe"
          aria-hidden
          style={{
            position: 'absolute',
            inset: '4%',
            borderRadius: '50%',
            pointerEvents: 'none',
            background:
              'radial-gradient(circle, var(--accent-weak) 0%, transparent 68%)',
            opacity: animate ? undefined : 0.4,
          }}
        />

        <svg
          viewBox={`0 0 ${VB} ${VB}`}
          width="100%"
          height="100%"
          style={{ display: 'block', overflow: 'visible', position: 'relative' }}
          role="img"
          aria-label="Progress toward the next block"
        >
          <defs>
            <linearGradient id="clk-arc" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor={arcColor} stopOpacity="0.5" />
              <stop offset="100%" stopColor={arcColor} stopOpacity="1" />
            </linearGradient>
            <filter id="clk-glow" x="-40%" y="-40%" width="180%" height="180%">
              <feGaussianBlur stdDeviation={flash ? 7 : 4} result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <linearGradient id="clk-sweep" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={accent} stopOpacity="0.55" />
              <stop offset="100%" stopColor={accent} stopOpacity="0" />
            </linearGradient>
          </defs>

          {/* Clock tick marks */}
          <g stroke="var(--rule-strong)" strokeLinecap="round">
            {TICKS.map((t, i) => (
              <line
                key={i}
                x1={t.a.x}
                y1={t.a.y}
                x2={t.b.x}
                y2={t.b.y}
                strokeWidth={t.major ? 2.4 : 1}
                opacity={t.major ? 0.9 : 0.5}
              />
            ))}
          </g>

          {/* Track */}
          <circle cx={C} cy={C} r={R} fill="none" stroke="var(--rule)" strokeWidth={10} />

          {/* Slow radar sweep hand — ambient "ticking" life, independent of
              progress. SMIL rotation (CSP-safe, no CSS) and only mounted while
              animating so it fully stops off-screen / under reduced motion. */}
          {animate && (
            <g opacity={0.5}>
              <line
                x1={C}
                y1={C}
                x2={C}
                y2={C - R + 4}
                stroke="url(#clk-sweep)"
                strokeWidth={3}
                strokeLinecap="round"
              />
              <animateTransform
                attributeName="transform"
                attributeType="XML"
                type="rotate"
                from={`0 ${C} ${C}`}
                to={`360 ${C} ${C}`}
                dur="18s"
                repeatCount="indefinite"
              />
            </g>
          )}

          {hasTip ? (
            <>
              {/* Progress arc — starts at 12 o'clock, sweeps clockwise. Fills
                  with an accent glow; sweeps back to empty on a new block. */}
              <g transform={`rotate(-90 ${C} ${C})`}>
                <circle
                  cx={C}
                  cy={C}
                  r={R}
                  fill="none"
                  stroke="url(#clk-arc)"
                  strokeWidth={11}
                  strokeLinecap="round"
                  strokeDasharray={CIRC}
                  strokeDashoffset={dashOffset}
                  filter="url(#clk-glow)"
                  style={{ transition: 'stroke-dashoffset 950ms linear' }}
                />
              </g>

              {/* Glowing leading edge of the arc (the "hand"). */}
              {progress > 0.004 && (
                <g>
                  <circle
                    className="bc-headglow"
                    cx={head.x}
                    cy={head.y}
                    r={flash ? 15 : 12}
                    fill={arcColor}
                    filter="url(#clk-glow)"
                    opacity={animate ? undefined : 0.6}
                    style={{ transition: 'cx 950ms linear, cy 950ms linear' }}
                  />
                  <circle
                    cx={head.x}
                    cy={head.y}
                    r={flash ? 8 : 6}
                    fill={arcColor}
                    filter="url(#clk-glow)"
                    style={{ transition: 'cx 950ms linear, cy 950ms linear, r 300ms ease' }}
                  />
                </g>
              )}
            </>
          ) : (
            // No tip yet — an indeterminate, breathing spinner. Alive, never a
            // dead grey circle.
            <g transform={`rotate(-90 ${C} ${C})`}>
              <circle
                className="bc-breathe"
                cx={C}
                cy={C}
                r={R}
                fill="none"
                stroke={accent}
                strokeWidth={11}
                strokeLinecap="round"
                strokeDasharray={SPIN_DASH}
                filter="url(#clk-glow)"
                opacity={animate ? undefined : 0.5}
              />
              {animate && (
                <animateTransform
                  attributeName="transform"
                  attributeType="XML"
                  type="rotate"
                  from={`-90 ${C} ${C}`}
                  to={`270 ${C} ${C}`}
                  dur="2.8s"
                  repeatCount="indefinite"
                />
              )}
            </g>
          )}
        </svg>

        {/* Centre readout, overlaid on the ring */}
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            textAlign: 'center',
            padding: '18%',
          }}
        >
          {/* Soft core glow behind the number. */}
          <div
            className="bc-corepulse"
            aria-hidden
            style={{
              position: 'absolute',
              width: '62%',
              aspectRatio: '1 / 1',
              borderRadius: '50%',
              pointerEvents: 'none',
              background:
                'radial-gradient(circle, var(--accent-weak) 0%, transparent 70%)',
              opacity: animate ? undefined : 0.35,
            }}
          />
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(9px, 1vw, 12px)',
              textTransform: 'uppercase',
              letterSpacing: '0.24em',
              color: 'var(--dim)',
              marginBottom: 'clamp(4px, 1vh, 10px)',
              zIndex: 1,
            }}
          >
            since last block
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontVariantNumeric: 'tabular-nums',
              fontWeight: 300,
              lineHeight: 1,
              fontSize: 'clamp(38px, 9vmin, 96px)',
              color: flash ? 'var(--green)' : 'var(--fg)',
              transition: 'color 600ms ease',
              zIndex: 1,
            }}
          >
            {isNum(tipSecs) ? formatClock(tipSecs) : waiting ? '· · ·' : DASH}
          </div>
          <div
            style={{
              marginTop: 'clamp(6px, 1.4vh, 14px)',
              fontFamily: 'var(--font-sans)',
              fontSize: 'clamp(11px, 1.3vw, 15px)',
              color: 'var(--dim)',
              zIndex: 1,
              maxWidth: '92%',
            }}
          >
            {hasTip ? (
              overdue ? (
                <>
                  <span style={{ color: 'var(--accent)', fontWeight: 600 }}>
                    running long
                  </span>{' '}
                  · +{formatShort(overSecs)} over the ~10-min average
                </>
              ) : (
                <>
                  <span style={{ color: 'var(--accent)', fontWeight: 600 }}>
                    {Math.round(progress * 100)}%
                  </span>{' '}
                  of the ~10-min average · ~{formatShort(remainingSecs)} to go
                </>
              )
            ) : (
              <span style={{ color: 'var(--fainter)' }}>
                {waiting ? 'connecting to node…' : 'waiting for chain tip…'}
              </span>
            )}
          </div>
          {isNum(roundId) && (
            <div
              style={{
                marginTop: 'clamp(2px, 0.6vh, 6px)',
                fontFamily: 'var(--font-mono)',
                fontSize: 'clamp(9px, 1vw, 11px)',
                letterSpacing: '0.12em',
                color: 'var(--fainter)',
                zIndex: 1,
              }}
            >
              ROUND #{roundId}
            </div>
          )}
        </div>
      </div>

      {/* Supporting readouts */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          justifyContent: 'center',
          alignItems: 'flex-start',
          gap: 'clamp(28px, 7vw, 88px)',
          zIndex: 1,
        }}
      >
        <Readout
          label="Block height"
          value={isNum(height) ? height.toLocaleString() : DASH}
        />
        <Readout label="Difficulty" value={formatDifficulty(difficulty)} />
        <Readout label="Network hashrate" value={formatHashrate(netHashrate)} />
      </div>
    </div>
  );
}

function Readout({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ textAlign: 'center', minWidth: 96 }}>
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontVariantNumeric: 'tabular-nums',
          fontWeight: 500,
          fontSize: 'clamp(20px, 3.4vmin, 34px)',
          color: 'var(--fg)',
          lineHeight: 1.1,
        }}
      >
        {value}
      </div>
      <div
        style={{
          marginTop: 6,
          fontFamily: 'var(--font-mono)',
          fontSize: 'clamp(9px, 1vw, 12px)',
          textTransform: 'uppercase',
          letterSpacing: '0.18em',
          color: 'var(--fainter)',
        }}
      >
        {label}
      </div>
    </div>
  );
}
