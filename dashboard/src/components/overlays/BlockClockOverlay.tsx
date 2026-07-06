/**
 * Overlay: Block Clock
 *
 * CONCEPT — a giant, ambient next-block countdown: estimated time to the next
 * block, round progress, current difficulty, and network hashrate. The
 * centrepiece is the clock itself; everything else is quiet supporting detail.
 *
 * A large circular ring fills with the current round's progress (elapsed vs
 * the node's estimated time to the next block). At its centre a big, room-
 * legible counter ticks up the time since the last block. Block height,
 * network difficulty and network hashrate sit underneath as calm readouts.
 * When a new block lands (the height increments between polls) the whole clock
 * gives a satisfying golden pulse and the ring resets to the fresh round.
 *
 * IMPLEMENTER NOTES:
 *  - Keep the `export function BlockClockOverlay({ active }: OverlayProps)`
 *    signature exactly. Replace only the body of this file.
 *  - Honour `active`: the 1s tick that drives the counter/ring and the pulse
 *    timeout run ONLY while `active === true`; both are torn down on inactive
 *    and on unmount. Polling backs right off while off-screen.
 *  - CSP-safe only: inline SVG, no external assets, no injected stylesheets.
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

// ─── overlay ─────────────────────────────────────────────────────────────────

export function BlockClockOverlay({ active }: OverlayProps) {
  // Poll at a calm cadence while on-screen; back right off when parked so we
  // are not doing background work for an overlay nobody is looking at.
  const poll = active ? 5_000 : 120_000;
  const { data: chain, isLoading: chainLoading } = useBlockchainStatus({
    refetchInterval: poll,
  });
  const { data: pool, dataUpdatedAt: poolAt } = usePoolStatus({ refetchInterval: poll });
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
        if (prev !== null && h > prev) setFlashUntil(Date.now() + 1500);
        prevHeightRef.current = h;
      }
    };
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, [active]);

  const flash = active && now < flashUntil;

  // ── derived live values ────────────────────────────────────────────────────

  // Time since the last block: ticks up from the chain tip timestamp.
  const tipSecs = isNum(chain?.tip_time)
    ? Math.max(0, now / 1000 - chain!.tip_time!)
    : null;

  // Ring fill = round progress (elapsed vs estimated time-to-block), advanced
  // smoothly between polls off the query's own update time.
  const roundBase = pool?.current_round_duration_secs ?? null;
  const eta = pool?.estimated_time_to_block_secs ?? null;
  const hasRound = isNum(roundBase) && isNum(eta) && eta > 0;
  const sincePoll = poolAt ? Math.max(0, (now - poolAt) / 1000) : 0;
  const liveElapsed = isNum(roundBase) ? roundBase + sincePoll : null;
  const liveEta = isNum(eta) ? Math.max(1, eta - sincePoll) : null;
  const remaining = isNum(eta) ? Math.max(0, eta - sincePoll) : null;
  const progress =
    hasRound && isNum(liveElapsed) && isNum(liveEta)
      ? Math.min(0.9999, liveElapsed / (liveElapsed + liveEta))
      : 0;

  const height = isNum(heightNow) ? heightNow : null;
  const difficulty =
    chain?.difficulty ?? mining?.difficulty ?? best?.best_difficulty ?? null;
  const netHashrate = best?.network_hashrate ?? null;
  const roundId = pool?.round_id ?? best?.round_id ?? mining?.round_id ?? null;

  const waiting = chainLoading && !isNum(tipSecs) && height === null;

  // ── ring geometry ──────────────────────────────────────────────────────────

  const dashOffset = CIRC * (1 - progress);
  const head = polar(progress * 360, R); // glowing tip of the arc

  const accent = 'var(--accent)';
  const arcColor = flash ? 'var(--green)' : accent;

  return (
    <div
      className="relative flex h-full w-full flex-col items-center justify-center select-none"
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
        <svg
          viewBox={`0 0 ${VB} ${VB}`}
          width="100%"
          height="100%"
          style={{ display: 'block', overflow: 'visible' }}
          role="img"
          aria-label="Round progress toward the next block"
        >
          <defs>
            <linearGradient id="clk-arc" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stopColor={arcColor} stopOpacity="0.55" />
              <stop offset="100%" stopColor={arcColor} stopOpacity="1" />
            </linearGradient>
            <filter id="clk-glow" x="-40%" y="-40%" width="180%" height="180%">
              <feGaussianBlur stdDeviation={flash ? 7 : 4} result="b" />
              <feMerge>
                <feMergeNode in="b" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
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

          {/* Progress arc — starts at 12 o'clock, sweeps clockwise */}
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

          {/* Glowing head of the arc (the "hand") */}
          {progress > 0.002 && (
            <circle
              cx={head.x}
              cy={head.y}
              r={flash ? 9 : 6.5}
              fill={arcColor}
              filter="url(#clk-glow)"
              style={{ transition: 'r 300ms ease' }}
            />
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
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 'clamp(9px, 1vw, 12px)',
              textTransform: 'uppercase',
              letterSpacing: '0.24em',
              color: 'var(--dim)',
              marginBottom: 'clamp(4px, 1vh, 10px)',
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
            }}
          >
            {hasRound ? (
              <>
                <span style={{ color: 'var(--accent)', fontWeight: 600 }}>
                  {Math.round(progress * 100)}%
                </span>{' '}
                of round · ~{formatShort(remaining)} to block
              </>
            ) : (
              <span style={{ color: 'var(--fainter)' }}>
                {waiting ? 'connecting to node…' : 'no block-time estimate yet'}
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
