/**
 * Overlay: Earnings Ticker
 *
 * CONCEPT — shares and payouts accumulating over time: an ambient ticker of the
 * capability shares building up and recent payouts streaming past. Money and
 * work, visualised as a calm, ever-rising flow.
 *
 * IMPLEMENTER NOTES:
 *  - Keep the `export function EarningsTickerOverlay({ active }: OverlayProps)`
 *    signature exactly. Replace only the body of this file.
 *  - Honour `active`: run your rAF / animation loop and any polling ONLY while
 *    `active === true`; cancel the rAF and stop polling when it flips to false.
 *  - CSP-safe only: draw with <canvas> or inline SVG. No external assets.
 *
 * DATA (all same-origin, reused hooks):
 *  - useShares()            → SharesInfo: the 5-4-3-2-1 capability breakdown,
 *                             total/max shares, uptime gatekeeper.
 *  - useRewardsCurrent()    → RewardsCurrent: pending + lifetime earned (sats).
 *  - useNodePayoutHistory() → NodePayoutEntry[]: recent payouts to this node.
 *
 * RENDER: a calm canvas of gently rising motes behind three honest surfaces —
 * a running "shares earning" figure, the 5-4-3-2-1 capability chips (what is
 * qualified = what you earn), and a scrolling recent-payouts ticker. Figures
 * count up when they increase; zero states read as intentional, not broken.
 */
'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import type { CSSProperties } from 'react';
import type { OverlayProps } from './types';
import { useShares } from '@/hooks/queries/useNodeQueries';
import { useRewardsCurrent, useNodePayoutHistory } from '@/hooks/queries/useRewardsQueries';
import type { SharesInfo, NodePayoutEntry } from '@/types/api';

// ---------------------------------------------------------------------------
// The 5-4-3-2-1 capability model. Each tier is a boolean on SharesInfo; a
// qualified tier earns its bonus (5+4+3+2+1 = 15 max).
// ---------------------------------------------------------------------------
const TIERS = [
  { key: 'archive_mode', label: 'Archive', bonus: 5 },
  { key: 'ghost_pay', label: 'Ghost Pay', bonus: 4 },
  { key: 'public_mining', label: 'Public Mining', bonus: 3 },
  { key: 'reaper', label: 'Reaper', bonus: 2 },
  { key: 'elder', label: 'Elder', bonus: 1 },
] as const;

function fmtInt(n: number): string {
  return Math.max(0, Math.round(n)).toLocaleString();
}

function fmtBtc(sats: number): string {
  return (Math.max(0, sats) / 100_000_000).toFixed(8);
}

function timeAgo(ts: number): string {
  if (!ts) return '';
  const diff = Math.floor(Date.now() / 1000) - ts;
  if (diff < 0) return 'just now';
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function payoutAmount(p: NodePayoutEntry): number {
  return p.amount_satoshis ?? p.balance_sats ?? 0;
}

function payoutTime(p: NodePayoutEntry): number {
  return p.timestamp ?? p.updated_at ?? p.created_at ?? 0;
}

// ---------------------------------------------------------------------------
// useCountUp — eases a displayed number toward its target, so figures visibly
// accumulate when they grow (and on first load, from 0). Snaps + parks its rAF
// whenever the overlay is inactive.
// ---------------------------------------------------------------------------
function useCountUp(target: number, active: boolean, duration = 1100): number {
  const [value, setValue] = useState(0);
  const rafRef = useRef<number | null>(null);
  const prevTargetRef = useRef(0);

  useEffect(() => {
    const cancel = () => {
      if (rafRef.current !== null) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };

    if (!active) {
      // Off-screen: no animation. Snap to the true value (on a frame, not
      // synchronously in the effect body) and remember it so we resume from
      // there — not from a stale mid-tween — when we come back.
      cancel();
      prevTargetRef.current = target;
      rafRef.current = requestAnimationFrame(() => setValue(target));
      return cancel;
    }

    const from = prevTargetRef.current;
    prevTargetRef.current = target;

    let start = 0;
    const step = (ts: number) => {
      if (start === 0) start = ts;
      const t = Math.min(1, (ts - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      setValue(from + (target - from) * eased);
      if (t < 1) {
        rafRef.current = requestAnimationFrame(step);
      } else {
        rafRef.current = null;
        setValue(target);
      }
    };
    rafRef.current = requestAnimationFrame(step);
    return cancel;
  }, [target, active, duration]);

  return value;
}

// ---------------------------------------------------------------------------
// Reads a CSS custom property from :root — lets the canvas stay theme-aware
// without hard-coding colours.
// ---------------------------------------------------------------------------
function readVar(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback;
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v || fallback;
}

interface Mote {
  x: number;
  y: number;
  vy: number;
  drift: number;
  phase: number;
  r: number;
  a: number;
}

// ---------------------------------------------------------------------------
// Ambient rising motes — the "accumulation" texture. Density scales with the
// number of qualified shares, so a fresh node stays calm (a few slow motes)
// while a fully-qualified node shimmers. Pauses entirely when inactive.
// ---------------------------------------------------------------------------
function RisingMotes({ active, intensity }: { active: boolean; intensity: number }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const intensityRef = useRef(intensity);

  // Keep the latest intensity in a ref so the rAF loop can read it each frame
  // without restarting the animation whenever qualified-share count changes.
  useEffect(() => {
    intensityRef.current = intensity;
  }, [intensity]);

  useEffect(() => {
    if (!active) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let accent = readVar('--accent', '#f7931a');
    const themeObserver = new MutationObserver(() => {
      accent = readVar('--accent', '#f7931a');
    });
    themeObserver.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme', 'class'],
    });

    let width = 0;
    let height = 0;
    let dpr = 1;
    const motes: Mote[] = [];

    const spawn = (atBottom: boolean): Mote => ({
      x: Math.random() * width,
      y: atBottom ? height + Math.random() * 40 : Math.random() * height,
      vy: 8 + Math.random() * 22, // px/sec upward
      drift: 0.4 + Math.random() * 1.2,
      phase: Math.random() * Math.PI * 2,
      r: 0.8 + Math.random() * 2.2,
      a: 0.12 + Math.random() * 0.4,
    });

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width;
      height = rect.height;
      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    // Target mote count: a calm floor of ~16, rising with qualified shares.
    const targetCount = () => 16 + Math.round(Math.min(15, intensityRef.current) * 4.4);

    let raf = 0;
    let last = performance.now();
    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;

      const want = targetCount();
      if (motes.length < want) motes.push(spawn(true));
      else if (motes.length > want) motes.pop();

      ctx.clearRect(0, 0, width, height);
      for (const m of motes) {
        m.y -= m.vy * dt;
        m.phase += dt * 0.8;
        m.x += Math.sin(m.phase) * m.drift * dt * 20;
        if (m.y < -6) Object.assign(m, spawn(true));

        // Fade in from the bottom, fade out toward the top.
        const edge = Math.min(m.y / (height * 0.25), (height - m.y) / (height * 0.35), 1);
        const alpha = m.a * Math.max(0, edge);
        ctx.beginPath();
        ctx.arc(m.x, m.y, m.r, 0, Math.PI * 2);
        ctx.fillStyle = accent;
        ctx.globalAlpha = alpha;
        ctx.fill();
      }
      ctx.globalAlpha = 1;
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      themeObserver.disconnect();
    };
  }, [active]);

  return (
    <canvas
      ref={canvasRef}
      aria-hidden
      style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}
    />
  );
}

// ---------------------------------------------------------------------------
// Recent-payouts ticker — a seamless horizontal marquee. The item strip is
// rendered twice; the rAF slides it left and wraps at one strip-width. Pauses
// when inactive or when there is nothing to show.
// ---------------------------------------------------------------------------
function PayoutTicker({ active, payouts }: { active: boolean; payouts: NodePayoutEntry[] }) {
  const trackRef = useRef<HTMLDivElement | null>(null);
  const setRef = useRef<HTMLDivElement | null>(null);
  const offsetRef = useRef(0);

  const hasPayouts = payouts.length > 0;

  useEffect(() => {
    if (!active || !hasPayouts) return;
    const track = trackRef.current;
    const set = setRef.current;
    if (!track || !set) return;

    let raf = 0;
    let last = performance.now();
    const speed = 42; // px/sec
    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      const setWidth = set.offsetWidth || 1;
      offsetRef.current -= speed * dt;
      if (offsetRef.current <= -setWidth) offsetRef.current += setWidth;
      track.style.transform = `translate3d(${offsetRef.current}px,0,0)`;
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf);
  }, [active, hasPayouts, payouts]);

  if (!hasPayouts) {
    return (
      <div
        style={{
          textAlign: 'center',
          fontFamily: 'var(--font-mono)',
          fontSize: 'clamp(11px, 1.4vw, 13px)',
          letterSpacing: '0.04em',
          color: 'var(--fainter)',
        }}
      >
        No payouts yet — you earn as your capabilities qualify.
      </div>
    );
  }

  const chip = (p: NodePayoutEntry, key: string) => {
    const sats = payoutAmount(p);
    return (
      <div
        key={key}
        style={{
          display: 'inline-flex',
          alignItems: 'baseline',
          gap: 8,
          padding: '7px 14px',
          borderRadius: 9999,
          border: '1px solid var(--rule)',
          background: 'var(--surface)',
          whiteSpace: 'nowrap',
          flex: '0 0 auto',
        }}
      >
        <span
          style={{
            width: 6,
            height: 6,
            borderRadius: 9999,
            background: 'var(--accent)',
            alignSelf: 'center',
            boxShadow: '0 0 10px 1px var(--accent-weak)',
          }}
        />
        <span
          style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 13,
            fontWeight: 600,
            color: 'var(--fg)',
          }}
        >
          +{fmtInt(sats)} sats
        </span>
        <span style={{ fontSize: 11, color: 'var(--dim)', textTransform: 'capitalize' }}>
          {(p.payout_type ?? 'reward').replace(/_/g, ' ')}
        </span>
        {payoutTime(p) > 0 && (
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--fainter)' }}>
            {timeAgo(payoutTime(p))}
          </span>
        )}
      </div>
    );
  };

  const strip = (bindRef: boolean, keyBase: string) => (
    <div
      ref={bindRef ? setRef : undefined}
      aria-hidden={bindRef ? undefined : true}
      style={{ display: 'inline-flex', gap: 12, paddingRight: 12, flex: '0 0 auto' }}
    >
      {payouts.map((p, i) => chip(p, `${keyBase}-${i}`))}
    </div>
  );

  return (
    <div
      style={{
        overflow: 'hidden',
        width: '100%',
        maskImage: 'linear-gradient(90deg, transparent, #000 6%, #000 94%, transparent)',
        WebkitMaskImage: 'linear-gradient(90deg, transparent, #000 6%, #000 94%, transparent)',
      }}
    >
      <div ref={trackRef} style={{ display: 'inline-flex', willChange: 'transform' }}>
        {strip(true, 'a')}
        {strip(false, 'b')}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
export function EarningsTickerOverlay({ active }: OverlayProps) {
  // Reused, same-origin data hooks (react-query, shared cache).
  const { data: sharesData } = useShares();
  const { data: rewards } = useRewardsCurrent();
  const { data: payoutData } = useNodePayoutHistory('7d');

  const shares: SharesInfo | undefined = sharesData;
  const total = shares?.total ?? 0;
  const maxShares = shares?.max_shares ?? 15;
  const uptimeQualified = shares?.uptime_qualified ?? true;
  const uptimePercent = shares?.uptime_percent;

  const pendingTarget = rewards?.pending_rewards_sats ?? 0;
  const earnedTarget = rewards?.total_earned_sats ?? 0;

  const payouts = useMemo(() => {
    // Defensive: only ever operate on an array. The node-history endpoint has
    // been seen to hand back a `{ history, total }` wrapper rather than a bare
    // array; guarding here keeps a shape surprise from blanking the overlay.
    const list = Array.isArray(payoutData) ? payoutData : [];
    return list
      .slice()
      .sort((a, b) => payoutTime(b) - payoutTime(a))
      .slice(0, 14);
  }, [payoutData]);

  const pending = useCountUp(pendingTarget, active);
  const earned = useCountUp(earnedTarget, active);
  const sharesUp = useCountUp(total, active, 900);

  const activeTierCount = uptimeQualified
    ? TIERS.reduce((n, t) => n + (shares?.[t.key] ? 1 : 0), 0)
    : 0;

  const labelStyle: CSSProperties = {
    fontFamily: 'var(--font-mono)',
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: '0.22em',
    color: 'var(--fainter)',
  };

  return (
    <div
      className="relative h-full w-full select-none overflow-hidden"
      style={{ background: 'var(--bg)', color: 'var(--fg)' }}
    >
      <RisingMotes active={active} intensity={activeTierCount === 0 ? total : activeTierCount} />

      <div
        className="relative flex h-full w-full flex-col items-center"
        style={{ padding: '6vh 5vw 128px', gap: 'clamp(24px, 4vh, 56px)' }}
      >
        <div style={{ ...labelStyle, marginTop: 'auto' }}>Earnings</div>

        {/* Headline figures: shares earning + pending rewards. */}
        <div
          className="flex w-full flex-wrap items-stretch justify-center"
          style={{ gap: 'clamp(24px, 6vw, 96px)' }}
        >
          {/* Shares earning */}
          <div className="flex flex-col items-center" style={{ gap: 6 }}>
            <div style={labelStyle}>Shares Earning</div>
            <div
              style={{
                fontFamily: 'var(--font-sans)',
                fontWeight: 300,
                fontSize: 'clamp(56px, 11vw, 128px)',
                lineHeight: 1,
                letterSpacing: '-0.02em',
                display: 'flex',
                alignItems: 'baseline',
                gap: 4,
              }}
            >
              <span style={{ color: total > 0 ? 'var(--accent)' : 'var(--dim)' }}>
                {Math.round(sharesUp)}
              </span>
              <span style={{ color: 'var(--fainter)', fontSize: '0.4em' }}>/ {maxShares}</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--dim)' }}>
              {uptimeQualified
                ? `${activeTierCount} of ${TIERS.length} capabilities qualified`
                : 'Earning suspended — uptime below 95%'}
            </div>
          </div>

          {/* Pending rewards */}
          <div className="flex flex-col items-center" style={{ gap: 6 }}>
            <div style={labelStyle}>Pending Rewards</div>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontWeight: 500,
                fontSize: 'clamp(40px, 8vw, 92px)',
                lineHeight: 1,
                letterSpacing: '-0.01em',
                color: 'var(--fg)',
                display: 'flex',
                alignItems: 'baseline',
                gap: 8,
              }}
            >
              <span>{fmtInt(pending)}</span>
              <span
                style={{ color: 'var(--fainter)', fontSize: '0.32em', fontFamily: 'var(--font-mono)' }}
              >
                sats
              </span>
            </div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--dim)' }}>
              {fmtBtc(pending)} BTC · lifetime {fmtBtc(earned)}
            </div>
          </div>
        </div>

        {/* 5-4-3-2-1 capability chips. */}
        <div
          className="flex w-full flex-wrap items-center justify-center"
          style={{ gap: 'clamp(10px, 1.6vw, 18px)', maxWidth: 960 }}
        >
          {TIERS.map((t) => {
            const on = uptimeQualified && !!shares?.[t.key];
            return (
              <div
                key={t.key}
                title={`${t.label} · +${t.bonus}`}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  padding: '10px 16px',
                  borderRadius: 12,
                  border: `1px solid ${on ? 'var(--accent)' : 'var(--rule)'}`,
                  background: on ? 'var(--accent-weak)' : 'var(--surface)',
                  boxShadow: on ? '0 0 22px -6px var(--accent)' : 'none',
                  transition: 'border-color 0.4s ease, background 0.4s ease, box-shadow 0.4s ease',
                  opacity: on ? 1 : 0.62,
                }}
              >
                <span
                  className={active && on ? 'animate-pulse' : ''}
                  style={{
                    width: 9,
                    height: 9,
                    borderRadius: 9999,
                    background: on ? 'var(--accent)' : 'var(--rule-strong)',
                    boxShadow: on ? '0 0 12px 2px var(--accent-weak)' : 'none',
                  }}
                />
                <span
                  style={{
                    fontFamily: 'var(--font-sans)',
                    fontSize: 14,
                    fontWeight: 500,
                    color: on ? 'var(--fg)' : 'var(--dim)',
                  }}
                >
                  {t.label}
                  {t.key === 'elder' && shares?.elder && shares?.elder_slot != null && (
                    <span style={{ color: 'var(--fainter)', marginLeft: 4 }}>#{shares.elder_slot}</span>
                  )}
                </span>
                <span
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: 13,
                    fontWeight: 600,
                    color: on ? 'var(--accent)' : 'var(--fainter)',
                  }}
                >
                  +{t.bonus}
                </span>
              </div>
            );
          })}
        </div>

        {!uptimeQualified && uptimePercent != null && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--red)' }}>
            Uptime {uptimePercent.toFixed(1)}% · shares re-qualify at 95%
          </div>
        )}

        {/* Recent-payouts ticker. */}
        <div className="w-full" style={{ marginTop: 'auto', maxWidth: 1160 }}>
          <div style={{ ...labelStyle, textAlign: 'center', marginBottom: 12 }}>Recent Payouts</div>
          <PayoutTicker active={active} payouts={payouts} />
        </div>
      </div>
    </div>
  );
}
