'use client';

/**
 * /overlays — full-bleed "rest screen" carousel.
 *
 * Shows ONE overlay at a time, full viewport, minimal chrome. Only the visible
 * overlay is mounted, so only it animates; switching unmounts the old one
 * (its rAF/cleanup runs) and mounts the next with `active`. The overlay set and
 * order come from `@/components/overlays/registry`.
 *
 * Switching:
 *   - bottom-centre ‹ › arrows (wrapping)
 *   - dot indicators (jump straight to one)
 *   - keyboard Left / Right
 *   - idle auto-advance every ~30s, paused while the user is interacting/hovering
 *     (any mouse move / pointer / key resets a 30s idle timer; auto-advance only
 *     resumes once the screen has been idle again).
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { OVERLAYS } from '@/components/overlays/registry';

const IDLE_MS = 30_000;

export default function OverlaysPage() {
  const count = OVERLAYS.length;
  const [index, setIndex] = useState(0);
  const [paused, setPaused] = useState(false);
  const resumeRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const go = useCallback(
    (dir: number) => setIndex((i) => (i + dir + count) % count),
    [count],
  );
  const goto = useCallback(
    (i: number) => setIndex(((i % count) + count) % count),
    [count],
  );

  // Mark the screen "active" (user interacting) and schedule a return to idle.
  const bump = useCallback(() => {
    setPaused(true);
    if (resumeRef.current) clearTimeout(resumeRef.current);
    resumeRef.current = setTimeout(() => setPaused(false), IDLE_MS);
  }, []);

  useEffect(() => {
    return () => {
      if (resumeRef.current) clearTimeout(resumeRef.current);
    };
  }, []);

  // Keyboard prev/next.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
      if (e.key === 'ArrowLeft') {
        e.preventDefault();
        go(-1);
        bump();
      } else if (e.key === 'ArrowRight') {
        e.preventDefault();
        go(1);
        bump();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [go, bump]);

  // Idle auto-advance: only while not paused. Resets whenever the index changes
  // (so a manual switch restarts the clock) or when we return from paused.
  useEffect(() => {
    if (paused) return;
    const t = setTimeout(() => go(1), IDLE_MS);
    return () => clearTimeout(t);
  }, [index, paused, go]);

  const current = OVERLAYS[index];
  const Current = current.Component;

  const navButton: React.CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: 34,
    height: 34,
    borderRadius: 8,
    border: '1px solid var(--rule)',
    background: 'var(--bg)',
    color: 'var(--dim)',
    cursor: 'pointer',
    pointerEvents: 'auto',
  };

  return (
    <div
      className="relative overflow-hidden -mt-14 -mx-4 -mb-4 md:-m-6 h-[100dvh]"
      style={{ background: 'var(--bg)' }}
      onMouseMove={bump}
      onPointerDown={bump}
    >
      {/* Only the current overlay is mounted → only it animates. */}
      <div className="absolute inset-0">
        <Current active />
      </div>

      {/* Bottom-centre chrome: dots + arrows + label. */}
      <div
        className="absolute bottom-0 left-0 right-0 flex flex-col items-center gap-3"
        style={{ padding: '20px 16px', pointerEvents: 'none' }}
      >
        {/* dot indicators */}
        <div className="flex items-center gap-2" style={{ pointerEvents: 'auto' }}>
          {OVERLAYS.map((o, i) => {
            const isActive = i === index;
            return (
              <button
                key={o.id}
                onClick={() => {
                  goto(i);
                  bump();
                }}
                aria-label={`Show ${o.title}`}
                aria-current={isActive ? 'true' : undefined}
                style={{
                  width: isActive ? 20 : 7,
                  height: 7,
                  borderRadius: 9999,
                  border: 'none',
                  padding: 0,
                  cursor: 'pointer',
                  background: isActive ? 'var(--accent)' : 'var(--rule-strong)',
                  transition: 'width 0.2s ease, background 0.2s ease',
                }}
              />
            );
          })}
        </div>

        {/* arrows + current title */}
        <div className="flex items-center gap-4" style={{ pointerEvents: 'none' }}>
          <button
            onClick={() => {
              go(-1);
              bump();
            }}
            aria-label="Previous overlay"
            style={navButton}
            onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--fg)')}
            onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--dim)')}
          >
            <ChevronLeft size={18} strokeWidth={1.75} />
          </button>

          <span
            style={{
              minWidth: 180,
              textAlign: 'center',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              textTransform: 'uppercase',
              letterSpacing: '0.16em',
              color: 'var(--dim)',
            }}
          >
            {current.title}
            <span style={{ color: 'var(--fainter)' }}>
              {'  ·  '}
              {index + 1}/{count}
            </span>
          </span>

          <button
            onClick={() => {
              go(1);
              bump();
            }}
            aria-label="Next overlay"
            style={navButton}
            onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--fg)')}
            onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--dim)')}
          >
            <ChevronRight size={18} strokeWidth={1.75} />
          </button>
        </div>
      </div>
    </div>
  );
}
