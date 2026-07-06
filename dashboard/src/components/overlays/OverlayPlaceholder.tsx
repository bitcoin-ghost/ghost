/**
 * Shared placeholder body for not-yet-implemented overlays.
 *
 * Each of the six overlay files renders this until a follow-up agent replaces
 * that file's body with the real visualisation. When you implement an overlay,
 * simply stop importing this and render your own <canvas>/SVG instead — this
 * component and the six placeholders are the only things that reference it.
 *
 * Theme-aware (CSS vars) and CSP-safe (no external assets).
 */
'use client';

import type { OverlayProps } from './types';

interface OverlayPlaceholderProps extends OverlayProps {
  title: string;
}

export function OverlayPlaceholder({ title, active }: OverlayPlaceholderProps) {
  return (
    <div
      className="flex h-full w-full flex-col items-center justify-center gap-5 select-none"
      style={{ background: 'var(--bg)', color: 'var(--fg)' }}
    >
      <span
        // The dot only pulses while this overlay is the active one — a small,
        // literal demonstration of the `active` contract every overlay honours.
        className={active ? 'animate-pulse' : ''}
        style={{
          width: 12,
          height: 12,
          borderRadius: '9999px',
          background: 'var(--accent)',
          boxShadow: '0 0 24px 4px var(--accent-weak)',
        }}
      />
      <div
        style={{
          fontFamily: 'var(--font-sans)',
          fontSize: 'clamp(28px, 5vw, 56px)',
          fontWeight: 300,
          letterSpacing: '0.01em',
        }}
      >
        {title}
      </div>
      <div
        style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '12px',
          textTransform: 'uppercase',
          letterSpacing: '0.22em',
          color: 'var(--fainter)',
        }}
      >
        coming soon
      </div>
    </div>
  );
}
