'use client';

/**
 * /overlays — full-bleed "rest screen".
 *
 * Renders the single Node Vitals overlay full viewport with no chrome. There is
 * only one overlay, so there is no carousel: no arrows, dots, counter label,
 * keyboard switching, or auto-advance. The overlay set still comes from
 * `@/components/overlays/registry`, so adding more overlays later is a matter of
 * reintroducing switching UI here.
 */

import { OVERLAYS } from '@/components/overlays/registry';

export default function OverlaysPage() {
  const only = OVERLAYS[0];
  const Overlay = only.Component;

  return (
    <div
      className="relative overflow-hidden -mt-14 -mx-4 -mb-4 md:-m-6 h-[100dvh]"
      style={{ background: 'var(--bg)' }}
    >
      <div className="absolute inset-0">
        <Overlay active />
      </div>
    </div>
  );
}
