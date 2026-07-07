'use client';

/**
 * /home — the node's "rest screen" / Home dashboard.
 *
 * Renders the Node Vitals scene full-viewport with no chrome: the 5-4-3-2-1
 * capability ring + ticking block height at the centre, a row of watchdog
 * service LEDs, vital stat tiles, CPU/memory/disk resource gauges and the
 * chain-sync bar — all over the ambient depth field. There is a single scene
 * (no carousel), so it is mounted permanently with `active` fixed on, which
 * keeps its rAF animation loop and data polling running.
 */

import { NodeVitalsOverlay } from '@/components/overlays/NodeVitalsOverlay';

export default function HomePage() {
  return (
    <div
      className="relative overflow-hidden -mt-14 -mx-4 -mb-4 md:-m-6 h-[100dvh]"
      style={{ background: 'var(--bg)' }}
    >
      <div className="absolute inset-0">
        <NodeVitalsOverlay active />
      </div>
    </div>
  );
}
