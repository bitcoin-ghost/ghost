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

import type { OverlayProps } from './types';
import { OverlayPlaceholder } from './OverlayPlaceholder';

export function NodeVitalsOverlay({ active }: OverlayProps) {
  return <OverlayPlaceholder title="Node Vitals" active={active} />;
}
