/**
 * Overlay: Block Clock
 *
 * CONCEPT — a giant, ambient next-block countdown: estimated time to the next
 * block, round progress, current difficulty, and network hashrate. The
 * centrepiece is the clock itself; everything else is quiet supporting detail.
 *
 * IMPLEMENTER NOTES:
 *  - Keep the `export function BlockClockOverlay({ active }: OverlayProps)`
 *    signature exactly. Replace only the body of this file.
 *  - Honour `active`: run your rAF / animation loop and any polling ONLY while
 *    `active === true`; cancel the rAF and stop polling when it flips to false.
 *  - CSP-safe only: draw with <canvas> or inline SVG. No external assets.
 */
'use client';

import type { OverlayProps } from './types';
import { OverlayPlaceholder } from './OverlayPlaceholder';

export function BlockClockOverlay({ active }: OverlayProps) {
  return <OverlayPlaceholder title="Block Clock" active={active} />;
}
