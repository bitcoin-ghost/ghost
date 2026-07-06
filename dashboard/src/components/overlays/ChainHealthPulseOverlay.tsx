/**
 * Overlay: Chain Health Pulse
 *
 * CONCEPT — tip stability and reorg history rendered as a calm EKG / pulse
 * line: a steady heartbeat while the tip is stable, with reorgs showing as
 * blips in the trace. Data: `/api/v1/chain/health` (this endpoint ships
 * separately — if it is not live yet, the implementer degrades gracefully;
 * this placeholder is fine to keep until then).
 *
 * IMPLEMENTER NOTES:
 *  - Keep the `export function ChainHealthPulseOverlay({ active }: OverlayProps)`
 *    signature exactly. Replace only the body of this file.
 *  - Honour `active`: run your rAF / animation loop and any polling ONLY while
 *    `active === true`; cancel the rAF and stop polling when it flips to false.
 *  - CSP-safe only: draw with <canvas> or inline SVG. No external assets.
 */
'use client';

import type { OverlayProps } from './types';
import { OverlayPlaceholder } from './OverlayPlaceholder';

export function ChainHealthPulseOverlay({ active }: OverlayProps) {
  return <OverlayPlaceholder title="Chain Health Pulse" active={active} />;
}
