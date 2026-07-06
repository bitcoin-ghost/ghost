/**
 * Overlay: Mempool River
 *
 * CONCEPT — live transaction particles flowing downstream like a river,
 * coloured by their BUDS class (T0 green → T3 red, via `@/lib/budsTiers`), with
 * the reaper visibly cutting T3 junk out of the current. Particle density
 * tracks mempool load. Data: `/api/v1/buds/mempool` plus reaper status.
 *
 * IMPLEMENTER NOTES:
 *  - Keep the `export function MempoolRiverOverlay({ active }: OverlayProps)`
 *    signature exactly. Replace only the body of this file.
 *  - Honour `active`: run your rAF / animation loop and any polling ONLY while
 *    `active === true`; cancel the rAF and stop polling when it flips to false.
 *  - CSP-safe only: draw with <canvas> or inline SVG. No external assets.
 */
'use client';

import type { OverlayProps } from './types';
import { OverlayPlaceholder } from './OverlayPlaceholder';

export function MempoolRiverOverlay({ active }: OverlayProps) {
  return <OverlayPlaceholder title="Mempool River" active={active} />;
}
