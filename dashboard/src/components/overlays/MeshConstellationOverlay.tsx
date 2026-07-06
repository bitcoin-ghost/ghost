/**
 * Overlay: Mesh Constellation
 *
 * CONCEPT — the 8-node swarm rendered as a living star map: glowing orbs
 * (elders brighter, sized by hashrate, placed by geo or on a ring), connection
 * lines that pulse as gossip flows between nodes, and slow-drifting particles
 * along the edges. Data: `/api/v1/pool/mesh-nodes` (+ the geo lib under
 * `@/lib/geo` for placement).
 *
 * IMPLEMENTER NOTES:
 *  - Keep the `export function MeshConstellationOverlay({ active }: OverlayProps)`
 *    signature exactly. Replace only the body of this file.
 *  - Honour `active`: run your rAF / animation loop and any polling ONLY while
 *    `active === true`; cancel the rAF and stop polling when it flips to false.
 *  - CSP-safe only: draw with <canvas> or inline SVG. No external assets.
 */
'use client';

import type { OverlayProps } from './types';
import { OverlayPlaceholder } from './OverlayPlaceholder';

export function MeshConstellationOverlay({ active }: OverlayProps) {
  return <OverlayPlaceholder title="Mesh Constellation" active={active} />;
}
