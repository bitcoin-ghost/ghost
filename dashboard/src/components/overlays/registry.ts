import type { OverlayDef } from './types';
import { MeshConstellationOverlay } from './MeshConstellationOverlay';
import { NodeVitalsOverlay } from './NodeVitalsOverlay';
import { MempoolRiverOverlay } from './MempoolRiverOverlay';
import { BlockClockOverlay } from './BlockClockOverlay';
import { EarningsTickerOverlay } from './EarningsTickerOverlay';
import { ChainHealthPulseOverlay } from './ChainHealthPulseOverlay';

/**
 * The ordered set of rest-screen overlays shown by /overlays.
 *
 * Order here is the carousel order (and the dot order). To add an overlay,
 * append a new `OverlayDef` and create its component file — nothing else in the
 * shell needs to change. Each follow-up agent owns exactly one component file
 * and replaces its body in place; this registry stays as-is.
 */
export const OVERLAYS: OverlayDef[] = [
  { id: 'mesh-constellation', title: 'Mesh Constellation', Component: MeshConstellationOverlay },
  { id: 'node-vitals', title: 'Node Vitals', Component: NodeVitalsOverlay },
  { id: 'mempool-river', title: 'Mempool River', Component: MempoolRiverOverlay },
  { id: 'block-clock', title: 'Block Clock', Component: BlockClockOverlay },
  { id: 'earnings-ticker', title: 'Earnings Ticker', Component: EarningsTickerOverlay },
  { id: 'chain-health-pulse', title: 'Chain Health Pulse', Component: ChainHealthPulseOverlay },
];
