import type { OverlayDef } from './types';
import { NodeVitalsOverlay } from './NodeVitalsOverlay';

/**
 * The rest-screen overlay(s) shown by /overlays.
 *
 * Node Vitals is currently the only overlay. The registry is kept (rather than
 * importing the component directly in the page) so more overlays can be added
 * later by appending an `OverlayDef` and a component file — nothing else needs
 * to change.
 */
export const OVERLAYS: OverlayDef[] = [
  { id: 'node-vitals', title: 'Node Vitals', Component: NodeVitalsOverlay },
];
