/**
 * Overlay: Earnings Ticker
 *
 * CONCEPT — shares and payouts accumulating over time: an ambient ticker of the
 * capability shares building up and recent payouts streaming past. Money and
 * work, visualised as a calm, ever-rising flow.
 *
 * IMPLEMENTER NOTES:
 *  - Keep the `export function EarningsTickerOverlay({ active }: OverlayProps)`
 *    signature exactly. Replace only the body of this file.
 *  - Honour `active`: run your rAF / animation loop and any polling ONLY while
 *    `active === true`; cancel the rAF and stop polling when it flips to false.
 *  - CSP-safe only: draw with <canvas> or inline SVG. No external assets.
 */
'use client';

import type { OverlayProps } from './types';
import { OverlayPlaceholder } from './OverlayPlaceholder';

export function EarningsTickerOverlay({ active }: OverlayProps) {
  return <OverlayPlaceholder title="Earnings Ticker" active={active} />;
}
