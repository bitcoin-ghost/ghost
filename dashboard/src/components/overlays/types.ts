import type React from 'react';

/**
 * Shared contract for the /overlays rest-screen carousel.
 *
 * The carousel shows ONE overlay at a time, full-bleed. Every overlay receives
 * `active`, which is `true` ONLY when this overlay is the one currently on
 * screen. Overlays MUST honour it:
 *
 *   - When `active === true`  → run animation loop / rAF, fetch/poll data.
 *   - When `active === false` → PAUSE the animation loop / cancel rAF, stop
 *     any polling. The component may stay mounted, but it must not burn CPU or
 *     hold a running requestAnimationFrame while it is off-screen.
 *
 * Overlays MUST be CSP-safe: render with canvas / inline SVG only. No external
 * assets (no remote images, fonts, script CDNs, stylesheets). Data comes from
 * the node's own same-origin `/api/...` endpoints.
 */
export interface OverlayProps {
  /**
   * true only when this overlay is the one currently shown — overlays MUST
   * pause their animation loop / rAF when active===false.
   */
  active: boolean;
}

export interface OverlayDef {
  /** stable kebab id */
  id: string;
  /** shown in the carousel label */
  title: string;
  Component: React.ComponentType<OverlayProps>;
}
