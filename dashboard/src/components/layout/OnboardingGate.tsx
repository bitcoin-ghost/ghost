'use client';

/**
 * Onboarding is opt-in, not forced.
 *
 * WHY THERE IS NO AUTO-REDIRECT
 * -----------------------------
 * The only completion signal available to the dashboard is the client-side
 * `ghost_dashboard_onboarded` localStorage flag (see `useOnboarding`) — the
 * ghost-node API exposes no "onboarded"/"configured" marker, and the node's
 * capability config CANNOT stand in for one: every capability defaults to `true`
 * server-side (`DashboardConfig::default`: archive/ghost_pay/public_mining/reaper
 * all on, mempool_profile "permissive"), so a heavily-configured production node
 * is byte-for-byte indistinguishable from a brand-new install over the API.
 *
 * The previous gate keyed the first-run redirect purely on that per-browser
 * localStorage flag, so any already-set-up node opened from a fresh browser /
 * cleared storage / new SSH-tunnel session was force-redirected into onboarding
 * before it could show Overview. Because "configured" can't be detected, the
 * correct behaviour is to NOT force onboarding at all: the dashboard always
 * lands on Overview, and onboarding remains reachable on demand as the first
 * entry under Settings → Onboarding (and re-runnable any time).
 *
 * Renders nothing.
 */
export function OnboardingGate() {
  return null;
}
