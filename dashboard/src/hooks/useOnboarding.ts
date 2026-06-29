'use client';

import { useCallback, useEffect, useState } from 'react';

// ---------------------------------------------------------------------------
// First-run onboarding completion flag
// ---------------------------------------------------------------------------
// The ghost-node API exposes only specific, typed config endpoints (archive
// mode, public mining, reaper, mempool/template profiles, payout address …).
// There is NO generic node-side key/value or dashboard-preferences endpoint we
// could persist an `onboarding_complete` marker to without inventing a new
// backend route — which is out of scope for a frontend change and would not be
// a "real" reused endpoint.
//
// So the completion flag lives in localStorage under `ghost_dashboard_onboarded`.
// LIMITATION: this is per-browser. An operator who opens the dashboard from a
// fresh browser / cleared storage will be re-offered onboarding. The flow is
// idempotent (it only confirms the node's already-applied config), so re-running
// it is harmless. The "Onboarding" entry under Settings re-opens it any time.
// ---------------------------------------------------------------------------

export const ONBOARDED_KEY = 'ghost_dashboard_onboarded';
// Per-tab marker so a "skip for now" doesn't re-trap the operator on every
// navigation within the same session (a fresh session re-offers it until done).
export const ONBOARD_SEEN_KEY = 'ghost_dashboard_onboard_seen';
export const ONBOARDING_PATH = '/settings/onboarding';

function readFlag(storage: 'local' | 'session', key: string): boolean {
  if (typeof window === 'undefined') return false;
  try {
    const store = storage === 'local' ? window.localStorage : window.sessionStorage;
    return store.getItem(key) === 'true';
  } catch {
    return false;
  }
}

export function isOnboarded(): boolean {
  return readFlag('local', ONBOARDED_KEY);
}

export function hasSeenOnboardingThisSession(): boolean {
  return readFlag('session', ONBOARD_SEEN_KEY);
}

export function markOnboardingSeen(): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.setItem(ONBOARD_SEEN_KEY, 'true');
  } catch {
    /* storage unavailable — fall through, gate simply re-checks next mount */
  }
}

export function setOnboarded(value: boolean): void {
  if (typeof window === 'undefined') return;
  try {
    if (value) window.localStorage.setItem(ONBOARDED_KEY, 'true');
    else window.localStorage.removeItem(ONBOARDED_KEY);
  } catch {
    /* storage unavailable */
  }
}

/**
 * React hook exposing the completion flag. `onboarded` is `null` until the
 * client has read localStorage (avoids an SSR/first-paint flash).
 */
export function useOnboarding() {
  const [onboarded, setOnboardedState] = useState<boolean | null>(null);

  useEffect(() => {
    setOnboardedState(isOnboarded());
  }, []);

  const complete = useCallback(() => {
    setOnboarded(true);
    setOnboardedState(true);
  }, []);

  const reset = useCallback(() => {
    setOnboarded(false);
    setOnboardedState(false);
  }, []);

  return { onboarded, complete, reset };
}
