'use client';

import { useEffect } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import {
  ONBOARDING_PATH,
  hasSeenOnboardingThisSession,
  isOnboarded,
  markOnboardingSeen,
} from '@/hooks/useOnboarding';

/**
 * First-run redirect. On the first dashboard load of a browser that has not yet
 * completed onboarding, send the operator to the onboarding flow exactly once
 * per session. After that (e.g. they hit "Skip for now"), they are not trapped:
 * the per-session `seen` marker stops further auto-redirects until they reopen
 * the dashboard in a fresh session, and completing the flow sets the persistent
 * flag so it never fires again.
 *
 * Renders nothing.
 */
export function OnboardingGate() {
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    if (pathname === ONBOARDING_PATH) return;
    if (isOnboarded()) return;
    if (hasSeenOnboardingThisSession()) return;

    markOnboardingSeen();
    router.replace(ONBOARDING_PATH);
  }, [pathname, router]);

  return null;
}
