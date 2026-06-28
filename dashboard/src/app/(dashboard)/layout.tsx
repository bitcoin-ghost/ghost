'use client';

import { ReactNode, useEffect } from 'react';
import { Sidebar } from '@/components/layout/Sidebar';
import { OnboardingGate } from '@/components/layout/OnboardingGate';
import { useRealtimeSync } from '@/hooks/useRealtimeSync';
import { useUIStore } from '@/stores';

function RealtimeBridge() {
  useRealtimeSync();
  return null;
}

function TooltipShortcut() {
  const toggleTooltips = useUIStore((s) => s.toggleTooltips);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === '?' && !e.ctrlKey && !e.metaKey && !e.altKey) {
        const target = e.target as HTMLElement;
        if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) return;
        toggleTooltips();
      }
    }

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [toggleTooltips]);

  return null;
}

export default function DashboardLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen">
      <RealtimeBridge />
      <TooltipShortcut />
      <OnboardingGate />
      <Sidebar />
      <main className="flex-1 overflow-auto md:ml-0 ml-0">
        <div className="p-4 md:p-6 pt-14 md:pt-6">
          {children}
        </div>
      </main>
    </div>
  );
}
