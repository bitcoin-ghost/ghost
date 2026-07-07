'use client';

import { useEffect, useRef } from 'react';
import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Toggle } from '@/components/ui/Toggle';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useSetGhostMode, useConfig } from '@/hooks/queries';

interface GhostModeData {
  enabled: boolean;
}

interface GhostModeWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function GhostModeWizard({ isOpen, onClose }: GhostModeWizardProps) {
  const { data: config } = useConfig();
  const setGhostMode = useSetGhostMode();
  const toast = useToast();

  const steps: WizardStep<GhostModeData>[] = [
    {
      id: 'status',
      title: 'Status',
      description: 'Current Ghost Mode status',
    },
    {
      id: 'toggle',
      title: 'Configure',
      description: 'Enable or disable Ghost Mode',
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Review and apply your changes',
      onSubmit: async (data) => {
        await setGhostMode.mutateAsync(data.enabled);
        toast.success(
          'Ghost Mode Updated',
          `Ghost Mode has been ${data.enabled ? 'enabled' : 'disabled'}`
        );
        onClose();
      },
    },
  ];

  const wizard = useWizard<GhostModeData>({
    steps,
    initialData: {
      enabled: config?.ghost_mode ?? false,
    },
  });

  // The wizard seeds its editable data once at mount, before `useConfig` has
  // resolved — so without this it would show the `false` fallback and an
  // untouched Finish would write Ghost Mode OFF over a node that had it ON.
  // Re-seed from live config each time the dialog opens (and once the query
  // lands if it opens first), so an untouched Finish is a no-op.
  const hydratedRef = useRef(false);
  useEffect(() => {
    if (!isOpen) {
      hydratedRef.current = false;
      return;
    }
    if (config && !hydratedRef.current) {
      hydratedRef.current = true;
      wizard.reset({ enabled: config.ghost_mode ?? false });
    }
  }, [isOpen, config]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Ghost Mode Setup"
      wizard={wizard}
      size="md"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <div className="flex items-center justify-between">
                  <span className="text-[color:var(--fg)] font-medium">Current Status</span>
                  <Badge variant={config?.ghost_mode ? 'success' : 'default'}>
                    {config?.ghost_mode ? 'Active' : 'Inactive'}
                  </Badge>
                </div>
                <p className="text-sm text-[color:var(--dim)] mt-1">
                  Ghost Mode enables Ghost protocol features including L2 participation,
                  privacy tools, and node reward eligibility.
                </p>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-2">What Ghost Mode does</h4>
                <ul className="space-y-2 text-sm text-[color:var(--dim)]">
                  <li className="flex items-center gap-2">
                    <span className="text-[color:var(--accent)]">--</span>
                    Signals your node as a Ghost protocol participant
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-[color:var(--accent)]">--</span>
                    Enables node capability verification eligibility
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-[color:var(--accent)]">--</span>
                    Individual capabilities (Ghost Pay, Archive, etc.) are configured separately
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-[color:var(--accent)]">--</span>
                    Does not grant shares on its own — shares come from verified capabilities
                  </li>
                </ul>
              </div>
            </div>
          )}

          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-[color:var(--fg)] font-medium">Ghost Mode</span>
                    <p className="text-sm text-[color:var(--dim)] mt-1">
                      Enable Ghost protocol features and L2 participation
                    </p>
                  </div>
                  <Toggle
                    enabled={data.enabled}
                    onChange={(enabled) => setData({ enabled })}
                    label="Ghost Mode"
                  />
                </div>
              </div>
              {data.enabled && (
                <div className="p-4 rounded-lg bg-[var(--green)]/20 border border-[var(--green)]">
                  <p className="text-sm text-[color:var(--green)]">
                    Your node will join the Ghost network and become eligible for node rewards.
                  </p>
                </div>
              )}
              {!data.enabled && (
                <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                  <p className="text-sm text-[color:var(--accent)]">
                    Disabling Ghost Mode will disconnect your node from the Ghost network.
                    You will no longer earn node rewards or participate in L2 services.
                  </p>
                </div>
              )}
            </div>
          )}

          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Change Summary</h4>
                <div className="flex items-center justify-between">
                  <span className="text-[color:var(--dim)]">Ghost Mode</span>
                  <div className="flex items-center gap-2">
                    <Badge variant={config?.ghost_mode ? 'success' : 'default'}>
                      {config?.ghost_mode ? 'Active' : 'Inactive'}
                    </Badge>
                    <span className="text-[color:var(--fainter)]">-&gt;</span>
                    <Badge variant={data.enabled ? 'success' : 'default'}>
                      {data.enabled ? 'Active' : 'Inactive'}
                    </Badge>
                  </div>
                </div>
              </div>
              {data.enabled !== (config?.ghost_mode ?? false) ? (
                <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                  <p className="text-sm text-[color:var(--accent)]">
                    Click Finish to apply this change. Your node configuration will be updated immediately.
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                  <p className="text-sm text-[color:var(--dim)]">
                    No changes detected. The setting matches the current configuration.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
