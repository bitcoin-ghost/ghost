'use client';

import { useEffect, useRef } from 'react';
import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Toggle } from '@/components/ui/Toggle';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useConfigureShroud } from '@/hooks/queries/useConfigQueries';
import { useShroudStatus } from '@/hooks/queries/useShroudQueries';

interface ShroudData {
  enabled: boolean;
}

interface ShroudWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function ShroudWizard({ isOpen, onClose }: ShroudWizardProps) {
  const { data: shroudStatus } = useShroudStatus();
  const configureShroud = useConfigureShroud();
  const toast = useToast();

  const steps: WizardStep<ShroudData>[] = [
    {
      id: 'status',
      title: 'Status',
      description: 'Current Ghost Shroud configuration',
    },
    {
      id: 'configure',
      title: 'Configure',
      description: 'Enable or disable transaction relay privacy',
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Review and apply changes',
      onSubmit: async (data) => {
        await configureShroud.mutateAsync({
          enabled: data.enabled,
        });
        toast.success(
          'Ghost Shroud Updated',
          data.enabled
            ? 'Shroud enabled — restart ghost-core to activate'
            : 'Shroud has been disabled — restart ghost-core to deactivate'
        );
        onClose();
      },
    },
  ];

  const wizard = useWizard<ShroudData>({
    steps,
    initialData: {
      enabled: shroudStatus?.enabled ?? false,
    },
  });

  // Re-seed the editable toggle from live shroud status each time the dialog
  // opens (the initial mount captured the `false` fallback before the status
  // query resolved), so an untouched Finish writes back the live value rather
  // than silently disabling Shroud.
  const hydratedRef = useRef(false);
  useEffect(() => {
    if (!isOpen) {
      hydratedRef.current = false;
      return;
    }
    if (shroudStatus && !hydratedRef.current) {
      hydratedRef.current = true;
      wizard.reset({ enabled: shroudStatus.enabled ?? false });
    }
  }, [isOpen, shroudStatus]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Ghost Shroud Setup"
      wizard={wizard}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 1: Current Status */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Current Shroud Status</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Shroud Enabled</span>
                    <Badge variant={shroudStatus?.enabled ? 'success' : 'default'}>
                      {shroudStatus?.enabled ? 'Active' : 'Inactive'}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Ghost Core Connected</span>
                    <Badge variant={shroudStatus?.ghost_core_connected ? 'success' : 'warning'}>
                      {shroudStatus?.ghost_core_connected ? 'Connected' : 'Not Connected'}
                    </Badge>
                  </div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <p className="text-sm text-[color:var(--dim)]">
                  Ghost Shroud adds a random 0-5 second delay before relaying transactions
                  to peers, making it harder for network observers to determine the origin
                  of a transaction. This setting requires a ghost-core restart to take effect.
                </p>
              </div>
            </div>
          )}

          {/* Step 2: Configure */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-[color:var(--fg)] font-medium">Enable Shroud</span>
                    <p className="text-sm text-[color:var(--dim)] mt-1">
                      Add random 0-5 second delays to transaction relay for privacy
                    </p>
                  </div>
                  <Toggle
                    enabled={data.enabled}
                    onChange={(enabled) => setData({ enabled })}
                    label="Enable Shroud"
                  />
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[color-mix(in_srgb,var(--blue)_14%,transparent)] border border-[color-mix(in_srgb,var(--blue)_35%,transparent)]">
                <p className="text-sm text-[color:var(--blue)]">
                  Ghost-core must be restarted for this change to take effect.
                  The node will start with the -shroud=1 flag when enabled.
                </p>
              </div>
            </div>
          )}

          {/* Step 3: Confirm */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Change Summary</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Shroud</span>
                    <div className="flex items-center gap-2">
                      <Badge variant={shroudStatus?.enabled ? 'success' : 'default'}>
                        {shroudStatus?.enabled ? 'Active' : 'Inactive'}
                      </Badge>
                      <span className="text-[color:var(--fainter)]">-&gt;</span>
                      <Badge variant={data.enabled ? 'success' : 'default'}>
                        {data.enabled ? 'Active' : 'Inactive'}
                      </Badge>
                    </div>
                  </div>
                </div>
              </div>
              {data.enabled ? (
                <div className="p-4 rounded-lg bg-[var(--green)]/20 border border-[var(--green)]">
                  <p className="text-sm text-[color:var(--green)]">
                    Shroud will add random 0-5 second delays before relaying transactions.
                    A ghost-core restart is required to activate this change.
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                  <p className="text-sm text-[color:var(--accent)]">
                    Shroud will be disabled. Transactions will be relayed immediately to
                    peers without privacy delays. A ghost-core restart is required.
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
