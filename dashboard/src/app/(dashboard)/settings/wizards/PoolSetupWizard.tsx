'use client';

import { useEffect, useRef } from 'react';
import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useSetPoolName } from '@/hooks/queries/useConfigQueries';

// Every node is a public pool node: there is no mining-mode choice and no
// node payout address any more, so the wizard only sets the coinbase pool name.
interface PoolSetupData {
  pool_name: string;
}

interface PoolSetupWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function PoolSetupWizard({ isOpen, onClose }: PoolSetupWizardProps) {
  const setPoolName = useSetPoolName();
  const toast = useToast();

  const steps: WizardStep<PoolSetupData>[] = [
    {
      id: 'info',
      title: 'Pool Info',
      description: 'Pool configuration details',
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Review and apply changes',
      onSubmit: async (data) => {
        if (data.pool_name.trim()) {
          await setPoolName.mutateAsync(data.pool_name.trim());
        }
        toast.success('Mining Setup Updated', 'Pool settings applied');
        onClose();
      },
    },
  ];

  const wizard = useWizard<PoolSetupData>({
    steps,
    initialData: {
      pool_name: '',
    },
  });

  // pool_name is a write-only input the status endpoints don't return, so the
  // wizard starts empty each time it opens.
  const wasOpenRef = useRef(false);
  useEffect(() => {
    if (isOpen && !wasOpenRef.current) {
      wizard.reset({ pool_name: '' });
    }
    wasOpenRef.current = isOpen;
  }, [isOpen]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Mining Setup Wizard"
      wizard={wizard}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 1: Pool Info */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <Input
                  label="Pool Name (optional)"
                  value={data.pool_name}
                  onChange={(e) => {
                    const val = e.target.value;
                    if (val.length <= 30 && /^[\x20-\x7E]*$/.test(val)) {
                      setData({ pool_name: val });
                    }
                  }}
                  placeholder="e.g. SatoshiPool"
                />
                <p className="text-sm text-[color:var(--dim)] mt-1">
                  Custom name shown in block coinbase. ASCII only, max 30 characters.
                </p>
                {data.pool_name.trim() && (
                  <div className="mt-2 p-2 rounded bg-[var(--surface)] font-mono text-sm text-[color:var(--accent)]">
                    - G H O S T - {data.pool_name.trim()}
                  </div>
                )}
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Pool Configuration</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Stratum Port</span>
                    <span className="text-[color:var(--fg)] font-mono">3333</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Protocol</span>
                    <span className="text-[color:var(--fg)]">Stratum V1</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Variable Difficulty</span>
                    <Badge variant="success">Active</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Target Rate</span>
                    <span className="text-[color:var(--fg)]">4 shares/minute</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Share Cap</span>
                    <span className="text-[color:var(--fg)]">10% per miner</span>
                  </div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-2">Miner Connection Format</h4>
                <p className="text-sm text-[color:var(--dim)] mb-2">
                  Miners connect with the following worker name format:
                </p>
                <div className="p-3 rounded bg-[var(--surface)] font-mono text-sm text-[color:var(--accent)]">
                  stratum+tcp://your-node-ip:3333
                </div>
                <p className="text-sm text-[color:var(--dim)] mt-2">
                  Worker name: <span className="text-[color:var(--accent)] font-mono">bitcoin_address.worker_id</span>
                </p>
              </div>
            </div>
          )}

          {/* Step 2: Confirm */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Configuration Summary</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Mining</span>
                    <Badge variant="success">Public pool</Badge>
                  </div>
                  {data.pool_name.trim() && (
                    <div className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">Pool Name</span>
                      <span className="text-[color:var(--accent)] font-mono text-sm">
                        - G H O S T - {data.pool_name.trim()}
                      </span>
                    </div>
                  )}
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                <p className="text-sm text-[color:var(--accent)]">
                  Click Finish to apply mining settings. Changes will take effect immediately.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
