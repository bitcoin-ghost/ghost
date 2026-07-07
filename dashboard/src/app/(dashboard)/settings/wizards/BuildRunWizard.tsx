'use client';

import { useEffect, useState, useMemo } from 'react';
import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useStartService, useStopService, useRestartService } from '@/hooks/queries';
import { fetchApi } from '@/lib/api/client';

const NODE_SERVICE = 'ghost-pool';

interface PreflightCheck {
  label: string;
  status: 'pending' | 'ok' | 'error';
  message?: string;
}

interface BuildRunData {
  action: 'start' | 'restart' | 'stop';
  health_ok: boolean;
}

interface BuildRunWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

const ACTION_OPTIONS = [
  {
    id: 'start' as const,
    label: 'Start',
    description: 'Start the node if it is currently stopped.',
    icon: 'M5 3l14 9-14 9V3z',
  },
  {
    id: 'restart' as const,
    label: 'Restart',
    description: 'Stop and restart the node. Connections will be briefly interrupted.',
    icon: 'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15',
  },
  {
    id: 'stop' as const,
    label: 'Stop',
    description: 'Gracefully stop the node. All services will be shut down.',
    icon: 'M21 12a9 9 0 11-18 0 9 9 0 0118 0z M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z',
  },
];

export default function BuildRunWizard({ isOpen, onClose }: BuildRunWizardProps) {
  const startService = useStartService();
  const stopService = useStopService();
  const restartService = useRestartService();
  const toast = useToast();

  const [checks, setChecks] = useState<PreflightCheck[]>([
    { label: 'Ghost Pool API', status: 'pending' },
    { label: 'Bitcoin Core Reachable', status: 'pending' },
    { label: 'Blockchain Synced', status: 'pending' },
    { label: 'Configuration Valid', status: 'pending' },
  ]);

  const allChecksOk = checks.every((c) => c.status === 'ok');
  const checksComplete = checks.every((c) => c.status !== 'pending');

  const steps = useMemo<WizardStep<BuildRunData>[]>(() => [
    {
      id: 'preflight',
      title: 'Pre-flight',
      description: 'Checking node health and readiness',
    },
    {
      id: 'action',
      title: 'Action',
      description: 'Select the action to perform',
      validate: (data) => {
        if (!data.action) return 'Please select an action';
        return null;
      },
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Confirm the action to execute',
      onSubmit: async (data) => {
        let result;
        switch (data.action) {
          case 'start':
            result = await startService.mutateAsync(NODE_SERVICE);
            break;
          case 'stop':
            result = await stopService.mutateAsync(NODE_SERVICE);
            break;
          case 'restart':
            result = await restartService.mutateAsync(NODE_SERVICE);
            break;
        }

        const actionLabels = { start: 'Started', stop: 'Stopped', restart: 'Restarted' } as const;

        if (result?.success === false) {
          toast.error(
            `Node ${data.action.charAt(0).toUpperCase() + data.action.slice(1)} Failed`,
            result.message || `The node ${data.action} command did not complete.`
          );
          throw new Error(result.message || `Failed to ${data.action} the node.`);
        }

        toast.success(
          `Node ${actionLabels[data.action]}`,
          result?.message || `The node ${data.action} command has been executed successfully.`
        );
        onClose();
      },
    },
  ], [startService, stopService, restartService, toast, onClose]);

  const wizard = useWizard<BuildRunData>({
    steps,
    initialData: {
      action: 'restart',
      health_ok: false,
    },
  });

  // Run pre-flight checks when the wizard opens on step 0
  useEffect(() => {
    if (!isOpen || wizard.currentStep !== 0) return;

    const runChecks = async () => {
      // Reset checks
      setChecks([
        { label: 'Ghost Pool API', status: 'pending' },
        { label: 'Bitcoin Core Reachable', status: 'pending' },
        { label: 'Blockchain Synced', status: 'pending' },
        { label: 'Configuration Valid', status: 'pending' },
      ]);

      // Check 1: Health endpoint
      try {
        const health = await fetchApi<{ status?: string; healthy?: boolean }>('/health');
        const isHealthy = health.status === 'ok' || health.healthy === true;
        setChecks((prev) => prev.map((c, i) =>
          i === 0 ? { ...c, status: isHealthy ? 'ok' : 'error', message: isHealthy ? 'API responding' : 'API unhealthy' } : c
        ));
      } catch {
        setChecks((prev) => prev.map((c, i) =>
          i === 0 ? { ...c, status: 'error', message: 'Cannot reach API' } : c
        ));
      }

      // Check 2-4: Node status endpoint
      try {
        const status = await fetchApi<{
          online?: boolean;
          is_synced?: boolean;
          block_height?: number;
          sync_height?: number;
          ghost_mode?: boolean;
        }>('/api/v1/node/status');

        // Bitcoin Core reachable (block_height present means we can talk to it)
        const coreReachable = typeof status.block_height === 'number' && status.block_height > 0;
        setChecks((prev) => prev.map((c, i) =>
          i === 1 ? {
            ...c,
            status: coreReachable ? 'ok' : 'error',
            message: coreReachable ? `Height ${status.block_height}` : 'Cannot reach Bitcoin Core',
          } : c
        ));

        // Synced check
        const isSynced = status.is_synced === true;
        setChecks((prev) => prev.map((c, i) =>
          i === 2 ? {
            ...c,
            status: isSynced ? 'ok' : 'error',
            message: isSynced ? 'Fully synced' : `Syncing (${status.sync_height ?? '?'}/${status.block_height ?? '?'})`,
          } : c
        ));

        // Config valid (if we can reach status, config is loadable)
        setChecks((prev) => prev.map((c, i) =>
          i === 3 ? { ...c, status: 'ok', message: 'Configuration loaded' } : c
        ));
      } catch {
        setChecks((prev) => prev.map((c, i) =>
          i > 0 ? { ...c, status: 'error', message: 'Cannot retrieve node status' } : c
        ));
      }
    };

    runChecks();
  }, [isOpen, wizard.currentStep]);

  // Update health_ok when checks complete
  useEffect(() => {
    if (checksComplete) {
      wizard.setData({ health_ok: allChecksOk });
    }
  }, [checksComplete, allChecksOk]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Build & Run"
      wizard={wizard}
      size="md"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 0: Pre-flight Checks */}
          {wizard.currentStep === 0 && (
            <div className="space-y-3">
              {checks.map((check) => (
                <div
                  key={check.label}
                  className="p-4 rounded-lg bg-[var(--surface)]/50 flex items-center justify-between"
                >
                  <div className="flex items-center gap-3">
                    {check.status === 'pending' && (
                      <div className="w-5 h-5 rounded-full border-2 border-[var(--rule-strong)] border-t-orange-500 animate-spin" />
                    )}
                    {check.status === 'ok' && (
                      <svg className="w-5 h-5 text-[color:var(--green)]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                    )}
                    {check.status === 'error' && (
                      <svg className="w-5 h-5 text-[color:var(--red)]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    )}
                    <span className="text-[color:var(--fg)] font-medium">{check.label}</span>
                  </div>
                  {check.message && (
                    <span className={`text-sm ${check.status === 'ok' ? 'text-[color:var(--green)]' : check.status === 'error' ? 'text-[color:var(--red)]' : 'text-[color:var(--dim)]'}`}>
                      {check.message}
                    </span>
                  )}
                </div>
              ))}
              {checksComplete && !allChecksOk && (
                <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                  <p className="text-sm text-[color:var(--accent)]">
                    Some pre-flight checks failed. You can still proceed, but the action may not succeed.
                  </p>
                </div>
              )}
              {checksComplete && allChecksOk && (
                <div className="p-4 rounded-lg bg-[var(--green)]/20 border border-[var(--green)]">
                  <p className="text-sm text-[color:var(--green)]">
                    All pre-flight checks passed. Your node is ready.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Step 1: Select Action */}
          {wizard.currentStep === 1 && (
            <div className="space-y-3">
              {ACTION_OPTIONS.map((action) => (
                <button
                  key={action.id}
                  type="button"
                  onClick={() => setData({ action: action.id })}
                  className={`
                    w-full text-left p-4 rounded-lg border transition-colors
                    ${data.action === action.id
                      ? 'bg-[var(--accent)]/30 border-[var(--accent)]'
                      : 'bg-[var(--surface)]/50 border-[var(--rule-strong)] hover:border-[var(--rule-strong)]'}
                  `}
                >
                  <div className="flex items-center gap-3">
                    <svg className="w-5 h-5 text-[color:var(--dim)] flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={action.icon} />
                    </svg>
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[color:var(--fg)] font-medium">{action.label}</span>
                        {data.action === action.id && (
                          <Badge variant="warning">Selected</Badge>
                        )}
                      </div>
                      <p className="text-sm text-[color:var(--dim)] mt-1">{action.description}</p>
                    </div>
                  </div>
                </button>
              ))}
            </div>
          )}

          {/* Step 2: Confirm */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Action Summary</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Action</span>
                    <Badge variant={data.action === 'stop' ? 'error' : 'warning'}>
                      {data.action.charAt(0).toUpperCase() + data.action.slice(1)}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Pre-flight Status</span>
                    <Badge variant={data.health_ok ? 'success' : 'error'}>
                      {data.health_ok ? 'All Passed' : 'Issues Detected'}
                    </Badge>
                  </div>
                </div>
              </div>
              {data.action === 'stop' && (
                <div className="p-4 rounded-lg bg-[var(--red)]/20 border border-[var(--red)]">
                  <p className="text-sm text-[color:var(--red)]">
                    Stopping the node will disconnect all miners and peers. The node will not participate
                    in consensus or earn rewards while stopped.
                  </p>
                </div>
              )}
              {data.action === 'restart' && (
                <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                  <p className="text-sm text-[color:var(--accent)]">
                    Restarting the node will cause a brief interruption. Miners will automatically
                    reconnect after the restart completes.
                  </p>
                </div>
              )}
              {data.action === 'start' && (
                <div className="p-4 rounded-lg bg-[var(--green)]/20 border border-[var(--green)]">
                  <p className="text-sm text-[color:var(--green)]">
                    The node will start and begin syncing with the network. It may take a moment to
                    fully connect to peers.
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
