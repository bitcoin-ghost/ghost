'use client';

import { useEffect, useRef } from 'react';
import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useConfigureHaze } from '@/hooks/queries/useConfigQueries';
import { useHazeStatus } from '@/hooks/queries/useHazeQueries';

type HazeMode = 'standard' | 'hazed' | 'full_archive';

interface HazeData {
  mode: HazeMode;
}

interface HazeWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

const modeLabels: Record<HazeMode, string> = {
  standard: 'Standard',
  hazed: 'Hazed',
  full_archive: 'Full Archive',
};

const modeDescriptions: Record<HazeMode, string> = {
  standard: 'Normal block storage. No privacy stripping applied. Blocks stored as-is from the network.',
  hazed: 'Privacy-enhanced storage. Witness data and non-financial metadata are stripped from stored blocks, reducing disk usage and improving privacy.',
  full_archive: 'Full archive with haze metadata. Stores complete blocks alongside stripped versions for maximum data availability.',
};

export default function HazeWizard({ isOpen, onClose }: HazeWizardProps) {
  const { data: hazeStatus } = useHazeStatus();
  const configureHaze = useConfigureHaze();
  const toast = useToast();

  const currentMode = hazeStatus?.mode ?? 'standard';

  const steps: WizardStep<HazeData>[] = [
    {
      id: 'status',
      title: 'Status',
      description: 'Current Ghost Haze configuration',
    },
    {
      id: 'select',
      title: 'Select Mode',
      description: 'Choose your block storage mode',
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Review and apply changes',
      onSubmit: async (data) => {
        await configureHaze.mutateAsync(data.mode);
        toast.success(
          'Ghost Haze Updated',
          `Storage mode changed to ${modeLabels[data.mode]}`
        );
        onClose();
      },
    },
  ];

  const wizard = useWizard<HazeData>({
    steps,
    initialData: {
      mode: currentMode as HazeMode,
    },
  });

  // Re-seed the selected mode from live haze status each time the dialog opens
  // (the initial mount captured the `standard` fallback before the status query
  // resolved), so an untouched Finish keeps the current mode instead of forcing
  // the node back to Standard.
  const hydratedRef = useRef(false);
  useEffect(() => {
    if (!isOpen) {
      hydratedRef.current = false;
      return;
    }
    if (hazeStatus && !hydratedRef.current) {
      hydratedRef.current = true;
      wizard.reset({ mode: (hazeStatus.mode ?? 'standard') as HazeMode });
    }
  }, [isOpen, hazeStatus]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Ghost Haze Setup"
      wizard={wizard}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 1: Current Status */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Current Haze Status</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Storage Mode</span>
                    <Badge
                      variant={
                        currentMode === 'hazed'
                          ? 'success'
                          : currentMode === 'full_archive'
                          ? 'info'
                          : 'default'
                      }
                    >
                      {modeLabels[currentMode as HazeMode] ?? 'Unknown'}
                    </Badge>
                  </div>
                  {hazeStatus && (
                    <>
                      <div className="flex items-center justify-between">
                        <span className="text-[color:var(--dim)]">Blocks Stored</span>
                        <span className="text-[color:var(--fg)]">
                          {hazeStatus.blocks?.toLocaleString() ?? 'N/A'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-[color:var(--dim)]">Size on Disk</span>
                        <span className="text-[color:var(--fg)]">
                          {hazeStatus.size_on_disk
                            ? `${(hazeStatus.size_on_disk / (1024 * 1024 * 1024)).toFixed(2)} GB`
                            : 'N/A'}
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-[color:var(--dim)]">Archive Mode</span>
                        <Badge variant={hazeStatus.archive_mode ? 'success' : 'default'}>
                          {hazeStatus.archive_mode ? 'Active' : 'Inactive'}
                        </Badge>
                      </div>
                    </>
                  )}
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <p className="text-sm text-[color:var(--dim)]">
                  Ghost Haze controls how your node stores block data. Hazed mode strips
                  non-financial witness data from blocks, reducing storage requirements while
                  maintaining full transaction verification capability.
                </p>
              </div>
            </div>
          )}

          {/* Step 2: Select Mode */}
          {wizard.currentStep === 1 && (
            <div className="space-y-3">
              {(['standard', 'hazed', 'full_archive'] as const).map((mode) => {
                const isSelected = data.mode === mode;
                const isCurrent = currentMode === mode;
                return (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => setData({ mode })}
                    className={`
                      w-full text-left p-4 rounded-lg border-2 transition-colors
                      ${
                        isSelected
                          ? 'border-[var(--accent)] bg-[var(--accent)]/20'
                          : 'border-[var(--rule-strong)] bg-[var(--surface)]/50 hover:border-[var(--rule-strong)]'
                      }
                    `}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[color:var(--fg)] font-medium">{modeLabels[mode]}</span>
                      <div className="flex items-center gap-2">
                        {isCurrent && (
                          <Badge variant="info">Current</Badge>
                        )}
                        {isSelected && (
                          <div className="w-4 h-4 rounded-full bg-[var(--accent)] flex items-center justify-center">
                            <div className="w-2 h-2 rounded-full bg-white" />
                          </div>
                        )}
                        {!isSelected && (
                          <div className="w-4 h-4 rounded-full border-2 border-[var(--rule-strong)]" />
                        )}
                      </div>
                    </div>
                    <p className="text-sm text-[color:var(--dim)]">{modeDescriptions[mode]}</p>
                  </button>
                );
              })}
            </div>
          )}

          {/* Step 3: Confirm */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Change Summary</h4>
                <div className="flex items-center justify-between">
                  <span className="text-[color:var(--dim)]">Storage Mode</span>
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={
                        currentMode === 'hazed'
                          ? 'success'
                          : currentMode === 'full_archive'
                          ? 'info'
                          : 'default'
                      }
                    >
                      {modeLabels[currentMode as HazeMode] ?? 'Unknown'}
                    </Badge>
                    <span className="text-[color:var(--fainter)]">-&gt;</span>
                    <Badge
                      variant={
                        data.mode === 'hazed'
                          ? 'success'
                          : data.mode === 'full_archive'
                          ? 'info'
                          : 'default'
                      }
                    >
                      {modeLabels[data.mode]}
                    </Badge>
                  </div>
                </div>
              </div>
              {data.mode !== currentMode ? (
                <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                  <p className="text-sm text-[color:var(--accent)]">
                    Click Finish to change the storage mode. This may require Ghost Core to
                    reprocess blocks depending on the mode transition.
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                  <p className="text-sm text-[color:var(--dim)]">
                    No changes detected. The selected mode matches the current configuration.
                  </p>
                </div>
              )}
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-2">Mode Details</h4>
                <p className="text-sm text-[color:var(--dim)]">{modeDescriptions[data.mode]}</p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
