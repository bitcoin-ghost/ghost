'use client';

import { useEffect, useMemo, useRef } from 'react';
import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Input } from '@/components/ui/Input';
import { Toggle } from '@/components/ui/Toggle';
import { Badge } from '@/components/ui/Badge';
import { Skeleton } from '@/components/ui/Skeleton';
import { useToast } from '@/components/ui/Toast';
import { isMainnetBech32Address } from '@/lib/bitcoinAddress';
import {
  useFullConfig,
  useSetNickname,
  useSetPublicMiningConfig,
  useSetMiningPayoutAddress,
  useSetGhostMode,
  useSetArchiveMode,
  useSetReaper,
  useSetGhostPay,
  useSetPolicyProfile,
} from '@/hooks/queries';
import { toPolicyProfile } from '@/lib/api/config';

interface ChangeSetupData {
  nickname: string;
  public_mining: boolean;
  payout_address: string;
  ghost_mode: boolean;
  archive_mode: boolean;
  reaper: boolean;
  ghost_pay: boolean;
  mempool_profile: string;
}

interface ChangeSetupWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

const MEMPOOL_PROFILES = [
  {
    id: 'standard',
    label: 'Permissive',
    description: 'Accept all standard transactions. Most inclusive mempool policy.',
  },
  {
    id: 'strict',
    label: 'Strict',
    description: 'Higher fee thresholds and stricter filtering for a leaner mempool.',
  },
  {
    id: 'ghost',
    label: 'Ghost',
    description: 'Ghost-optimized policy with privacy preferences and spam filtering.',
  },
];

// Ghost is Bitcoin MAINNET (#588). The old regex also accepted `tb1`/`bcrt1`, and its character
// class was the base58 one applied case-insensitively, so it did not describe bech32 either.
const isValidBech32 = isMainnetBech32Address;

export default function ChangeSetupWizard({ isOpen, onClose }: ChangeSetupWizardProps) {
  const { data: fullConfig, isLoading: configLoading } = useFullConfig();
  const setNickname = useSetNickname();
  const setPublicMiningConfig = useSetPublicMiningConfig();
  const setPayoutAddress = useSetMiningPayoutAddress();
  const setGhostMode = useSetGhostMode();
  const setArchiveMode = useSetArchiveMode();
  const setReaper = useSetReaper();
  const setGhostPay = useSetGhostPay();
  // The mempool step drives the REAL tier-policy lever (`/config/policy_profile`),
  // which persists to pool.toml and applies on the next graceful restart.
  const setPolicyProfile = useSetPolicyProfile();
  const toast = useToast();

  // Track original values to detect changes
  const originalRef = useRef<ChangeSetupData | null>(null);

  // Extract current config values
  const currentConfig = useMemo<ChangeSetupData>(() => {
    if (!fullConfig) {
      return {
        nickname: '',
        public_mining: false,
        payout_address: '',
        ghost_mode: false,
        archive_mode: false,
        reaper: false,
        ghost_pay: false,
        mempool_profile: 'standard',
      };
    }
    return {
      nickname: (fullConfig as Record<string, unknown>).nickname as string || '',
      public_mining: fullConfig.public_mining ?? fullConfig.node?.public_mining ?? false,
      payout_address: fullConfig.payout?.address || '',
      ghost_mode: fullConfig.ghost_mode ?? fullConfig.node?.ghost_mode ?? false,
      archive_mode: fullConfig.archive_mode ?? fullConfig.node?.archive_mode ?? false,
      reaper: fullConfig.reaper ?? false,
      ghost_pay: fullConfig.ghost_pay ?? false,
      // Derive the coarse wizard choice from the REAL tier policy (only "strict"
      // has a distinct wizard option; everything else shows as "standard").
      mempool_profile: fullConfig.policy?.profile === 'strict' ? 'strict' : 'standard',
    };
  }, [fullConfig]);

  const steps = useMemo<WizardStep<ChangeSetupData>[]>(() => [
    {
      id: 'load',
      title: 'Load',
      description: 'Loading current configuration',
      validate: () => {
        if (configLoading) return 'Configuration is still loading...';
        return null;
      },
    },
    {
      id: 'identity',
      title: 'Identity',
      description: 'Update your node identity',
      validate: (data) => {
        if (!data.nickname.trim()) return 'Please enter a nickname for your node';
        if (data.nickname.trim().length < 2) return 'Nickname must be at least 2 characters';
        if (data.nickname.trim().length > 32) return 'Nickname must be 32 characters or less';
        return null;
      },
    },
    {
      id: 'mining',
      title: 'Mining',
      description: 'Update mining settings',
      validate: (data) => {
        if (data.public_mining && !data.payout_address.trim()) {
          return 'Payout address is required when public mining is enabled';
        }
        if (data.payout_address.trim() && !isValidBech32(data.payout_address.trim())) {
          return 'Please enter a valid mainnet bech32 Bitcoin address (starts with bc1)';
        }
        return null;
      },
    },
    {
      id: 'modes',
      title: 'Modes',
      description: 'Update node capabilities',
    },
    {
      id: 'mempool',
      title: 'Mempool',
      description: 'Update mempool profile',
      validate: (data) => {
        if (!data.mempool_profile) return 'Please select a mempool profile';
        return null;
      },
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Review and apply changes',
      onSubmit: async (data) => {
        const original = originalRef.current;
        if (!original) throw new Error('Original configuration not loaded');

        let changeCount = 0;

        if (data.nickname.trim() !== original.nickname) {
          await setNickname.mutateAsync(data.nickname.trim());
          changeCount++;
        }
        if (data.public_mining !== original.public_mining) {
          await setPublicMiningConfig.mutateAsync(data.public_mining);
          changeCount++;
        }
        if (data.payout_address.trim() !== original.payout_address) {
          if (data.payout_address.trim()) {
            await setPayoutAddress.mutateAsync(data.payout_address.trim());
            changeCount++;
          }
        }
        if (data.ghost_mode !== original.ghost_mode) {
          await setGhostMode.mutateAsync(data.ghost_mode);
          changeCount++;
        }
        if (data.archive_mode !== original.archive_mode) {
          await setArchiveMode.mutateAsync(data.archive_mode);
          changeCount++;
        }
        if (data.reaper !== original.reaper) {
          await setReaper.mutateAsync(data.reaper);
          changeCount++;
        }
        if (data.ghost_pay !== original.ghost_pay) {
          await setGhostPay.mutateAsync(data.ghost_pay);
          changeCount++;
        }
        if (data.mempool_profile !== original.mempool_profile) {
          await setPolicyProfile.mutateAsync(toPolicyProfile(data.mempool_profile));
          changeCount++;
        }

        if (changeCount > 0) {
          toast.success(
            'Configuration Updated',
            `${changeCount} setting${changeCount > 1 ? 's' : ''} updated successfully.`
          );
        } else {
          toast.info('No Changes', 'No settings were modified.');
        }
        onClose();
      },
    },
  ], [
    configLoading, setNickname, setPublicMiningConfig, setPayoutAddress,
    setGhostMode, setArchiveMode, setReaper, setGhostPay,
    setPolicyProfile, toast, onClose,
  ]);

  const wizard = useWizard<ChangeSetupData>({
    steps,
    initialData: currentConfig,
  });

  // When config loads, populate wizard data and save original
  useEffect(() => {
    if (fullConfig && !originalRef.current) {
      originalRef.current = currentConfig;
      wizard.setData(currentConfig);
    }
  }, [fullConfig, currentConfig]); // eslint-disable-line react-hooks/exhaustive-deps

  // Reset original ref when dialog closes
  useEffect(() => {
    if (!isOpen) {
      originalRef.current = null;
    }
  }, [isOpen]);

  const original = originalRef.current;

  function hasChanged(key: keyof ChangeSetupData): boolean {
    if (!original) return false;
    return wizard.data[key] !== original[key];
  }

  const NODE_MODES = [
    {
      key: 'ghost_mode' as const,
      label: 'Ghost Mode',
      shares: null,
      description: 'Enable Ghost protocol features, L2 participation, and node reward eligibility.',
    },
    {
      key: 'archive_mode' as const,
      label: 'Archive Mode',
      shares: '+5 shares',
      description: 'Store full blockchain history. Enables archive challenges and earns the highest share bonus.',
    },
    {
      key: 'reaper' as const,
      label: 'Reaper',
      shares: '+2 shares',
      description: 'Strict transaction policy filtering. Only accept standard Bitcoin transactions.',
    },
    {
      key: 'ghost_pay' as const,
      label: 'Ghost Pay',
      shares: '+4 shares',
      description: 'Participate in the Ghost Pay L2 instant payment network.',
    },
  ];

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Change Node Setup"
      wizard={wizard}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 0: Load Config */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              {configLoading ? (
                <div className="space-y-3">
                  <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                    <div className="flex items-center gap-3 mb-3">
                      <div className="w-5 h-5 rounded-full border-2 border-[var(--rule-strong)] border-t-orange-500 animate-spin" />
                      <span className="text-[color:var(--fg)] font-medium">Loading current configuration...</span>
                    </div>
                    <div className="space-y-2">
                      <Skeleton className="h-4 w-full" />
                      <Skeleton className="h-4 w-3/4" />
                      <Skeleton className="h-4 w-1/2" />
                    </div>
                  </div>
                  <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                    <Skeleton className="h-4 w-2/3 mb-2" />
                    <Skeleton className="h-4 w-full" />
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="p-4 rounded-lg bg-[var(--green)]/20 border border-[var(--green)]">
                    <div className="flex items-center gap-3">
                      <svg className="w-5 h-5 text-[color:var(--green)]" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                      </svg>
                      <span className="text-[color:var(--green)] font-medium">Configuration loaded</span>
                    </div>
                  </div>
                  <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                    <h4 className="text-[color:var(--fg)] font-medium mb-3">Current Settings</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex items-center justify-between">
                        <span className="text-[color:var(--dim)]">Nickname</span>
                        <span className="text-[color:var(--fg)]">{currentConfig.nickname || '--'}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-[color:var(--dim)]">Ghost Mode</span>
                        <Badge variant={currentConfig.ghost_mode ? 'success' : 'default'}>
                          {currentConfig.ghost_mode ? 'On' : 'Off'}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-[color:var(--dim)]">Public Mining</span>
                        <Badge variant={currentConfig.public_mining ? 'success' : 'default'}>
                          {currentConfig.public_mining ? 'On' : 'Off'}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-[color:var(--dim)]">Mempool Profile</span>
                        <Badge variant="warning">{currentConfig.mempool_profile}</Badge>
                      </div>
                    </div>
                  </div>
                  <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                    <p className="text-sm text-[color:var(--dim)]">
                      Review your current settings above. Click Next to step through each section
                      and make changes. Only modified values will be submitted.
                    </p>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 1: Identity */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <Input
                  label="Node Nickname"
                  type="text"
                  placeholder="my-ghost-node"
                  value={data.nickname}
                  onChange={(e) => setData({ nickname: e.target.value })}
                  helperText="A human-readable name for your node. Visible to peers on the network."
                  maxLength={32}
                />
                {hasChanged('nickname') && (
                  <div className="mt-2 flex items-center gap-2">
                    <Badge variant="warning">Changed</Badge>
                    <span className="text-xs text-[color:var(--dim)]">
                      from &quot;{original?.nickname || '--'}&quot;
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Step 2: Mining */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-[color:var(--fg)] font-medium">Public Mining</span>
                    <p className="text-sm text-[color:var(--dim)] mt-1">
                      Open your Stratum port to external miners. Earns +3 shares.
                    </p>
                  </div>
                  <Toggle
                    enabled={data.public_mining}
                    onChange={(enabled) => setData({ public_mining: enabled })}
                    label="Public Mining"
                  />
                </div>
                {hasChanged('public_mining') && (
                  <div className="mt-2">
                    <Badge variant="warning">Changed</Badge>
                  </div>
                )}
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <Input
                  label="Mining Payout Address"
                  type="text"
                  placeholder="bc1q..."
                  value={data.payout_address}
                  onChange={(e) => setData({ payout_address: e.target.value })}
                  helperText="Bitcoin address for receiving mining payouts. Must be bech32 (bc1...)."
                />
                {hasChanged('payout_address') && (
                  <div className="mt-2 flex items-center gap-2">
                    <Badge variant="warning">Changed</Badge>
                    <span className="text-xs text-[color:var(--dim)] truncate max-w-[150px]">
                      from &quot;{original?.payout_address || '--'}&quot;
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Step 3: Node Modes */}
          {wizard.currentStep === 3 && (
            <div className="space-y-3">
              {NODE_MODES.map((mode) => (
                <div key={mode.key} className="p-4 rounded-lg bg-[var(--surface)]/50">
                  <div className="flex items-center justify-between">
                    <div className="flex-1 mr-4">
                      <div className="flex items-center gap-2">
                        <span className="text-[color:var(--fg)] font-medium">{mode.label}</span>
                        {mode.shares && (
                          <Badge variant="info">{mode.shares}</Badge>
                        )}
                        {hasChanged(mode.key) && (
                          <Badge variant="warning">Changed</Badge>
                        )}
                      </div>
                      <p className="text-sm text-[color:var(--dim)] mt-1">{mode.description}</p>
                    </div>
                    <Toggle
                      enabled={data[mode.key]}
                      onChange={(enabled) => setData({ [mode.key]: enabled })}
                      label={mode.label}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Step 4: Mempool Profile */}
          {wizard.currentStep === 4 && (
            <div className="space-y-3">
              {MEMPOOL_PROFILES.map((profile) => (
                <button
                  key={profile.id}
                  type="button"
                  onClick={() => setData({ mempool_profile: profile.id })}
                  className={`
                    w-full text-left p-4 rounded-lg border transition-colors
                    ${data.mempool_profile === profile.id
                      ? 'bg-[var(--accent)]/30 border-[var(--accent)]'
                      : 'bg-[var(--surface)]/50 border-[var(--rule-strong)] hover:border-[var(--rule-strong)]'}
                  `}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-[color:var(--fg)] font-medium">{profile.label}</span>
                      {data.mempool_profile === profile.id && hasChanged('mempool_profile') && (
                        <Badge variant="warning">Changed</Badge>
                      )}
                    </div>
                    {data.mempool_profile === profile.id && (
                      <Badge variant="warning">Selected</Badge>
                    )}
                  </div>
                  <p className="text-sm text-[color:var(--dim)] mt-1">{profile.description}</p>
                </button>
              ))}
            </div>
          )}

          {/* Step 5: Confirm */}
          {wizard.currentStep === 5 && (
            <div className="space-y-4">
              {(() => {
                const changes: { label: string; from: string; to: string }[] = [];
                if (hasChanged('nickname')) {
                  changes.push({ label: 'Nickname', from: original?.nickname || '--', to: data.nickname });
                }
                if (hasChanged('public_mining')) {
                  changes.push({ label: 'Public Mining', from: original?.public_mining ? 'Enabled' : 'Disabled', to: data.public_mining ? 'Enabled' : 'Disabled' });
                }
                if (hasChanged('payout_address')) {
                  changes.push({ label: 'Payout Address', from: original?.payout_address || '--', to: data.payout_address || '--' });
                }
                if (hasChanged('ghost_mode')) {
                  changes.push({ label: 'Ghost Mode', from: original?.ghost_mode ? 'Enabled' : 'Disabled', to: data.ghost_mode ? 'Enabled' : 'Disabled' });
                }
                if (hasChanged('archive_mode')) {
                  changes.push({ label: 'Archive Mode', from: original?.archive_mode ? 'Enabled' : 'Disabled', to: data.archive_mode ? 'Enabled' : 'Disabled' });
                }
                if (hasChanged('reaper')) {
                  changes.push({ label: 'Reaper', from: original?.reaper ? 'Enabled' : 'Disabled', to: data.reaper ? 'Enabled' : 'Disabled' });
                }
                if (hasChanged('ghost_pay')) {
                  changes.push({ label: 'Ghost Pay', from: original?.ghost_pay ? 'Enabled' : 'Disabled', to: data.ghost_pay ? 'Enabled' : 'Disabled' });
                }
                if (hasChanged('mempool_profile')) {
                  changes.push({ label: 'Mempool Profile', from: original?.mempool_profile || '--', to: data.mempool_profile });
                }

                if (changes.length === 0) {
                  return (
                    <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                      <p className="text-[color:var(--dim)] text-sm">
                        No changes detected. All settings match the current configuration.
                      </p>
                    </div>
                  );
                }

                return (
                  <>
                    <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                      <h4 className="text-[color:var(--fg)] font-medium mb-3">
                        Changes to Apply ({changes.length})
                      </h4>
                      <div className="space-y-3">
                        {changes.map((change) => (
                          <div key={change.label} className="flex items-center justify-between">
                            <span className="text-[color:var(--dim)]">{change.label}</span>
                            <div className="flex items-center gap-2 text-sm">
                              <span className="text-[color:var(--fainter)] truncate max-w-[100px]">{change.from}</span>
                              <span className="text-[color:var(--fainter)]">-&gt;</span>
                              <span className="text-[color:var(--accent)] font-medium truncate max-w-[100px]">{change.to}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                      <p className="text-sm text-[color:var(--accent)]">
                        Click Finish to apply {changes.length} change{changes.length > 1 ? 's' : ''}.
                        Only modified settings will be updated.
                      </p>
                    </div>
                  </>
                );
              })()}
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
