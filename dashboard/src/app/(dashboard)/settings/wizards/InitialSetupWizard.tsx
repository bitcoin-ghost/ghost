'use client';

import { useMemo } from 'react';
import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Input } from '@/components/ui/Input';
import { Toggle } from '@/components/ui/Toggle';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import {
  useSetNickname,
  useSetPublicMiningConfig,
  useSetMiningPayoutAddress,
  useSetGhostMode,
  useSetArchiveMode,
  useSetReaper,
  useSetGhostPay,
  useActivateMempoolProfile,
} from '@/hooks/queries';

interface InitialSetupData {
  nickname: string;
  public_mining: boolean;
  payout_address: string;
  ghost_mode: boolean;
  archive_mode: boolean;
  reaper: boolean;
  ghost_pay: boolean;
  mempool_profile: string;
}

interface InitialSetupWizardProps {
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

function isValidBech32(address: string): boolean {
  if (!address) return false;
  // Basic bech32/bech32m validation: bc1 or tb1 prefix, correct character set
  return /^(bc1|tb1|bcrt1)[a-zA-HJ-NP-Z0-9]{25,87}$/i.test(address);
}

export default function InitialSetupWizard({ isOpen, onClose }: InitialSetupWizardProps) {
  const setNickname = useSetNickname();
  const setPublicMiningConfig = useSetPublicMiningConfig();
  const setPayoutAddress = useSetMiningPayoutAddress();
  const setGhostMode = useSetGhostMode();
  const setArchiveMode = useSetArchiveMode();
  const setReaper = useSetReaper();
  const setGhostPay = useSetGhostPay();
  // The cosmetic `mempool_profile` field is written via the profile-activate
  // route; POST /config/mempool_profile is GET-only on the node and 405s.
  const activateMempoolProfile = useActivateMempoolProfile();
  const toast = useToast();

  const steps = useMemo<WizardStep<InitialSetupData>[]>(() => [
    {
      id: 'welcome',
      title: 'Welcome',
      description: 'First-time node setup',
    },
    {
      id: 'identity',
      title: 'Identity',
      description: 'Set your node identity',
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
      description: 'Configure mining settings',
      validate: (data) => {
        if (data.public_mining && !data.payout_address.trim()) {
          return 'Payout address is required when public mining is enabled';
        }
        if (data.payout_address.trim() && !isValidBech32(data.payout_address.trim())) {
          return 'Please enter a valid bech32 Bitcoin address (starts with bc1, tb1, or bcrt1)';
        }
        return null;
      },
    },
    {
      id: 'modes',
      title: 'Modes',
      description: 'Enable node capabilities',
    },
    {
      id: 'mempool',
      title: 'Mempool',
      description: 'Select a mempool profile',
      validate: (data) => {
        if (!data.mempool_profile) return 'Please select a mempool profile';
        return null;
      },
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Review and apply your setup',
      onSubmit: async (data) => {
        // Fire all config mutations sequentially
        await setNickname.mutateAsync(data.nickname.trim());
        await setPublicMiningConfig.mutateAsync(data.public_mining);
        if (data.payout_address.trim()) {
          await setPayoutAddress.mutateAsync(data.payout_address.trim());
        }
        await setGhostMode.mutateAsync(data.ghost_mode);
        await setArchiveMode.mutateAsync(data.archive_mode);
        await setReaper.mutateAsync(data.reaper);
        await setGhostPay.mutateAsync(data.ghost_pay);
        await activateMempoolProfile.mutateAsync(data.mempool_profile);
        toast.success(
          'Setup Complete',
          'Your node has been configured and is ready to operate.'
        );
        onClose();
      },
    },
  ], [
    setNickname, setPublicMiningConfig, setPayoutAddress,
    setGhostMode, setArchiveMode, setReaper, setGhostPay,
    activateMempoolProfile, toast, onClose,
  ]);

  const wizard = useWizard<InitialSetupData>({
    steps,
    // Default: Max Privacy/Shares (15/15) — all capabilities enabled
    initialData: {
      nickname: '',
      public_mining: true,
      payout_address: '',
      ghost_mode: true,
      archive_mode: true,
      reaper: true,
      ghost_pay: true,
      mempool_profile: 'standard',
    },
  });

  const NODE_MODES = [
    {
      key: 'ghost_mode' as const,
      label: 'Ghost Mode',
      shares: null,
      description: 'Enable Ghost protocol features, L2 participation, and node reward eligibility. Required for most other features.',
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
      description: 'Participate in the Ghost Pay L2 instant payment network. Requires L2 block storage.',
    },
  ];

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Initial Node Setup"
      wizard={wizard}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 0: Welcome */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-2">Welcome to Ghost Pool</h4>
                <p className="text-sm text-[color:var(--dim)]">
                  This wizard will guide you through the initial configuration of your Ghost node.
                  All capabilities are enabled by default for maximum privacy and shares (15/15).
                  You can disable anything you don&apos;t need.
                </p>
                <div className="mt-3 text-sm text-[color:var(--fainter)]">
                  <p className="font-medium text-[color:var(--dim)] mb-1">Share breakdown:</p>
                  <ul className="space-y-1 ml-2">
                    <li>Archive Mode: +5 shares</li>
                    <li>Ghost Pay: +4 shares</li>
                    <li>Public Mining: +3 shares</li>
                    <li>Reaper: +2 shares</li>
                    <li>Elder: +1 share (automatic via MPC ceremony)</li>
                  </ul>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-2">What we will set up</h4>
                <ul className="space-y-2 text-sm text-[color:var(--dim)]">
                  <li className="flex items-center gap-2">
                    <span className="text-[color:var(--accent)]">1.</span>
                    Node identity and nickname
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-[color:var(--accent)]">2.</span>
                    Mining configuration and payout address
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-[color:var(--accent)]">3.</span>
                    Node capabilities (Ghost Mode, Archive, Pure, Pay)
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-[color:var(--accent)]">4.</span>
                    Mempool transaction policy
                  </li>
                </ul>
              </div>
              <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                <p className="text-sm text-[color:var(--accent)]">
                  All settings can be changed later from the Settings page. Click Next to begin.
                </p>
              </div>
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
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <p className="text-sm text-[color:var(--dim)]">
                  Your node will also have a cryptographic node ID derived from its keys. The nickname
                  is an optional friendly label shown in the dashboard and to network peers.
                </p>
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
                      Open your Stratum port to external miners. Earns +3 shares in the node reward pool.
                    </p>
                  </div>
                  <Toggle
                    enabled={data.public_mining}
                    onChange={(enabled) => setData({ public_mining: enabled })}
                    label="Public Mining"
                  />
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <Input
                  label="Mining Payout Address"
                  type="text"
                  placeholder="bc1q..."
                  value={data.payout_address}
                  onChange={(e) => setData({ payout_address: e.target.value })}
                  helperText="Bitcoin address for receiving mining payouts. Must be a bech32 address (bc1...). Required if public mining is enabled."
                />
              </div>
              {data.public_mining && !data.payout_address && (
                <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                  <p className="text-sm text-[color:var(--accent)]">
                    A payout address is required for public mining. Miners connecting to your pool
                    will contribute shares to this address.
                  </p>
                </div>
              )}
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
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <p className="text-sm text-[color:var(--dim)]">
                  Capabilities are verified by the network through challenge-response checks.
                  Earning share bonuses requires passing verification with 95% accuracy over 7 days.
                </p>
              </div>
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
                    <span className="text-[color:var(--fg)] font-medium">{profile.label}</span>
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
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Setup Summary</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Nickname</span>
                    <span className="text-[color:var(--fg)] font-medium">{data.nickname || '--'}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Public Mining</span>
                    <Badge variant={data.public_mining ? 'success' : 'default'}>
                      {data.public_mining ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                  {data.payout_address && (
                    <div className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">Payout Address</span>
                      <span className="text-[color:var(--fg)] text-sm font-mono truncate max-w-[200px]">
                        {data.payout_address}
                      </span>
                    </div>
                  )}
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Node Capabilities</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Ghost Mode</span>
                    <Badge variant={data.ghost_mode ? 'success' : 'default'}>
                      {data.ghost_mode ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Archive Mode (+5)</span>
                    <Badge variant={data.archive_mode ? 'success' : 'default'}>
                      {data.archive_mode ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Reaper (+2)</span>
                    <Badge variant={data.reaper ? 'success' : 'default'}>
                      {data.reaper ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Ghost Pay (+4)</span>
                    <Badge variant={data.ghost_pay ? 'success' : 'default'}>
                      {data.ghost_pay ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <div className="flex items-center justify-between">
                  <span className="text-[color:var(--dim)]">Mempool Profile</span>
                  <Badge variant="warning">{data.mempool_profile}</Badge>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                <p className="text-sm text-[color:var(--accent)]">
                  Click Finish to apply all settings. Your node will be configured and start
                  operating with the selected parameters.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
