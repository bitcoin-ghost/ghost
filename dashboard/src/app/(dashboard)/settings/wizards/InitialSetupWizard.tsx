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
  useSetArchiveMode,
  useSetReaper,
  useSetPolicyProfile,
} from '@/hooks/queries';
import { toPolicyProfile } from '@/lib/api/config';

interface InitialSetupData {
  nickname: string;
  archive_mode: boolean;
  reaper: boolean;
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

export default function InitialSetupWizard({ isOpen, onClose }: InitialSetupWizardProps) {
  const setNickname = useSetNickname();
  const setArchiveMode = useSetArchiveMode();
  const setReaper = useSetReaper();
  // The mempool step drives the REAL tier-policy lever (`/config/policy_profile`),
  // which persists to pool.toml and applies on the next graceful restart.
  const setPolicyProfile = useSetPolicyProfile();
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
      id: 'modes',
      title: 'Modes',
      description: 'Choose node settings',
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
        await setArchiveMode.mutateAsync(data.archive_mode);
        await setReaper.mutateAsync(data.reaper);
        await setPolicyProfile.mutateAsync(toPolicyProfile(data.mempool_profile));
        toast.success(
          'Setup Complete',
          'Your node has been configured and is ready to operate.'
        );
        onClose();
      },
    },
  ], [
    setNickname, setArchiveMode, setReaper,
    setPolicyProfile, toast, onClose,
  ]);

  const wizard = useWizard<InitialSetupData>({
    steps,
    initialData: {
      nickname: '',
      archive_mode: true,
      reaper: true,
      mempool_profile: 'standard',
    },
  });

  const NODE_MODES = [
    {
      key: 'archive_mode' as const,
      label: 'Archive Mode',
      description: 'Store full blockchain history (disables pruning).',
    },
    {
      key: 'reaper' as const,
      label: 'Reaper',
      description: 'Strict transaction policy filtering. Only accept standard Bitcoin transactions.',
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
                  Archive Mode and Reaper are enabled by default. You can disable anything you
                  don&apos;t need.
                </p>
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
                    Node settings (Archive Mode, Reaper)
                  </li>
                  <li className="flex items-center gap-2">
                    <span className="text-[color:var(--accent)]">3.</span>
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

          {/* Step 2: Node Modes */}
          {wizard.currentStep === 2 && (
            <div className="space-y-3">
              {NODE_MODES.map((mode) => (
                <div key={mode.key} className="p-4 rounded-lg bg-[var(--surface)]/50">
                  <div className="flex items-center justify-between">
                    <div className="flex-1 mr-4">
                      <div className="flex items-center gap-2">
                        <span className="text-[color:var(--fg)] font-medium">{mode.label}</span>
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

          {/* Step 3: Mempool Profile */}
          {wizard.currentStep === 3 && (
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

          {/* Step 4: Confirm */}
          {wizard.currentStep === 4 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Setup Summary</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Nickname</span>
                    <span className="text-[color:var(--fg)] font-medium">{data.nickname || '--'}</span>
                  </div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Node Settings</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Archive Mode</span>
                    <Badge variant={data.archive_mode ? 'success' : 'default'}>
                      {data.archive_mode ? 'Enabled' : 'Disabled'}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Reaper</span>
                    <Badge variant={data.reaper ? 'success' : 'default'}>
                      {data.reaper ? 'Enabled' : 'Disabled'}
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
