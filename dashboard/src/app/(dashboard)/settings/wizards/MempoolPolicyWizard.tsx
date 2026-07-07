'use client';

import { useMemo } from 'react';
import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Input } from '@/components/ui/Input';
import { Toggle } from '@/components/ui/Toggle';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import {
  useSaveMempoolProfile,
  useActivateMempoolProfile,
  useActivateTemplateProfile,
} from '@/hooks/queries';
import { DEFAULT_MEMPOOL_PROFILE } from '../MempoolProfileDialog';
import type { CustomMempoolProfile } from '@/lib/api/config';

interface MempoolPolicyData {
  mempool_profile: string;
  template_profile: string;
  profile_name: string;
  min_relay_tx_fee: number;
  max_mempool_size: number;
  mempool_expiry: number;
  filter_inscriptions: boolean;
  filter_brc20: boolean;
  filter_runes: boolean;
  datacarrier: boolean;
}

interface MempoolPolicyWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

const MEMPOOL_PROFILES = [
  {
    id: 'standard',
    label: 'Permissive',
    description: 'Accept all standard transactions. Largest mempool, most inclusive.',
  },
  {
    id: 'strict',
    label: 'Strict',
    description: 'Higher fee thresholds, filter spam-like transactions. Smaller mempool.',
  },
  {
    id: 'custom',
    label: 'Custom',
    description: 'Configure individual mempool parameters and filtering rules.',
  },
];

const TEMPLATE_PROFILES = [
  {
    id: 'standard',
    label: 'Default',
    description: 'Standard block template with fee-rate priority ordering.',
  },
  {
    id: 'strict',
    label: 'Compact',
    description: 'Smaller blocks, higher minimum fee, prioritize efficient transactions.',
  },
  {
    id: 'max_fee',
    label: 'Maximum',
    description: 'Maximize fee revenue. Include all valid transactions up to weight limit.',
  },
];

export default function MempoolPolicyWizard({ isOpen, onClose }: MempoolPolicyWizardProps) {
  // The mempool/template profile fields are the node's cosmetic dashboard
  // mirror, written via the profile-activate routes. The old POST
  // /config/{mempool,template}_profile endpoints are GET-only and 405.
  const saveMempoolProfile = useSaveMempoolProfile();
  const activateMempoolProfile = useActivateMempoolProfile();
  const activateTemplateProfile = useActivateTemplateProfile();
  const toast = useToast();

  const steps = useMemo<WizardStep<MempoolPolicyData>[]>(() => {
    const allSteps: WizardStep<MempoolPolicyData>[] = [
      {
        id: 'mempool-profile',
        title: 'Mempool',
        description: 'Select a mempool policy profile',
        validate: (data) => {
          if (!data.mempool_profile) return 'Please select a mempool profile';
          return null;
        },
      },
      {
        id: 'core-settings',
        title: 'Core Settings',
        description: 'Configure core mempool parameters',
        validate: (data) => {
          if (data.mempool_profile !== 'custom') return null;
          if (!data.profile_name.trim()) return 'Please name this custom profile';
          if (!Number.isFinite(data.min_relay_tx_fee) || data.min_relay_tx_fee <= 0)
            return 'Minimum relay fee must be greater than 0';
          if (!Number.isFinite(data.max_mempool_size) || data.max_mempool_size < 5)
            return 'Mempool size must be at least 5 MB';
          if (data.max_mempool_size > 10000) return 'Mempool size must be at most 10000 MB';
          if (!Number.isFinite(data.mempool_expiry) || data.mempool_expiry < 1)
            return 'Mempool expiry must be at least 1 hour';
          if (data.mempool_expiry > 8760) return 'Mempool expiry must be at most 8760 hours (1 year)';
          return null;
        },
      },
      {
        id: 'filtering',
        title: 'Filtering',
        description: 'Configure transaction filtering rules',
      },
      {
        id: 'template-profile',
        title: 'Template',
        description: 'Select a block template profile',
        validate: (data) => {
          if (!data.template_profile) return 'Please select a template profile';
          return null;
        },
      },
      {
        id: 'confirm',
        title: 'Confirm',
        description: 'Review and apply your mempool policy',
        onSubmit: async (data) => {
          if (data.mempool_profile === 'custom') {
            // Build a real custom profile from the collected fields (defaults
            // fill in everything the wizard doesn't surface), persist it, then
            // activate it — mirroring MempoolProfileDialog's save+activate flow.
            const customProfile: CustomMempoolProfile = {
              ...DEFAULT_MEMPOOL_PROFILE,
              name: data.profile_name.trim(),
              min_relay_tx_fee: data.min_relay_tx_fee,
              max_mempool_size: data.max_mempool_size,
              mempool_expiry: data.mempool_expiry,
              datacarrier: data.datacarrier,
              filter_inscriptions: data.filter_inscriptions,
              filter_brc20: data.filter_brc20,
              filter_runes: data.filter_runes,
            };
            await saveMempoolProfile.mutateAsync(customProfile);
            await activateMempoolProfile.mutateAsync(customProfile.name);
          } else {
            await activateMempoolProfile.mutateAsync(data.mempool_profile);
          }
          await activateTemplateProfile.mutateAsync(data.template_profile);
          toast.success(
            'Mempool Policy Updated',
            data.mempool_profile === 'custom'
              ? `Custom profile "${data.profile_name.trim()}" saved and activated, template set to ${data.template_profile}`
              : `Mempool profile set to ${data.mempool_profile}, template set to ${data.template_profile}`
          );
          onClose();
        },
      },
    ];
    return allSteps;
  }, [saveMempoolProfile, activateMempoolProfile, activateTemplateProfile, toast, onClose]);

  const wizard = useWizard<MempoolPolicyData>({
    steps,
    initialData: {
      mempool_profile: 'standard',
      template_profile: 'standard',
      profile_name: 'Custom Policy',
      min_relay_tx_fee: 1,
      max_mempool_size: 300,
      mempool_expiry: 336,
      filter_inscriptions: false,
      filter_brc20: false,
      filter_runes: false,
      datacarrier: true,
    },
  });

  const isCustom = wizard.data.mempool_profile === 'custom';

  // Skip core-settings and filtering steps when not custom
  const handleNext = async () => {
    if (wizard.currentStep === 0 && !isCustom) {
      // Validate, then skip to template step (index 3)
      const err = steps[0].validate?.(wizard.data);
      if (err) return;
      // We need to advance past steps 1 and 2
      await wizard.next(); // go to 1
      await wizard.next(); // go to 2
      await wizard.next(); // go to 3
      return;
    }
    await wizard.next();
  };

  const handleBack = () => {
    if (!isCustom && wizard.currentStep === 3) {
      // Jump back to mempool profile step
      wizard.back(); // go to 2
      wizard.back(); // go to 1
      wizard.back(); // go to 0
      return;
    }
    wizard.back();
  };

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Mempool Policy Configuration"
      wizard={{ ...wizard, next: handleNext, back: handleBack }}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 0: Mempool Profile */}
          {wizard.currentStep === 0 && (
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

          {/* Step 1: Core Settings (custom only) */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <Input
                  label="Profile Name"
                  type="text"
                  value={data.profile_name}
                  onChange={(e) => setData({ profile_name: e.target.value })}
                  helperText="A label for this custom profile; it is saved and activated on your node"
                />
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <Input
                  label="Minimum Relay TX Fee (sat/vB)"
                  type="number"
                  min={0.1}
                  step={0.1}
                  value={data.min_relay_tx_fee}
                  onChange={(e) => setData({ min_relay_tx_fee: parseFloat(e.target.value) || 0 })}
                  helperText="Transactions below this fee rate will not be relayed or accepted into the mempool"
                />
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <Input
                  label="Max Mempool Size (MB)"
                  type="number"
                  min={5}
                  step={1}
                  value={data.max_mempool_size}
                  onChange={(e) => setData({ max_mempool_size: parseInt(e.target.value) || 0 })}
                  helperText="Maximum size of the in-memory transaction pool. Lower values evict low-fee transactions sooner."
                />
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <Input
                  label="Mempool Expiry (hours)"
                  type="number"
                  min={1}
                  step={1}
                  value={data.mempool_expiry}
                  onChange={(e) => setData({ mempool_expiry: parseInt(e.target.value) || 0 })}
                  helperText="Transactions older than this will be evicted from the mempool"
                />
              </div>
            </div>
          )}

          {/* Step 2: Filtering (custom only) */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-[color:var(--fg)] font-medium">Filter Inscriptions</span>
                    <p className="text-sm text-[color:var(--dim)] mt-1">
                      Reject Ordinal inscription transactions from the mempool
                    </p>
                  </div>
                  <Toggle
                    enabled={data.filter_inscriptions}
                    onChange={(enabled) => setData({ filter_inscriptions: enabled })}
                    label="Filter Inscriptions"
                  />
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-[color:var(--fg)] font-medium">Filter BRC-20</span>
                    <p className="text-sm text-[color:var(--dim)] mt-1">
                      Reject BRC-20 token transfer transactions
                    </p>
                  </div>
                  <Toggle
                    enabled={data.filter_brc20}
                    onChange={(enabled) => setData({ filter_brc20: enabled })}
                    label="Filter BRC-20"
                  />
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-[color:var(--fg)] font-medium">Filter Runes</span>
                    <p className="text-sm text-[color:var(--dim)] mt-1">
                      Reject Rune protocol transactions from the mempool
                    </p>
                  </div>
                  <Toggle
                    enabled={data.filter_runes}
                    onChange={(enabled) => setData({ filter_runes: enabled })}
                    label="Filter Runes"
                  />
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-[color:var(--fg)] font-medium">Allow OP_RETURN (Datacarrier)</span>
                    <p className="text-sm text-[color:var(--dim)] mt-1">
                      Accept transactions with OP_RETURN data outputs
                    </p>
                  </div>
                  <Toggle
                    enabled={data.datacarrier}
                    onChange={(enabled) => setData({ datacarrier: enabled })}
                    label="Datacarrier"
                  />
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Template Profile */}
          {wizard.currentStep === 3 && (
            <div className="space-y-3">
              {TEMPLATE_PROFILES.map((profile) => (
                <button
                  key={profile.id}
                  type="button"
                  onClick={() => setData({ template_profile: profile.id })}
                  className={`
                    w-full text-left p-4 rounded-lg border transition-colors
                    ${data.template_profile === profile.id
                      ? 'bg-[var(--accent)]/30 border-[var(--accent)]'
                      : 'bg-[var(--surface)]/50 border-[var(--rule-strong)] hover:border-[var(--rule-strong)]'}
                  `}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--fg)] font-medium">{profile.label}</span>
                    {data.template_profile === profile.id && (
                      <Badge variant="warning">Selected</Badge>
                    )}
                  </div>
                  <p className="text-sm text-[color:var(--dim)] mt-1">{profile.description}</p>
                </button>
              ))}
            </div>
          )}

          {/* Step 4: Confirm Summary */}
          {wizard.currentStep === 4 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Configuration Summary</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Mempool Profile</span>
                    <Badge variant="warning">{data.mempool_profile}</Badge>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Template Profile</span>
                    <Badge variant="warning">{data.template_profile}</Badge>
                  </div>
                </div>
              </div>
              {isCustom && (
                <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                  <h4 className="text-[color:var(--fg)] font-medium mb-3">Custom Settings</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">Profile Name</span>
                      <span className="text-[color:var(--fg)]">{data.profile_name}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">Min Relay Fee</span>
                      <span className="text-[color:var(--fg)]">{data.min_relay_tx_fee} sat/vB</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">Max Mempool Size</span>
                      <span className="text-[color:var(--fg)]">{data.max_mempool_size} MB</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">Mempool Expiry</span>
                      <span className="text-[color:var(--fg)]">{data.mempool_expiry} hours</span>
                    </div>
                  </div>
                </div>
              )}
              {isCustom && (
                <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                  <h4 className="text-[color:var(--fg)] font-medium mb-3">Filtering</h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">Filter Inscriptions</span>
                      <Badge variant={data.filter_inscriptions ? 'error' : 'success'}>
                        {data.filter_inscriptions ? 'Blocked' : 'Allowed'}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">Filter BRC-20</span>
                      <Badge variant={data.filter_brc20 ? 'error' : 'success'}>
                        {data.filter_brc20 ? 'Blocked' : 'Allowed'}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">Filter Runes</span>
                      <Badge variant={data.filter_runes ? 'error' : 'success'}>
                        {data.filter_runes ? 'Blocked' : 'Allowed'}
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">OP_RETURN Data</span>
                      <Badge variant={data.datacarrier ? 'success' : 'error'}>
                        {data.datacarrier ? 'Allowed' : 'Blocked'}
                      </Badge>
                    </div>
                  </div>
                </div>
              )}
              <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                <p className="text-sm text-[color:var(--accent)]">
                  Click Finish to apply these changes. Your node mempool and template configuration will be updated immediately.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
