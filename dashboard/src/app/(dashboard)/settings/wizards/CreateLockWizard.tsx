'use client';

import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useCreateLock } from '@/hooks/queries';
import type { LockDenomination, TimelockTier } from '@/lib/api/ghostpay';

type Denomination = LockDenomination;
type Timelock = '1w' | '1m' | '3m' | '6m' | '1y';

// ghost-pay exposes three timelock tiers; map the friendlier UI durations
// onto them (shorter durations → short tier, longer → long tier).
const TIMELOCK_TIERS: Record<Timelock, TimelockTier> = {
  '1w': 'short',
  '1m': 'standard',
  '3m': 'standard',
  '6m': 'long',
  '1y': 'long',
};

interface CreateLockData {
  denomination: Denomination;
  timelock: Timelock;
  label: string;
}

const DENOMINATIONS: { value: Denomination; label: string; sats: string }[] = [
  { value: 'micro', label: 'Micro', sats: '10,000 sats' },
  { value: 'tiny', label: 'Tiny', sats: '100,000 sats' },
  { value: 'small', label: 'Small', sats: '1,000,000 sats' },
  { value: 'medium', label: 'Medium', sats: '10,000,000 sats' },
  { value: 'large', label: 'Large', sats: '100,000,000 sats' },
];

const TIMELOCKS: { value: Timelock; label: string }[] = [
  { value: '1w', label: '1 week' },
  { value: '1m', label: '1 month' },
  { value: '3m', label: '3 months' },
  { value: '6m', label: '6 months' },
  { value: '1y', label: '1 year' },
];

interface CreateLockWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function CreateLockWizard({ isOpen, onClose }: CreateLockWizardProps) {
  const toast = useToast();
  const createLock = useCreateLock();

  const steps: WizardStep<CreateLockData>[] = [
    {
      id: 'denomination',
      title: 'Denomination',
      description: 'Select the lock denomination',
    },
    {
      id: 'timelock',
      title: 'Timelock',
      description: 'Select the lock duration',
    },
    {
      id: 'label',
      title: 'Label',
      description: 'Add an optional label',
      validate: (data) => {
        if (data.label && data.label.length > 64) {
          return 'Label must be 64 characters or less';
        }
        return null;
      },
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Review and create the lock',
      onSubmit: async (data) => {
        try {
          const result = await createLock.mutateAsync({
            denomination: data.denomination,
            timelock_tier: TIMELOCK_TIERS[data.timelock],
          });
          const denom = DENOMINATIONS.find((d) => d.value === data.denomination);
          toast.success(
            'Ghost Lock Created',
            `${denom?.label} lock ${result.lock.id} created. Fund the address ${result.lock.address} to activate it.`
          );
          onClose();
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to create lock';
          toast.error('Lock Creation Failed', message);
          throw err;
        }
      },
    },
  ];

  const wizard = useWizard<CreateLockData>({
    steps,
    initialData: {
      denomination: 'small',
      timelock: '3m',
      label: '',
    },
  });

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Create Ghost Lock"
      wizard={wizard}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 1: Denomination */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Select Denomination</h4>
                <div className="space-y-2">
                  {DENOMINATIONS.map((denom) => (
                    <button
                      key={denom.value}
                      onClick={() => setData({ denomination: denom.value })}
                      className={`w-full p-3 rounded-lg border text-left transition ${
                        data.denomination === denom.value
                          ? 'border-orange-500 bg-orange-900/20'
                          : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-gray-100 font-medium">{denom.label}</span>
                        <span className="text-gray-400">{denom.sats}</span>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 2: Timelock */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Select Timelock Duration</h4>
                <p className="text-sm text-gray-400 mb-3">
                  Funds are locked for this duration and cannot be withdrawn early.
                </p>
                <div className="space-y-2">
                  {TIMELOCKS.map((tl) => (
                    <button
                      key={tl.value}
                      onClick={() => setData({ timelock: tl.value })}
                      className={`w-full p-3 rounded-lg border text-left transition ${
                        data.timelock === tl.value
                          ? 'border-orange-500 bg-orange-900/20'
                          : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
                      }`}
                    >
                      <span className="text-gray-100">{tl.label}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Label */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <Input
                  label="Lock Label (optional)"
                  type="text"
                  value={data.label}
                  onChange={(e) => setData({ label: e.target.value })}
                  placeholder="e.g. Savings, Cold Storage"
                />
                <p className="text-sm text-gray-400 mt-2">
                  A label to identify this lock. Stored locally only.
                </p>
              </div>
            </div>
          )}

          {/* Step 4: Confirm */}
          {wizard.currentStep === 3 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Lock Summary</h4>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Denomination</span>
                    <span className="text-gray-100">
                      {DENOMINATIONS.find((d) => d.value === data.denomination)?.label}{' '}
                      ({DENOMINATIONS.find((d) => d.value === data.denomination)?.sats})
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Timelock</span>
                    <span className="text-gray-100">
                      {TIMELOCKS.find((t) => t.value === data.timelock)?.label}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Label</span>
                    <span className="text-gray-100">{data.label || '(none)'}</span>
                  </div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                <p className="text-sm text-orange-300">
                  Click Finish to create this Ghost Lock. Funds will be locked and cannot
                  be withdrawn until the timelock expires.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
