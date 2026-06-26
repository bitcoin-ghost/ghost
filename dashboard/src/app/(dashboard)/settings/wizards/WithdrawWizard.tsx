'use client';

import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useReconcileLock } from '@/hooks/queries';
import type { SettlementClass } from '@/lib/api/ghostpay';

interface WithdrawData {
  lock_id: string;
  destination_address: string;
  settlement_class: SettlementClass;
}

// Settlement classes accepted by ghost-pay's reconcile_lock handler:
// "express" (highest fee, fastest), "standard", "economy" (lowest fee).
const SETTLEMENT_CLASSES: { value: SettlementClass; label: string; desc: string }[] = [
  { value: 'express', label: 'Express', desc: 'Highest priority, fastest inclusion' },
  { value: 'standard', label: 'Standard', desc: 'Next checkpoint (~10 min)' },
  { value: 'economy', label: 'Economy', desc: 'Aggregate with others (lower fees)' },
];

function isValidBech32Address(addr: string): boolean {
  return /^(bc1|tb1|bcrt1)[a-zA-HJ-NP-Z0-9]{25,87}$/i.test(addr);
}

interface WithdrawWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function WithdrawWizard({ isOpen, onClose }: WithdrawWizardProps) {
  const toast = useToast();
  const reconcileLock = useReconcileLock();

  const steps: WizardStep<WithdrawData>[] = [
    {
      id: 'lock',
      title: 'Select Lock',
      description: 'Choose which Ghost Lock to withdraw from',
      validate: (data) => {
        if (!data.lock_id.trim()) {
          return 'Enter a lock ID';
        }
        return null;
      },
    },
    {
      id: 'address',
      title: 'Destination',
      description: 'Enter the L1 Bitcoin address',
      validate: (data) => {
        if (!data.destination_address.trim()) {
          return 'Enter a destination address';
        }
        if (!isValidBech32Address(data.destination_address.trim())) {
          return 'Invalid bech32 address (must start with bc1, tb1, or bcrt1)';
        }
        return null;
      },
    },
    {
      id: 'settlement',
      title: 'Settlement',
      description: 'Select settlement class',
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Review and submit withdrawal',
      onSubmit: async (data) => {
        try {
          const result = await reconcileLock.mutateAsync({
            lockId: data.lock_id.trim(),
            destinationAddress: data.destination_address.trim(),
            settlementClass: data.settlement_class,
          });
          // The reconcile route returns HTTP 200 with { success: false, error }
          // for business failures (lock not active/funded, pending withdrawal).
          if (!result.success) {
            throw new Error(result.error || 'Lock reconciliation was rejected');
          }
          const cls = SETTLEMENT_CLASSES.find((c) => c.value === data.settlement_class);
          toast.success(
            'Withdrawal Submitted',
            `Lock ${data.lock_id} settling ${result.settlement_amount ?? 0} sats to ${data.destination_address.slice(0, 12)}... via ${cls?.label} (fee ${result.fee_sats ?? 0} sats, withdrawal #${result.withdrawal_id ?? '?'})`
          );
          onClose();
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to submit withdrawal';
          toast.error('Withdrawal Failed', message);
          throw err;
        }
      },
    },
  ];

  const wizard = useWizard<WithdrawData>({
    steps,
    initialData: {
      lock_id: '',
      destination_address: '',
      settlement_class: 'standard',
    },
  });

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Withdraw / Reconcile Lock"
      wizard={wizard}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 1: Select Lock */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <Input
                  label="Lock ID"
                  type="text"
                  value={data.lock_id}
                  onChange={(e) => setData({ lock_id: e.target.value })}
                  placeholder="Enter the Ghost Lock ID to withdraw from"
                />
                <p className="text-sm text-gray-400 mt-2">
                  The lock must have an expired timelock to be eligible for withdrawal.
                </p>
              </div>
            </div>
          )}

          {/* Step 2: Destination Address */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <Input
                  label="Bitcoin Address"
                  type="text"
                  value={data.destination_address}
                  onChange={(e) => setData({ destination_address: e.target.value })}
                  placeholder="bc1q..."
                />
                <p className="text-sm text-gray-400 mt-2">
                  L1 Bitcoin address for settlement. Must be a valid bech32 address.
                </p>
              </div>
            </div>
          )}

          {/* Step 3: Settlement Class */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Settlement Class</h4>
                <div className="space-y-2">
                  {SETTLEMENT_CLASSES.map((cls) => (
                    <button
                      key={cls.value}
                      onClick={() => setData({ settlement_class: cls.value })}
                      className={`w-full p-3 rounded-lg border text-left transition ${
                        data.settlement_class === cls.value
                          ? 'border-orange-500 bg-orange-900/20'
                          : 'border-gray-700 bg-gray-800/50 hover:border-gray-600'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-gray-100 font-medium">{cls.label}</span>
                        {data.settlement_class === cls.value && (
                          <Badge variant="info">Selected</Badge>
                        )}
                      </div>
                      <p className="text-sm text-gray-400 mt-1">{cls.desc}</p>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 4: Confirm */}
          {wizard.currentStep === 3 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Withdrawal Summary</h4>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Lock ID</span>
                    <span className="text-gray-100 font-mono text-sm">{data.lock_id}</span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Destination</span>
                    <span className="text-gray-100 font-mono text-sm">
                      {data.destination_address.slice(0, 16)}...
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Settlement</span>
                    <Badge variant="info">
                      {SETTLEMENT_CLASSES.find((c) => c.value === data.settlement_class)?.label}
                    </Badge>
                  </div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                <p className="text-sm text-orange-300">
                  Click Finish to submit the withdrawal request. Settlement will occur
                  according to the selected class.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
