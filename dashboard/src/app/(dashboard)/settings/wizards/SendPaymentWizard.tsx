'use client';

import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useGhostId, useGhostPayStatus, useSendL2Payment } from '@/hooks/queries';

interface SendPaymentData {
  recipient: string;
  label: string;
  amount: string;
  memo: string;
}

interface ParsedRecipient {
  address: string;
  label: string | null;
  valid: boolean;
}

// A Ghost ID is a bech32m identity string. Mainnet uses the `ghost1...`
// human-readable prefix; test networks prepend the network name
// (e.g. `signetghost1...`, `testghost1...`). An optional `?l=N` query hint
// carries a label index the sender can attach to the payment.
function parseRecipient(raw: string): ParsedRecipient {
  const trimmed = raw.trim();
  let address = trimmed;
  let label: string | null = null;

  const queryIndex = trimmed.indexOf('?');
  if (queryIndex !== -1) {
    address = trimmed.slice(0, queryIndex);
    const query = new URLSearchParams(trimmed.slice(queryIndex + 1));
    const l = query.get('l');
    if (l !== null && l.trim() !== '') {
      label = l.trim();
    }
  }

  // bech32m Ghost ID: an optional lowercase network prefix, then `ghost1`,
  // then the bech32 data part (lowercase alphanumeric, excluding 1/b/i/o).
  const valid = /^[a-z]*ghost1[ac-hj-np-z02-9]{6,}$/.test(address);

  return { address, label, valid };
}

interface SendPaymentWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function SendPaymentWizard({ isOpen, onClose }: SendPaymentWizardProps) {
  const toast = useToast();
  const sendPayment = useSendL2Payment();
  const ghostIdQuery = useGhostId({ enabled: isOpen });
  const statusQuery = useGhostPayStatus();

  const availableSats = statusQuery.data?.total_balances ?? null;

  const steps: WizardStep<SendPaymentData>[] = [
    {
      id: 'recipient',
      title: 'Recipient',
      description: "Enter the recipient's Ghost ID",
      validate: (data) => {
        const parsed = parseRecipient(data.recipient);
        if (!parsed.address) {
          return 'Enter a recipient Ghost ID';
        }
        if (!parsed.valid) {
          return 'Invalid Ghost ID (must be a bech32m identity, e.g. ghost1...)';
        }
        return null;
      },
    },
    {
      id: 'amount',
      title: 'Amount',
      description: 'Enter the amount to send',
      validate: (data) => {
        const amount = Number(data.amount);
        if (!data.amount.trim() || !Number.isFinite(amount)) {
          return 'Enter an amount in satoshis';
        }
        if (!Number.isInteger(amount) || amount <= 0) {
          return 'Amount must be a whole number of satoshis greater than 0';
        }
        if (availableSats !== null && amount > availableSats) {
          return `Amount exceeds your available L2 balance (${availableSats.toLocaleString()} sats)`;
        }
        if (data.memo.length > 59) {
          return 'Memo cannot exceed 59 characters';
        }
        return null;
      },
    },
    {
      id: 'review',
      title: 'Review',
      description: 'Review the payment details',
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Send the payment',
      onSubmit: async (data) => {
        const parsed = parseRecipient(data.recipient);
        const senderGhostId = ghostIdQuery.data?.ghost_id;
        if (!senderGhostId) {
          throw new Error('Could not determine this node’s Ghost ID');
        }
        try {
          const result = await sendPayment.mutateAsync({
            senderGhostId,
            recipient: parsed.address,
            amountSats: Number(data.amount),
            memo: data.memo.trim() || undefined,
          });
          // The send route returns HTTP 200 with { success: false, error }
          // for business failures (insufficient balance, zero amount, etc.).
          if (!result.success) {
            const detail =
              result.available_sats !== undefined && result.requested_sats !== undefined
                ? `${result.error ?? 'Payment rejected'} (have ${result.available_sats.toLocaleString()} sats, need ${result.requested_sats.toLocaleString()})`
                : result.error || 'Payment was rejected';
            throw new Error(detail);
          }
          toast.success(
            'Payment Sent',
            `${Number(data.amount).toLocaleString()} sats to ${parsed.address.slice(0, 14)}... — payment ${result.payment_id ?? '(pending)'} (${result.status ?? 'pending'})`
          );
          onClose();
        } catch (err) {
          const message = err instanceof Error ? err.message : 'Failed to send payment';
          toast.error('Payment Failed', message);
          throw err;
        }
      },
    },
  ];

  const wizard = useWizard<SendPaymentData>({
    steps,
    initialData: {
      recipient: '',
      label: '',
      amount: '',
      memo: '',
    },
  });

  const parsed = parseRecipient(wizard.data.recipient);

  return (
    <WizardDialog
      isOpen={isOpen}
      onClose={onClose}
      title="Send L2 Payment"
      wizard={wizard}
      size="lg"
    >
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 1: Recipient */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <Input
                  label="Recipient Ghost ID"
                  type="text"
                  value={data.recipient}
                  onChange={(e) => setData({ recipient: e.target.value })}
                  placeholder="ghost1..."
                />
                <p className="text-sm text-gray-400 mt-2">
                  A bech32m Ghost identity. An optional <code>?l=N</code> label hint is
                  recognised and stripped automatically.
                </p>
                {parsed.label !== null && parsed.address && (
                  <p className="text-sm text-gray-300 mt-2">
                    Label hint detected: <Badge variant="info">{parsed.label}</Badge>
                  </p>
                )}
              </div>
            </div>
          )}

          {/* Step 2: Amount */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-gray-400 text-sm">Available L2 balance</span>
                  <span className="text-gray-100 font-mono text-sm">
                    {statusQuery.isLoading
                      ? 'Loading…'
                      : availableSats !== null
                        ? `${availableSats.toLocaleString()} sats`
                        : 'Unavailable'}
                  </span>
                </div>
                <Input
                  label="Amount (sats)"
                  type="number"
                  min={1}
                  step={1}
                  value={data.amount}
                  onChange={(e) => setData({ amount: e.target.value })}
                  placeholder="e.g. 10000"
                />
                <div className="mt-4">
                  <Input
                    label="Memo (optional)"
                    type="text"
                    value={data.memo}
                    onChange={(e) => setData({ memo: e.target.value })}
                    placeholder="Up to 59 characters"
                  />
                  <p className="text-sm text-gray-400 mt-2">
                    Attached to the payment for your reference. Maximum 59 characters.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Review */}
          {wizard.currentStep === 2 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Payment Summary</h4>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Recipient</span>
                    <span className="text-gray-100 font-mono text-sm">
                      {parsed.address.slice(0, 18)}...
                    </span>
                  </div>
                  {parsed.label !== null && (
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Label</span>
                      <Badge variant="info">{parsed.label}</Badge>
                    </div>
                  )}
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Amount</span>
                    <span className="text-gray-100 font-mono">
                      {Number(data.amount || 0).toLocaleString()} sats
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Network fee</span>
                    <span className="text-gray-100">
                      None (off-chain L2 transfer)
                    </span>
                  </div>
                  {data.memo.trim() && (
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">Memo</span>
                      <span className="text-gray-100 text-sm">{data.memo.trim()}</span>
                    </div>
                  )}
                </div>
              </div>
              <div className="p-4 rounded-lg bg-gray-800/50">
                <div className="flex items-center justify-between">
                  <span className="text-gray-400 text-sm">Paying from (this node)</span>
                  <span className="text-gray-100 font-mono text-sm">
                    {ghostIdQuery.data?.ghost_id
                      ? `${ghostIdQuery.data.ghost_id.slice(0, 18)}...`
                      : ghostIdQuery.isLoading
                        ? 'Loading…'
                        : 'Unavailable'}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Step 4: Confirm */}
          {wizard.currentStep === 3 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-gray-800/50">
                <h4 className="text-gray-100 font-medium mb-3">Ready to Send</h4>
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Amount</span>
                    <span className="text-gray-100 font-mono">
                      {Number(data.amount || 0).toLocaleString()} sats
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-gray-400">Recipient</span>
                    <span className="text-gray-100 font-mono text-sm">
                      {parsed.address.slice(0, 18)}...
                    </span>
                  </div>
                </div>
              </div>
              <div className="p-4 rounded-lg bg-orange-900/20 border border-orange-800">
                <p className="text-sm text-orange-300">
                  Click Finish to send this instant L2 payment. The transfer is recorded
                  immediately and cannot be reversed.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
