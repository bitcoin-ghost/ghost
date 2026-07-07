'use client';

import { useEffect, useRef } from 'react';
import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import {
  useSetPublicMiningConfig,
  useSetMiningPayoutAddress,
  useSetPoolName,
} from '@/hooks/queries/useConfigQueries';
import { useSetPrivateMining, useSetPublicMining } from '@/hooks/queries';
import { useNodeStatus, useMiningStatus } from '@/hooks/queries';

type MiningMode = 'private_solo' | 'private_pool' | 'pool';

interface PoolSetupData {
  mining_mode: MiningMode;
  public_mining: boolean;
  payout_address: string;
  pool_name: string;
}

interface PoolSetupWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

function isValidBech32Address(address: string): boolean {
  if (!address) return false;
  const trimmed = address.trim().toLowerCase();
  const validPrefixes = ['bc1', 'tb1', 'bcrt1'];
  const hasValidPrefix = validPrefixes.some((prefix) => trimmed.startsWith(prefix));
  if (!hasValidPrefix) return false;
  // Basic length check: bech32 addresses are typically 42-62 characters for segwit v0,
  // or 62 characters for segwit v1 (taproot). Allow a reasonable range.
  if (trimmed.length < 14 || trimmed.length > 90) return false;
  // Character set: bech32 uses lowercase alphanumeric excluding 1, b, i, o
  const bech32Chars = /^(bc1|tb1|bcrt1)[0-9a-z]{6,87}$/;
  return bech32Chars.test(trimmed);
}

const MODES: { key: MiningMode; label: string; desc: string }[] = [
  { key: 'private_solo', label: 'Private Solo', desc: 'Your miners only. Stratum port closed to external connections. All block rewards go to you.' },
  { key: 'private_pool', label: 'Private Pool', desc: 'Your miners + accept connected miners. You operate a pool and share rewards with connected miners.' },
  { key: 'pool', label: 'Public Pool', desc: 'Public pool only. Your node acts as a pool server for external miners.' },
];

function getMiningMode(privateMining?: boolean, publicMining?: boolean): MiningMode {
  if (privateMining && publicMining) return 'private_pool';
  if (publicMining) return 'pool';
  return 'private_solo';
}

export default function PoolSetupWizard({ isOpen, onClose }: PoolSetupWizardProps) {
  const { data: nodeStatus } = useNodeStatus();
  const { data: miningStatus } = useMiningStatus();
  const setPublicMiningConfig = useSetPublicMiningConfig();
  const setMiningPayoutAddress = useSetMiningPayoutAddress();
  const setPoolName = useSetPoolName();
  const setPrivateMining = useSetPrivateMining();
  const setPublicMining = useSetPublicMining();
  const toast = useToast();

  const currentMode = getMiningMode(miningStatus?.private_mining, miningStatus?.public_mining ?? nodeStatus?.public_mining);

  const steps: WizardStep<PoolSetupData>[] = [
    {
      id: 'mode',
      title: 'Mining Mode',
      description: 'Choose how your node participates in mining',
    },
    {
      id: 'payout',
      title: 'Payout',
      description: 'Set your mining payout address',
      validate: (data) => {
        if ((data.mining_mode === 'private_pool' || data.mining_mode === 'pool') && !data.payout_address.trim()) {
          return 'Payout address is required for pool modes';
        }
        if (data.payout_address.trim() && !isValidBech32Address(data.payout_address)) {
          return 'Invalid address. Must be a valid bech32 address starting with bc1, tb1, or bcrt1';
        }
        return null;
      },
    },
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
        const privateMining = data.mining_mode === 'private_solo' || data.mining_mode === 'private_pool';
        // Only Public Pool claims the +3 Public Mining capability. Private Pool
        // accepts connected miners but must NOT claim public-mining shares.
        const publicMining = data.mining_mode === 'pool';

        await Promise.all([
          setPrivateMining.mutateAsync(privateMining),
          setPublicMining.mutateAsync(publicMining),
          setPublicMiningConfig.mutateAsync(publicMining),
        ]);
        if (data.payout_address.trim()) {
          await setMiningPayoutAddress.mutateAsync(data.payout_address.trim());
        }
        if (data.pool_name.trim()) {
          await setPoolName.mutateAsync(data.pool_name.trim());
        }
        const modeLabel = MODES.find(m => m.key === data.mining_mode)?.label ?? data.mining_mode;
        toast.success(
          'Mining Setup Updated',
          `Mining mode set to ${modeLabel}`
        );
        onClose();
      },
    },
  ];

  const wizard = useWizard<PoolSetupData>({
    steps,
    initialData: {
      mining_mode: currentMode,
      public_mining: nodeStatus?.public_mining ?? false,
      payout_address: '',
      pool_name: '',
    },
  });

  // The wizard captures its initial mining mode at mount, before the node/mining
  // status queries resolve — so without this it defaults to `private_solo` and
  // an untouched Finish would switch a public pool back to private solo. Re-seed
  // the live mode each time the dialog opens. (payout_address / pool_name are
  // write-only inputs the status endpoints don't return, so they start empty.)
  const hydratedRef = useRef(false);
  useEffect(() => {
    if (!isOpen) {
      hydratedRef.current = false;
      return;
    }
    if ((miningStatus || nodeStatus) && !hydratedRef.current) {
      hydratedRef.current = true;
      wizard.reset({
        mining_mode: currentMode,
        public_mining: nodeStatus?.public_mining ?? false,
        payout_address: '',
        pool_name: '',
      });
    }
  }, [isOpen, miningStatus, nodeStatus]); // eslint-disable-line react-hooks/exhaustive-deps

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
          {/* Step 1: Mining Mode Selection */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              {MODES.map(({ key, label, desc }) => {
                const isActive = data.mining_mode === key;
                return (
                  <button
                    key={key}
                    onClick={() => setData({
                      mining_mode: key,
                      public_mining: key === 'pool',
                    })}
                    className={`w-full p-4 rounded-lg border text-left transition-all ${
                      isActive
                        ? 'bg-[var(--accent)]/20 border-[var(--accent)] ring-1 ring-[var(--accent)]/50'
                        : 'bg-[var(--surface)]/30 border-[var(--rule-strong)] hover:border-[var(--rule-strong)]'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <div className={`w-3 h-3 rounded-full border-2 flex items-center justify-center ${
                        isActive ? 'border-[var(--accent)]' : 'border-[var(--rule-strong)]'
                      }`}>
                        {isActive && <div className="w-1.5 h-1.5 rounded-full bg-[var(--accent)]" />}
                      </div>
                      <span className={`font-medium ${isActive ? 'text-[color:var(--accent)]' : 'text-[color:var(--dim)]'}`}>{label}</span>
                      {isActive && <Badge variant="success">Selected</Badge>}
                      {key === 'pool' && <Badge variant="info">+3 Shares</Badge>}
                    </div>
                    <div className="text-xs text-[color:var(--fainter)] ml-5">{desc}</div>
                  </button>
                );
              })}
            </div>
          )}

          {/* Step 2: Payout Address */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <Input
                  label="Mining Payout Address"
                  value={data.payout_address}
                  onChange={(e) => setData({ payout_address: e.target.value })}
                  placeholder="bc1q... / tb1q... / bcrt1q..."
                />
                <p className="text-sm text-[color:var(--dim)] mt-1">
                  Enter a bech32 Bitcoin address to receive mining payouts. Must start with
                  bc1 (mainnet), tb1 (testnet/signet), or bcrt1 (regtest).
                </p>
              </div>
              {data.payout_address.trim() && (
                <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Address Valid</span>
                    {isValidBech32Address(data.payout_address) ? (
                      <Badge variant="success">Valid</Badge>
                    ) : (
                      <Badge variant="error">Invalid</Badge>
                    )}
                  </div>
                  {isValidBech32Address(data.payout_address) && (
                    <div className="mt-2">
                      <span className="text-[color:var(--dim)] text-sm">Network: </span>
                      <span className="text-[color:var(--accent)] text-sm">
                        {data.payout_address.trim().toLowerCase().startsWith('bc1')
                          ? 'Mainnet'
                          : data.payout_address.trim().toLowerCase().startsWith('bcrt1')
                          ? 'Regtest'
                          : 'Testnet/Signet'}
                      </span>
                    </div>
                  )}
                </div>
              )}
              {data.mining_mode !== 'private_solo' && !data.payout_address.trim() && (
                <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                  <p className="text-sm text-[color:var(--accent)]">
                    A payout address is required for pool modes (the node receives its own share of pool rewards here).
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Step 3: Pool Info */}
          {wizard.currentStep === 2 && (
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

          {/* Step 4: Confirm */}
          {wizard.currentStep === 3 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <h4 className="text-[color:var(--fg)] font-medium mb-3">Configuration Summary</h4>
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[color:var(--dim)]">Mining Mode</span>
                    <div className="flex items-center gap-2">
                      <Badge variant="default">
                        {MODES.find(m => m.key === currentMode)?.label ?? currentMode}
                      </Badge>
                      <span className="text-[color:var(--fainter)]">-&gt;</span>
                      <Badge variant="success">
                        {MODES.find(m => m.key === data.mining_mode)?.label ?? data.mining_mode}
                      </Badge>
                    </div>
                  </div>
                  {data.payout_address.trim() && (
                    <div className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">Payout Address</span>
                      <span className="text-[color:var(--fg)] font-mono text-sm">
                        {data.payout_address.trim().slice(0, 12)}...
                        {data.payout_address.trim().slice(-8)}
                      </span>
                    </div>
                  )}
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
                  {data.mining_mode !== 'private_solo'
                    ? ' Miners will be able to connect to your node on port 3333.'
                    : ''}
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
