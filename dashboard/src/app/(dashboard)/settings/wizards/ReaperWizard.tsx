'use client';

import { useEffect, useRef } from 'react';
import { useWizard, WizardStep } from '@/hooks/useWizard';
import { WizardDialog } from '@/components/ui/Wizard';
import { Toggle } from '@/components/ui/Toggle';
import { Input } from '@/components/ui/Input';
import { Badge } from '@/components/ui/Badge';
import { useToast } from '@/components/ui/Toast';
import { useSetReaper, useReaperConfig } from '@/hooks/queries';
import { type ReaperSettings, REAPER_DEFAULTS } from '@/lib/api/config';

interface ReaperWizardProps {
  isOpen: boolean;
  onClose: () => void;
}

// Per-detector metadata, grouped by which enforcement layer honours it.
type Vector = { key: keyof ReaperSettings; label: string; desc: string };

const SHARED: Vector[] = [
  { key: 'reject_inscription', label: 'Inscription envelopes', desc: 'OP_FALSE OP_IF … OP_ENDIF ordinal/inscription wrappers' },
  { key: 'reject_dropstuffing', label: 'Drop stuffing', desc: 'A large data push immediately followed by OP_DROP / OP_2DROP' },
  { key: 'reject_fakepubkey', label: 'Fake pubkeys', desc: 'Bare multisig outputs with invalid pubkey prefixes' },
  { key: 'reject_annex', label: 'P2TR annex', desc: 'Taproot inputs carrying a witness annex' },
];
const NODE_ONLY: Vector[] = [
  { key: 'reject_opreturn', label: 'Oversized OP_RETURN', desc: 'OP_RETURN payloads larger than the max below' },
  { key: 'reject_runestone', label: 'Runestones', desc: 'Runestone protocol outputs (OP_RETURN OP_13)' },
  { key: 'reject_dustflood', label: 'Dust-flood (UTXO spam)', desc: '1-in/1-out txs whose sole non-OP_RETURN output is at/below the dust-flood threshold below' },
];
const POOL_ONLY: Vector[] = [
  { key: 'reject_unreachable_code', label: 'Unreachable code', desc: 'Witness code after an OP_RETURN opcode' },
  { key: 'reject_excess_witness', label: 'Excess witness', desc: 'Witness data beyond what execution requires' },
  { key: 'reject_legacy_data_stuffing', label: 'Legacy scriptSig stuffing', desc: 'Non-sig/non-pubkey data pushes in legacy scriptSig' },
  { key: 'validate_pubkey_curve_point', label: 'Pubkey curve check', desc: 'Also verify bare-multisig pubkeys are on the secp256k1 curve' },
];

export default function ReaperWizard({ isOpen, onClose }: ReaperWizardProps) {
  const { data: reaper } = useReaperConfig();
  const setReaper = useSetReaper();
  const toast = useToast();

  const steps: WizardStep<ReaperSettings>[] = [
    { id: 'enable', title: 'Enable', description: 'Master switch for Ghost Reaper' },
    { id: 'detectors', title: 'Detectors', description: 'Choose which vectors to reject' },
    {
      id: 'thresholds',
      title: 'Thresholds',
      description: 'Tune detector limits',
      validate: (d) =>
        d.max_op_return_bytes < 1 || d.min_drop_size < 1
          ? 'Thresholds must be greater than zero'
          : null,
    },
    {
      id: 'confirm',
      title: 'Confirm',
      description: 'Apply Ghost Reaper settings',
      onSubmit: async (data) => {
        const res = await setReaper.mutateAsync(data);
        toast.success(
          'Ghost Reaper Updated',
          res.persisted
            ? 'Applied to both reapers automatically — the pool template reaper on the ghost-pool restart and the ghostd mempool reaper (ghostd briefly restarts). No manual step needed.'
            : 'Reaper settings received but nothing was persisted.'
        );
        onClose();
      },
    },
  ];

  const wizard = useWizard<ReaperSettings>({
    steps,
    initialData: reaper?.settings ?? REAPER_DEFAULTS,
  });

  // The wizard captures its initial data at mount, before `useReaperConfig` has
  // resolved — so without this it would show REAPER_DEFAULTS and an untouched
  // Finish would overwrite the node's live per-vector reaper config with
  // all-on defaults. Re-seed from the live settings each time the dialog opens.
  const hydratedRef = useRef(false);
  useEffect(() => {
    if (!isOpen) {
      hydratedRef.current = false;
      return;
    }
    if (reaper?.settings && !hydratedRef.current) {
      hydratedRef.current = true;
      wizard.reset(reaper.settings);
    }
  }, [isOpen, reaper]); // eslint-disable-line react-hooks/exhaustive-deps

  const renderGroup = (
    title: string,
    note: string,
    vectors: Vector[],
    data: ReaperSettings,
    setData: (patch: Partial<ReaperSettings>) => void
  ) => (
    <div className="p-4 rounded-lg bg-[var(--surface)]/50 space-y-4">
      <div>
        <h4 className="text-[color:var(--fg)] font-medium">{title}</h4>
        <p className="text-xs text-[color:var(--fainter)] mt-0.5">{note}</p>
      </div>
      {vectors.map((v) => (
        <div key={v.key} className="flex items-center justify-between">
          <div className="pr-4">
            <span className="text-[color:var(--fg)]">{v.label}</span>
            <p className="text-sm text-[color:var(--dim)] mt-1">{v.desc}</p>
          </div>
          <Toggle
            enabled={Boolean(data[v.key])}
            onChange={(val) => setData({ [v.key]: val } as Partial<ReaperSettings>)}
            label={v.label}
            disabled={!data.enabled}
          />
        </div>
      ))}
    </div>
  );

  return (
    <WizardDialog isOpen={isOpen} onClose={onClose} title="Ghost Reaper Setup" wizard={wizard} size="lg">
      {(data, setData) => (
        <div className="space-y-6">
          {/* Step 1: Enable */}
          {wizard.currentStep === 0 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <div className="flex items-center justify-between">
                  <div className="pr-4">
                    <span className="text-[color:var(--fg)] font-medium">Reaper Mode</span>
                    <p className="text-sm text-[color:var(--dim)] mt-1">
                      Master switch. When off, every detector is disabled on both the pool template
                      reaper and the node mempool reaper. When on, the per-detector choices below apply.
                    </p>
                  </div>
                  <Toggle enabled={data.enabled} onChange={(e) => setData({ enabled: e })} label="Reaper" />
                </div>
              </div>
              {data.enabled && (
                <div className="p-4 rounded-lg bg-[var(--green)]/20 border border-[var(--green)]">
                  <div className="flex items-center gap-2">
                    <Badge variant="success">+2 Shares</Badge>
                    <span className="text-sm text-[color:var(--green)]">Enables Reaper capability verification for node rewards</span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Step 2: Detectors */}
          {wizard.currentStep === 1 && (
            <div className="space-y-4">
              {!data.enabled && (
                <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                  <p className="text-sm text-[color:var(--accent)]">Reaper is disabled — these choices take effect once you enable it.</p>
                </div>
              )}
              {renderGroup('Shared detectors', 'Apply to both the pool (block templates) and the node (mempool relay).', SHARED, data, setData)}
              {renderGroup('Node-level only', 'Apply to the ghostd mempool reaper. Applied automatically on save (ghostd briefly restarts).', NODE_ONLY, data, setData)}
              {renderGroup('Pool-level only', 'Apply to the pool template reaper (what this node mines).', POOL_ONLY, data, setData)}
            </div>
          )}

          {/* Step 3: Thresholds */}
          {wizard.currentStep === 2 && (
            <div className="p-4 rounded-lg bg-[var(--surface)]/50 space-y-4">
              <h4 className="text-[color:var(--fg)] font-medium">Thresholds</h4>
              <Input label="Max OP_RETURN bytes (shared)" type="number" value={data.max_op_return_bytes}
                onChange={(e) => setData({ max_op_return_bytes: Number(e.target.value) })} disabled={!data.enabled} />
              <Input label="Min drop-stuffing push size (shared)" type="number" value={data.min_drop_size}
                onChange={(e) => setData({ min_drop_size: Number(e.target.value) })} disabled={!data.enabled} />
              <Input label="Dust-flood threshold (sats)" type="number" value={data.dust_flood_threshold}
                onChange={(e) => setData({ dust_flood_threshold: Number(e.target.value) })} disabled={!data.enabled} />
              <Input label="Min excess-witness bytes (pool)" type="number" value={data.min_excess_witness_bytes}
                onChange={(e) => setData({ min_excess_witness_bytes: Number(e.target.value) })} disabled={!data.enabled} />
              <Input label="Legacy max push bytes (pool)" type="number" value={data.legacy_max_push_bytes}
                onChange={(e) => setData({ legacy_max_push_bytes: Number(e.target.value) })} disabled={!data.enabled} />
            </div>
          )}

          {/* Step 4: Confirm */}
          {wizard.currentStep === 3 && (
            <div className="space-y-4">
              <div className="p-4 rounded-lg bg-[var(--surface)]/50">
                <div className="flex items-center justify-between">
                  <span className="text-[color:var(--dim)]">Reaper Mode</span>
                  <Badge variant={data.enabled ? 'success' : 'default'}>{data.enabled ? 'Enabled' : 'Disabled'}</Badge>
                </div>
                <div className="border-t border-[var(--rule-strong)] mt-3 pt-3 grid grid-cols-2 gap-2 text-sm">
                  {[...SHARED, ...NODE_ONLY, ...POOL_ONLY].map((v) => (
                    <div key={v.key} className="flex items-center justify-between">
                      <span className="text-[color:var(--dim)]">{v.label}</span>
                      <Badge variant={data.enabled && Boolean(data[v.key]) ? 'error' : 'default'}>
                        {data.enabled && Boolean(data[v.key]) ? 'Reject' : 'Allow'}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
              <div className="p-4 rounded-lg bg-[var(--accent)]/20 border border-[var(--accent)]">
                <p className="text-sm text-[color:var(--accent)]">
                  Click Finish to save. Both reapers apply automatically: the pool reaper on the next
                  ghost-pool restart, and the ghostd mempool reaper is regenerated for you (ghostd briefly
                  restarts). No manual <code>ghost-setup apply-reaper</code> step is needed.
                </p>
              </div>
            </div>
          )}
        </div>
      )}
    </WizardDialog>
  );
}
