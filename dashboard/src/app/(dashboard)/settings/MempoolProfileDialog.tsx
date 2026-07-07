"use client";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Dialog } from "@/components/ui/Dialog";
import { type CustomMempoolProfile } from "@/hooks/queries";
import { ToggleRow, NumberInput } from "./shared";

export const DEFAULT_MEMPOOL_PROFILE: Omit<CustomMempoolProfile, "name"> = {
  // Core settings
  min_relay_tx_fee: 1,
  max_mempool_size: 300,
  mempool_expiry: 336,
  max_orphan_tx: 100,
  permit_bare_multisig: true,
  datacarrier: true,
  datacarrier_size: 83,
  accept_non_std_outputs: false,
  mempool_full_rbf: true,
  incremental_relay_fee: 1,
  // Ghost Extensions
  dust_limit: 546,
  max_tx_size: 100000,
  prefer_native_segwit: false,
  reject_legacy_p2pkh: false,
  filter_inscriptions: false,
  filter_brc20: false,
  filter_runes: false,
  max_witness_size: 500000,
  prioritize_ln_opens: false,
  prioritize_ln_closes: false,
  prefer_coinjoin: false,
  min_coinjoin_participants: 3,
  max_ancestor_count: 25,
  max_descendant_count: 25,
  max_ancestor_size: 101000,
  // BUDS tiers
  accept_t0: true,
  accept_t1: false,
  accept_t2: false,
  accept_t3: false,
};

interface MempoolProfileDialogProps {
  isOpen: boolean;
  onClose: () => void;
  profile: CustomMempoolProfile | null;
  onProfileChange: (profile: CustomMempoolProfile) => void;
  onSave: () => void;
  saving: boolean;
  budsEnabled: boolean;
}

export function MempoolProfileDialog({
  isOpen,
  onClose,
  profile,
  onProfileChange,
  onSave,
  saving,
  budsEnabled,
}: MempoolProfileDialogProps) {
  if (!profile) return null;

  const update = (patch: Partial<CustomMempoolProfile>) => {
    onProfileChange({ ...profile, ...patch });
  };

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title={profile.name ? `Edit Profile: ${profile.name}` : "New Mempool Profile"}
    >
      <div className="space-y-4 max-h-[70vh] overflow-y-auto">
        {/* Advanced User Warning */}
        <div className="p-4 bg-[var(--accent)]/20 border border-[var(--accent)] rounded-lg">
          <div className="flex items-start gap-3">
            <span className="text-[color:var(--accent)] text-xl">&#9888;</span>
            <div>
              <h4 className="text-[color:var(--accent)] font-medium">Advanced Configuration</h4>
              <p className="text-[color:var(--accent)]/80 text-sm mt-1">
                Custom mempool profiles are intended for advanced users. Incorrect settings may
                cause your node to reject valid transactions or accept unwanted ones.
              </p>
              <p className="text-[color:var(--accent)]/80 text-sm mt-2">
                If you&apos;re unsure, use one of the preset profiles instead. For guidance, refer to
                the <a href="/docs/mempool-profiles" className="text-[color:var(--accent)] underline hover:text-[color:var(--accent)]">Mempool Profile Guide</a>.
              </p>
            </div>
          </div>
        </div>

        {/* Profile Name */}
        <div>
          <label className="block text-sm text-[color:var(--dim)] mb-1">Profile Name</label>
          <Input
            value={profile.name}
            onChange={(e) => update({ name: e.target.value })}
            placeholder="My Custom Profile"
          />
        </div>

        {/* Core Mempool Settings */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--dim)] mb-3">Core Mempool Settings</h4>
          <div className="space-y-2">
            <NumberInput
              label="Min Relay Fee"
              value={profile.min_relay_tx_fee}
              onChange={(v) => update({ min_relay_tx_fee: v })}
              min={0}
              step={0.1}
              unit="sat/vB"
            />
            <NumberInput
              label="Max Mempool Size"
              value={profile.max_mempool_size}
              onChange={(v) => update({ max_mempool_size: v })}
              min={50}
              max={1000}
              unit="MB"
            />
            <NumberInput
              label="Mempool Expiry"
              value={profile.mempool_expiry}
              onChange={(v) => update({ mempool_expiry: v })}
              min={1}
              unit="hours"
            />
            <NumberInput
              label="Max Orphan Transactions"
              value={profile.max_orphan_tx}
              onChange={(v) => update({ max_orphan_tx: v })}
              min={0}
              max={1000}
              unit=""
            />
          </div>
        </div>

        {/* Transaction Acceptance */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--dim)] mb-3">Transaction Acceptance</h4>
          <div className="space-y-2">
            <ToggleRow
              label="Permit Bare Multisig"
              description="Allow bare multisig without P2SH wrapper"
              enabled={profile.permit_bare_multisig}
              onChange={(v) => update({ permit_bare_multisig: v })}
            />
            <ToggleRow
              label="Allow OP_RETURN"
              description="Accept transactions with OP_RETURN outputs"
              enabled={profile.datacarrier}
              onChange={(v) => update({ datacarrier: v })}
            />
            {profile.datacarrier && (
              <NumberInput
                label="Max OP_RETURN Size"
                value={profile.datacarrier_size}
                onChange={(v) => update({ datacarrier_size: v })}
                min={0}
                max={10000}
                unit="bytes"
              />
            )}
            <ToggleRow
              label="Accept Non-Standard Outputs"
              description="Accept outputs that don't match standard templates"
              enabled={profile.accept_non_std_outputs}
              onChange={(v) => update({ accept_non_std_outputs: v })}
            />
          </div>
        </div>

        {/* RBF Settings */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--dim)] mb-3">Replace-By-Fee (RBF)</h4>
          <div className="space-y-2">
            <ToggleRow
              label="Full RBF"
              description="Allow replacement of any unconfirmed transaction"
              enabled={profile.mempool_full_rbf}
              onChange={(v) => update({ mempool_full_rbf: v })}
            />
            <NumberInput
              label="Incremental Relay Fee"
              value={profile.incremental_relay_fee}
              onChange={(v) => update({ incremental_relay_fee: v })}
              min={0}
              step={0.1}
              unit="sat/vB"
            />
          </div>
        </div>

        {/* Ghost Extensions - Spam/Dust Protection */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--accent)] mb-3">Spam & Dust Protection</h4>
          <div className="space-y-2">
            <NumberInput
              label="Dust Limit"
              value={profile.dust_limit}
              onChange={(v) => update({ dust_limit: v })}
              min={0}
              unit="sats"
            />
            <NumberInput
              label="Max Transaction Size"
              value={profile.max_tx_size}
              onChange={(v) => update({ max_tx_size: v })}
              min={1000}
              max={400000}
              unit="vB"
            />
            <NumberInput
              label="Max Witness Size"
              value={profile.max_witness_size}
              onChange={(v) => update({ max_witness_size: v })}
              min={0}
              max={4000000}
              unit="bytes"
            />
          </div>
        </div>

        {/* Ghost Extensions - Output Preferences */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--accent)] mb-3">Output Type Preferences</h4>
          <div className="space-y-2">
            <ToggleRow
              label="Prefer Native SegWit"
              description="Prioritize bc1q/bc1p (bech32/bech32m) outputs"
              enabled={profile.prefer_native_segwit}
              onChange={(v) => update({ prefer_native_segwit: v })}
            />
            <ToggleRow
              label="Reject Legacy P2PKH"
              description="Reject transactions with legacy 1xxx outputs"
              enabled={profile.reject_legacy_p2pkh}
              onChange={(v) => update({ reject_legacy_p2pkh: v })}
            />
          </div>
        </div>

        {/* Ghost Extensions - Inscription Filtering */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--accent)] mb-3">Inscription Filtering</h4>
          <div className="space-y-2">
            <ToggleRow
              label="Filter Ordinal Inscriptions"
              description="Reject transactions containing Ordinal inscriptions"
              enabled={profile.filter_inscriptions}
              onChange={(v) => update({ filter_inscriptions: v })}
            />
            <ToggleRow
              label="Filter BRC-20 Tokens"
              description="Reject BRC-20 token transfer transactions"
              enabled={profile.filter_brc20}
              onChange={(v) => update({ filter_brc20: v })}
            />
            <ToggleRow
              label="Filter Runes"
              description="Reject Rune protocol transactions"
              enabled={profile.filter_runes}
              onChange={(v) => update({ filter_runes: v })}
            />
          </div>
        </div>

        {/* Ghost Extensions - Lightning & Privacy */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--accent)] mb-3">Lightning & Privacy</h4>
          <div className="space-y-2">
            <ToggleRow
              label="Prioritize Lightning Opens"
              description="Boost priority for Lightning channel opening transactions"
              enabled={profile.prioritize_ln_opens}
              onChange={(v) => update({ prioritize_ln_opens: v })}
            />
            <ToggleRow
              label="Prioritize Lightning Closes"
              description="Boost priority for cooperative channel close transactions"
              enabled={profile.prioritize_ln_closes}
              onChange={(v) => update({ prioritize_ln_closes: v })}
            />
            <ToggleRow
              label="Prefer CoinJoin"
              description="Boost priority for CoinJoin transactions"
              enabled={profile.prefer_coinjoin}
              onChange={(v) => update({ prefer_coinjoin: v })}
            />
            {profile.prefer_coinjoin && (
              <NumberInput
                label="Min CoinJoin Participants"
                value={profile.min_coinjoin_participants}
                onChange={(v) => update({ min_coinjoin_participants: v })}
                min={2}
                max={100}
                unit=""
              />
            )}
          </div>
        </div>

        {/* Ghost Extensions - Chain Limits */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--accent)] mb-3">Chain Limits (CPFP)</h4>
          <div className="space-y-2">
            <NumberInput
              label="Max Ancestor Count"
              value={profile.max_ancestor_count}
              onChange={(v) => update({ max_ancestor_count: v })}
              min={1}
              max={100}
              unit=""
            />
            <NumberInput
              label="Max Descendant Count"
              value={profile.max_descendant_count}
              onChange={(v) => update({ max_descendant_count: v })}
              min={1}
              max={100}
              unit=""
            />
            <NumberInput
              label="Max Ancestor Size"
              value={profile.max_ancestor_size}
              onChange={(v) => update({ max_ancestor_size: v })}
              min={1000}
              max={500000}
              unit="vB"
            />
          </div>
        </div>

        {/* BUDS Tiers */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <h4 className="text-sm font-medium text-[color:var(--dim)]">BUDS Transaction Tiers</h4>
            {!budsEnabled && (
              <Badge variant="warning">Requires Ghost Pay</Badge>
            )}
          </div>
          {!budsEnabled && (
            <div className="p-3 bg-yellow-900/20 border border-yellow-800 rounded-lg mb-3">
              <p className="text-yellow-400 text-sm">
                Enable Ghost Pay to use BUDS transaction tiers. T1-T3 tiers provide enhanced
                transaction capabilities.
              </p>
            </div>
          )}
          <div className="space-y-2">
            <ToggleRow
              label="T0 - Standard"
              description="Standard Bitcoin transactions"
              enabled={profile.accept_t0}
              onChange={(v) => update({ accept_t0: v })}
            />
            <ToggleRow
              label="T1 - Privacy-Enhanced"
              description="CoinJoin, PayJoin, and privacy-focused transactions"
              enabled={profile.accept_t1}
              onChange={(v) => update({ accept_t1: v })}
              disabled={!budsEnabled}
              badge={!budsEnabled ? <Badge variant="default">Locked</Badge> : undefined}
            />
            <ToggleRow
              label="T2 - Complex"
              description="Smart contracts, DLCs, and complex scripts"
              enabled={profile.accept_t2}
              onChange={(v) => update({ accept_t2: v })}
              disabled={!budsEnabled}
              badge={!budsEnabled ? <Badge variant="default">Locked</Badge> : undefined}
            />
            <ToggleRow
              label="T3 - Experimental"
              description="New and experimental transaction types"
              enabled={profile.accept_t3}
              onChange={(v) => update({ accept_t3: v })}
              disabled={!budsEnabled}
              badge={!budsEnabled ? <Badge variant="default">Locked</Badge> : undefined}
            />
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-3 pt-4 border-t border-[var(--rule)]">
          <Button
            variant="ghost"
            className="flex-1"
            onClick={onClose}
          >
            Cancel
          </Button>
          <Button
            variant="primary"
            className="flex-1"
            onClick={onSave}
            loading={saving}
            disabled={!profile.name.trim()}
          >
            Save Profile
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
