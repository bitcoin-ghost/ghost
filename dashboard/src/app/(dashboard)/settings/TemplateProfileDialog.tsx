"use client";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { Dialog } from "@/components/ui/Dialog";
import { type CustomTemplateProfile } from "@/hooks/queries";
import { ToggleRow, NumberInput } from "./shared";

export const DEFAULT_TEMPLATE_PROFILE: Omit<CustomTemplateProfile, "name"> = {
  // Core settings
  block_max_weight: 4000000,
  block_min_tx_fee: 1,
  prioritise_by_fee: true,
  prioritise_by_age: false,
  // Ghost Extensions
  reserve_weight_for_ln: 0,
  max_sigops_per_block: 80000,
  prefer_small_txs: false,
  filter_inscriptions: false,
  filter_brc20: false,
  filter_runes: false,
  max_witness_item: 500000,
  boost_consolidations: false,
  boost_batched_payments: false,
  enable_package_relay: true,
  max_package_count: 25,
  randomize_tx_order: false,
  fee_band_size: 1,
  include_free_relay: false,
  free_relay_limit: 0,
  // BUDS tiers
  include_t0: true,
  include_t1: false,
  include_t2: false,
  include_t3: false,
  priority_order: ["t0", "t1", "t2", "t3"],
};

interface TemplateProfileDialogProps {
  isOpen: boolean;
  onClose: () => void;
  profile: CustomTemplateProfile | null;
  onProfileChange: (profile: CustomTemplateProfile) => void;
  onSave: () => void;
  saving: boolean;
  budsEnabled: boolean;
}

export function TemplateProfileDialog({
  isOpen,
  onClose,
  profile,
  onProfileChange,
  onSave,
  saving,
  budsEnabled,
}: TemplateProfileDialogProps) {
  if (!profile) return null;

  const update = (patch: Partial<CustomTemplateProfile>) => {
    onProfileChange({ ...profile, ...patch });
  };

  return (
    <Dialog
      isOpen={isOpen}
      onClose={onClose}
      title={
        profile.name
          ? `Edit Profile: ${profile.name}`
          : "New Template Profile"
      }
    >
      <div className="space-y-4 max-h-[70vh] overflow-y-auto">
        {/* Advanced User Warning */}
        <div className="p-4 bg-[var(--accent)]/20 border border-[var(--accent)] rounded-lg">
          <div className="flex items-start gap-3">
            <span className="text-[color:var(--accent)] text-xl">&#9888;</span>
            <div>
              <h4 className="text-[color:var(--accent)] font-medium">Advanced Configuration</h4>
              <p className="text-[color:var(--accent)]/80 text-sm mt-1">
                Custom block templates are intended for advanced users. Incorrect settings may
                affect your mining efficiency or block validity.
              </p>
              <p className="text-[color:var(--accent)]/80 text-sm mt-2">
                If you&apos;re unsure, use one of the preset profiles instead.
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
            placeholder="My Custom Template"
          />
        </div>

        {/* Core Template Settings */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--dim)] mb-3">Core Template Settings</h4>
          <div className="space-y-2">
            <NumberInput
              label="Block Max Weight"
              value={profile.block_max_weight}
              onChange={(v) => update({ block_max_weight: v })}
              min={100000}
              max={4000000}
              step={100000}
              unit="WU"
            />
            <NumberInput
              label="Block Min TX Fee"
              value={profile.block_min_tx_fee}
              onChange={(v) => update({ block_min_tx_fee: v })}
              min={0}
              step={0.1}
              unit="sat/vB"
            />
          </div>
        </div>

        {/* Priority Settings */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--dim)] mb-3">Priority Settings</h4>
          <div className="space-y-2">
            <ToggleRow
              label="Prioritise by Fee"
              description="Order transactions by fee rate (highest first)"
              enabled={profile.prioritise_by_fee}
              onChange={(v) => update({ prioritise_by_fee: v })}
            />
            <ToggleRow
              label="Prioritise by Age"
              description="Factor in transaction age when ordering"
              enabled={profile.prioritise_by_age}
              onChange={(v) => update({ prioritise_by_age: v })}
            />
          </div>
        </div>

        {/* Ghost Extensions - Block Composition */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--accent)] mb-3">Block Composition</h4>
          <div className="space-y-2">
            <NumberInput
              label="Reserve Weight for Lightning"
              value={profile.reserve_weight_for_ln}
              onChange={(v) => update({ reserve_weight_for_ln: v })}
              min={0}
              max={1000000}
              unit="WU"
            />
            <NumberInput
              label="Max Sigops per Block"
              value={profile.max_sigops_per_block}
              onChange={(v) => update({ max_sigops_per_block: v })}
              min={1000}
              max={100000}
              unit=""
            />
            <ToggleRow
              label="Prefer Small Transactions"
              description="Include more smaller txs vs fewer larger ones"
              enabled={profile.prefer_small_txs}
              onChange={(v) => update({ prefer_small_txs: v })}
            />
          </div>
        </div>

        {/* Ghost Extensions - Inscription Filtering */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--accent)] mb-3">Inscription Filtering</h4>
          <div className="space-y-2">
            <ToggleRow
              label="Filter Ordinal Inscriptions"
              description="Exclude Ordinal inscriptions from blocks you mine"
              enabled={profile.filter_inscriptions}
              onChange={(v) => update({ filter_inscriptions: v })}
            />
            <ToggleRow
              label="Filter BRC-20 Tokens"
              description="Exclude BRC-20 transfers from blocks"
              enabled={profile.filter_brc20}
              onChange={(v) => update({ filter_brc20: v })}
            />
            <ToggleRow
              label="Filter Runes"
              description="Exclude Rune protocol transactions"
              enabled={profile.filter_runes}
              onChange={(v) => update({ filter_runes: v })}
            />
            <NumberInput
              label="Max Witness Item Size"
              value={profile.max_witness_item}
              onChange={(v) => update({ max_witness_item: v })}
              min={0}
              max={4000000}
              unit="bytes"
            />
          </div>
        </div>

        {/* Ghost Extensions - Transaction Preferences */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--accent)] mb-3">Transaction Preferences</h4>
          <div className="space-y-2">
            <ToggleRow
              label="Boost Consolidations"
              description="Prioritize UTXO consolidation transactions"
              enabled={profile.boost_consolidations}
              onChange={(v) => update({ boost_consolidations: v })}
            />
            <ToggleRow
              label="Boost Batched Payments"
              description="Prioritize batched payment transactions"
              enabled={profile.boost_batched_payments}
              onChange={(v) => update({ boost_batched_payments: v })}
            />
          </div>
        </div>

        {/* Ghost Extensions - Package Relay */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--accent)] mb-3">Package Relay (CPFP)</h4>
          <div className="space-y-2">
            <ToggleRow
              label="Enable Package Relay"
              description="Use package-aware transaction selection"
              enabled={profile.enable_package_relay}
              onChange={(v) => update({ enable_package_relay: v })}
            />
            {profile.enable_package_relay && (
              <NumberInput
                label="Max Package Count"
                value={profile.max_package_count}
                onChange={(v) => update({ max_package_count: v })}
                min={2}
                max={100}
                unit="txs"
              />
            )}
          </div>
        </div>

        {/* Ghost Extensions - MEV Protection */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--accent)] mb-3">MEV Protection</h4>
          <div className="space-y-2">
            <ToggleRow
              label="Randomize Transaction Order"
              description="Randomize tx order within same fee bands"
              enabled={profile.randomize_tx_order}
              onChange={(v) => update({ randomize_tx_order: v })}
            />
            {profile.randomize_tx_order && (
              <NumberInput
                label="Fee Band Size"
                value={profile.fee_band_size}
                onChange={(v) => update({ fee_band_size: v })}
                min={1}
                max={10}
                unit="sat/vB"
              />
            )}
          </div>
        </div>

        {/* Ghost Extensions - Economic Preferences */}
        <div>
          <h4 className="text-sm font-medium text-[color:var(--accent)] mb-3">Economic Preferences</h4>
          <div className="space-y-2">
            <ToggleRow
              label="Include Free Relay"
              description="Altruistically include some 0-fee transactions"
              enabled={profile.include_free_relay}
              onChange={(v) => update({ include_free_relay: v })}
            />
            {profile.include_free_relay && (
              <NumberInput
                label="Free Relay Limit"
                value={profile.free_relay_limit}
                onChange={(v) => update({ free_relay_limit: v })}
                min={0}
                max={100000}
                unit="WU"
              />
            )}
          </div>
        </div>

        {/* BUDS Tiers */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <h4 className="text-sm font-medium text-[color:var(--dim)]">BUDS Transaction Tiers</h4>
            {!budsEnabled && <Badge variant="warning">Requires Ghost Pay</Badge>}
          </div>
          {!budsEnabled && (
            <div className="p-3 bg-[color-mix(in_srgb,var(--yellow)_14%,transparent)] border border-[color-mix(in_srgb,var(--yellow)_35%,transparent)] rounded-lg mb-3">
              <p className="text-[color:var(--yellow)] text-sm">
                Enable Ghost Pay to use BUDS transaction tiers in block templates.
              </p>
            </div>
          )}
          <div className="space-y-2">
            <ToggleRow
              label="Include T0 - Standard"
              description="Include standard Bitcoin transactions"
              enabled={profile.include_t0}
              onChange={(v) => update({ include_t0: v })}
            />
            <ToggleRow
              label="Include T1 - Privacy-Enhanced"
              description="Include privacy-focused transactions"
              enabled={profile.include_t1}
              onChange={(v) => update({ include_t1: v })}
              disabled={!budsEnabled}
              badge={!budsEnabled ? <Badge variant="default">Locked</Badge> : undefined}
            />
            <ToggleRow
              label="Include T2 - Complex"
              description="Include complex script transactions"
              enabled={profile.include_t2}
              onChange={(v) => update({ include_t2: v })}
              disabled={!budsEnabled}
              badge={!budsEnabled ? <Badge variant="default">Locked</Badge> : undefined}
            />
            <ToggleRow
              label="Include T3 - Experimental"
              description="Include experimental transaction types"
              enabled={profile.include_t3}
              onChange={(v) => update({ include_t3: v })}
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
