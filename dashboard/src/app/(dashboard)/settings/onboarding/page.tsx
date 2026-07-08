"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { StepIndicator } from "@/components/ui/Wizard";
import { useToast } from "@/components/ui/Toast";
import { ToggleRow, StatusRow } from "../shared";
import { CapabilityToggles } from "@/components/settings/CapabilityToggles";
import ReaperWizard from "../wizards/ReaperWizard";
import {
  useNodeStatus,
  useHealth,
  useShares,
  useConfig,
  useFullConfig,
  useGhostPayStatus,
  useSetWraith,
  useSetPolicyProfile,
} from "@/hooks/queries";
import type { PolicyProfileType } from "@/lib/api/config";
import { useOnboarding } from "@/hooks/useOnboarding";

// The REAL tier-policy presets (pool.toml [policy].profile). This is the lever
// the block builder actually keys off; the advanced custom policy lives on the
// Filtering page. Selecting one persists via `/config/policy_profile`.
const POLICY_PRESETS: { name: PolicyProfileType; desc: string }[] = [
  { name: "permissive", desc: "Accept all standard transactions — balanced, most inclusive" },
  { name: "strict", desc: "Higher fee thresholds, reject low-value and spam-like transactions" },
  { name: "full_open", desc: "Accept everything, including data-carrier transactions" },
];

const STEPS = [
  { id: "welcome", title: "Welcome" },
  { id: "capabilities", title: "Capabilities" },
  { id: "policy", title: "Policy" },
  { id: "finish", title: "Finish" },
];

function StatItem({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between p-3 bg-[var(--surface)]/50 rounded-lg">
      <span className="text-sm text-[color:var(--dim)]">{label}</span>
      <span className="text-sm text-[color:var(--fg)] font-medium">{value}</span>
    </div>
  );
}

export default function OnboardingPage() {
  const router = useRouter();
  const { success, error } = useToast();
  const { complete } = useOnboarding();

  const [step, setStep] = useState(0);

  // Reads — current node state, used to pre-fill every step.
  const { data: status } = useNodeStatus();
  const { data: health } = useHealth();
  const { data: shares } = useShares();
  const { data: config } = useConfig();
  const { data: fullConfig } = useFullConfig();
  const { data: ghostPay } = useGhostPayStatus();

  // Writes — Wraith mixing and the tier policy still live here; the five
  // canonical capability rows are driven inside the shared CapabilityToggles
  // component (the SAME hooks Settings › Capabilities uses).
  const setWraith = useSetWraith();
  const setPolicyProfile = useSetPolicyProfile();

  // Composed wizard state.
  const [reaperWizardOpen, setReaperWizardOpen] = useState(false);

  const activePolicyProfile = String(fullConfig?.policy?.profile ?? "permissive");
  const ghostPayRunning = Boolean(ghostPay?.l2_height);
  const wraithEnabled = ghostPay?.wraith_enabled ?? false;

  const handleWraithToggle = async (enabled: boolean) => {
    try {
      await setWraith.mutateAsync(enabled);
      success("Saved", `Wraith mixing ${enabled ? "enabled" : "disabled"} — restart ghost-pool to apply`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleActivatePreset = async (name: PolicyProfileType) => {
    try {
      await setPolicyProfile.mutateAsync(name);
      success("Policy Applied", `Tier policy "${name}" set — restart applies it`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const finish = () => {
    complete();
    success("Setup Complete", "Your node is configured. You can re-run setup from Settings → Onboarding.");
    router.push("/");
  };

  const skip = () => {
    router.push("/");
  };

  const reaperEnabled = config?.reaper ?? false;
  const archiveEnabled = status?.archive_mode ?? false;
  const publicMiningEnabled = status?.public_mining ?? false;

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader
          title="Node Setup"
          subtitle="Review and confirm your node's capabilities and policy. Everything is pre-filled with your node's current values — adjust what you like, or accept the sane defaults."
        />
        <div className="py-2">
          <StepIndicator steps={STEPS} currentStep={step} />
        </div>
      </Card>

      {/* Step 1: Welcome / status */}
      {step === 0 && (
        <Card>
          <CardHeader title="Welcome" subtitle="A quick look at your node's current status." />
          <div className="space-y-3">
            <StatItem label="Node version" value={status?.version ?? "—"} />
            <StatItem
              label="Sync status"
              value={
                status?.is_synced ? (
                  <Badge variant="success">Synced</Badge>
                ) : (
                  <Badge variant="warning">Syncing</Badge>
                )
              }
            />
            <StatItem label="Block height" value={status?.block_height?.toLocaleString() ?? status?.sync_height?.toLocaleString() ?? "—"} />
            <StatItem label="Peers" value={status?.peer_count ?? "—"} />
            <StatItem
              label="Health"
              value={
                health?.healthy ?? status?.online ? (
                  <Badge variant="success">Healthy</Badge>
                ) : (
                  <Badge variant="warning">Unknown</Badge>
                )
              }
            />
            <StatItem
              label="Elder status"
              value={
                shares?.elder ? (
                  <Badge variant="success">Elder #{shares.elder_slot ?? "?"}</Badge>
                ) : (
                  <Badge variant="default">Not Elder</Badge>
                )
              }
            />
            <StatItem
              label="Reward shares"
              value={`${shares?.total ?? 0} / ${shares?.max_shares ?? 15}`}
            />
          </div>
        </Card>
      )}

      {/* Step 2: Capabilities */}
      {step === 1 && (
        <Card>
          <CardHeader
            title="Capabilities"
            subtitle="Capabilities earn shares in the node reward pool (5-4-3-2-1). Toggles are pre-set to your node's current values and save immediately."
          />
          <div className="space-y-3">
            {/*
             * The five reward capabilities share their markup + hooks with
             * Settings › Capabilities. Onboarding presents Ghost Pay as an
             * editable toggle and slots its Wraith mixing control in right
             * after it.
             */}
            <CapabilityToggles
              ghostPayControl="toggle"
              afterGhostPay={
                <ToggleRow
                  label="Wraith Mixing"
                  description="Let any L2 participant initiate a CoinJoin session through this node. Off means this node won't take part in mixing. Not a reward capability — a restart applies the change."
                  enabled={wraithEnabled}
                  onChange={handleWraithToggle}
                  disabled={setWraith.isPending}
                  badge={wraithEnabled ? <Badge variant="info">Mixing On</Badge> : null}
                />
              }
            />
          </div>
        </Card>
      )}

      {/* Step 3: Policy */}
      {step === 2 && (
        <div className="space-y-6">
          <Card>
            <CardHeader
              title="Transaction Policy"
              subtitle="Choose which transactions your node accepts and mines. This tier policy is a sane starting point — tune the advanced per-field controls later from Settings → Filtering."
            />
            <div className="space-y-4">
              {reaperEnabled && (
                <div className="p-3 bg-[color-mix(in_srgb,var(--yellow)_18%,transparent)] border border-[color-mix(in_srgb,var(--yellow)_45%,transparent)] rounded-lg">
                  <div className="text-[color:var(--yellow)] font-medium">Locked by Reaper Mode</div>
                  <div className="text-sm text-[color:var(--yellow)]/80">
                    Disable Reaper Mode in the previous step to change the tier policy.
                  </div>
                </div>
              )}

              <div
                className={`p-3 bg-[var(--surface)]/50 rounded-lg flex justify-between items-center ${
                  reaperEnabled ? "opacity-50" : ""
                }`}
              >
                <div>
                  <div className="text-[color:var(--fg)]">Current Policy</div>
                  <div className="text-sm text-[color:var(--dim)] capitalize">{activePolicyProfile.replace(/_/g, " ")}</div>
                </div>
                <Badge variant="info">{activePolicyProfile.replace(/_/g, " ")}</Badge>
              </div>

              <div
                className={`grid grid-cols-1 md:grid-cols-2 gap-2 ${
                  reaperEnabled ? "opacity-50 pointer-events-none" : ""
                }`}
              >
                {POLICY_PRESETS.map((p) => (
                  <button
                    key={p.name}
                    onClick={() => handleActivatePreset(p.name)}
                    disabled={reaperEnabled || setPolicyProfile.isPending}
                    className={`p-3 rounded-lg border transition-colors text-left ${
                      activePolicyProfile === p.name
                        ? "bg-[var(--accent)]/30 border-[var(--accent)] text-[color:var(--accent)]"
                        : "bg-[var(--surface)]/50 border-[var(--rule-strong)] text-[color:var(--dim)] hover:border-[var(--rule-strong)]"
                    }`}
                  >
                    <div className="font-medium capitalize">{p.name.replace(/_/g, " ")}</div>
                    <div className="text-xs text-[color:var(--fainter)] mt-1">{p.desc}</div>
                  </button>
                ))}
              </div>
            </div>
          </Card>

          <Card>
            <CardHeader
              title="Reaper Detectors"
              subtitle="Fine-tune which transaction patterns Ghost Reaper rejects. Opens the same detector wizard used in Settings → Wizards."
            />
            <div className="space-y-3">
              <StatusRow
                label="Ghost Reaper"
                description="Per-vector detector and threshold configuration."
                badge={
                  reaperEnabled ? (
                    <Badge variant="success">Enabled</Badge>
                  ) : (
                    <Badge variant="default">Disabled</Badge>
                  )
                }
              />
              <Button variant="secondary" className="w-full" onClick={() => setReaperWizardOpen(true)}>
                Configure Detectors
              </Button>
            </div>
          </Card>
        </div>
      )}

      {/* Step 4: Finish */}
      {step === 3 && (
        <Card>
          <CardHeader title="All Set" subtitle="Here's your node's configuration. Finishing marks setup complete." />
          <div className="space-y-3">
            <StatItem
              label="Archive Mode"
              value={<Badge variant={archiveEnabled ? "success" : "default"}>{archiveEnabled ? "On" : "Off"}</Badge>}
            />
            <StatItem
              label="Ghost Pay"
              value={<Badge variant={ghostPayRunning ? "success" : "default"}>{ghostPayRunning ? "Running" : "Not Running"}</Badge>}
            />
            <StatItem
              label="Public Mining"
              value={<Badge variant={publicMiningEnabled ? "success" : "default"}>{publicMiningEnabled ? "On" : "Off"}</Badge>}
            />
            <StatItem
              label="Ghost Reaper"
              value={<Badge variant={reaperEnabled ? "success" : "default"}>{reaperEnabled ? "On" : "Off"}</Badge>}
            />
            <StatItem
              label="Transaction Policy"
              value={
                reaperEnabled ? (
                  <Badge variant="warning">Reaper Mode</Badge>
                ) : (
                  <Badge variant="info">{activePolicyProfile.replace(/_/g, " ")}</Badge>
                )
              }
            />
            <StatItem label="Reward shares" value={`${shares?.total ?? 0} / ${shares?.max_shares ?? 15}`} />
          </div>
        </Card>
      )}

      {/* Navigation */}
      <div className="flex items-center justify-between">
        <div>
          {step > 0 && (
            <Button variant="ghost" onClick={() => setStep((s) => Math.max(0, s - 1))}>
              Back
            </Button>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" onClick={skip}>
            Skip for now
          </Button>
          {step < STEPS.length - 1 ? (
            <Button variant="primary" onClick={() => setStep((s) => Math.min(STEPS.length - 1, s + 1))}>
              Next
            </Button>
          ) : (
            <Button variant="primary" onClick={finish}>
              Done
            </Button>
          )}
        </div>
      </div>

      {/* Composed real wizards */}
      <ReaperWizard isOpen={reaperWizardOpen} onClose={() => setReaperWizardOpen(false)} />
    </div>
  );
}
