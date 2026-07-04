"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import { StepIndicator } from "@/components/ui/Wizard";
import { useToast } from "@/components/ui/Toast";
import { ToggleRow, StatusRow } from "../shared";
import { MempoolProfileDialog, DEFAULT_MEMPOOL_PROFILE } from "../MempoolProfileDialog";
import ReaperWizard from "../wizards/ReaperWizard";
import {
  useNodeStatus,
  useHealth,
  useShares,
  useConfig,
  useGhostPayStatus,
  useSetArchiveMode,
  useSetPublicMining,
  useSetReaper,
  useSetGhostPay,
  useSetWraith,
  useActivateMempoolProfile,
  useSaveMempoolProfile,
  type CustomMempoolProfile,
} from "@/hooks/queries";
import { useOnboarding } from "@/hooks/useOnboarding";

// Preset mempool profiles, mirroring the Policy settings page. Selecting one
// goes through the real `activateMempoolProfile` endpoint.
const MEMPOOL_PRESETS = [
  { name: "standard", desc: "Bitcoin Core defaults — balanced acceptance" },
  { name: "strict", desc: "Higher fees, reject low-value transactions" },
  { name: "clean", desc: "Filter inscriptions, ordinals, and BRC-20" },
  { name: "structured", desc: "Optimized for transaction batching" },
  { name: "app_friendly", desc: "Accept more experimental tx types" },
  { name: "ghost", desc: "Full Ghost protocol support (requires Ghost Mode)" },
];

const STEPS = [
  { id: "welcome", title: "Welcome" },
  { id: "capabilities", title: "Capabilities" },
  { id: "policy", title: "Policy" },
  { id: "finish", title: "Finish" },
];

function StatItem({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
      <span className="text-sm text-gray-400">{label}</span>
      <span className="text-sm text-gray-100 font-medium">{value}</span>
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
  const { data: ghostPay } = useGhostPayStatus();

  // Writes — the SAME hooks the Capabilities/Policy settings pages use.
  const setArchiveMode = useSetArchiveMode();
  const setPublicMining = useSetPublicMining();
  const setReaper = useSetReaper();
  const setGhostPay = useSetGhostPay();
  const setWraith = useSetWraith();
  const activateMempoolProfile = useActivateMempoolProfile();
  const saveMempoolProfile = useSaveMempoolProfile();

  // Composed wizard / dialog state.
  const [reaperWizardOpen, setReaperWizardOpen] = useState(false);
  const [mempoolDialogOpen, setMempoolDialogOpen] = useState(false);
  const [editingMempool, setEditingMempool] = useState<CustomMempoolProfile | null>(null);

  const activeMempoolProfile = String(config?.mempool_profile ?? "standard");
  const activeTemplateProfile = String(config?.template_profile ?? "default");
  const ghostPayRunning = Boolean(ghostPay?.l2_height);
  const ghostPayEnabled = status?.ghost_pay ?? false;
  const budsEnabled = status?.ghost_pay ?? false;
  const wraithEnabled = ghostPay?.wraith_enabled ?? false;

  const handleArchiveToggle = async (enabled: boolean) => {
    try {
      await setArchiveMode.mutateAsync(enabled);
      success("Saved", `Archive Mode ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handlePublicMiningToggle = async (enabled: boolean) => {
    try {
      await setPublicMining.mutateAsync(enabled);
      success("Saved", `Public Mining ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleGhostPayToggle = async (enabled: boolean) => {
    try {
      await setGhostPay.mutateAsync(enabled);
      success("Saved", `Ghost Pay ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleWraithToggle = async (enabled: boolean) => {
    try {
      await setWraith.mutateAsync(enabled);
      success("Saved", `Wraith mixing ${enabled ? "enabled" : "disabled"} — restart ghost-pool to apply`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleReaperToggle = async (enabled: boolean) => {
    try {
      await setReaper.mutateAsync(enabled);
      success("Saved", `Ghost Reaper ${enabled ? "enabled" : "disabled"}`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleActivatePreset = async (name: string) => {
    try {
      await activateMempoolProfile.mutateAsync(name);
      success("Profile Applied", `Mempool profile "${name}" is now active`);
    } catch (err) {
      error("Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleMempoolSave = async () => {
    if (!editingMempool || !editingMempool.name.trim()) {
      error("Invalid Name", "Profile name is required");
      return;
    }
    try {
      await saveMempoolProfile.mutateAsync(editingMempool);
      success("Profile Saved", `Custom mempool profile "${editingMempool.name}" saved`);
      setMempoolDialogOpen(false);
      setEditingMempool(null);
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
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
            <ToggleRow
              label="Archive Mode"
              description="Store full blockchain history. Archive +5 shares."
              enabled={archiveEnabled}
              onChange={handleArchiveToggle}
              disabled={setArchiveMode.isPending}
              badge={archiveEnabled ? <Badge variant="success">+5 Shares</Badge> : null}
            />
            <ToggleRow
              label="Ghost Pay"
              description={`L2 payment network participation — requires ghost-pay-node${ghostPay?.l2_height ? ` (L2 height: ${ghostPay.l2_height})` : ""}. Ghost Pay +4 shares.`}
              enabled={ghostPayEnabled}
              onChange={handleGhostPayToggle}
              disabled={setGhostPay.isPending}
              badge={
                ghostPayEnabled ? (
                  ghostPayRunning ? (
                    <Badge variant="success">+4 Shares</Badge>
                  ) : (
                    <Badge variant="warning">Not Running</Badge>
                  )
                ) : null
              }
            />
            <ToggleRow
              label="Wraith Mixing"
              description="Let any L2 participant initiate a CoinJoin session through this node. Off means this node won't take part in mixing. Not a reward capability — a restart applies the change."
              enabled={wraithEnabled}
              onChange={handleWraithToggle}
              disabled={setWraith.isPending}
              badge={wraithEnabled ? <Badge variant="info">Mixing On</Badge> : null}
            />
            <ToggleRow
              label="Public Mining"
              description="Accept connections from public miners. Public Mining +3 shares."
              enabled={publicMiningEnabled}
              onChange={handlePublicMiningToggle}
              disabled={setPublicMining.isPending}
              badge={publicMiningEnabled ? <Badge variant="success">+3 Shares</Badge> : null}
            />
            <ToggleRow
              label="Ghost Reaper"
              description="Reject non-financial data (inscriptions, drop-stuffing, dust-flood) from your mempool and blocks. Reaper +2 shares."
              enabled={reaperEnabled}
              onChange={handleReaperToggle}
              disabled={setReaper.isPending}
              badge={reaperEnabled ? <Badge variant="success">+2 Shares</Badge> : null}
            />
            <StatusRow
              label="Elder Status"
              description={
                shares?.elder
                  ? `MPC contributor — Elder slot #${shares.elder_slot ?? "?"}`
                  : "Contribute to the MPC ceremony to earn Elder status. Elder +1 share."
              }
              badge={
                shares?.elder ? (
                  <Badge variant="success">+1 Share</Badge>
                ) : (
                  <Badge variant="default">Not Elder</Badge>
                )
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
              title="Mempool Policy"
              subtitle="Choose which transactions your node accepts. The default profile is a sane starting point — tune later from Settings → Policy."
            />
            <div className="space-y-4">
              {reaperEnabled && (
                <div className="p-3 bg-yellow-900/30 border border-yellow-700/50 rounded-lg">
                  <div className="text-yellow-400 font-medium">Locked by Reaper Mode</div>
                  <div className="text-sm text-yellow-500/80">
                    Disable Reaper Mode in the previous step to change profiles.
                  </div>
                </div>
              )}

              <div
                className={`p-3 bg-gray-800/50 rounded-lg flex justify-between items-center ${
                  reaperEnabled ? "opacity-50" : ""
                }`}
              >
                <div>
                  <div className="text-gray-100">Current Profile</div>
                  <div className="text-sm text-gray-400">{activeMempoolProfile}</div>
                </div>
                <Badge variant="info">{activeMempoolProfile}</Badge>
              </div>

              <div
                className={`grid grid-cols-1 md:grid-cols-2 gap-2 ${
                  reaperEnabled ? "opacity-50 pointer-events-none" : ""
                }`}
              >
                {MEMPOOL_PRESETS.map((p) => (
                  <button
                    key={p.name}
                    onClick={() => handleActivatePreset(p.name)}
                    disabled={reaperEnabled || activateMempoolProfile.isPending}
                    className={`p-3 rounded-lg border transition-colors text-left ${
                      activeMempoolProfile === p.name
                        ? "bg-orange-900/30 border-orange-600 text-orange-300"
                        : "bg-gray-800/50 border-gray-700 text-gray-300 hover:border-gray-500"
                    }`}
                  >
                    <div className="font-medium capitalize">{p.name.replace(/_/g, " ")}</div>
                    <div className="text-xs text-gray-500 mt-1">{p.desc}</div>
                  </button>
                ))}
              </div>

              <Button
                variant="secondary"
                className="w-full"
                disabled={reaperEnabled}
                onClick={() => {
                  setEditingMempool({ name: "", ...DEFAULT_MEMPOOL_PROFILE });
                  setMempoolDialogOpen(true);
                }}
              >
                Create Custom Mempool Profile
              </Button>
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
              label="Mempool Profile"
              value={
                reaperEnabled ? (
                  <Badge variant="warning">Reaper Mode</Badge>
                ) : (
                  <Badge variant="info">{activeMempoolProfile}</Badge>
                )
              }
            />
            <StatItem
              label="Pool Template Profile"
              value={
                reaperEnabled ? (
                  <Badge variant="warning">Reaper Mode</Badge>
                ) : (
                  <Badge variant="info">{activeTemplateProfile}</Badge>
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

      {/* Composed real wizards / dialogs */}
      <ReaperWizard isOpen={reaperWizardOpen} onClose={() => setReaperWizardOpen(false)} />
      <MempoolProfileDialog
        isOpen={mempoolDialogOpen}
        onClose={() => {
          setMempoolDialogOpen(false);
          setEditingMempool(null);
        }}
        profile={editingMempool}
        onProfileChange={setEditingMempool}
        onSave={handleMempoolSave}
        saving={saveMempoolProfile.isPending}
        budsEnabled={budsEnabled}
      />
    </div>
  );
}
