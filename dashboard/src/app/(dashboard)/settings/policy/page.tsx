"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import {
  useConfig,
  useNodeStatus,
  useMempoolProfiles,
  useSaveMempoolProfile,
  useDeleteMempoolProfile,
  useActivateMempoolProfile,
  useTemplateProfiles,
  useSaveTemplateProfile,
  useDeleteTemplateProfile,
  useActivateTemplateProfile,
  useGhostPayStatus,
  type CustomMempoolProfile,
  type CustomTemplateProfile,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { MempoolProfileDialog, DEFAULT_MEMPOOL_PROFILE } from "../MempoolProfileDialog";
import { TemplateProfileDialog, DEFAULT_TEMPLATE_PROFILE } from "../TemplateProfileDialog";

const MEMPOOL_PRESETS = [
  { name: "standard", desc: "Bitcoin Core defaults - balanced acceptance" },
  { name: "strict", desc: "Higher fees, reject low-value transactions" },
  { name: "clean", desc: "Filter inscriptions, ordinals, and BRC-20" },
  { name: "structured", desc: "Optimized for transaction batching" },
  { name: "app_friendly", desc: "Accept more experimental tx types" },
  { name: "ghost", desc: "Full Ghost protocol support (requires Ghost Mode)" },
];

const TEMPLATE_PRESETS = [
  { name: "standard", desc: "Balanced fee optimization" },
  { name: "max_fee", desc: "Maximize fee revenue per block" },
  { name: "strict", desc: "Only high-fee, standard transactions" },
  { name: "clean_block", desc: "Exclude inscriptions and ordinals" },
  { name: "structured", desc: "Prioritize batched payments" },
  { name: "app_friendly", desc: "Include experimental tx types" },
  { name: "ghost_block", desc: "Full Ghost protocol (requires Ghost Mode)" },
];

function ReaperLockBanner() {
  return (
    <div className="p-3 bg-yellow-900/30 border border-yellow-700/50 rounded-lg">
      <div className="text-yellow-400 font-medium">Locked by Reaper Mode</div>
      <div className="text-sm text-yellow-500/80">
        Disable Reaper in Capabilities to change profiles
      </div>
    </div>
  );
}

function ProfileGrid({
  profiles,
  activeProfile,
  onActivate,
  disabled,
  ghostModeRequired,
  ghostModeActive,
}: {
  profiles: { name: string; desc: string }[];
  activeProfile: string;
  onActivate: (name: string) => void;
  disabled: boolean;
  ghostModeRequired?: string;
  ghostModeActive: boolean;
}) {
  return (
    <div className={`grid grid-cols-1 md:grid-cols-2 gap-2 ${disabled ? "opacity-50 pointer-events-none" : ""}`}>
      {profiles.map((profile) => (
        <button
          key={profile.name}
          className={`p-3 rounded-lg border transition-colors text-left ${
            activeProfile === profile.name
              ? "bg-[var(--accent)]/30 border-[var(--accent)] text-[color:var(--accent)]"
              : "bg-[var(--surface)]/50 border-[var(--rule-strong)] text-[color:var(--dim)] hover:border-[var(--rule-strong)]"
          }`}
          onClick={() => onActivate(profile.name)}
          disabled={disabled || (profile.name === ghostModeRequired && !ghostModeActive)}
        >
          <div className="font-medium capitalize">{profile.name.replace(/_/g, " ")}</div>
          <div className="text-xs text-[color:var(--fainter)] mt-1">{profile.desc}</div>
        </button>
      ))}
    </div>
  );
}

function CustomProfileList<T extends { name: string }>({
  profiles,
  disabled,
  onEdit,
  onActivate,
  onDelete,
  renderDetails,
}: {
  profiles: T[];
  disabled: boolean;
  onEdit: (p: T) => void;
  onActivate: (name: string) => void;
  onDelete: (name: string) => void;
  renderDetails: (p: T) => string;
}) {
  if (profiles.length === 0) return null;
  return (
    <div className={`space-y-2 ${disabled ? "opacity-50 pointer-events-none" : ""}`}>
      <h4 className="text-sm font-medium text-[color:var(--dim)]">Custom Profiles</h4>
      {profiles.map((profile) => (
        <div
          key={profile.name}
          className="p-3 bg-[var(--surface)]/50 rounded-lg flex justify-between items-center"
        >
          <div>
            <div className="text-[color:var(--fg)]">{profile.name}</div>
            <div className="text-xs text-[color:var(--fainter)]">{renderDetails(profile)}</div>
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="secondary" onClick={() => onEdit(profile)} disabled={disabled}>Edit</Button>
            <Button size="sm" variant="primary" onClick={() => onActivate(profile.name)} disabled={disabled}>Use</Button>
            <Button size="sm" variant="ghost" onClick={() => onDelete(profile.name)} disabled={disabled}>Delete</Button>
          </div>
        </div>
      ))}
    </div>
  );
}

function AdvancedToggle({ open, onToggle, count }: { open: boolean; onToggle: () => void; count: number }) {
  return (
    <button
      className="flex items-center gap-2 text-sm text-[color:var(--dim)] hover:text-[color:var(--fg)] transition-colors"
      onClick={onToggle}
    >
      <svg
        className={`w-4 h-4 transition-transform ${open ? "rotate-90" : ""}`}
        fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
      >
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
      </svg>
      {open ? "Hide Advanced" : "Show Advanced"}
      {count > 0 && !open && (
        <span className="text-xs text-[color:var(--fainter)]">({count} custom)</span>
      )}
    </button>
  );
}

export default function PolicySettingsPage() {
  const { data: config } = useConfig();
  const { data: status } = useNodeStatus();
  const { data: mempoolProfilesData } = useMempoolProfiles();
  const { data: templateProfilesData } = useTemplateProfiles();
  useGhostPayStatus();

  const saveMempoolProfile = useSaveMempoolProfile();
  const deleteMempoolProfile = useDeleteMempoolProfile();
  const activateMempoolProfile = useActivateMempoolProfile();
  const saveTemplateProfile = useSaveTemplateProfile();
  const deleteTemplateProfile = useDeleteTemplateProfile();
  const activateTemplateProfile = useActivateTemplateProfile();

  const { success, error } = useToast();

  const [mempoolDialogOpen, setMempoolDialogOpen] = useState(false);
  const [editingMempool, setEditingMempool] = useState<CustomMempoolProfile | null>(null);
  const [showMempoolAdvanced, setShowMempoolAdvanced] = useState(false);

  const [templateDialogOpen, setTemplateDialogOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<CustomTemplateProfile | null>(null);
  const [showTemplateAdvanced, setShowTemplateAdvanced] = useState(false);

  const mempoolProfiles = mempoolProfilesData?.profiles ?? [];
  const templateProfiles = templateProfilesData?.profiles ?? [];
  const reaperLocked = config?.reaper ?? false;
  const ghostModeActive = status?.ghost_mode ?? false;
  const budsEnabled = status?.ghost_pay ?? false;

  // Mempool handlers
  const handleMempoolNew = () => {
    setEditingMempool({ name: "", ...DEFAULT_MEMPOOL_PROFILE });
    setMempoolDialogOpen(true);
  };
  const handleMempoolEdit = (p: CustomMempoolProfile) => {
    setEditingMempool({ ...p });
    setMempoolDialogOpen(true);
  };
  const handleMempoolSave = async () => {
    if (!editingMempool || !editingMempool.name.trim()) {
      error("Invalid Name", "Profile name is required");
      return;
    }
    try {
      await saveMempoolProfile.mutateAsync(editingMempool);
      success("Profile Saved", `Mempool profile "${editingMempool.name}" saved`);
      setMempoolDialogOpen(false);
      setEditingMempool(null);
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };
  const handleMempoolDelete = async (name: string) => {
    try {
      await deleteMempoolProfile.mutateAsync(name);
      success("Profile Deleted", `Mempool profile "${name}" deleted`);
    } catch (err) {
      error("Delete Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  // Template handlers
  const handleTemplateNew = () => {
    setEditingTemplate({ name: "", ...DEFAULT_TEMPLATE_PROFILE });
    setTemplateDialogOpen(true);
  };
  const handleTemplateEdit = (p: CustomTemplateProfile) => {
    setEditingTemplate({ ...p });
    setTemplateDialogOpen(true);
  };
  const handleTemplateSave = async () => {
    if (!editingTemplate || !editingTemplate.name.trim()) {
      error("Invalid Name", "Profile name is required");
      return;
    }
    try {
      await saveTemplateProfile.mutateAsync(editingTemplate);
      success("Profile Saved", `Template profile "${editingTemplate.name}" saved`);
      setTemplateDialogOpen(false);
      setEditingTemplate(null);
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };
  const handleTemplateDelete = async (name: string) => {
    try {
      await deleteTemplateProfile.mutateAsync(name);
      success("Profile Deleted", `Template profile "${name}" deleted`);
    } catch (err) {
      error("Delete Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader
          title="Transaction Policy"
          subtitle="Control which transactions enter your mempool and blocks"
        />
        <div className="space-y-4">
          {reaperLocked && <ReaperLockBanner />}
        </div>
      </Card>

      {/* Mempool Policy */}
      <Card>
        <CardHeader title="Mempool Policy" subtitle="Configure which transactions to accept in your mempool" />
        <div className="space-y-4">
          <div className="p-3 bg-[var(--surface)]/50 rounded-lg flex justify-between items-center">
            <div>
              <div className="text-[color:var(--fg)]">Current Profile</div>
              <div className="text-sm text-[color:var(--dim)]">{config?.mempool_profile ?? "standard"}</div>
            </div>
            <Badge variant="info">{config?.mempool_profile ?? "standard"}</Badge>
          </div>

          <ProfileGrid
            profiles={MEMPOOL_PRESETS}
            activeProfile={String(config?.mempool_profile ?? "standard")}
            onActivate={(name) => activateMempoolProfile.mutate(name)}
            disabled={reaperLocked}
            ghostModeRequired="ghost"
            ghostModeActive={ghostModeActive}
          />

          <AdvancedToggle
            open={showMempoolAdvanced}
            onToggle={() => setShowMempoolAdvanced(!showMempoolAdvanced)}
            count={mempoolProfiles.length}
          />

          {showMempoolAdvanced && (
            <>
              <CustomProfileList
                profiles={mempoolProfiles}
                disabled={reaperLocked}
                onEdit={handleMempoolEdit}
                onActivate={(name) => activateMempoolProfile.mutate(name)}
                onDelete={handleMempoolDelete}
                renderDetails={(p) =>
                  `Fee: ${p.min_relay_tx_fee} sat/vB | Tiers: ${[p.accept_t0 && "T0", p.accept_t1 && "T1", p.accept_t2 && "T2", p.accept_t3 && "T3"].filter(Boolean).join(", ") || "None"}`
                }
              />
              <Button onClick={handleMempoolNew} variant="secondary" className="w-full" disabled={reaperLocked}>
                Create Custom Mempool Profile
              </Button>
            </>
          )}
        </div>
      </Card>

      {/* Block Template Policy */}
      <Card>
        <CardHeader title="Block Template Policy" subtitle="Configure which transactions to include when mining blocks" />
        <div className="space-y-4">
          <div className="p-3 bg-[var(--surface)]/50 rounded-lg flex justify-between items-center">
            <div>
              <div className="text-[color:var(--fg)]">Current Profile</div>
              <div className="text-sm text-[color:var(--dim)]">{config?.template_profile ?? "standard"}</div>
            </div>
            <Badge variant="info">{config?.template_profile ?? "standard"}</Badge>
          </div>

          <ProfileGrid
            profiles={TEMPLATE_PRESETS}
            activeProfile={String(config?.template_profile ?? "standard")}
            onActivate={(name) => activateTemplateProfile.mutate(name)}
            disabled={reaperLocked}
            ghostModeRequired="ghost_block"
            ghostModeActive={ghostModeActive}
          />

          <AdvancedToggle
            open={showTemplateAdvanced}
            onToggle={() => setShowTemplateAdvanced(!showTemplateAdvanced)}
            count={templateProfiles.length}
          />

          {showTemplateAdvanced && (
            <>
              <CustomProfileList
                profiles={templateProfiles}
                disabled={reaperLocked}
                onEdit={handleTemplateEdit}
                onActivate={(name) => activateTemplateProfile.mutate(name)}
                onDelete={handleTemplateDelete}
                renderDetails={(p) =>
                  `Min Fee: ${p.block_min_tx_fee} sat/vB | Tiers: ${[p.include_t0 && "T0", p.include_t1 && "T1", p.include_t2 && "T2", p.include_t3 && "T3"].filter(Boolean).join(", ") || "None"}`
                }
              />
              <Button onClick={handleTemplateNew} variant="secondary" className="w-full" disabled={reaperLocked}>
                Create Custom Template Profile
              </Button>
            </>
          )}
        </div>
      </Card>

      <MempoolProfileDialog
        isOpen={mempoolDialogOpen}
        onClose={() => { setMempoolDialogOpen(false); setEditingMempool(null); }}
        profile={editingMempool}
        onProfileChange={setEditingMempool}
        onSave={handleMempoolSave}
        saving={saveMempoolProfile.isPending}
        budsEnabled={budsEnabled}
      />
      <TemplateProfileDialog
        isOpen={templateDialogOpen}
        onClose={() => { setTemplateDialogOpen(false); setEditingTemplate(null); }}
        profile={editingTemplate}
        onProfileChange={setEditingTemplate}
        onSave={handleTemplateSave}
        saving={saveTemplateProfile.isPending}
        budsEnabled={budsEnabled}
      />
    </div>
  );
}
