"use client";

import { useState, useEffect } from "react";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { useNodeInfo, useNickname, useSetNickname } from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { SettingsSection } from "./shared";

export function IdentitySection() {
  const { data: nodeInfo } = useNodeInfo();
  const { data: nicknameData } = useNickname();
  const setNicknameMutation = useSetNickname();
  const { success, error } = useToast();

  const [nickname, setNickname] = useState("");

  useEffect(() => {
    if (nicknameData?.nickname) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setNickname(nicknameData.nickname);
    }
  }, [nicknameData]);

  const handleSaveNickname = async () => {
    try {
      await setNicknameMutation.mutateAsync(nickname);
      success("Nickname Saved", "Node nickname updated successfully");
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <SettingsSection title="Node Identity" subtitle="Configure your node identification">
      <div className="space-y-4">
        <div>
          <label className="block text-sm text-[color:var(--dim)] mb-1">Node Nickname</label>
          <div className="flex gap-3">
            <Input
              value={nickname}
              onChange={(e) => setNickname(e.target.value)}
              placeholder="Enter a nickname for this node"
              className="flex-1"
            />
            <Button
              onClick={handleSaveNickname}
              loading={setNicknameMutation.isPending}
              disabled={nickname === nicknameData?.nickname}
            >
              Save
            </Button>
          </div>
          <p className="text-xs text-[color:var(--fainter)] mt-1">
            Useful for identifying nodes in multi-node setups
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-3 bg-[var(--surface)]/50 rounded-lg">
            <div className="text-sm text-[color:var(--dim)] mb-1">Node ID</div>
            <code className="text-[color:var(--fg)] text-sm break-all">
              {nodeInfo?.node_id ?? "Loading..."}
            </code>
          </div>
          <div className="p-3 bg-[var(--surface)]/50 rounded-lg">
            <div className="text-sm text-[color:var(--dim)] mb-1">Ghost ID (Short)</div>
            <code className="text-[color:var(--accent)] text-sm">
              {nodeInfo?.node_id_short ?? "Loading..."}
            </code>
          </div>
        </div>

        <div className="p-3 bg-[var(--surface)]/50 rounded-lg">
          <div className="flex justify-between items-center">
            <div className="text-sm text-[color:var(--dim)]">Version</div>
            <Badge variant="info">{nodeInfo?.version ?? "Unknown"}</Badge>
          </div>
        </div>
      </div>
    </SettingsSection>
  );
}
