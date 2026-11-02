"use client";

import { useState } from "react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import {
  useFullConfig,
  useSetPayoutAddress,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { SettingsSection } from "./shared";

export function PayoutSection() {
  const { data: fullConfig } = useFullConfig();
  const setPayoutAddressMutation = useSetPayoutAddress();
  const { success, error } = useToast();

  const [miningPayoutAddress, setMiningPayoutAddress] = useState("");
  // Seed the input fields once from the fetched config, the moment it arrives.
  // Done during render (React's "adjust state when data changes" pattern) rather
  // than in an effect — the `seeded` guard runs it exactly once so it never
  // clobbers an edit the operator has since typed.
  const [seeded, setSeeded] = useState(false);
  if (!seeded && fullConfig?.payout) {
    setSeeded(true);
    if (fullConfig.payout.address) setMiningPayoutAddress(fullConfig.payout.address);
  }

  const handleSaveMiningPayoutAddress = async () => {
    try {
      const address = miningPayoutAddress.trim() || null;
      await setPayoutAddressMutation.mutateAsync(address);
      success("Address Saved", "Mining payout address updated successfully");
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  return (
    <SettingsSection
      title="Payout Addresses"
      subtitle="Configure where your rewards are sent"
    >
      <div className="space-y-4">
        {/* Mining Payout Address */}
        <div>
          <label className="block text-sm text-[color:var(--dim)] mb-1">Mining Payout Address</label>
          <div className="flex gap-3">
            <Input
              value={miningPayoutAddress}
              onChange={(e) => setMiningPayoutAddress(e.target.value)}
              placeholder="Enter your Bitcoin address (bc1q...)"
              className="flex-1 font-mono text-sm"
            />
            <Button
              onClick={handleSaveMiningPayoutAddress}
              loading={setPayoutAddressMutation.isPending}
              disabled={miningPayoutAddress === (fullConfig?.payout?.address ?? "")}
            >
              Save
            </Button>
          </div>
          <p className="text-xs text-[color:var(--fainter)] mt-1">
            Mining block rewards and coinbase fees will be sent to this address
          </p>
        </div>
      </div>
    </SettingsSection>
  );
}
