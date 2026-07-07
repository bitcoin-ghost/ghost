"use client";

import { useState, useEffect } from "react";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import {
  useFullConfig,
  useSetPayoutAddress,
  useSetGhostPayPayoutAddress,
  useGhostPayStatus,
} from "@/hooks/queries";
import { useToast } from "@/components/ui/Toast";
import { SettingsSection } from "./shared";

export function PayoutSection() {
  const { data: fullConfig } = useFullConfig();
  const { data: ghostPayStatus } = useGhostPayStatus();
  const setPayoutAddressMutation = useSetPayoutAddress();
  const setGhostPayPayoutAddressMutation = useSetGhostPayPayoutAddress();
  const { success, error } = useToast();

  const [miningPayoutAddress, setMiningPayoutAddress] = useState("");
  const [ghostPayPayoutAddress, setGhostPayPayoutAddress] = useState("");

  useEffect(() => {
    if (fullConfig?.payout?.address && !miningPayoutAddress) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setMiningPayoutAddress(fullConfig.payout.address);
    }
    if (fullConfig?.payout?.ghostpay_address && !ghostPayPayoutAddress) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setGhostPayPayoutAddress(fullConfig.payout.ghostpay_address);
    }
  }, [fullConfig?.payout?.address, fullConfig?.payout?.ghostpay_address]);

  const handleSaveMiningPayoutAddress = async () => {
    try {
      const address = miningPayoutAddress.trim() || null;
      await setPayoutAddressMutation.mutateAsync(address);
      success("Address Saved", "Mining payout address updated successfully");
    } catch (err) {
      error("Save Failed", err instanceof Error ? err.message : "Unknown error");
    }
  };

  const handleSaveGhostPayPayoutAddress = async () => {
    try {
      const address = ghostPayPayoutAddress.trim() || null;
      await setGhostPayPayoutAddressMutation.mutateAsync(address);
      success("Address Saved", "GhostPay payout address updated successfully");
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

        {/* GhostPay Payout Address */}
        <div>
          <label className="block text-sm text-[color:var(--dim)] mb-1">GhostPay Fee Address</label>
          <div className="flex gap-3">
            <Input
              value={ghostPayPayoutAddress}
              onChange={(e) => setGhostPayPayoutAddress(e.target.value)}
              placeholder="Enter your Bitcoin address (bc1q...)"
              className="flex-1 font-mono text-sm"
            />
            <Button
              onClick={handleSaveGhostPayPayoutAddress}
              loading={setGhostPayPayoutAddressMutation.isPending}
              disabled={ghostPayPayoutAddress === (fullConfig?.payout?.ghostpay_address ?? "")}
            >
              Save
            </Button>
          </div>
          <p className="text-xs text-[color:var(--fainter)] mt-1">
            GhostPay L2 transaction fee distributions will be sent to this address.
            Requires Ghost Pay to be enabled.
          </p>
          {!ghostPayStatus?.l2_height && (
            <p className="text-xs text-[color:var(--yellow)] mt-1">
              Ghost Pay is not running - fee distributions require an active ghost-pay-node
            </p>
          )}
        </div>
      </div>
    </SettingsSection>
  );
}
