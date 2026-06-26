"use client";

import { useState } from "react";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import InitialSetupWizard from "./InitialSetupWizard";
import ChangeSetupWizard from "./ChangeSetupWizard";
import BuildRunWizard from "./BuildRunWizard";
import PoolSetupWizard from "./PoolSetupWizard";
import GhostModeWizard from "./GhostModeWizard";
import ReaperWizard from "./ReaperWizard";
import HazeWizard from "./HazeWizard";
import ShroudWizard from "./ShroudWizard";
import MempoolPolicyWizard from "./MempoolPolicyWizard";
import GhostIdWizard from "./GhostIdWizard";
import CreateLockWizard from "./CreateLockWizard";
import WithdrawWizard from "./WithdrawWizard";
import SendPaymentWizard from "./SendPaymentWizard";
import GlyphWizard from "./GlyphWizard";

export default function WizardsSettingsPage() {
  const [initialSetupOpen, setInitialSetupOpen] = useState(false);
  const [changeSetupOpen, setChangeSetupOpen] = useState(false);
  const [buildRunOpen, setBuildRunOpen] = useState(false);
  const [poolSetupOpen, setPoolSetupOpen] = useState(false);
  const [ghostModeOpen, setGhostModeOpen] = useState(false);
  const [reaperOpen, setReaperOpen] = useState(false);
  const [hazeOpen, setHazeOpen] = useState(false);
  const [shroudOpen, setShroudOpen] = useState(false);
  const [mempoolPolicyOpen, setMempoolPolicyOpen] = useState(false);
  const [ghostIdOpen, setGhostIdOpen] = useState(false);
  const [createLockOpen, setCreateLockOpen] = useState(false);
  const [withdrawOpen, setWithdrawOpen] = useState(false);
  const [sendPaymentOpen, setSendPaymentOpen] = useState(false);
  const [glyphOpen, setGlyphOpen] = useState(false);

  return (
    <>
      <Card>
        <CardHeader title="Quick Setup" subtitle="Guided wizards for common configuration tasks" />
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
          <Button variant="primary" size="lg" onClick={() => setInitialSetupOpen(true)} className="w-full">
            Initial Setup
          </Button>
          <Button variant="outline" size="lg" onClick={() => setChangeSetupOpen(true)} className="w-full">
            Change Setup
          </Button>
          <Button variant="primary" size="lg" onClick={() => setBuildRunOpen(true)} className="w-full">
            Build &amp; Run
          </Button>
          <Button variant="outline" size="lg" onClick={() => setPoolSetupOpen(true)} className="w-full">
            Mining Setup
          </Button>
          <Button variant="outline" size="lg" onClick={() => setGhostModeOpen(true)} className="w-full">
            Ghost Mode
          </Button>
          <Button variant="outline" size="lg" onClick={() => setReaperOpen(true)} className="w-full">
            Reaper
          </Button>
          <Button variant="outline" size="lg" onClick={() => setHazeOpen(true)} className="w-full">
            Haze
          </Button>
          <Button variant="outline" size="lg" onClick={() => setShroudOpen(true)} className="w-full">
            Shroud
          </Button>
          <Button variant="outline" size="lg" onClick={() => setMempoolPolicyOpen(true)} className="w-full">
            Mempool Policy
          </Button>
          <Button variant="outline" size="lg" onClick={() => setGhostIdOpen(true)} className="w-full">
            Ghost ID
          </Button>
          <Button variant="outline" size="lg" onClick={() => setCreateLockOpen(true)} className="w-full">
            Create Lock
          </Button>
          <Button variant="outline" size="lg" onClick={() => setWithdrawOpen(true)} className="w-full">
            Withdraw
          </Button>
          <Button variant="outline" size="lg" onClick={() => setSendPaymentOpen(true)} className="w-full">
            Send Payment
          </Button>
          <Button variant="outline" size="lg" onClick={() => setGlyphOpen(true)} className="w-full">
            Glyph
          </Button>
        </div>
      </Card>

      <InitialSetupWizard isOpen={initialSetupOpen} onClose={() => setInitialSetupOpen(false)} />
      <ChangeSetupWizard isOpen={changeSetupOpen} onClose={() => setChangeSetupOpen(false)} />
      <BuildRunWizard isOpen={buildRunOpen} onClose={() => setBuildRunOpen(false)} />
      <PoolSetupWizard isOpen={poolSetupOpen} onClose={() => setPoolSetupOpen(false)} />
      <GhostModeWizard isOpen={ghostModeOpen} onClose={() => setGhostModeOpen(false)} />
      <ReaperWizard isOpen={reaperOpen} onClose={() => setReaperOpen(false)} />
      <HazeWizard isOpen={hazeOpen} onClose={() => setHazeOpen(false)} />
      <ShroudWizard isOpen={shroudOpen} onClose={() => setShroudOpen(false)} />
      <MempoolPolicyWizard isOpen={mempoolPolicyOpen} onClose={() => setMempoolPolicyOpen(false)} />
      <GhostIdWizard isOpen={ghostIdOpen} onClose={() => setGhostIdOpen(false)} />
      <CreateLockWizard isOpen={createLockOpen} onClose={() => setCreateLockOpen(false)} />
      <WithdrawWizard isOpen={withdrawOpen} onClose={() => setWithdrawOpen(false)} />
      <SendPaymentWizard isOpen={sendPaymentOpen} onClose={() => setSendPaymentOpen(false)} />
      <GlyphWizard isOpen={glyphOpen} onClose={() => setGlyphOpen(false)} />
    </>
  );
}
