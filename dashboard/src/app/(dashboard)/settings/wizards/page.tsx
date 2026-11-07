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
    </>
  );
}
