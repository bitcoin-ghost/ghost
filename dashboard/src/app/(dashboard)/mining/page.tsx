"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { CopyButton } from "@/components/ui/CopyButton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useMiningStatus } from "@/hooks/queries";
import PoolSetupWizard from "../settings/wizards/PoolSetupWizard";

// How a miner reaches this node. The node pool has no shared pool hostname: a miner points at
// a listed node or its own, so the host is this node's own public address, which the dashboard
// (bound to loopback) cannot know.
const HOST = "<this node's public address>";

function EndpointField({ label, value, unknown }: { label: string; value: string; unknown?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-2 p-2 bg-[var(--surface)] rounded">
      <div className="min-w-0">
        <div className="text-xs text-[color:var(--fainter)]">{label}</div>
        <code
          className="text-sm block truncate"
          style={{ color: unknown ? "var(--fainter)" : "var(--fg)", fontStyle: unknown ? "italic" : undefined }}
        >
          {value}
        </code>
      </div>
      {!unknown && <CopyButton text={value} />}
    </div>
  );
}

export default function MiningPage() {
  const { data: status, error } = useMiningStatus();
  const [poolSetupOpen, setPoolSetupOpen] = useState(false);
  const sv1 = status?.stratum_v1_port;
  const sv2 = status?.stratum_v2_port;
  const key = status?.authority_public_key;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="node pool"
        title="Point a miner here."
        subtitle="Stratum endpoints of this node, and the username rule"
      />

      <SectionErrorBoundary section="Connection Endpoints">
        <Card>
          <CardHeader
            title="Connection endpoints"
            subtitle={error ? `Mining status unavailable: ${error instanceof Error ? error.message : String(error)}` : "How miners connect to this node"}
            action={
              <Button variant="outline" size="sm" onClick={() => setPoolSetupOpen(true)}>
                Pool Setup Wizard
              </Button>
            }
          />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-3 rounded-lg border border-[var(--rule-strong)]">
              <div className="text-sm text-[color:var(--dim)] mb-2">Stratum V1</div>
              <div className="space-y-1.5">
                <EndpointField label="Host" value={HOST} unknown />
                <EndpointField label="Port" value={sv1 ? String(sv1) : "unknown"} unknown={!sv1} />
              </div>
              <p className="text-xs text-[color:var(--fainter)] mt-2 leading-relaxed">
                For SV1 firmware, through the translator. Its slot class is sensed from the user
                agent: an unknown model starts at the smallest class.
              </p>
            </div>
            <div className="p-3 rounded-lg border border-[var(--rule-strong)]">
              <div className="text-sm text-[color:var(--dim)] mb-2">Stratum V2 (native)</div>
              <div className="space-y-1.5">
                <EndpointField label="Host" value={HOST} unknown />
                <EndpointField label="Port" value={sv2 ? String(sv2) : "unknown"} unknown={!sv2} />
                <EndpointField label="Authority public key" value={key ?? "unknown"} unknown={!key} />
              </div>
              <p className="text-xs text-[color:var(--fainter)] mt-2 leading-relaxed">
                Standard channels get only a header, so they always carry the full class.
              </p>
            </div>
          </div>
          <div className="mt-4 p-3 border border-[var(--rule-strong)] rounded">
            <div className="text-sm text-[color:var(--fg)] mb-1">Username rule (SV1 and SV2)</div>
            <code className="text-[color:var(--fg)] text-xs block my-1.5">
              &lt;payout-address&gt;.&lt;worker&gt;
            </code>
            <p className="text-xs text-[color:var(--dim)] leading-relaxed">
              The address is the ledger key the miner&apos;s shares credit. Only P2SH, P2WPKH, P2WSH
              and P2TR addresses of this node&apos;s network can be paid. The password is ignored.
            </p>
          </div>
        </Card>
      </SectionErrorBoundary>

      <PoolSetupWizard isOpen={poolSetupOpen} onClose={() => setPoolSetupOpen(false)} />
    </div>
  );
}
