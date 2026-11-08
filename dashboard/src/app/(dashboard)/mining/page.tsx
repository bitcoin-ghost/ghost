"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { CopyButton } from "@/components/ui/CopyButton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { useMiningStatus } from "@/hooks/queries";
import { usePoolStatus } from "@/hooks/queries/usePoolQueries";
import PoolSetupWizard from "../settings/wizards/PoolSetupWizard";

// How a miner reaches this node: the host is this node's own public address or hostname, which
// the dashboard (bound to loopback) cannot know.
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
  const pool = usePoolStatus();
  // The pool status lists both SV1 ports (3333, 4444); the mining status only the first.
  const sv1 = pool.data?.ports.sv1.length ? pool.data.ports.sv1.join(", ") : status?.stratum_v1_port ? String(status.stratum_v1_port) : null;
  const sv2 = status?.stratum_v2_port;
  const key = status?.authority_public_key;

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="ghost pool"
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
                <EndpointField label={pool.data?.ports.sv1.length === 1 ? "Port" : "Ports"} value={sv1 ?? "unknown"} unknown={!sv1} />
              </div>
              <p className="text-xs text-[color:var(--fainter)] mt-2 leading-relaxed">
                For SV1 firmware, through the translator: 3333 for small miners (Bitaxe, NerdAxe),
                4444 for large ones (Antminer, Whatsminer, Avalon A-series); 4444 starts at a higher
                share difficulty.
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
                Encrypted; the miner checks this node against its authority key. Standard and
                extended channels both work. Job Declaration is coming soon.
              </p>
            </div>
          </div>
          <div className="mt-4 p-3 border border-[var(--rule-strong)] rounded">
            <div className="text-sm text-[color:var(--fg)] mb-1">Username rule (SV1 and SV2)</div>
            <code className="text-[color:var(--fg)] text-xs block my-1.5">
              &lt;bitcoin-address&gt; or &lt;bitcoin-address&gt;.&lt;worker&gt;
            </code>
            <p className="text-xs text-[color:var(--dim)] leading-relaxed">
              A block the miner finds pays this address directly: the subsidy less 0.5% to the
              treasury, plus every fee. P2WPKH, P2TR, P2WSH and P2SH addresses of this node&apos;s
              network are accepted; legacy P2PKH (1…) is refused. The password is ignored.
            </p>
          </div>
        </Card>
      </SectionErrorBoundary>

      <PoolSetupWizard isOpen={poolSetupOpen} onClose={() => setPoolSetupOpen(false)} />
    </div>
  );
}
