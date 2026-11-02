"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { CopyButton } from "@/components/ui/CopyButton";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { formatHashrate } from "@/components/ui/DataTable";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useMiningStatus, useBestHash } from "@/hooks/queries";
import PoolSetupWizard from "../settings/wizards/PoolSetupWizard";
import type { BestHashEntry, BestHashResponse } from "@/types/api";

const TOOLTIPS = {
  network_hashrate: "Estimated total hashrate of the Bitcoin network, derived from current difficulty. This is the global network, not just Ghost.",
  ghost_network_hashrate: "Combined hashrate of every node in the Ghost mesh pool, aggregated across the whole network.",
  node_hashrate: "Combined hashrate of miners connected to this node's stratum port. Updated every few seconds from share submissions.",
  connected_miners: "Number of mining devices currently connected to your stratum port and actively submitting shares.",
  shares_round: "Total accepted shares in the current mining round. The accept rate shows valid vs rejected shares.",
  blocks_found: "Total blocks your pool has found since first startup.",
  best_hash: "The lowest (best) hash value submitted by miners. More leading zeros means closer to finding a block. Measured by share difficulty.",
};

function formatTimeAgo(timestamp: number): string {
  if (!timestamp) return "Never";
  const diff = Math.floor(Date.now() / 1000) - timestamp;
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function calculateLeadingZeros(difficulty: number): number {
  if (difficulty <= 0) return 0;
  return Math.floor(8 + Math.log2(difficulty) / 4);
}

// Human-readable difficulty with auto-scaling K/M/G/T/P/E suffixes.
// Mirrors `formatDifficulty` in ghost-web/pool.html so the dashboard and the
// public pool site render identical numbers (e.g. "1.20 T", "340.00 G").
function formatDifficulty(d: number): string {
  if (!isFinite(d) || d <= 0) return "—";
  if (d < 1e3) return d.toFixed(2);
  if (d < 1e6) return (d / 1e3).toFixed(2) + "K";
  if (d < 1e9) return (d / 1e6).toFixed(2) + "M";
  if (d < 1e12) return (d / 1e9).toFixed(2) + "G";
  if (d < 1e15) return (d / 1e12).toFixed(2) + "T";
  if (d < 1e18) return (d / 1e15).toFixed(2) + "P";
  return (d / 1e18).toFixed(2) + "E";
}

// Public pool hostname (round-robin DNS across all nodes).
const PUBLIC_POOL_HOST = "pool.bitcoinghost.org";

// SV2/Noise clients must pin the pool's authority public key to connect.
// The node now surfaces this on /api/v1/mining/status as `authority_public_key`
// (sourced from pool_sv2's pool.toml, identical across every node). This
// constant is the FALLBACK used only when that field is absent — i.e. a
// pre-redeploy node — so the copyable row never renders blank.
const SV2_AUTHORITY_PUBLIC_KEY_FALLBACK = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";

// The backend currently derives every window (current round / last hour /
// last 24h / all time) from the same source and returns an IDENTICAL entry for
// all four — and that entry is the network tip block (miner_id === null,
// difficulty === block-level), not the best SHARE a connected miner submitted.
// Detect that state so the UI can flag it instead of silently showing four
// identical "133.87T · 5s ago" cards, which reads as a bug to operators.
// Backend follow-up: /api/v1/mining/best-hash must track per-window best miner
// shares (with the submitting miner_id), not repeat the chain tip.
function bestHashLooksBlockLevel(data: BestHashResponse | undefined): boolean {
  if (!data) return false;
  const windows = [data.current_round, data.last_hour, data.last_24h, data.all_time];
  const populated = windows.filter((w) => w?.hash);
  if (populated.length < 2) return false;
  const allSameHash = populated.every((w) => w!.hash === populated[0]!.hash);
  // Real miner best-shares carry a miner_id; the repeated chain tip does not.
  const noMinerAttribution = populated.every((w) => !w!.miner_id);
  return allSameHash && noMinerAttribution;
}

// One labelled, copyable key/value row in a connection panel. Shared by both the
// SV1 and SV2 endpoint columns, and mirrors the public site's quick-start field
// rows (ghost-web/miners.html) so operators see the same set in both places.
function EndpointField({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-2 p-2 bg-[var(--surface)] rounded">
      <div className="min-w-0">
        <div className="text-xs text-[color:var(--fainter)]">{label}</div>
        <code className="text-[color:var(--fg)] text-sm block truncate">{value}</code>
      </div>
      <CopyButton text={value} />
    </div>
  );
}

function BestHashCard({ title, entry }: { title: string; entry: BestHashEntry | undefined }) {
  const diff = entry?.difficulty ?? 0;
  const hasData = entry && diff > 0;
  return (
    <div className="p-3 bg-[var(--surface)] rounded-lg">
      <div className="text-xs text-[color:var(--dim)] mb-1">{title}</div>
      {hasData ? (
        <>
          <div className="text-lg text-[color:var(--fg)]">{formatDifficulty(diff)}</div>
          <div className="font-mono text-xs text-[color:var(--dim)] truncate">{entry.hash}</div>
          <div className="text-xs text-[color:var(--fainter)] mt-0.5">{calculateLeadingZeros(diff)} leading zeros</div>
          <div className="flex justify-between items-center mt-1">
            {/* Block height of the round this share was solving for. Only shown
                when the backend populated it (joined from `rounds`); some rounds
                lack it, in which case we drop the line rather than render "?" —
                the timestamp alone conveys recency. */}
            {typeof entry.block_height === "number" && entry.block_height > 0 ? (
              <span className="text-xs text-[color:var(--fainter)]">Block #{entry.block_height.toLocaleString()}</span>
            ) : (
              <span />
            )}
            <span className="text-xs text-[color:var(--fainter)]">{formatTimeAgo(entry.timestamp ?? 0)}</span>
          </div>
        </>
      ) : (
        <div className="text-[color:var(--fainter)] text-sm">No data yet</div>
      )}
    </div>
  );
}

export default function MiningPage() {
  const { data: status, isLoading: statusLoading } = useMiningStatus();
  const { data: bestHashData, isLoading: bestHashLoading } = useBestHash();
  const [poolSetupOpen, setPoolSetupOpen] = useState(false);

  // Authority key: prefer the value the node now reports, fall back to the
  // bundled constant for pre-redeploy nodes that don't expose it yet.
  const authorityPublicKey = status?.authority_public_key ?? SV2_AUTHORITY_PUBLIC_KEY_FALLBACK;

  const totalSubmitted = status?.shares_submitted ?? 0;
  const totalAccepted = status?.shares_accepted ?? 0;
  // Null until a share has been submitted — a fresh node showing "0% accept
  // rate" reads as "everything rejected" when nothing has been mined yet.
  const acceptRate = totalSubmitted > 0 ? ((totalAccepted / totalSubmitted) * 100).toFixed(1) : null;

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="mining" title="Hashrate, shares, miners." subtitle="Hashrate, miners, and mining configuration" />

      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard
          label="Network Hashrate"
          value={bestHashData?.network_hashrate ? formatHashrate(bestHashData.network_hashrate, 0) : "--"}
          sublabel="global estimate"
          tooltip={TOOLTIPS.network_hashrate}
          loading={bestHashLoading}
        />
        <StatCard
          label="Ghost Network Total"
          value={status ? formatHashrate((status.hashrate_th ?? status.total_hashrate ?? 0) * 1e12) : "--"}
          sublabel="all Ghost nodes"
          tooltip={TOOLTIPS.ghost_network_hashrate}
          loading={statusLoading}
        />
        <StatCard
          label="This Node"
          value={status && status.local_hashrate_th != null ? formatHashrate(status.local_hashrate_th * 1e12) : "--"}
          sublabel="local hashrate"
          tooltip={TOOLTIPS.node_hashrate}
          loading={statusLoading}
        />
        <StatCard
          label="Connected Miners"
          value={status?.local_connected_miners ?? status?.connected_miners ?? 0}
          sublabel="connected to this node"
          tooltip={TOOLTIPS.connected_miners}
          loading={statusLoading}
        />
        <StatCard
          label="Shares / Round"
          value={(totalAccepted).toLocaleString()}
          sublabel={acceptRate === null ? "no shares yet" : `${acceptRate}% accept rate`}
          tooltip={TOOLTIPS.shares_round}
          loading={statusLoading}
        />
        <StatCard
          label="Blocks Found"
          value={status?.blocks_found ?? 0}
          sublabel="all time"
          tooltip={TOOLTIPS.blocks_found}
          loading={statusLoading}
        />
      </div>

      {/* Pool setup — every node is a public pool node; the wizard sets the
          coinbase pool name. */}
      <SectionErrorBoundary section="Pool Setup">
        <Card>
          <CardHeader
            title="Pool Setup"
            subtitle="This node serves the public Ghost pool"
            action={
              <Button variant="outline" size="sm" onClick={() => setPoolSetupOpen(true)}>
                Pool Setup Wizard
              </Button>
            }
          />
        </Card>
      </SectionErrorBoundary>

      {/* Connection Endpoints — how miners reach this node. */}
      <SectionErrorBoundary section="Connection Endpoints">
        <Card>
          <CardHeader
            title="Connection Endpoints"
            subtitle="How miners connect to your node"
          />
          <div className="space-y-4">
              <div className="p-4 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]">
                <div className="text-sm text-[color:var(--dim)] mb-3">Public Pool Endpoints</div>

                {/* Two side-by-side stratum columns: SV1 left, SV2 right.
                    Stacks on narrow screens. Every field is individually
                    copyable. */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* SV1 */}
                  <div className="p-3 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]">
                    <div className="text-sm text-[color:var(--dim)] mb-2">Stratum V1</div>
                    <div className="space-y-1.5">
                      <EndpointField label="Host" value={PUBLIC_POOL_HOST} />
                      <EndpointField label="Port" value={String(status?.stratum_v1_port || 3333)} />
                      <EndpointField label="Username" value="<your-address>.worker1" />
                      <EndpointField label="Protocol" value="Stratum V1" />
                    </div>
                    <p className="text-xs text-[color:var(--fainter)] mt-2 leading-relaxed">
                      For SV1 miners and firmware — connects through the pool translator.
                    </p>
                  </div>

                  {/* SV2 */}
                  <div className="p-3 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]">
                    <div className="text-sm text-[color:var(--dim)] mb-2">Stratum V2 (native)</div>
                    <div className="space-y-1.5">
                      <EndpointField label="Host" value={PUBLIC_POOL_HOST} />
                      <EndpointField label="Port" value={String(status?.stratum_v2_port || 34255)} />
                      <EndpointField label="Username" value="<your-address>.worker1" />
                      <EndpointField label="Protocol" value="Stratum V2" />
                      <EndpointField label="Channel type" value="Extended" />
                      <EndpointField label="Authority public key" value={authorityPublicKey} />
                    </div>
                    <p className="text-xs text-[color:var(--fainter)] mt-2 leading-relaxed">
                      For native SV2 firmware (e.g. a Bitaxe on AxeOS). The authority key is the
                      same on every public Ghost node — no separate TLS or cert required.
                    </p>
                  </div>
                </div>

                {/* Shared row — the authorize rule applies to BOTH stratums. */}
                <div className="mt-4 p-3 bg-[var(--surface)] border border-[var(--rule-strong)] rounded">
                  <div className="text-sm text-[color:var(--fg)] mb-1">Username rule — SV1 and SV2</div>
                  <p className="text-xs text-[color:var(--dim)] leading-relaxed">
                    Set your miner&apos;s username to your bech32 payout address followed by a
                    worker suffix:
                  </p>
                  <code className="text-[color:var(--fg)] text-xs block my-1.5">
                    &lt;your-payout-address&gt;.&lt;worker&gt;
                    <span className="text-[color:var(--fainter)]"> — e.g. bc1q….worker1</span>
                  </code>
                  <p className="text-xs text-[color:var(--dim)] leading-relaxed">
                    This is how block rewards are routed to you. Bare worker names (no{" "}
                    <code className="text-[color:var(--dim)]">.</code> separator, no address) are
                    rejected — the miner would mine for nobody. The password field is ignored.
                  </p>
                </div>
              </div>
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Best Hashes */}
      <SectionErrorBoundary section="Best Hashes">
        <Card>
          <CardHeader
            title="Best Hashes"
            subtitle="Lowest hash values achieved by connected miners — more leading zeros means closer to winning a block"
          />
          {bestHashLoading ? (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <SkeletonCard /><SkeletonCard /><SkeletonCard /><SkeletonCard />
            </div>
          ) : (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              <BestHashCard title="Current Round" entry={bestHashData?.current_round} />
              <BestHashCard title="Last Hour" entry={bestHashData?.last_hour} />
              <BestHashCard title="Last 24h" entry={bestHashData?.last_24h} />
              <BestHashCard title="All Time" entry={bestHashData?.all_time} />
            </div>
          )}
          {!bestHashLoading && bestHashLooksBlockLevel(bestHashData) && (
            <div className="mt-3 text-xs text-[color:var(--fainter)] border-t border-[var(--rule)] pt-3">
              All four windows are currently reporting the same value — the network&apos;s latest block
              hash rather than the best share submitted per window. Per-window miner best-shares are not
              yet tracked by the node API, so these cards will read identically until that lands.
            </div>
          )}
        </Card>
      </SectionErrorBoundary>

      {/* Wizard dialog */}
      <PoolSetupWizard isOpen={poolSetupOpen} onClose={() => setPoolSetupOpen(false)} />
    </div>
  );
}
