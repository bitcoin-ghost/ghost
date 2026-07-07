"use client";

import { useState } from "react";
import { PageHeader } from "@/components/ui/PageHeader";
import { StatCard } from "@/components/ui/StatCard";
import { Card, CardHeader } from "@/components/ui/Card";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { CopyButton } from "@/components/ui/CopyButton";
import { ConfirmDialog } from "@/components/ui/Dialog";
import { SectionErrorBoundary } from "@/components/ui/SectionErrorBoundary";
import { formatHashrate } from "@/components/ui/DataTable";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { useMiningStatus, useBestHash, useSetPrivateMining, useSetPublicMining, useSelfCheck } from "@/hooks/queries";
import { selfCheckFailures, type SelfCheckState } from "@/lib/api/selfCheck";
import { useToast } from "@/components/ui/Toast";
import { useQueryClient } from "@tanstack/react-query";
import PoolSetupWizard from "../settings/wizards/PoolSetupWizard";
import type { BestHashEntry, BestHashResponse } from "@/types/api";

const TOOLTIPS = {
  network_hashrate: "Estimated total hashrate of the Bitcoin network, derived from current difficulty. This is the global network, not just Ghost.",
  ghost_network_hashrate: "Combined hashrate of every node in the Ghost mesh pool, aggregated across the whole network.",
  node_hashrate: "Combined hashrate of miners connected to this node's stratum port. Updated every few seconds from share submissions.",
  connected_miners: "Number of mining devices currently connected to your stratum port and actively submitting shares.",
  shares_round: "Total accepted shares in the current mining round. The accept rate shows valid vs rejected shares.",
  blocks_found: "Total blocks your pool has found since first startup. Each block found triggers a payout distribution.",
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
        <code className="text-[color:var(--accent)] text-sm block truncate">{value}</code>
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
          <div className="text-lg font-semibold text-[color:var(--accent)]">{formatDifficulty(diff)}</div>
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

// Human-readable names for the self-check capabilities, used in the drift
// warning banner. Keys mirror ghost-pool's `SelfCheckState` fields.
const CAPABILITY_LABELS: Record<keyof SelfCheckState, string> = {
  public_mining: "Public Mining",
  archive: "Archive Mode",
  ghost_pay: "Ghost Pay",
  reaper: "Reaper",
};

type MiningMode = "private_solo" | "private_pool" | "pool";

function getMiningMode(privateMining?: boolean, publicMining?: boolean): MiningMode {
  if (privateMining && publicMining) return "private_pool";
  if (publicMining) return "pool";
  return "private_solo"; // default: private solo (includes both-off state)
}

const MODES: { key: MiningMode; label: string; desc: string }[] = [
  { key: "private_solo", label: "Private Solo", desc: "Your miners only. Stratum port closed to external connections. All block rewards go to you." },
  { key: "private_pool", label: "Private Pool", desc: "Your miners + accept public miners. You operate a public pool and share rewards with connected miners." },
  { key: "pool", label: "Pool", desc: "Public pool only. No private mining — your node acts as a pool server for external miners." },
];

export default function MiningPage() {
  const { data: status, isLoading: statusLoading } = useMiningStatus();
  const { data: bestHashData, isLoading: bestHashLoading } = useBestHash();
  // Capability self-check: warn when a CLAIMED capability's prerequisite is
  // missing (e.g. public_mining enabled but no stratum listening) so the
  // operator isn't silently failing to earn its shares. `null` (older backend,
  // 404, or all-passing) yields no failures → banner renders nothing.
  const { data: selfCheck } = useSelfCheck();
  const selfCheckFailureList = selfCheckFailures(selfCheck);
  // Dismissible per session (useState resets on reload), so the banner
  // re-appears on the next page load while the condition persists.
  const [selfCheckDismissed, setSelfCheckDismissed] = useState(false);
  const showSelfCheckBanner = selfCheckFailureList.length > 0 && !selfCheckDismissed;
  const setPrivateMining = useSetPrivateMining();
  const setPublicMining = useSetPublicMining();
  const queryClient = useQueryClient();
  const { addToast } = useToast();
  const [poolSetupOpen, setPoolSetupOpen] = useState(false);
  // The mode the operator has clicked but not yet confirmed. Changing mining
  // mode on a live node is disruptive (it flips which stratum ports accept
  // connections), so the click only stages the change — nothing is sent to the
  // node until the confirmation dialog is accepted.
  const [pendingMode, setPendingMode] = useState<MiningMode | null>(null);

  // Authority key: prefer the value the node now reports, fall back to the
  // bundled constant for pre-redeploy nodes that don't expose it yet.
  const authorityPublicKey = status?.authority_public_key ?? SV2_AUTHORITY_PUBLIC_KEY_FALLBACK;
  const nodeHost = typeof window !== "undefined" ? window.location.hostname : "localhost";
  const isPending = setPrivateMining.isPending || setPublicMining.isPending;

  const currentMode = getMiningMode(status?.private_mining, status?.public_mining);

  // Stage a mode change: record the click and open the confirmation dialog.
  // No request is fired here — that happens only on confirm.
  const requestModeChange = (mode: MiningMode) => {
    if (mode === currentMode || isPending) return;
    setPendingMode(mode);
  };

  // Fire the actual mode change once the operator confirms.
  const confirmModeChange = async () => {
    const mode = pendingMode;
    if (!mode) return;
    try {
      // Set both flags - order doesn't matter since both must succeed
      const privateMining = mode === "private_solo" || mode === "private_pool";
      const publicMining = mode === "private_pool" || mode === "pool";

      const results = await Promise.allSettled([
        setPrivateMining.mutateAsync(privateMining),
        setPublicMining.mutateAsync(publicMining),
      ]);

      const failures = results.filter((r) => r.status === "rejected");
      if (failures.length > 0) {
        const reason = (failures[0] as PromiseRejectedResult).reason;
        throw reason instanceof Error ? reason : new Error(String(reason));
      }

      await queryClient.invalidateQueries({ queryKey: ["mining"] });
      await queryClient.invalidateQueries({ queryKey: ["config"] });
      addToast({ type: "success", title: `Mining mode: ${MODES.find((m) => m.key === mode)?.label}` });
    } catch (err: unknown) {
      const message = err instanceof Error
        ? err.message
        : typeof err === "object" && err !== null && "message" in err
          ? String((err as { message: unknown }).message)
          : "Failed to update mining mode";
      addToast({ type: "error", title: message });
    } finally {
      setPendingMode(null);
    }
  };

  const totalSubmitted = status?.shares_submitted ?? 0;
  const totalAccepted = status?.shares_accepted ?? 0;
  const acceptRate = totalSubmitted > 0 ? ((totalAccepted / totalSubmitted) * 100).toFixed(1) : "0";

  // Show stratum endpoints based on mode
  const showPrivateEndpoints = currentMode === "private_solo" || currentMode === "private_pool";
  const showPublicEndpoints = currentMode === "private_pool" || currentMode === "pool";

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="mining" title="Hashrate, shares, miners." subtitle="Hashrate, miners, and mining configuration" />

      {/* Capability drift warning — a claimed capability whose prerequisite the
          node can't satisfy right now. Primary case: Public Mining enabled but
          no stratum serving, so miners can't connect and the +3 shares aren't
          being earned. Only rendered when the self-check reports a failure;
          dismissible for the session but re-shows on reload. */}
      {showSelfCheckBanner && (
        <div
          role="alert"
          className="rounded-lg border border-[color:var(--accent)] bg-[var(--surface)] p-4"
        >
          <div className="flex items-start gap-3">
            <span aria-hidden className="text-[color:var(--accent)] text-lg leading-none mt-0.5">⚠</span>
            <div className="flex-1 min-w-0 space-y-2">
              <div className="text-sm font-semibold text-[color:var(--accent)]">
                Capability prerequisite missing
              </div>
              <ul className="space-y-2">
                {selfCheckFailureList.map((f) => (
                  <li key={f.capability} className="text-sm text-[color:var(--accent)] leading-relaxed">
                    {f.capability === "public_mining" ? (
                      <>
                        You&apos;ve enabled <span className="font-medium">Public Mining</span>, but no stratum
                        server is responding on this node (port {status?.stratum_v1_port || 3333}). Miners
                        can&apos;t connect and you are{" "}
                        <span className="font-semibold">NOT earning the +3 Public Mining shares</span>. Start
                        the stratum stack (sri-translator/sri-pool) or change your mining mode.
                      </>
                    ) : (
                      <>
                        You&apos;ve enabled{" "}
                        <span className="font-medium">{CAPABILITY_LABELS[f.capability]}</span>, but its
                        prerequisite isn&apos;t satisfied on this node, so you are not earning its shares.
                      </>
                    )}
                    {/* Exact reason straight from the node probe (true port,
                        remediation hint) so the friendly copy above stays
                        correct even when the configured port differs. */}
                    <div className="text-xs text-[color:var(--accent)] mt-1">{f.reason}</div>
                  </li>
                ))}
              </ul>
            </div>
            <button
              type="button"
              onClick={() => setSelfCheckDismissed(true)}
              className="text-[color:var(--accent)] hover:text-[color:var(--accent)] text-sm shrink-0"
              aria-label="Dismiss warning"
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

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
          value={status?.connected_miners ?? 0}
          sublabel="active workers"
          tooltip={TOOLTIPS.connected_miners}
          loading={statusLoading}
        />
        <StatCard
          label="Shares / Round"
          value={(totalAccepted).toLocaleString()}
          sublabel={`${acceptRate}% accept rate`}
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

      {/* Mining Mode — the mode selector only. Connection endpoints live in
          their own section below so the two concerns don't get conflated. */}
      <SectionErrorBoundary section="Mining Mode">
        <Card>
          <CardHeader
            title="Mining Mode"
            subtitle="Select how your node participates in mining"
            action={
              <Button variant="outline" size="sm" onClick={() => setPoolSetupOpen(true)}>
                Pool Setup Wizard
              </Button>
            }
          />

          {/* Mode selector - 3 radio-style options */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {MODES.map(({ key, label, desc }) => {
              const isActive = currentMode === key;
              return (
                <button
                  key={key}
                  onClick={() => requestModeChange(key)}
                  disabled={isPending}
                  className={`p-4 rounded-lg border text-left transition-all ${
                    isActive
                      ? "bg-[var(--surface)] border-[color:var(--accent)] ring-1 ring-[color:var(--accent)]"
                      : "bg-[var(--surface)] border-[var(--rule-strong)] hover:border-[var(--rule-strong)]"
                  } ${isPending ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <div className={`w-3 h-3 rounded-full border-2 flex items-center justify-center ${
                      isActive ? "border-[color:var(--accent)]" : "border-[var(--rule-strong)]"
                    }`}>
                      {isActive && <div className="w-1.5 h-1.5 rounded-full bg-orange-500" />}
                    </div>
                    <span className={`font-medium ${isActive ? "text-[color:var(--accent)]" : "text-[color:var(--dim)]"}`}>{label}</span>
                    {isActive && <Badge variant="success">Active</Badge>}
                  </div>
                  <div className="text-xs text-[color:var(--fainter)] ml-5">{desc}</div>
                </button>
              );
            })}
          </div>
        </Card>
      </SectionErrorBoundary>

      {/* Connection Endpoints — how miners reach this node. Kept separate from
          the Mining Mode selector above. */}
      {(showPrivateEndpoints || showPublicEndpoints) && (
        <SectionErrorBoundary section="Connection Endpoints">
          <Card>
            <CardHeader
              title="Connection Endpoints"
              subtitle="How miners connect to your node"
            />
            <div className="space-y-4">
              {showPrivateEndpoints && (
                <div className="p-4 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]">
                  <div className="text-sm text-[color:var(--dim)] font-medium mb-3">Your Stratum Endpoints</div>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between p-2 bg-[var(--surface)] rounded">
                      <div>
                        <div className="text-xs text-[color:var(--fainter)]">Stratum V1</div>
                        <code className="text-[color:var(--accent)] text-sm">stratum+tcp://{nodeHost}:{status?.stratum_v1_port || 3333}</code>
                      </div>
                      <CopyButton text={`stratum+tcp://${nodeHost}:${status?.stratum_v1_port || 3333}`} />
                    </div>
                    <div className="flex items-center justify-between p-2 bg-[var(--surface)] rounded">
                      <div>
                        <div className="text-xs text-[color:var(--fainter)]">Stratum V2</div>
                        <code className="text-[color:var(--accent)] text-sm">stratum+tcp://{nodeHost}:{status?.stratum_v2_port || 34255}</code>
                      </div>
                      <CopyButton text={`stratum+tcp://${nodeHost}:${status?.stratum_v2_port || 34255}`} />
                    </div>
                  </div>
                </div>
              )}

              {showPublicEndpoints && (
                <div className="p-4 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]">
                  <div className="text-sm text-[color:var(--dim)] font-medium mb-3">Public Pool Endpoints</div>

                  {/* Two side-by-side stratum columns: SV1 left, SV2 right.
                      Stacks on narrow screens. Every field is individually
                      copyable. */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* SV1 */}
                    <div className="p-3 bg-[var(--surface)] rounded-lg border border-[var(--rule-strong)]">
                      <div className="text-sm text-[color:var(--dim)] font-medium mb-2">Stratum V1</div>
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
                      <div className="text-sm text-[color:var(--dim)] font-medium mb-2">Stratum V2 (native)</div>
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
                  <div className="mt-4 p-3 bg-[var(--surface)] border border-[color:var(--accent)] rounded">
                    <div className="text-sm text-[color:var(--accent)] font-medium mb-1">Username rule — SV1 and SV2</div>
                    <p className="text-xs text-[color:var(--dim)] leading-relaxed">
                      Set your miner&apos;s username to your{" "}
                      <span className="text-[color:var(--dim)] font-medium">bech32 payout address</span> followed by a
                      worker suffix:
                    </p>
                    <code className="text-[color:var(--accent)] text-xs block my-1.5">
                      &lt;your-payout-address&gt;.&lt;worker&gt;
                      <span className="text-[color:var(--fainter)]"> — e.g. bc1q….worker1</span>
                    </code>
                    <p className="text-xs text-[color:var(--dim)] leading-relaxed">
                      This is how block rewards are routed to you. Bare worker names (no{" "}
                      <code className="text-[color:var(--dim)]">.</code> separator, no address) are{" "}
                      <span className="text-[color:var(--dim)]">rejected</span> — the miner would mine for nobody. The
                      password field is ignored.
                    </p>
                  </div>
                </div>
              )}
            </div>
          </Card>
        </SectionErrorBoundary>
      )}

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

      {/* Confirmation for a mining-mode change. Nothing is sent to the node
          until this is accepted. */}
      <ConfirmDialog
        isOpen={pendingMode !== null}
        onClose={() => setPendingMode(null)}
        onConfirm={confirmModeChange}
        title="Change mining mode?"
        message={`Change mining mode to ${MODES.find((m) => m.key === pendingMode)?.label ?? ""}? This affects how miners connect to your node.`}
        confirmLabel="Change mode"
        cancelLabel="Cancel"
        loading={isPending}
      />

      {/* Wizard dialog */}
      <PoolSetupWizard isOpen={poolSetupOpen} onClose={() => setPoolSetupOpen(false)} />
    </div>
  );
}
