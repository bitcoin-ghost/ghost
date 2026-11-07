import Link from "next/link";
import { Card, CardHeader } from "@/components/ui/Card";
import type { PoolStatus } from "@/lib/api/pool";
import type { NodeStatus } from "@/types/api";
import {
  bestRate,
  expectedSeconds,
  fmtBtc,
  fmtDifficulty,
  fmtDuration,
  fmtHashrate,
  fmtInt,
  isNum,
  poolHealth,
  reachabilityText,
  shortHash,
  submitNodes,
  UNKNOWN,
} from "@/lib/pool/view";
import { Grid, Kv, LevelBadge, Loading, Note, Unavailable } from "./parts";

export interface OverviewViewProps {
  status?: PoolStatus;
  statusError?: unknown;
  statusLoading?: boolean;
  /** The node backend's own status (`/api/v1/node/status`): the Bitcoin node's sync. */
  node?: NodeStatus;
  nodeError?: unknown;
  /** Unix seconds now; defaults to the status's `generated_at`. */
  now?: number;
}

const LEVEL_WORD = { ok: "Healthy", warn: "Needs attention", error: "Unhealthy", unknown: "Unknown" };

function BitcoinCard({ status, node, nodeError }: { status?: PoolStatus; node?: NodeStatus; nodeError?: unknown }) {
  const synced = node?.is_synced;
  const uptime = node?.uptime_seconds ?? node?.uptime_secs;
  return (
    <Card>
      <CardHeader
        title="Bitcoin node"
        action={
          synced === true ? (
            <LevelBadge level="ok">Synced</LevelBadge>
          ) : synced === false ? (
            <LevelBadge level="warn">Syncing</LevelBadge>
          ) : (
            <LevelBadge level="unknown">Sync unknown</LevelBadge>
          )
        }
      />
      {nodeError && !node ? <Unavailable what="Node status" error={nodeError} /> : null}
      <Grid>
        <Kv label="Block height" value={fmtInt(node?.block_height)} />
        <Kv label="Synced to" value={fmtInt(node?.sync_height ?? node?.block_height)} />
        <Kv label="Pool's tip" value={fmtInt(status?.bitcoin.tip_height)} hint="the height before the one jobs are built at" />
        <Kv label="Tip hash" value={shortHash(status?.bitcoin.tip_hash)} mono />
        <Kv label="Network difficulty" value={fmtDifficulty(status?.bitcoin.network_difficulty)} />
        <Kv label="Network" value={status?.network ?? UNKNOWN} />
        <Kv label="Backend version" value={node?.version ?? UNKNOWN} />
        <Kv label="Uptime" value={isNum(uptime) ? fmtDuration(uptime) : UNKNOWN} />
      </Grid>
    </Card>
  );
}

export function OverviewView({ status, statusError, statusLoading, node, nodeError, now }: OverviewViewProps) {
  const at = now ?? status?.generated_at ?? 0;
  const nodes = submitNodes(status);
  const health = poolHealth(status, statusError);
  const rate = bestRate(status?.pool_hashrate_hs);
  const mean = expectedSeconds(status?.bitcoin.network_difficulty, rate);
  const fp = status?.fee_policy;
  const last = status?.blocks_found.length ? status.blocks_found[status.blocks_found.length - 1] : null;
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader
          title="Ghost Pool health"
          action={<LevelBadge level={health.level}>{LEVEL_WORD[health.level]}</LevelBadge>}
        />
        {statusLoading && !status ? <Loading what="the pool status" /> : null}
        {!status && statusError ? <Unavailable what="Pool status" error={statusError} /> : null}
        <ul className="space-y-2" data-testid="health-checks">
          {health.checks.map((c) => (
            <li key={c.label} className="flex flex-wrap items-center gap-2 text-sm">
              <LevelBadge level={c.level}>{c.label}</LevelBadge>
              <span style={{ color: "var(--dim)" }}>{c.detail}</span>
            </li>
          ))}
        </ul>
      </Card>

      <Card>
        <CardHeader
          title="Mining on this node"
          action={<Link href="/miners" className="text-sm" style={{ color: "var(--accent)" }}>Miners</Link>}
        />
        <Grid>
          <Kv label="Pool hashrate, 15 min" value={fmtHashrate(status?.pool_hashrate_hs["15m"])} />
          <Kv label="Pool hashrate, 1 hour" value={fmtHashrate(status?.pool_hashrate_hs["1h"])} />
          <Kv label="Pool hashrate, 24 hours" value={fmtHashrate(status?.pool_hashrate_hs["24h"])} />
          <Kv label="Miners connected" value={fmtInt(status?.miners.connected)} hint="distinct payout addresses with an open channel" />
          <Kv label="Worker connections" value={fmtInt(status?.miners.workers)} hint="open channels" />
          <Kv label="Best share ever" value={fmtDifficulty(status?.best_share.ever)} />
          <Kv label="Best share, 24 hours" value={fmtDifficulty(status?.best_share["24h"])} />
          <Kv
            label="This node finds a block every"
            value={mean === null ? (status ? "unknown: needs hashrate and a tip" : UNKNOWN) : `~${fmtDuration(mean)}`}
            hint="network difficulty x 2^32 / pool hashrate: an average; luck decides the real wait"
          />
          <Kv label="Collecting statistics since" value={status ? new Date(status.collecting_since * 1000).toLocaleString() : UNKNOWN} />
        </Grid>
      </Card>

      <Card>
        <CardHeader
          title="Blocks found"
          action={<Link href="/blocks" className="text-sm" style={{ color: "var(--accent)" }}>All blocks</Link>}
        />
        <Grid>
          <Kv label="Blocks found" value={fmtInt(status?.blocks_found.length)} />
          <Kv label="Latest" value={last ? `height ${fmtInt(last.height)}` : status ? "none yet" : UNKNOWN} />
          <Kv label="Latest paid its miner" value={last ? fmtBtc(last.reward_sats) : status ? "none yet" : UNKNOWN} />
        </Grid>
      </Card>

      <BitcoinCard status={status} node={node} nodeError={nodeError} />

      <Card>
        <CardHeader title="Other nodes" subtitle="Every block a miner finds here is also sent to these" />
        {status && nodes.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--dim)" }}>
            None configured. A block found here reaches the network through this node only.
          </p>
        ) : null}
        <Grid>
          {nodes.map((n) => {
            const lastResult = last?.submitted.find((s) => s.node === n.node);
            return (
              <Kv
                key={n.node}
                label={n.node}
                value={
                  <span data-testid="submit-node">
                    <LevelBadge level={n.reachable === true ? "ok" : n.reachable === false ? "warn" : "unknown"}>
                      {n.reachable === true ? "Reachable" : n.reachable === false ? "Unreachable" : "Not checked"}
                    </LevelBadge>{" "}
                    {reachabilityText(n, at)} · {lastResult ? `last block: ${lastResult.result}` : "no block sent yet"}
                  </span>
                }
                mono
              />
            );
          })}
        </Grid>
        <Note>
          Each node is checked every minute (<code>getblockchaininfo</code>); a found block is sent to every
          one of them whatever the last check said.
        </Note>
      </Card>

      <Card>
        <CardHeader title="Payout rule" subtitle="Compiled into pool_sv2; the same on every Ghost Pool node" />
        <Grid>
          <Kv label="Treasury address" value={fp?.treasury_address ?? UNKNOWN} mono />
          <Kv label="Treasury share" value={fp ? `${(fp.treasury_share_of_subsidy * 100).toFixed(1)}% of the subsidy` : UNKNOWN} />
          <Kv label="Next block: treasury" value={fmtBtc(fp?.treasury_sats_next_block)} />
          <Kv label="Next block: miner, before fees" value={fmtBtc(fp?.miner_sats_next_block_before_fees)} />
          <Kv label="Transaction fees go to" value={fp ? (fp.fees_to === "miner" ? "the miner who found the block" : fp.fees_to) : UNKNOWN} />
          <Kv label="Ports" value={status ? `SV1 ${status.ports.sv1.join(", ")} · SV2 ${status.ports.sv2}` : UNKNOWN} />
          <Kv
            label="SV2 authority key"
            value={status ? (status.ports.sv2_authority_public_key ?? "not reported by this pool_sv2") : UNKNOWN}
            hint="the key SV2 miners pin"
            mono
          />
        </Grid>
      </Card>
    </div>
  );
}
