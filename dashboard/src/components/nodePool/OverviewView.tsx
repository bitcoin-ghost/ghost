import Link from "next/link";
import { Card, CardHeader } from "@/components/ui/Card";
import type { NodePoolStatus } from "@/lib/api/nodePool";
import type { NodeStatus } from "@/types/api";
import {
  fmtDuration,
  fmtInt,
  groupByAddress,
  isNum,
  nodePoolHealth,
  shortHash,
  UNKNOWN,
} from "@/lib/nodePool/view";
import { Grid, Kv, LevelBadge, Loading, Note, Unavailable } from "./parts";

export interface OverviewViewProps {
  status?: NodePoolStatus;
  statusError?: unknown;
  statusLoading?: boolean;
  /** The node backend's own status (`/api/v1/node/status`): the Bitcoin node's sync. */
  node?: NodeStatus;
  nodeError?: unknown;
}

const LEVEL_WORD = { ok: "Healthy", warn: "Needs attention", error: "Unhealthy", unknown: "Unknown" };

function BitcoinCard({ node, nodeError }: { node?: NodeStatus; nodeError?: unknown }) {
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
        <Kv label="Backend version" value={node?.version ?? UNKNOWN} />
        <Kv label="Uptime" value={isNum(uptime) ? fmtDuration(uptime) : UNKNOWN} />
      </Grid>
    </Card>
  );
}

export function OverviewView({ status, statusError, statusLoading, node, nodeError }: OverviewViewProps) {
  const health = nodePoolHealth(status, statusError);
  const groups = status ? groupByAddress(status.miners) : [];
  const warnings = status ? status.miners.filter((m) => m.firmware_warning).length : null;
  const st = status?.settlement;
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader
          title="Node pool health"
          action={<LevelBadge level={health.level}>{LEVEL_WORD[health.level]}</LevelBadge>}
        />
        {statusLoading && !status ? <Loading what="the node pool status" /> : null}
        {!status && statusError ? <Unavailable what="Node pool status" error={statusError} /> : null}
        <ul className="space-y-2" data-testid="health-checks">
          {health.checks.map((c) => (
            <li key={c.label} className="flex flex-wrap items-center gap-2 text-sm">
              <LevelBadge level={c.level}>{c.label}</LevelBadge>
              <span style={{ color: "var(--dim)" }}>{c.detail}</span>
            </li>
          ))}
        </ul>
      </Card>

      <BitcoinCard node={node} nodeError={nodeError} />

      <Card>
        <CardHeader
          title="Share chain"
          action={<Link href="/share-chain" className="text-sm" style={{ color: "var(--accent)" }}>Details</Link>}
        />
        <Grid>
          <Kv label="Anchor height" value={fmtInt(status?.share_chain.anchor_height)} />
          <Kv label="Tip" value={shortHash(status?.share_chain.tip)} mono />
          <Kv label="Tip's Bitcoin height" value={fmtInt(status?.share_chain.btc_height)} />
          <Kv label="Network tier (T_net)" value={fmtInt(status?.share_chain.t_net)} />
          <Kv label="Relay peers" value={fmtInt(status?.peers)} />
          <Kv label="Anchors waiting for their batch" value={fmtInt(status?.share_chain.unseen_anchors)} />
        </Grid>
      </Card>

      <Card>
        <CardHeader
          title="Settlement"
          action={<Link href="/blocks" className="text-sm" style={{ color: "var(--accent)" }}>Pool blocks</Link>}
        />
        <Grid>
          <Kv
            label="State"
            value={st ? (st.caught_up ? "caught up" : "catching up") : UNKNOWN}
          />
          <Kv label="Checked to Bitcoin height" value={fmtInt(st?.synced_height)} />
          <Kv label="Bitcoin tip it last saw" value={fmtInt(st?.bitcoin_tip)} />
          <Kv label="Provisional blocks" value={fmtInt(st?.provisional.length)} />
          <Kv label="Pool blocks listed" value={fmtInt(status?.recent_blocks.length)} />
          <Kv label="Ledger rows" value={fmtInt(status?.ledger_rows)} />
        </Grid>
      </Card>

      <Card>
        <CardHeader
          title="Miners on this node"
          action={<Link href="/miners" className="text-sm" style={{ color: "var(--accent)" }}>All miners</Link>}
        />
        <Grid>
          <Kv label="Open channels" value={fmtInt(status?.miners.length)} />
          <Kv label="Payout addresses" value={status ? fmtInt(groups.length) : UNKNOWN} />
          <Kv label="Firmware warnings" value={fmtInt(warnings)} />
        </Grid>
      </Card>

      <Card>
        <CardHeader title="This node" />
        <Grid>
          <Kv label="Network" value={status?.network ?? UNKNOWN} />
          <Kv label="Node id" value={status?.node_id ? shortHash(status.node_id, 12) : UNKNOWN} mono />
          <Kv
            label="Fee address (finder output)"
            value={status?.fee_address ?? UNKNOWN}
            mono
            hint="Every transaction fee of a block this node's miners find goes here."
          />
        </Grid>
      </Card>

      <Card>
        <CardHeader title="Share-chain start" subtitle="Where this node's share chain begins" />
        <Grid>
          <Kv label="Genesis anchor" value={shortHash(status?.start.genesis_anchor, 12)} mono />
          <Kv label="Genesis Bitcoin height" value={fmtInt(status?.start.genesis_btc_height)} />
          <Kv label="Source" value={status?.start.source ?? UNKNOWN} />
          <Kv label="Genesis tier" value={fmtInt(status?.start.genesis_tier)} />
          <Kv label="Genesis table digest" value={shortHash(status?.start.genesis_table_digest, 12)} mono />
          <Kv
            label="Pinned table digest"
            value={
              status
                ? status.start.pinned_genesis_table_digest
                  ? shortHash(status.start.pinned_genesis_table_digest, 12)
                  : "none pinned"
                : UNKNOWN
            }
            mono
          />
        </Grid>
        <Note>
          A node on a different genesis anchor or table digest is on a different share chain and
          never agrees with this one.
        </Note>
      </Card>
    </div>
  );
}
