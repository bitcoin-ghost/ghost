import { Card, CardHeader } from "@/components/ui/Card";
import type { NodePoolStatus } from "@/lib/api/nodePool";
import { fmtAgo, fmtInt, shortHash, UNKNOWN } from "@/lib/nodePool/view";
import { Grid, Kv, Loading, Note, Table, Td, Unavailable } from "./parts";

export interface ShareChainViewProps {
  status?: NodePoolStatus;
  statusError?: unknown;
  statusLoading?: boolean;
  now: number;
}

const NOT_REPORTED = "not reported by this pool_sv2";

export function ShareChainView({ status, statusError, statusLoading, now }: ShareChainViewProps) {
  if (!status) {
    return (
      <Card>
        <CardHeader title="Share chain" />
        {statusError ? <Unavailable what="Node pool status" error={statusError} /> : null}
        {!statusError && statusLoading !== false ? <Loading what="the share chain" /> : null}
      </Card>
    );
  }
  const c = status.share_chain;
  const r = status.relay_stats;
  const ret = status.retention;
  const syncing = c.unseen_anchors > 0;
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="Tip" subtitle="The best anchor by cumulative work" />
        <Grid>
          <Kv label="Anchor height" value={fmtInt(c.anchor_height)} />
          <Kv label="Tip anchor" value={c.tip} mono />
          <Kv label="Bitcoin height its job saw" value={fmtInt(c.btc_height)} />
          <Kv label="Network tier (T_net)" value={fmtInt(c.t_net)} />
          <Kv label="Cumulative work" value={c.work} mono />
          <Kv label="Relay peers" value={fmtInt(status.peers)} />
        </Grid>
      </Card>

      <Card>
        <CardHeader title="Sync" />
        <Grid>
          <Kv
            label="State"
            value={syncing ? `fetching batches for ${c.unseen_anchors} anchor(s)` : "no anchor waiting for its batch"}
          />
          <Kv label="Loose network shares (waiting for a batch)" value={fmtInt(c.loose_shares)} />
          <Kv label="Anchors held without their batch" value={fmtInt(c.unseen_anchors)} />
        </Grid>
        <Note>
          Whether a peer holds a heavier chain this node has not fetched yet is not reported; with no
          relay peers this node cannot tell.
        </Note>
      </Card>

      <Card>
        <CardHeader title="Relay counters" subtitle="Since this node's pool service started" />
        {r ? (
          <Grid>
            <Kv label="Network shares accepted" value={fmtInt(r.shares_accepted)} />
            <Kv label="Network shares stale" value={fmtInt(r.shares_stale)} />
            <Kv label="Network shares invalid" value={fmtInt(r.shares_invalid)} />
            <Kv label="Anchors valid" value={fmtInt(r.anchors_valid)} />
            <Kv label="Anchors invalid" value={fmtInt(r.anchors_invalid)} />
            <Kv label="Reorgs" value={fmtInt(r.reorgs)} />
          </Grid>
        ) : (
          <Kv label="Relay counters" value={`${UNKNOWN}: ${NOT_REPORTED}`} />
        )}
      </Card>

      <Card>
        <CardHeader title="Checkpoints and pruning" />
        {ret ? (
          <>
            <Grid>
              <Kv
                label="Checkpoint depth"
                value={ret.checkpoint_depth === 0 ? "never (checkpoints off)" : `${fmtInt(ret.checkpoint_depth)} Bitcoin blocks below the tip`}
              />
              <Kv
                label="Pruning"
                value={ret.prune ? "on: batches below the older checkpoint are deleted" : "off: archive node, serves sync from genesis"}
              />
              <Kv label="Stored checkpoints" value={fmtInt(ret.checkpoints.length)} />
            </Grid>
            {ret.checkpoints.length > 0 ? (
              <div className="mt-4">
                <Table head={["Anchor height", "Anchor", "Bitcoin height", "Digest", "Written"]}>
                  {ret.checkpoints.map((k) => (
                    <tr key={k.anchor} data-testid="checkpoint-row">
                      <Td>{fmtInt(k.anchor_height)}</Td>
                      <Td mono>{shortHash(k.anchor, 8)}</Td>
                      <Td>{fmtInt(k.btc_height)}</Td>
                      <Td mono>{shortHash(k.digest, 8)}</Td>
                      <Td>{fmtAgo(k.created_at, now)}</Td>
                    </tr>
                  ))}
                </Table>
              </div>
            ) : (
              <Note>No checkpoint yet: one is folded every 144 Bitcoin blocks once the chain is deep enough.</Note>
            )}
          </>
        ) : (
          <Kv label="Retention" value={`${UNKNOWN}: ${NOT_REPORTED}`} />
        )}
      </Card>
    </div>
  );
}
