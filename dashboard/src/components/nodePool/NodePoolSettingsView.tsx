import { Card, CardHeader } from "@/components/ui/Card";
import type { NodePoolStatus } from "@/lib/api/nodePool";
import { fmtInt, UNKNOWN } from "@/lib/nodePool/view";
import { Grid, Kv, Loading, Note, Unavailable } from "./parts";

export interface NodePoolSettingsViewProps {
  status?: NodePoolStatus;
  statusError?: unknown;
  statusLoading?: boolean;
}

/**
 * The node pool's settings, read-only. The fee address is a money destination: the node
 * backend refuses to write one (fleet control's `money_destination` refusal) and the dashboard
 * has no other safe path, so it is shown with how to change it on the node.
 */
export function NodePoolSettingsView({ status, statusError, statusLoading }: NodePoolSettingsViewProps) {
  const ret = status?.retention;
  return (
    <Card>
      <CardHeader title="Node pool" subtitle="Read-only: set by the installer in pool_sv2's config" />
      {!status && statusError ? <Unavailable what="Node pool status" error={statusError} /> : null}
      {!status && !statusError && statusLoading !== false ? <Loading what="node pool settings" /> : null}
      <Grid>
        <Kv
          label="Fee address (finder output)"
          value={status?.fee_address ?? UNKNOWN}
          mono
          hint="Every transaction fee of a block this node's miners find goes here."
        />
        <Kv label="Network" value={status?.network ?? UNKNOWN} />
        <Kv
          label="Checkpoint depth"
          value={ret ? (ret.checkpoint_depth === 0 ? "never" : `${fmtInt(ret.checkpoint_depth)} Bitcoin blocks`) : UNKNOWN}
        />
        <Kv label="Pruning" value={ret ? (ret.prune ? "on" : "off (archive node)") : UNKNOWN} />
      </Grid>
      <Note>
        To change the fee address, re-run the installer with <code>--fee-address</code>, or edit
        <code> fee_address</code> under <code>[node_pool]</code> in{" "}
        <code>/etc/ghost/pool-config.toml</code> on the node and restart pool_sv2. Retention is
        <code> checkpoint_depth</code> and <code>prune</code> under <code>[node_pool.relay]</code>.
        The dashboard does not write money destinations.
      </Note>
    </Card>
  );
}
