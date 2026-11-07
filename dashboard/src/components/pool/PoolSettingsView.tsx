import { Card, CardHeader } from "@/components/ui/Card";
import type { PoolStatus } from "@/lib/api/pool";
import { submitNodes, UNKNOWN } from "@/lib/pool/view";
import { Grid, Kv, Loading, Note, Unavailable } from "./parts";

export interface PoolSettingsViewProps {
  status?: PoolStatus;
  statusError?: unknown;
  statusLoading?: boolean;
}

/** The pool's settings, read-only: the installer writes them to pool_sv2's `[solo]` section. */
export function PoolSettingsView({ status, statusError, statusLoading }: PoolSettingsViewProps) {
  return (
    <Card>
      <CardHeader title="Ghost Pool" subtitle="Read-only: set by the installer in pool_sv2's config" />
      {!status && statusError ? <Unavailable what="Pool status" error={statusError} /> : null}
      {!status && !statusError && statusLoading !== false ? <Loading what="the pool settings" /> : null}
      <Grid>
        <Kv label="Network" value={status?.network ?? UNKNOWN} />
        <Kv label="SV1 ports" value={status ? status.ports.sv1.join(", ") : UNKNOWN} />
        <Kv label="SV2 port" value={status ? String(status.ports.sv2) : UNKNOWN} />
        <Kv label="SV2 authority key" value={status?.ports.sv2_authority_public_key ?? UNKNOWN} mono />
        <Kv
          label="Found blocks also sent to"
          value={
            status
              ? submitNodes(status).length
                ? submitNodes(status)
                    .map((n) => n.node)
                    .join(", ")
                : "no other node"
              : UNKNOWN
          }
          mono
        />
        <Kv label="Treasury address" value={status?.fee_policy.treasury_address ?? UNKNOWN} mono />
      </Grid>
      <Note>
        The other nodes are <code>submit_rpc</code> under <code>[solo]</code> in{" "}
        <code>/etc/ghost/pool-config.toml</code>, set by the installer&apos;s <code>--peer-node</code> or{" "}
        <code>--submit-node</code>; their credentials are in <code>/etc/ghost/solo-submit-rpc.auth</code>.
        The payout rule and the treasury are compiled into pool_sv2 and cannot be changed here.
      </Note>
    </Card>
  );
}
