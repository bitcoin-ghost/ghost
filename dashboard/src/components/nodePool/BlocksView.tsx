import { Card, CardHeader } from "@/components/ui/Card";
import type { NodePoolStatus } from "@/lib/api/nodePool";
import { fmtAgo, fmtInt, fmtSats, shortHash } from "@/lib/nodePool/view";
import { Grid, Kv, Loading, Note, Table, Td, Unavailable } from "./parts";

export interface BlocksViewProps {
  status?: NodePoolStatus;
  statusError?: unknown;
  statusLoading?: boolean;
  now: number;
}

export function BlocksView({ status, statusError, statusLoading, now }: BlocksViewProps) {
  if (!status) {
    return (
      <Card>
        <CardHeader title="Pool blocks" />
        {statusError ? <Unavailable what="Node pool status" error={statusError} /> : null}
        {!statusError && statusLoading !== false ? <Loading what="pool blocks" /> : null}
      </Card>
    );
  }
  const st = status.settlement;
  const blocks = status.recent_blocks;
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="Settlement" subtitle="Each pool block retires what it paid from the ledger" />
        <Grid>
          <Kv label="State" value={st.caught_up ? "caught up" : "catching up"} />
          <Kv label="Checked to Bitcoin height" value={fmtInt(st.synced_height)} />
          <Kv label="Bitcoin tip it last saw" value={fmtInt(st.bitcoin_tip)} />
          <Kv label="Matched since start" value={fmtInt(st.matched)} />
          <Kv label="Provisional later confirmed" value={fmtInt(st.confirmed)} />
          <Kv label="Mismatched (refused)" value={fmtInt(st.mismatched)} />
          <Kv label="Undone by a Bitcoin reorg" value={fmtInt(st.disconnected)} />
        </Grid>
        {st.provisional.length > 0 ? (
          <div className="mt-4" data-testid="provisional">
            <div className="text-xs mb-2" style={{ color: "var(--fainter)" }}>
              Provisional: retired from their coinbase because this node does not hold their anchor
              yet; checked when it arrives
            </div>
            <ul className="text-sm font-mono">
              {st.provisional.map((p) => (
                <li key={p.block_hash}>
                  {fmtInt(p.height)} · {shortHash(p.block_hash, 10)}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </Card>

      <Card>
        <CardHeader title="Recent pool blocks" subtitle="Highest first; the treasury gets S/200 plus any change" />
        {blocks.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--dim)" }} data-testid="no-blocks">
            The node pool has not found a block on this share chain yet.
          </p>
        ) : (
          <Table head={["Height", "Block", "Status", "Subsidy", "Paid to miners", "Outputs", "Treasury base", "Treasury change", "Treasury total", "Applied"]}>
            {blocks.map((b) => (
              <tr key={b.block_hash} data-testid="block-row">
                <Td>{fmtInt(b.height)}</Td>
                <Td mono>{shortHash(b.block_hash, 8)}</Td>
                <Td>{b.status}</Td>
                <Td>{fmtSats(b.subsidy_sats)}</Td>
                <Td>{fmtSats(b.miners_paid_sats)}</Td>
                <Td>{b.payouts.length}</Td>
                <Td>{fmtSats(b.treasury_base_sats)}</Td>
                <Td>{fmtSats(b.treasury_change_sats)}</Td>
                <Td>{fmtSats(b.treasury_sats)}</Td>
                <Td>{fmtAgo(b.applied_at, now)}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      {blocks.map((b) =>
        b.payouts.length > 0 ? (
          <Card key={`p-${b.block_hash}`} collapsible defaultCollapsed>
            <CardHeader title={`Block ${fmtInt(b.height)}: ${b.payouts.length} payout(s)`} subtitle={`${b.status} · ${shortHash(b.block_hash, 10)}`} />
            <Table head={["#", "Address", "Paid"]}>
              {b.payouts.map((p, i) => (
                <tr key={`${p.address}-${i}`}>
                  <Td>{i + 1}</Td>
                  <Td mono>{p.address}</Td>
                  <Td>{fmtSats(p.sats)}</Td>
                </tr>
              ))}
            </Table>
          </Card>
        ) : null,
      )}
      <Note>
        Payouts are in pay order: the oldest balances first, the largest balance last with whatever
        is left. All transaction fees go to the finder&apos;s node and are not shown here.
      </Note>
    </div>
  );
}
