import Link from "next/link";
import { Card, CardHeader } from "@/components/ui/Card";
import type { PoolMiner, PoolStatus } from "@/lib/api/pool";
import {
  bestRate,
  errorText,
  fmtAgo,
  fmtDifficulty,
  fmtDuration,
  fmtHashrate,
  fmtInt,
  shortHash,
  UNKNOWN,
} from "@/lib/pool/view";
import { Grid, Kv, Loading, Note, Table, Td, Unavailable } from "./parts";

/** One address's answer: undefined while loading, `error` when the call failed. */
export interface PerAddress<T> {
  data?: T;
  error?: unknown;
}

export interface MinersViewProps {
  status?: PoolStatus;
  statusError?: unknown;
  statusLoading?: boolean;
  /** The addresses to list: finders of found blocks and the ones looked up here. */
  addresses: string[];
  /** Miner answers by address. */
  miners: Record<string, PerAddress<PoolMiner>>;
  now: number;
}

export function minerHref(address: string): string {
  return `/miners/${encodeURIComponent(address)}`;
}

function Failed({ error }: { error: unknown }) {
  return (
    <span style={{ color: "var(--red)" }} title={errorText(error)}>
      unavailable
    </span>
  );
}

function Unk() {
  return <span style={{ color: "var(--fainter)", fontStyle: "italic" }}>{UNKNOWN}</span>;
}

/** A per-address cell: the value, "unavailable" on a failed call, "unknown" while waiting. */
function cell<T>(r: PerAddress<T> | undefined, f: (d: T) => React.ReactNode) {
  if (r?.data !== undefined) return f(r.data);
  if (r?.error) return <Failed error={r.error} />;
  return <Unk />;
}

export function MinersView({ status, statusError, statusLoading, addresses, miners, now }: MinersViewProps) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="Connected now" subtitle="This node's own connections" />
        {statusLoading && !status ? <Loading what="the pool status" /> : null}
        {!status && statusError ? <Unavailable what="Pool status" error={statusError} /> : null}
        <Grid>
          <Kv label="Miners (payout addresses)" value={fmtInt(status?.miners.connected)} />
          <Kv label="Worker connections" value={fmtInt(status?.miners.workers)} />
          <Kv label="Pool hashrate, 1 hour" value={fmtHashrate(status?.pool_hashrate_hs["1h"])} />
        </Grid>
        <Note>
          The pool status counts connections but does not name them. Look up an address below to see its
          workers; addresses that found a block here, and the ones looked up in this browser, are listed.
        </Note>
      </Card>

      <Card>
        <CardHeader title="Miners" subtitle={`${fmtInt(addresses.length)} listed`} />
        {addresses.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--dim)" }} data-testid="no-miners">
            No address to list yet. Look one up above.
          </p>
        ) : (
          <Table head={["Address", "Workers online", "Hashrate", "Shares, 24 h", "Best share", "Last share", "Blocks", "Expected time to a block"]}>
            {addresses.map((a) => {
              const r = miners[a];
              return (
                <tr key={a} data-testid="miner-row">
                  <Td mono>
                    <Link href={minerHref(a)} style={{ color: "var(--accent)" }}>
                      {shortHash(a, 8)}
                    </Link>
                  </Td>
                  <Td>{cell(r, (m) => `${fmtInt(m.summary.online)} of ${fmtInt(m.summary.workers)}`)}</Td>
                  <Td>{cell(r, (m) => fmtHashrate(bestRate(m.summary.hashrate_hs)))}</Td>
                  <Td>{cell(r, (m) => fmtInt(m.summary.shares_24h.accepted))}</Td>
                  <Td>{cell(r, (m) => fmtDifficulty(m.summary.best_share.ever))}</Td>
                  <Td>{cell(r, (m) => (m.summary.last_share_at ? fmtAgo(m.summary.last_share_at, now) : "never"))}</Td>
                  <Td>{cell(r, (m) => fmtInt(m.blocks_found.length))}</Td>
                  <Td>
                    {cell(r, (m) =>
                      m.expected_time_to_block.known
                        ? `~${fmtDuration(m.expected_time_to_block.seconds)}`
                        : `${UNKNOWN}: ${m.expected_time_to_block.reason ?? "no hashrate"}`,
                    )}
                  </Td>
                </tr>
              );
            })}
          </Table>
        )}
      </Card>
    </div>
  );
}
