import Link from "next/link";
import { Card, CardHeader } from "@/components/ui/Card";
import type { PoolMiner, PoolMinerList, PoolStatus } from "@/lib/api/pool";
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
  /** Every active payout address on this node (`/api/v1/pool/miners`). */
  list?: PoolMinerList;
  listError?: unknown;
  listLoading?: boolean;
  /** Other addresses to show: finders of found blocks and the ones looked up here. Those already
   *  in `list` are left out of this table. */
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

function ActiveMiners({ list, error, loading, now }: { list?: PoolMinerList; error?: unknown; loading?: boolean; now: number }) {
  return (
    <Card>
      <CardHeader
        title="Active miners"
        subtitle={list ? `${fmtInt(list.miners.length)} payout address(es) connected or seen in the last 24 hours` : undefined}
      />
      {loading && !list ? <Loading what="the miner list" /> : null}
      {!list && error ? <Unavailable what="Miner list" error={error} /> : null}
      {list && list.miners.length === 0 ? (
        <p className="text-sm" style={{ color: "var(--dim)" }} data-testid="no-active-miners">
          No miner is connected, and none sent a share in the last 24 hours.
        </p>
      ) : null}
      {list && list.miners.length > 0 ? (
        <Table head={["Address", "Connected", "Workers online / idle / offline", "Hashrate", "Shares, 24 h", "Best share", "Last share", "Blocks"]}>
          {list.miners.map((m) => (
            <tr key={m.address} data-testid="active-miner-row">
              <Td mono>
                <Link href={minerHref(m.address)} style={{ color: "var(--accent)" }}>
                  {shortHash(m.address, 8)}
                </Link>
              </Td>
              <Td>{m.connected ? "yes" : "no"}</Td>
              <Td>{`${fmtInt(m.online)} / ${fmtInt(m.idle)} / ${fmtInt(m.offline)}`}</Td>
              <Td>{fmtHashrate(bestRate(m.hashrate_hs))}</Td>
              <Td>{fmtInt(m.shares_24h.accepted)}</Td>
              <Td>{fmtDifficulty(m.best_share.ever)}</Td>
              <Td>{m.last_share_at ? fmtAgo(m.last_share_at, now) : "never"}</Td>
              <Td>{fmtInt(m.blocks_found)}</Td>
            </tr>
          ))}
        </Table>
      ) : null}
      <Note>
        This list names miners&apos; payout addresses, so the node serves it only to this dashboard (signed
        requests); the public website never shows it.
      </Note>
    </Card>
  );
}

export function MinersView({
  status,
  statusError,
  statusLoading,
  list,
  listError,
  listLoading,
  addresses,
  miners,
  now,
}: MinersViewProps) {
  const listed = new Set((list?.miners ?? []).map((m) => m.address));
  const others = addresses.filter((a) => !listed.has(a));
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
      </Card>

      <ActiveMiners list={list} error={listError} loading={listLoading} now={now} />

      <Card>
        <CardHeader title="Other addresses" subtitle={`${fmtInt(others.length)} block finder(s) and looked-up address(es) not active now`} />
        {others.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--dim)" }} data-testid="no-miners">
            No other address to list. Look one up above.
          </p>
        ) : (
          <Table head={["Address", "Workers online", "Hashrate", "Shares, 24 h", "Best share", "Last share", "Blocks", "Expected time to a block"]}>
            {others.map((a) => {
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
