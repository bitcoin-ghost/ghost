import Link from "next/link";
import { Card, CardHeader } from "@/components/ui/Card";
import type { NodePoolLedger, NodePoolMiner, NodePoolStatus } from "@/lib/api/nodePool";
import {
  bestRate,
  errorText,
  fmtHashrate,
  fmtInt,
  fmtSats,
  groupByAddress,
  sensingLabel,
  shortHash,
  UNKNOWN,
  waitLabel,
} from "@/lib/nodePool/view";
import { Grid, Kv, Loading, Note, Table, Td, Unavailable } from "./parts";

/** One address's answers: undefined while loading, `error` when the call failed. */
export interface PerAddress<T> {
  data?: T;
  error?: unknown;
}

export interface MinersViewProps {
  status?: NodePoolStatus;
  statusError?: unknown;
  statusLoading?: boolean;
  /** Ledger answers by address. */
  ledgers: Record<string, PerAddress<NodePoolLedger>>;
  /** Miner-page answers by address. */
  miners: Record<string, PerAddress<NodePoolMiner>>;
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

function queueText(l: NodePoolLedger): string {
  if (!l.queue) return l.queue_unavailable ? `${UNKNOWN}: ${l.queue_unavailable}` : UNKNOWN;
  const q = l.queue;
  if (!q.eligible) return `not eligible (below ${fmtSats(l.min_payout_sats)})`;
  if (q.is_top) return `top balance of ${fmtInt(q.eligible_count)}`;
  const parts: string[] = [];
  if (q.age_rank != null) parts.push(`#${q.age_rank} oldest`);
  if (q.size_rank != null) parts.push(`#${q.size_rank} largest`);
  return `${parts.join(", ") || UNKNOWN} of ${fmtInt(q.eligible_count)}`;
}

export function MinersView({ status, statusError, statusLoading, ledgers, miners }: MinersViewProps) {
  if (!status) {
    return (
      <Card>
        <CardHeader title="Connected miners" />
        {statusError ? <Unavailable what="Node pool status" error={statusError} /> : null}
        {!statusError && statusLoading !== false ? <Loading what="connected miners" /> : null}
      </Card>
    );
  }
  const groups = groupByAddress(status.miners);
  const warned = status.miners.filter((m) => m.firmware_warning);
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="Summary" />
        <Grid>
          <Kv label="Open channels" value={fmtInt(status.miners.length)} />
          <Kv label="Payout addresses" value={fmtInt(groups.length)} />
          <Kv label="Firmware warnings" value={fmtInt(warned.length)} />
        </Grid>
      </Card>

      {warned.length > 0 ? (
        <Card>
          <CardHeader title="Firmware warnings" subtitle="Low-limit firmware: its blocks pay fewer balances" />
          <ul className="space-y-2 text-sm" data-testid="firmware-warnings">
            {warned.map((m) => (
              <li key={`${m.downstream_id}-${m.channel_id}`}>
                <span className="font-mono text-xs">{shortHash(m.address, 10)}</span>
                {m.worker ? <span style={{ color: "var(--dim)" }}> · {m.worker}</span> : null}
                <div style={{ color: "var(--accent)" }}>{m.firmware_warning}</div>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}

      <Card>
        <CardHeader title="By payout address" subtitle="Shares and hashrate are this node's; balance and queue are the share chain's" />
        {groups.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--dim)" }}>
            No miner is connected to this node.
          </p>
        ) : (
          <Table head={["Address", "Workers", "Hashrate", "Shares 24 h (acc / stale / rej)", "Balance", "Queue", "Expected wait"]}>
            {groups.map(({ address, channels }) => {
              const l = ledgers[address];
              const m = miners[address];
              return (
                <tr key={address} data-testid="miner-row">
                  <Td mono>
                    <Link href={minerHref(address)} style={{ color: "var(--accent)" }}>
                      {shortHash(address, 10)}
                    </Link>
                  </Td>
                  <Td>{channels.length}</Td>
                  <Td>{cell(m, (d) => fmtHashrate(bestRate(d.summary.hashrate_hs)))}</Td>
                  <Td>
                    {cell(
                      m,
                      (d) => `${fmtInt(d.summary.shares_24h.accepted)} / ${fmtInt(d.summary.shares_24h.stale)} / ${fmtInt(d.summary.shares_24h.rejected)}`,
                    )}
                  </Td>
                  <Td>{cell(l, (d) => (d.known ? fmtSats(d.balance.sats) : "no balance yet"))}</Td>
                  <Td>{cell(l, queueText)}</Td>
                  <Td>{cell(m, (d) => waitLabel(d.expected_wait))}</Td>
                </tr>
              );
            })}
          </Table>
        )}
      </Card>

      <Card>
        <CardHeader title="Connected channels" subtitle="Slot class is how many miner outputs this channel's jobs carry" />
        {status.miners.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--dim)" }}>
            No open channels.
          </p>
        ) : (
          <Table head={["Address", "Worker", "Channel", "Slot class", "Firmware", "Sensing", "Warning"]}>
            {status.miners.map((c) => (
              <tr key={`${c.downstream_id}-${c.channel_id}`} data-testid="channel-row">
                <Td mono>{shortHash(c.address, 8)}</Td>
                <Td>{c.worker || "(no worker name)"}</Td>
                <Td>
                  {c.kind} {c.downstream_id}/{c.channel_id}
                </Td>
                <Td>{c.slot_class}</Td>
                <Td>
                  {c.sensing ? (
                    <>
                      {c.sensing.model}
                      {c.sensing.firmware ? ` ${c.sensing.firmware}` : ""}
                    </>
                  ) : c.kind === "standard" ? (
                    "n/a"
                  ) : (
                    <Unk />
                  )}
                </Td>
                <Td>{sensingLabel(c.kind, c.sensing)}</Td>
                <Td>{c.firmware_warning ? <span style={{ color: "var(--accent)" }}>{c.firmware_warning}</span> : "none"}</Td>
              </tr>
            ))}
          </Table>
        )}
        <Note>
          A miner starts at the smallest class and is stepped up only while valid shares keep
          arriving, never past its firmware&apos;s known-safe ceiling. A standard SV2 channel gets
          only a header, so it always carries the full class.
        </Note>
      </Card>
    </div>
  );
}
