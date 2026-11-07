import { Card, CardHeader } from "@/components/ui/Card";
import type { PoolHistory, PoolMiner } from "@/lib/api/pool";
import {
  chanceWithin,
  fmtAgo,
  fmtBtc,
  fmtChance,
  fmtDifficulty,
  fmtDuration,
  fmtHashrate,
  fmtInt,
  isNum,
  shortHash,
  submitSummary,
  UNKNOWN,
} from "@/lib/pool/view";
import { Grid, Kv, LevelBadge, Loading, Note, Table, Td, Unavailable } from "./parts";

export interface MinerDetailViewProps {
  address: string;
  miner?: PoolMiner;
  minerError?: unknown;
  history?: PoolHistory;
  historyError?: unknown;
  now: number;
}

const STATUS_LEVEL = { online: "ok", idle: "warn", offline: "unknown" } as const;

/** Sum of the known values of a series, or null when none is known. */
function knownSum(v: (number | null)[] | undefined): number | null {
  if (!v) return null;
  let s: number | null = null;
  for (const x of v) if (isNum(x)) s = (s ?? 0) + x;
  return s;
}

function knownMax(v: (number | null)[] | undefined): number | null {
  if (!v) return null;
  let s: number | null = null;
  for (const x of v) if (isNum(x)) s = s === null ? x : Math.max(s, x);
  return s;
}

export function MinerDetailView({ address, miner, minerError, history, historyError, now }: MinerDetailViewProps) {
  if (!address) return <Unavailable what="Miner" error="no address given" />;
  if (!miner) {
    return minerError ? <Unavailable what="Miner" error={minerError} /> : <Loading what="the miner" />;
  }
  const s = miner.summary;
  const e = miner.expected_time_to_block;
  const mean = e.known && isNum(e.seconds) ? e.seconds : null;
  const blocks = [...miner.blocks_found].reverse();
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="Summary" subtitle={`${miner.network} · ${address}`} />
        <Grid>
          <Kv label="Workers online" value={`${fmtInt(s.online)} of ${fmtInt(s.workers)}`} />
          <Kv label="Idle / offline" value={`${fmtInt(s.idle)} / ${fmtInt(s.offline)}`} />
          <Kv label="Hashrate, 15 min" value={fmtHashrate(s.hashrate_hs["15m"])} />
          <Kv label="Hashrate, 1 hour" value={fmtHashrate(s.hashrate_hs["1h"])} />
          <Kv label="Hashrate, 24 hours" value={fmtHashrate(s.hashrate_hs["24h"])} />
          <Kv
            label="Shares, 24 hours"
            value={`${fmtInt(s.shares_24h.accepted)} accepted · ${fmtInt(s.shares_24h.stale)} stale · ${fmtInt(s.shares_24h.rejected)} rejected`}
          />
          <Kv label="Last share" value={s.last_share_at ? fmtAgo(s.last_share_at, now) : "never"} />
          <Kv label="Best share ever" value={fmtDifficulty(s.best_share.ever)} />
          <Kv label="Best share, 24 hours" value={fmtDifficulty(s.best_share["24h"])} />
          <Kv label="Blocks found" value={fmtInt(miner.blocks_found.length)} />
          <Kv label="Output script" value={miner.script_hex} mono />
          <Kv label="Collecting since" value={new Date(miner.collecting_since * 1000).toLocaleString()} />
        </Grid>
        {Object.keys(s.shares_24h.reject_reasons).length > 0 ? (
          <Note>
            Rejected, by reason:{" "}
            {Object.entries(s.shares_24h.reject_reasons)
              .map(([k, v]) => `${k} ${fmtInt(v)}`)
              .join(", ")}
          </Note>
        ) : null}
      </Card>

      <Card>
        <CardHeader title="Expected time to a block" subtitle="At this address's hashrate on this node" />
        <Grid>
          <Kv label="Average wait" value={mean !== null ? `~${fmtDuration(mean)}` : `${UNKNOWN}: ${e.reason ?? "no estimate"}`} />
          <Kv label="Chance within a day" value={fmtChance(chanceWithin(86_400, mean))} />
          <Kv label="Chance within a year" value={fmtChance(chanceWithin(365.25 * 86_400, mean))} />
          <Kv label="Hashrate assumed" value={e.known ? `${fmtHashrate(e.hashrate_hs)} (${e.hashrate_window ?? UNKNOWN})` : UNKNOWN} />
          <Kv label="Network difficulty" value={fmtDifficulty(e.network_difficulty)} />
        </Grid>
        <Note>
          network difficulty x 2^32 / hashrate. An average: block finding is random, and the real wait is
          often far shorter or far longer. This node sees only the workers connected to it.
        </Note>
      </Card>

      <Card>
        <CardHeader title="Workers" />
        {miner.workers.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--dim)" }}>
            No worker seen on this node for this address.
          </p>
        ) : (
          <Table head={["Worker", "Status", "Hashrate, 1 h", "Shares, 24 h", "Best share", "Last share", "Channels"]}>
            {miner.workers.map((w) => (
              <tr key={w.name} data-testid="worker-row">
                <Td mono>{w.name || "(no worker name)"}</Td>
                <Td>
                  <LevelBadge level={STATUS_LEVEL[w.status as keyof typeof STATUS_LEVEL] ?? "unknown"}>{w.status}</LevelBadge>
                </Td>
                <Td>{fmtHashrate(w.hashrate_hs["1h"])}</Td>
                <Td>
                  {fmtInt(w.shares_24h.accepted)}
                  <span style={{ color: "var(--fainter)" }}>
                    {" "}
                    · {fmtInt(w.shares_24h.stale)} stale · {fmtInt(w.shares_24h.rejected)} rejected
                  </span>
                </Td>
                <Td>{fmtDifficulty(w.best_share.ever)}</Td>
                <Td>{w.last_share_at ? fmtAgo(w.last_share_at, now) : "never"}</Td>
                <Td>{w.connections.length ? w.connections.map((c) => c.kind).join(", ") : "none"}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card>
        <CardHeader title="History" subtitle={history ? `last ${history.window}, ${history.buckets.length} buckets` : undefined} />
        {!history && historyError ? <Unavailable what="History" error={historyError} /> : null}
        {!history && !historyError ? <Loading what="the history" /> : null}
        {history ? (
          <Grid>
            <Kv label="Accepted shares" value={fmtInt(knownSum(history.total.accepted))} />
            <Kv label="Stale shares" value={fmtInt(knownSum(history.total.stale))} />
            <Kv label="Rejected shares" value={fmtInt(knownSum(history.total.rejected))} />
            <Kv label="Peak hashrate in a bucket" value={fmtHashrate(knownMax(history.total.hashrate_hs))} />
            <Kv label="Best share in the window" value={fmtDifficulty(knownMax(history.total.best_share))} />
            <Kv label="Workers left out of the series" value={fmtInt(history.workers_omitted)} />
          </Grid>
        ) : null}
      </Card>

      <Card>
        <CardHeader title="Blocks found" />
        {blocks.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--dim)" }}>
            None yet.
          </p>
        ) : (
          <Table head={["Height", "Block", "Worker", "Paid", "Fees", "Check", "Other nodes", "Found"]}>
            {blocks.map((b) => (
              <tr key={b.hash}>
                <Td>{fmtInt(b.height)}</Td>
                <Td mono>{shortHash(b.hash)}</Td>
                <Td>{b.worker || "—"}</Td>
                <Td>{fmtBtc(b.reward_sats)}</Td>
                <Td>{fmtBtc(b.fees_sats)}</Td>
                <Td>{b.check ?? "not checked yet"}</Td>
                <Td>{submitSummary(b)}</Td>
                <Td>{fmtAgo(b.found_at, now)}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>
    </div>
  );
}
