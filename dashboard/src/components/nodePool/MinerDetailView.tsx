import { Card, CardHeader } from "@/components/ui/Card";
import type { NodePoolLedger, NodePoolMiner } from "@/lib/api/nodePool";
import {
  bestRate,
  fmtAgo,
  fmtAmountSats,
  fmtDuration,
  fmtHashrate,
  fmtInt,
  fmtSats,
  isNum,
  sensingLabel,
  shortHash,
  UNKNOWN,
  waitLabel,
} from "@/lib/nodePool/view";
import { Grid, Kv, Loading, Note, Table, Td, Unavailable } from "./parts";

/** `last_share_at` is null when this node has seen no share from the address in its window:
 *  a reported absence, not an unknown. */
const NO_SHARE = "none on this node";

export interface MinerDetailViewProps {
  address: string;
  ledger?: NodePoolLedger;
  ledgerError?: unknown;
  miner?: NodePoolMiner;
  minerError?: unknown;
  /** Unix seconds now, for "ago" columns. */
  now: number;
}

function LedgerCard({ ledger, ledgerError }: { ledger?: NodePoolLedger; ledgerError?: unknown }) {
  if (!ledger) {
    return (
      <Card>
        <CardHeader title="Ledger" />
        {ledgerError ? <Unavailable what="Ledger" error={ledgerError} /> : <Loading what="the ledger" />}
      </Card>
    );
  }
  const q = ledger.queue;
  return (
    <Card>
      <CardHeader title="Ledger" subtitle="The share chain's record: the same on every node" />
      {!ledger.known && ledger.message ? (
        <p className="text-sm mb-3" style={{ color: "var(--dim)" }}>
          {ledger.message}
        </p>
      ) : null}
      <Grid>
        <Kv label="Balance owed" value={fmtAmountSats(ledger.balance)} hint={`${ledger.balance.units} units of 2^-32 sat`} />
        <Kv label="Queued since height" value={ledger.queue_since != null ? fmtInt(ledger.queue_since) : "not queued (below the floor)"} />
        {ledger.genesis ? (
          <Kv
            label="Carried over at the cutover"
            value={fmtAmountSats(ledger.genesis.owed)}
            hint={`at height ${fmtInt(ledger.genesis.export_height)}; included in the balance owed`}
          />
        ) : null}
        <Kv label="Minimum payout" value={fmtSats(ledger.min_payout_sats)} />
        <Kv label="Next block height" value={fmtInt(q?.next_block_height)} />
        <Kv label="Owed on the next block's table" value={q ? fmtAmountSats(q.owed) : UNKNOWN} />
        <Kv label="Eligible" value={q ? (q.eligible ? "yes" : "no") : UNKNOWN} />
        <Kv label="Oldest-queue rank" value={q ? (q.age_rank != null ? `#${q.age_rank}` : q.is_top ? "top balance (paid last)" : "not ranked") : UNKNOWN} />
        <Kv label="Size rank" value={q ? (q.size_rank != null ? `#${q.size_rank}` : "not ranked") : UNKNOWN} />
        <Kv label="Eligible balances" value={fmtInt(q?.eligible_count)} />
      </Grid>
      {!q && ledger.queue_unavailable ? <Note>Queue unknown: {ledger.queue_unavailable}</Note> : null}
      <Note>
        Every share you submit is credited its expected value in sats the moment it is accepted, and
        your balance is the total of those credits less what has been paid. It is paid only when
        the pool finds a block, straight from that block&apos;s coinbase; until then it carries
        forward, never expires and is never shared out. When a block pays every balance of 1,000 sats
        or more in full, what is left goes to the block&apos;s finder.
      </Note>
      {q ? (
        <div className="mt-4">
          <div className="text-xs mb-2" style={{ color: "var(--fainter)" }}>
            What the next block would pay this address, by the finder&apos;s slot class
          </div>
          <Table head={["Slot class", "Oldest slots", "In oldest half", "Would pay"]}>
            {q.next_block.map((c) => (
              <tr key={c.slot_class}>
                <Td>{c.slot_class}</Td>
                <Td>{c.oldest_slots}</Td>
                <Td>{c.in_oldest ? "yes" : "no"}</Td>
                <Td>{fmtSats(c.sats)}</Td>
              </tr>
            ))}
          </Table>
        </div>
      ) : null}
    </Card>
  );
}

export function MinerDetailView({ address, ledger, ledgerError, miner, minerError, now }: MinerDetailViewProps) {
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader title="On this node" subtitle="Only the node a miner is connected to sees its shares" />
        {!miner ? (
          minerError ? <Unavailable what="Miner statistics" error={minerError} /> : <Loading what="miner statistics" />
        ) : (
          <>
            <Grid>
              <Kv label="Workers (online / idle / offline)" value={`${miner.summary.online} / ${miner.summary.idle} / ${miner.summary.offline}`} />
              <Kv label="Hashrate 15 min" value={fmtHashrate(miner.summary.hashrate_hs["15m"])} />
              <Kv label="Hashrate 1 h" value={fmtHashrate(miner.summary.hashrate_hs["1h"])} />
              <Kv label="Hashrate 24 h" value={fmtHashrate(miner.summary.hashrate_hs["24h"])} />
              <Kv
                label="Shares 24 h (accepted / stale / rejected)"
                value={`${fmtInt(miner.summary.shares_24h.accepted)} / ${fmtInt(miner.summary.shares_24h.stale)} / ${fmtInt(miner.summary.shares_24h.rejected)}`}
              />
              <Kv
                label="Last share"
                value={miner.summary.last_share_at == null ? NO_SHARE : fmtAgo(miner.summary.last_share_at, now)}
              />
              <Kv label="Expected wait" value={waitLabel(miner.expected_wait)} />
              <Kv label="Earned, last 24 h" value={fmtSats(miner.expected_wait.credited_sats_24h)} />
              <Kv
                label="Pool finds a block about every"
                value={
                  isNum(miner.expected_wait.pool_expected_block_interval_secs)
                    ? fmtDuration(miner.expected_wait.pool_expected_block_interval_secs)
                    : UNKNOWN
                }
                hint="what the work credited to every miner over the last day should find on average"
              />
              <Kv label="Collecting since" value={fmtAgo(miner.collecting_since, now)} />
            </Grid>
            {miner.expected_wait.assumptions.length > 0 ? (
              <Note>Wait assumes: {miner.expected_wait.assumptions.join("; ")}.</Note>
            ) : null}
            {miner.workers.length > 0 ? (
              <div className="mt-4">
                <Table head={["Worker", "Status", "Hashrate", "Shares 24 h", "Last share", "Slot class", "Sensing", "Warning"]}>
                  {miner.workers.map((w) => (
                    <tr key={w.name || "(none)"} data-testid="worker-row">
                      <Td>{w.name || "(no worker name)"}</Td>
                      <Td>{w.status}</Td>
                      <Td>{fmtHashrate(bestRate(w.hashrate_hs))}</Td>
                      <Td>
                        {fmtInt(w.shares_24h.accepted)} / {fmtInt(w.shares_24h.stale)} / {fmtInt(w.shares_24h.rejected)}
                      </Td>
                      <Td>{w.last_share_at == null ? NO_SHARE : fmtAgo(w.last_share_at, now)}</Td>
                      <Td>{isNum(w.slot_class) ? w.slot_class : UNKNOWN}</Td>
                      <Td>
                        {w.connections.length === 0
                          ? "not connected"
                          : w.connections
                              .map((c) =>
                                c.kind === "standard"
                                  ? sensingLabel("standard", null)
                                  : `${c.model ?? "unknown model"}${c.firmware ? ` ${c.firmware}` : ""}: ${
                                      c.settled == null ? "not sensed" : c.settled ? "settled" : "testing"
                                    }${isNum(c.ceiling_class) ? `, ceiling ${c.ceiling_class}` : ""}`,
                              )
                              .join("; ")}
                      </Td>
                      <Td>{w.firmware_warning ? <span style={{ color: "var(--accent)" }}>{w.firmware_warning}</span> : "none"}</Td>
                    </tr>
                  ))}
                </Table>
              </div>
            ) : null}
          </>
        )}
      </Card>

      <LedgerCard ledger={ledger} ledgerError={ledgerError} />

      <Card>
        <CardHeader title="Payouts" subtitle="Pool blocks that paid this address, highest first" />
        {!ledger ? (
          ledgerError ? <Unavailable what="Payouts" error={ledgerError} /> : <Loading what="payouts" />
        ) : ledger.payouts.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--dim)" }}>
            No payout to {shortHash(address, 10)} yet.
          </p>
        ) : (
          <Table head={["Height", "Block", "Paid", "Status", "Confirmations", "Spendable"]}>
            {ledger.payouts.map((p) => (
              <tr key={`${p.height}-${p.block_hash}`} data-testid="payout-row">
                <Td>{fmtInt(p.height)}</Td>
                <Td mono>{shortHash(p.block_hash, 8)}</Td>
                <Td>{fmtSats(p.sats)}</Td>
                <Td>{p.status}</Td>
                <Td>{fmtInt(p.confirmations)}</Td>
                <Td>{p.mature == null ? UNKNOWN : p.mature ? "yes" : "not yet (100 needed)"}</Td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card>
        <CardHeader title="Recent credited shares" subtitle="Network shares an anchor's batch credited" />
        {!ledger ? (
          ledgerError ? <Unavailable what="Shares" error={ledgerError} /> : <Loading what="shares" />
        ) : ledger.recent_shares.length === 0 ? (
          <p className="text-sm" style={{ color: "var(--dim)" }}>
            No credited share yet. Only shares at or above the network tier are credited, about a
            minute after an anchor includes them.
          </p>
        ) : (
          <Table head={["Share", "Anchor", "Job height", "Tier", "Credit", "Received"]}>
            {ledger.recent_shares.map((s) => (
              <tr key={s.share_id}>
                <Td mono>{shortHash(s.share_id, 6)}</Td>
                <Td mono>{shortHash(s.anchor, 6)}</Td>
                <Td>{fmtInt(s.job_height)}</Td>
                <Td>{s.credited_tier}</Td>
                <Td>{fmtAmountSats(s.credit)}</Td>
                <Td>{fmtAgo(s.received_at, now)}</Td>
              </tr>
            ))}
          </Table>
        )}
        {ledger && !ledger.settlement.caught_up ? (
          <Note>
            Settlement is still catching up ({fmtInt(ledger.settlement.synced_height)} of{" "}
            {fmtInt(ledger.settlement.bitcoin_tip)}), so payouts may be missing.
          </Note>
        ) : null}
      </Card>
    </div>
  );
}
