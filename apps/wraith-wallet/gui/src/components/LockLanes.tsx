/**
 * A Ghost Lock's four lanes, and the one number a person actually asks for.
 *
 * The total comes first because "how much have I got" is the question. The
 * lanes sit under it because the answer has four compartments that do not mean
 * the same thing.
 *
 * Two figures are deliberately never folded into the total:
 *
 * - **Pending.** Money that can still vanish must not read as settled.
 * - **Custodial.** Investments is the one lane where the quorum can move funds
 *   without you. Hiding that inside a single balance would let a reader assume
 *   all four lanes carry the same risk, and they do not.
 */

import type { GhostLockLane, GhostLockLanes } from "../lib/tauri";

function sats(n: number): string {
  return n.toLocaleString("en-GB");
}

function LaneRow({ lane }: { lane: GhostLockLane }) {
  return (
    <div className={`lane-row${lane.quorum_can_spend_alone ? " lane-custodial" : ""}`}>
      <div className="lane-head">
        <span className="lane-name">{lane.label}</span>
        {lane.quorum_can_spend_alone && (
          <span className="pill warn" title="The quorum can move these funds without you">
            custodial
          </span>
        )}
        {!lane.round_eligible && (
          <span className="pill mute" title="Already public — a round would gain nothing">
            not private
          </span>
        )}
      </div>
      <div className="lane-figures">
        <span className="mono lane-settled">{sats(lane.balance_sats)}</span>
        {lane.pending_sats > 0 && (
          <span className="mono muted lane-pending">
            +{sats(lane.pending_sats)} pending
          </span>
        )}
      </div>
      <div className="mono muted lane-addr">{lane.address}</div>
    </div>
  );
}

export function LockLanes({ data }: { data: GhostLockLanes }) {
  return (
    <div className="card lock-lanes">
      <div className="lock-total">
        <span className="eyebrow">Ghost Lock</span>
        <span className="mono lock-total-figure">{sats(data.total_sats)}</span>
        <span className="muted">sats</span>
        {data.total_pending_sats > 0 && (
          <span className="muted lock-total-pending">
            +{sats(data.total_pending_sats)} pending
          </span>
        )}
      </div>

      {data.custodial_sats > 0 && (
        <p className="lock-custodial-note">
          <strong>{sats(data.custodial_sats)} sats</strong> of this is in
          Investments, where the quorum can move funds without you. You can
          recall it, but not instantly.
        </p>
      )}

      <div className="lane-list">
        {data.lanes.map((l) => (
          <LaneRow key={l.kind} lane={l} />
        ))}
      </div>

      <p className="muted lock-height">
        Balances at block {data.chain_height}. Settled only — pending is shown
        separately.
      </p>
    </div>
  );
}
