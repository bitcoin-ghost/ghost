/**
 * Leaving a lane alone, after the delay.
 *
 * Every lane but Cash has a leaf that spends with one key and a wait: Savings
 * after ~14 months, Spending after ~7 days, Investments recalled after ~14.
 * No quorum, no backup device, no ceremony. This is the path that stops a
 * silent quorum from being the end of the money.
 *
 * # Why it asks before it signs
 *
 * A relative timelock is enforced against the input's `nSequence`, so the
 * number is dictated by the leaf. Get it wrong and the network rejects the
 * transaction as non-final — which looks like nothing happening rather than
 * like an error. So the plan comes first, and it states the number to use.
 *
 * # Why the coins are listed even when they are not ready
 *
 * Somebody opening this screen is usually asking "can I get out yet". An
 * immature coin hidden until it matures answers that question with silence.
 * Each one shows how much longer it has, in days, because a block count is not
 * a duration anybody feels.
 */

import { useState } from "react";
import {
  ghostLockEscapePlan,
  ghostLockEscapeSign,
  type GhostLockEscapePlan,
  type GhostLockRecord,
} from "../lib/tauri";

function sats(n: number): string {
  return n.toLocaleString("en-GB");
}

function days(blocks: number): string {
  const d = blocks / 144;
  if (d >= 30) return `~${(d / 30.4).toFixed(1)} months`;
  if (d >= 1) return `~${d.toFixed(1)} days`;
  return `~${(d * 24).toFixed(0)} hours`;
}

export function EscapePanel({ locks }: { locks: GhostLockRecord[] }) {
  const [lockId, setLockId] = useState("");
  const [lane, setLane] = useState("spending");
  const [plan, setPlan] = useState<GhostLockEscapePlan | null>(null);
  const [psbt, setPsbt] = useState("");
  const [inputIndex, setInputIndex] = useState(0);
  const [signed, setSigned] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const ready = plan?.coins.filter((c) => c.blocks_remaining === 0) ?? [];
  const waiting = plan?.coins.filter((c) => c.blocks_remaining > 0) ?? [];

  async function run<T>(fn: () => Promise<T>, then: (v: T) => void) {
    setBusy(true);
    setError(null);
    try {
      then(await fn());
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card escape-panel">
      <h2>Leaving alone</h2>
      <p className="muted">
        Every lane but Cash has a way out that needs nobody else — not the
        quorum, not your backup device. It costs a wait, and that is the whole
        trade: the quorum can stop answering and it cannot keep your money.
      </p>

      {error && <div className="card error-card">{error}</div>}

      <div className="form-row">
        <label>Lock</label>
        <select
          value={lockId}
          onChange={(e) => {
            setLockId(e.target.value);
            setPlan(null);
            setSigned(null);
          }}
        >
          <option value="">Choose a Lock…</option>
          {locks.map((l) => (
            <option key={l.lock_id} value={l.lock_id}>
              {l.label ?? l.lock_id}
            </option>
          ))}
        </select>
      </div>

      <div className="form-row">
        <label>Lane</label>
        <select
          value={lane}
          onChange={(e) => {
            setLane(e.target.value);
            setPlan(null);
            setSigned(null);
          }}
        >
          <option value="spending">Spending — exit without the quorum</option>
          <option value="investments">Investments — recall</option>
          <option value="savings">Savings — recovery</option>
        </select>
        <p className="muted">
          Cash has no escape: it already spends with your key alone, so there is
          nothing to wait for.
        </p>
      </div>

      <button
        className="btn-secondary"
        disabled={busy || !lockId}
        onClick={() =>
          run(() => ghostLockEscapePlan(lockId, lane), (p) => {
            setPlan(p);
            setSigned(null);
          })
        }
      >
        {busy && !plan ? "Checking…" : "What would this need?"}
      </button>

      {plan && (
        <div className="escape-plan">
          <h3>{plan.escape}</h3>
          <div className="escape-facts">
            <div>
              <span className="muted">Wait</span>
              <span className="mono">
                {plan.delay_blocks} blocks ({days(plan.delay_blocks)})
              </span>
            </div>
            <div>
              <span className="muted">nSequence each input must carry</span>
              <span className="mono">{plan.required_sequence}</span>
            </div>
            <div>
              <span className="muted">Lane</span>
              <span className="mono escape-addr">{plan.lane_address}</span>
            </div>
          </div>

          {plan.coins.length === 0 && (
            <p className="muted">No coins in this lane.</p>
          )}

          {ready.length > 0 && (
            <>
              <h4>Ready now</h4>
              <ul className="escape-coins">
                {ready.map((c) => (
                  <li key={`${c.txid}:${c.vout}`}>
                    <span className="mono">{sats(c.sats)} sats</span>{" "}
                    <span className="muted mono">
                      {c.txid.slice(0, 12)}…:{c.vout}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}

          {waiting.length > 0 && (
            <>
              <h4>Still waiting</h4>
              <ul className="escape-coins">
                {waiting.map((c) => (
                  <li key={`${c.txid}:${c.vout}`}>
                    <span className="mono">{sats(c.sats)} sats</span>{" "}
                    <span className="muted">
                      {c.blocks_remaining} more blocks (
                      {days(c.blocks_remaining)})
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}

          <div className="form-row">
            <label>
              The spend (base64 PSBT) — build it with nSequence{" "}
              <span className="mono">{plan.required_sequence}</span>
            </label>
            <textarea
              rows={3}
              value={psbt}
              onChange={(e) => setPsbt(e.target.value)}
              placeholder="cHNidP8B..."
            />
          </div>
          <div className="form-row">
            <label>Which input</label>
            <input
              type="number"
              min={0}
              value={inputIndex}
              onChange={(e) => setInputIndex(Number(e.target.value))}
            />
          </div>
          <button
            className="btn-primary"
            disabled={busy || !psbt.trim()}
            onClick={() =>
              run(
                () =>
                  ghostLockEscapeSign({
                    lockId,
                    lane,
                    psbt: psbt.trim(),
                    inputIndex,
                  }),
                (r) => setSigned(r.tx_hex),
              )
            }
          >
            {busy ? "Signing…" : "Sign the escape"}
          </button>
        </div>
      )}

      {signed && (
        <div className="escape-done">
          <h3>Signed</h3>
          <p className="muted">
            Broadcast this. It confirms once the wait has passed for the coin it
            spends.
          </p>
          <pre className="mono escape-tx">{signed}</pre>
          <button
            className="btn-secondary"
            onClick={() => navigator.clipboard?.writeText(signed)}
          >
            Copy
          </button>
        </div>
      )}
    </div>
  );
}
