import { Fragment, useEffect, useState } from "react";
import {
  locksList,
  locksPrepare,
  locksConfirm,
  locksRecover,
  type LockEntry,
  type LocksPreparedResponse,
  type LocksRecoveredResult,
} from "../lib/tauri";

interface Tier {
  id: string;
  label: string;
  sats: number;
}

const TIERS: Tier[] = [
  { id: "tiny", label: "Tiny", sats: 100_000 },
  { id: "small", label: "Small", sats: 1_000_000 },
  { id: "medium", label: "Medium", sats: 10_000_000 },
  { id: "large", label: "Large", sats: 100_000_000 },
];

/// Per-row inline form state. Only one form is open at a time —
/// the table row expands beneath itself when an action button is
/// clicked. Cleaner than a modal for this density and matches the
/// inline-form style of the Mix and Receive screens.
type RowForm =
  | { kind: "confirm"; lock_id: string }
  | { kind: "recover"; lock_id: string };

export function Locks() {
  const [locks, setLocks] = useState<LockEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [prep, setPrep] = useState<LocksPreparedResponse | null>(null);
  const [recovery, setRecovery] = useState<LocksRecoveredResult | null>(null);

  // Expandable forms.
  const [showPrepare, setShowPrepare] = useState(false);
  const [prepareTier, setPrepareTier] = useState<string>(TIERS[0].id);
  const [prepareCustom, setPrepareCustom] = useState("");
  const [openRow, setOpenRow] = useState<RowForm | null>(null);
  const [confirmTxid, setConfirmTxid] = useState("");
  const [recoverDest, setRecoverDest] = useState("");
  const [recoverFee, setRecoverFee] = useState("1000");

  const refresh = async () => {
    setErr(null);
    try {
      const list = await locksList();
      setLocks(list.locks);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const resolveCapacity = (): number | null => {
    if (prepareTier === "custom") {
      const n = Number(prepareCustom);
      if (!Number.isFinite(n) || n <= 0 || !Number.isInteger(n)) return null;
      return n;
    }
    const tier = TIERS.find((t) => t.id === prepareTier);
    return tier ? tier.sats : null;
  };

  const onPrepareSubmit = async () => {
    const sats = resolveCapacity();
    if (sats == null) {
      setErr("Capacity must be a positive integer (sats).");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      const result = await locksPrepare(sats);
      setPrep(result);
      setShowPrepare(false);
      setPrepareCustom("");
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const openConfirm = (lock_id: string) => {
    setOpenRow({ kind: "confirm", lock_id });
    setConfirmTxid("");
  };

  const openRecover = (lock_id: string) => {
    setOpenRow({ kind: "recover", lock_id });
    setRecoverDest("");
    setRecoverFee("1000");
  };

  const closeRow = () => {
    setOpenRow(null);
    setConfirmTxid("");
    setRecoverDest("");
  };

  const onConfirmSubmit = async (lock_id: string) => {
    const txid = confirmTxid.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(txid)) {
      setErr("Funding txid must be a 64-character hex string.");
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      await locksConfirm(lock_id, txid);
      closeRow();
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onRecoverSubmit = async (lock_id: string) => {
    const dest = recoverDest.trim();
    if (!dest) {
      setErr("Destination address is required.");
      return;
    }
    const fee = Number(recoverFee);
    if (!Number.isFinite(fee) || fee <= 0 || !Number.isInteger(fee)) {
      setErr("Fee must be a positive integer (sats).");
      return;
    }
    setBusy(true);
    setErr(null);
    setRecovery(null);
    try {
      const result = await locksRecover(lock_id, dest, fee);
      setRecovery(result);
      closeRow();
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">custody primitive</span>
          <h1>Ghost Locks</h1>
          <p className="lead">
            Time-locked taproot outputs that mix you in with every
            other CoinJoin output of the same denomination. Recover
            unilaterally without operator cooperation if the
            timelock has matured.
          </p>
        </div>
      </div>
      {err && <div className="card error-card">{err}</div>}

      <div className="card">
        <div className="card-header">
          <h2>{locks.length === 0 ? "No locks yet" : "Your locks"}</h2>
          {!showPrepare && (
            <button
              className="primary"
              onClick={() => setShowPrepare(true)}
              disabled={busy}
            >
              + Prepare lock
            </button>
          )}
        </div>

        {showPrepare && (
          <div
            className="card"
            style={{
              margin: "12px 0",
              borderColor: "var(--accent, var(--border))",
            }}
          >
            <h2 style={{ marginTop: 0 }}>Prepare a new lock</h2>
            <p className="muted" style={{ margin: 0, fontSize: 13 }}>
              Pick a tier — the four canonical denominations match
              the Wraith mix tiers, so the lock's funding output is
              indistinguishable from any other CoinJoin output of
              the same size. Custom capacities are accepted but
              break that anonymity property.
            </p>
            <div className="col">
              <label>Capacity</label>
              <select
                value={prepareTier}
                onChange={(e) => setPrepareTier(e.target.value)}
                disabled={busy}
              >
                {TIERS.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.label} — {t.sats.toLocaleString()} sats
                  </option>
                ))}
                <option value="custom">Custom amount…</option>
              </select>
            </div>
            {prepareTier === "custom" && (
              <div className="col">
                <label>Custom capacity (sats)</label>
                <input
                  type="number"
                  min={1}
                  value={prepareCustom}
                  onChange={(e) => setPrepareCustom(e.target.value)}
                  disabled={busy}
                  placeholder="e.g. 500000"
                  autoFocus
                />
              </div>
            )}
            <div className="row" style={{ marginTop: 12 }}>
              <button
                className="secondary"
                onClick={() => {
                  setShowPrepare(false);
                  setPrepareCustom("");
                }}
                disabled={busy}
                style={{ marginRight: 8 }}
              >
                Cancel
              </button>
              <button
                className="primary"
                onClick={onPrepareSubmit}
                disabled={busy}
              >
                {busy ? "Preparing…" : "Prepare"}
              </button>
            </div>
          </div>
        )}

        {locks.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Capacity</th>
                <th>State</th>
                <th>Created height</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {locks.map((l) => {
                const isOpen = openRow?.lock_id === l.lock_id;
                return (
                  <Fragment key={l.lock_id}>
                    <tr>
                      <td className="mono muted">{l.lock_id.slice(0, 18)}…</td>
                      <td>{l.capacity_sats.toLocaleString()} sats</td>
                      <td>
                        <span
                          className={`pill ${
                            l.status === "active"
                              ? "pass"
                              : l.status === "pending"
                                ? "warn"
                                : "mute"
                          }`}
                        >
                          {l.status}
                        </span>
                      </td>
                      <td className="mono muted">{l.creation_height ?? "—"}</td>
                      <td style={{ textAlign: "right" }}>
                        {l.status === "pending" && (
                          <button
                            className="secondary"
                            onClick={() => openConfirm(l.lock_id)}
                            disabled={busy}
                            style={{ marginRight: 6 }}
                          >
                            Confirm funding
                          </button>
                        )}
                        {l.status === "active" && (
                          <button
                            className="danger"
                            onClick={() => openRecover(l.lock_id)}
                            disabled={busy}
                            title="Unilateral exit — sends a recovery tx straight to bitcoind, no operator cooperation. Only works after the timelock has matured."
                          >
                            Recover
                          </button>
                        )}
                      </td>
                    </tr>
                    {isOpen && openRow.kind === "confirm" && (
                      <tr key={`${l.lock_id}-form`}>
                        <td colSpan={5}>
                          <div
                            style={{
                              padding: 12,
                              background: "var(--bg-subtle, rgba(0,0,0,0.04))",
                              borderRadius: 6,
                            }}
                          >
                            <strong>Confirm funding for {l.lock_id.slice(0, 16)}…</strong>
                            <p
                              className="muted"
                              style={{ margin: "4px 0 8px", fontSize: 13 }}
                            >
                              Paste the txid of the funding transaction you
                              broadcast to the lock's funding address. The
                              daemon verifies it lands at the right output
                              before promoting the lock to active.
                            </p>
                            <div className="row" style={{ alignItems: "stretch" }}>
                              <input
                                className="mono"
                                value={confirmTxid}
                                onChange={(e) => setConfirmTxid(e.target.value)}
                                placeholder="64-hex-char txid"
                                disabled={busy}
                                style={{ flex: 1 }}
                                autoFocus
                                onKeyDown={(e) => {
                                  if (e.key === "Enter") onConfirmSubmit(l.lock_id);
                                }}
                              />
                              <button
                                className="primary"
                                onClick={() => onConfirmSubmit(l.lock_id)}
                                disabled={busy}
                                style={{ marginLeft: 6 }}
                              >
                                Submit
                              </button>
                              <button
                                className="secondary"
                                onClick={closeRow}
                                disabled={busy}
                                style={{ marginLeft: 6 }}
                              >
                                Cancel
                              </button>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                    {isOpen && openRow.kind === "recover" && (
                      <tr key={`${l.lock_id}-form`}>
                        <td colSpan={5}>
                          <div
                            style={{
                              padding: 12,
                              background: "var(--bg-subtle, rgba(0,0,0,0.04))",
                              borderRadius: 6,
                            }}
                          >
                            <strong style={{ color: "var(--fail)" }}>
                              Unilateral exit — {l.lock_id.slice(0, 16)}…
                            </strong>
                            <p
                              className="muted"
                              style={{ margin: "4px 0 8px", fontSize: 13 }}
                            >
                              Builds, signs, and broadcasts a recovery tx
                              with the wallet's recovery secret. Only works
                              after the timelock (tier {l.timelock_tier})
                              matures — lock created at height{" "}
                              {l.creation_height ?? "—"}. The
                              operator is bypassed entirely — this is the
                              wallet's safety net for an unresponsive Ghost
                              Pay node.
                            </p>
                            <div className="col">
                              <label>L1 destination address</label>
                              <input
                                className="mono"
                                value={recoverDest}
                                onChange={(e) => setRecoverDest(e.target.value)}
                                placeholder="bc1q… / tb1p… / bcrt1…"
                                disabled={busy}
                                autoFocus
                              />
                            </div>
                            <div className="col">
                              <label>Mining fee (sats)</label>
                              <input
                                type="number"
                                min={1}
                                value={recoverFee}
                                onChange={(e) => setRecoverFee(e.target.value)}
                                disabled={busy}
                              />
                              <span
                                className="muted"
                                style={{ fontSize: 12 }}
                              >
                                Subtracted from the recovered amount.
                                {" "}{(l.capacity_sats - Number(recoverFee || 0)).toLocaleString()}
                                {" sats will arrive at the destination."}
                              </span>
                            </div>
                            <div className="row" style={{ marginTop: 8 }}>
                              <button
                                className="secondary"
                                onClick={closeRow}
                                disabled={busy}
                                style={{ marginRight: 6 }}
                              >
                                Cancel
                              </button>
                              <button
                                className="danger"
                                onClick={() => onRecoverSubmit(l.lock_id)}
                                disabled={busy}
                              >
                                {busy ? "Broadcasting…" : "Broadcast recovery"}
                              </button>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {recovery && (
        <div className="card" style={{ borderColor: "var(--pass)" }}>
          <h2>Unilateral exit broadcast ✓</h2>
          <p className="muted" style={{ margin: 0 }}>
            Recovery tx hit bitcoind's mempool. Once it confirms, the
            funds land at the destination address.
          </p>
          <div className="kv">
            <div className="k">Lock ID</div>
            <div className="v mono" style={{ fontSize: 12 }}>
              {recovery.lock_id}
            </div>
            <div className="k">Broadcast txid</div>
            <div className="v mono" style={{ fontSize: 12 }}>
              {recovery.broadcast_txid}
            </div>
            <div className="k">Destination</div>
            <div className="v mono" style={{ fontSize: 12 }}>
              {recovery.destination}
            </div>
            <div className="k">Recovered</div>
            <div className="v">{recovery.recovered_sats.toLocaleString()} sats</div>
            <div className="k">Fee</div>
            <div className="v">{recovery.fee_sats.toLocaleString()} sats</div>
          </div>
        </div>
      )}

      {prep && (
        <div className="card">
          <h2>Lock prepared — fund it now</h2>
          <p className="muted" style={{ margin: 0 }}>
            Send <strong>{prep.required_sats.toLocaleString()}</strong> sats
            to the address below from any Bitcoin wallet, then come
            back and click "Confirm funding" with the resulting txid.
          </p>
          <div className="kv">
            <div className="k">Lock ID</div>
            <div className="v mono" style={{ fontSize: 12 }}>
              {prep.lock_id}
            </div>
            <div className="k">Funding address</div>
            <div className="v mono" style={{ fontSize: 12 }}>
              {prep.funding_address}
            </div>
            <div className="k">Required</div>
            <div className="v">{prep.required_sats.toLocaleString()} sats</div>
          </div>
        </div>
      )}
    </div>
  );
}
