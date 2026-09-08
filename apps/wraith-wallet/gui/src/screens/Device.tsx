/**
 * The offline signing device.
 *
 * A Ghost Lock's Savings lane spends with you *and* your backup device, and
 * that device is meant to live somewhere with no network. So a spend is not one
 * click: it is two trips across the gap, because MuSig2 needs two rounds.
 *
 * This screen is the near side of that gap. It shows what to carry out and
 * takes back what the device returns. It never sees the backup key.
 *
 * # Why the payload is big, and why that is the point
 *
 * Each trip carries the whole transaction, not a hash. A device handed a bare
 * 32-byte sighash cannot tell a legitimate spend from an attacker's — it would
 * ask "sign this?" either way, and the air gap would have protected the key
 * while the coins left. The device derives the hash from the transaction it is
 * shown, so what it displays and what it signs are the same thing.
 *
 * QR is offered alongside the text because a camera crosses an air gap without
 * a USB stick, which is the whole reason the device has no ports worth using.
 */

import { useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  ghostLockList,
  ghostLockSignBegin,
  ghostLockSignComplete,
  ghostLockSignNonce,
  type GhostLockRecord,
  type GhostLockSignBegun,
  type LockSpendSummary,
} from "../lib/tauri";

/** Lucide `ghost`, inline to match the rest of the app's icons. */
function GhostIcon({ size = 20 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M9 10h.01" />
      <path d="M15 10h.01" />
      <path d="M12 2a8 8 0 0 0-8 8v12l3-3 2.5 2.5L12 19l2.5 2.5L17 19l3 3V10a8 8 0 0 0-8-8z" />
    </svg>
  );
}

function sats(n: number): string {
  return n.toLocaleString("en-GB");
}

/** A payload to carry across the gap: readable, copyable, scannable. */
function Payload({ label, body }: { label: string; body: string }) {
  const [copied, setCopied] = useState(false);
  // QR has a practical ceiling; a large PSBT will exceed it. Say so rather
  // than rendering an unscannable block of noise.
  const qrOk = body.length <= 2000;
  return (
    <div className="device-payload">
      <div className="device-payload-head">
        <span className="eyebrow">{label}</span>
        <button
          className="btn-secondary"
          onClick={() => {
            navigator.clipboard?.writeText(body);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      {qrOk ? (
        <div className="device-qr">
          <QRCodeSVG value={body} size={220} level="M" />
        </div>
      ) : (
        <p className="muted">
          Too large for a QR code ({body.length} characters). Copy the text, or
          move it on removable media.
        </p>
      )}
      <pre className="device-payload-body mono">{body}</pre>
    </div>
  );
}

/** What the spend does. The numbers to check before anything is carried. */
function Summary({ s }: { s: LockSpendSummary }) {
  return (
    <div className="card device-summary">
      <h3>Check this before you carry anything</h3>
      <div className="device-summary-row">
        <span className="muted">Spending</span>
        <span className="mono">{sats(s.input_sats)} sats</span>
      </div>
      <div className="device-summary-row">
        <span className="muted">From</span>
        <span className="mono device-addr">
          {s.input_address ?? "(unrenderable script)"}
        </span>
      </div>
      {s.outputs.map((o, i) => (
        <div className="device-summary-row" key={i}>
          <span className="muted">Pays</span>
          <span className="mono">
            {sats(o.sats)} sats → {o.address ?? "(unrenderable script)"}
          </span>
        </div>
      ))}
      <div className="device-summary-row">
        <span className="muted">Fee</span>
        <span className="mono">{sats(s.fee_sats)} sats</span>
      </div>
      {s.input_count > 1 && (
        <p className="device-warn">
          This transaction spends {s.input_count} inputs. You are signing input{" "}
          {s.input_index}; the others are signed by whoever owns them.
        </p>
      )}
    </div>
  );
}

export function Device() {
  const [locks, setLocks] = useState<GhostLockRecord[]>([]);
  const [lockId, setLockId] = useState("");
  const [lane, setLane] = useState("savings");
  const [psbt, setPsbt] = useState("");
  const [inputIndex, setInputIndex] = useState(0);

  const [begun, setBegun] = useState<GhostLockSignBegun | null>(null);
  const [deviceNonce, setDeviceNonce] = useState("");
  const [round2, setRound2] = useState<string | null>(null);
  const [devicePartial, setDevicePartial] = useState("");
  const [signed, setSigned] = useState<{ signature: string; psbt: string } | null>(
    null,
  );

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadLocks() {
    setError(null);
    try {
      const l = await ghostLockList();
      setLocks(l);
      if (l.length > 0 && !lockId) setLockId(l[0].lock_id);
      if (l.length === 0) {
        setError("No remembered Locks. Save one on the Locks screen first.");
      }
    } catch (e) {
      setError(String(e));
    }
  }

  async function step<T>(fn: () => Promise<T>, then: (v: T) => void) {
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

  function reset() {
    setBegun(null);
    setDeviceNonce("");
    setRound2(null);
    setDevicePartial("");
    setSigned(null);
    setError(null);
  }

  return (
    <div className="screen device-screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">custody</span>
          <h1 className="device-title">
            <GhostIcon size={26} /> Offline device
          </h1>
          <p className="lead">
            Savings spends with you and your backup device together. The device
            keeps no network connection, so a spend crosses the gap twice — once
            to commit to the spend, once to sign it. Nothing here ever sees the
            backup key.
          </p>
        </div>
      </div>

      {error && <div className="card error-card">{error}</div>}

      {/* Step 1 — describe the spend. */}
      {!begun && (
        <div className="card">
          <h2>1. The spend</h2>
          <div className="form-row">
            <label>Lock</label>
            <div className="device-lock-pick">
              <select value={lockId} onChange={(e) => setLockId(e.target.value)}>
                {locks.length === 0 && <option value="">(none loaded)</option>}
                {locks.map((l) => (
                  <option key={l.lock_id} value={l.lock_id}>
                    {l.label ?? l.lock_id}
                  </option>
                ))}
              </select>
              <button className="btn-secondary" onClick={loadLocks}>
                Load Locks
              </button>
            </div>
          </div>
          <div className="form-row">
            <label>Lane</label>
            <select value={lane} onChange={(e) => setLane(e.target.value)}>
              <option value="savings">Savings — you + backup device</option>
              <option value="spending">Spending — you + Wraith quorum</option>
            </select>
            <p className="muted">
              Cash spends with your key alone, on the Sign screen. Investments
              spends by the quorum's key alone — your route out of it is the
              recall path, not this one.
            </p>
          </div>
          <div className="form-row">
            <label>Unsigned transaction (base64 PSBT)</label>
            <textarea
              rows={4}
              value={psbt}
              onChange={(e) => setPsbt(e.target.value)}
              placeholder="cHNidP8B..."
            />
          </div>
          <div className="form-row">
            <label>Which input belongs to this lane</label>
            <input
              type="number"
              min={0}
              value={inputIndex}
              onChange={(e) => setInputIndex(Number(e.target.value))}
            />
          </div>
          <button
            className="btn-primary"
            disabled={busy || !lockId || !psbt.trim()}
            onClick={() =>
              step(
                () =>
                  ghostLockSignBegin({
                    lockId,
                    lane,
                    psbt: psbt.trim(),
                    inputIndex,
                  }),
                setBegun,
              )
            }
          >
            {busy ? "Reading…" : "Review the spend"}
          </button>
        </div>
      )}

      {/* Step 2 — carry it out, bring the nonce back. */}
      {begun && !round2 && (
        <>
          <Summary s={begun.summary} />
          <div className="card">
            <h2>2. Carry this to the device</h2>
            <p className="muted">
              Run <code>ghost-lock-signer sign</code> there. It will show you the
              same figures — check they match this screen before you approve.
            </p>
            <Payload label="round 1 — to the device" body={begun.device_request} />
            <div className="form-row">
              <label>The device's public nonce</label>
              <input
                value={deviceNonce}
                onChange={(e) => setDeviceNonce(e.target.value)}
                placeholder="hex"
              />
            </div>
            <button
              className="btn-primary"
              disabled={busy || !deviceNonce.trim()}
              onClick={() =>
                step(
                  () => ghostLockSignNonce(begun.session, deviceNonce.trim()),
                  (r) => setRound2(r.device_request),
                )
              }
            >
              {busy ? "Signing our share…" : "Continue"}
            </button>
            <button className="btn-secondary" onClick={reset}>
              Start again
            </button>
          </div>
        </>
      )}

      {/* Step 3 — second trip. */}
      {begun && round2 && !signed && (
        <>
          <Summary s={begun.summary} />
          <div className="card">
            <h2>3. One more trip</h2>
            <p className="muted">
              This wallet has signed its share and its nonce is burned, so
              nothing secret is waiting here while you walk.
            </p>
            <Payload label="round 2 — to the device" body={round2} />
            <div className="form-row">
              <label>The device's partial signature</label>
              <input
                value={devicePartial}
                onChange={(e) => setDevicePartial(e.target.value)}
                placeholder="hex"
              />
            </div>
            <button
              className="btn-primary"
              disabled={busy || !devicePartial.trim()}
              onClick={() =>
                step(
                  () =>
                    ghostLockSignComplete(begun.session, devicePartial.trim()),
                  (r) => setSigned({ signature: r.signature, psbt: r.psbt }),
                )
              }
            >
              {busy ? "Combining…" : "Finish"}
            </button>
            <button className="btn-secondary" onClick={reset}>
              Start again
            </button>
          </div>
        </>
      )}

      {/* Done. */}
      {signed && (
        <div className="card device-done">
          <h2>
            <GhostIcon size={20} /> Signed
          </h2>
          <p className="muted">
            The signature was verified against the lane's own key as it was
            combined, so this is one that will spend.
          </p>
          <Payload label="signed transaction (PSBT)" body={signed.psbt} />
          <button className="btn-secondary" onClick={reset}>
            Sign another
          </button>
        </div>
      )}
    </div>
  );
}
