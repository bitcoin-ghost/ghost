import { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  lightReceive,
  watchForPayments,
  walletGhostId,
  type DetectedPayment,
} from "../lib/tauri";

interface ReceiveProps {
  /// Bumped by App whenever a coin arrives, so the "received" badge lights up
  /// without this screen subscribing twice.
  paymentTick?: number;
}

/// Build a BIP-21 URI for the L1 receive address. Same shape the
/// Merchant screen emits, minus the amount param. The `ghost=`
/// extension carries the bech32 ghost-id so Ghost-aware wallets
/// route via BIP-352 silent payments.
function bip21ReceiveUri(address: string, ghost_id: string | null): string {
  if (!ghost_id) return `bitcoin:${address}`;
  const params = new URLSearchParams();
  params.set("ghost", ghost_id);
  return `bitcoin:${address}?${params.toString()}`;
}

export function Receive({ paymentTick: _ }: ReceiveProps = {}) {
  const [ghostId, setGhostId] = useState<string | null>(null);
  const [address, setAddress] = useState<string | null>(null);
  const [index, setIndex] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState<"ghost" | "address" | null>(null);
  const [latestDetect, setLatestDetect] = useState<DetectedPayment | null>(
    null,
  );

  const refresh = async () => {
    setErr(null);
    try {
      const id = await walletGhostId();
      setGhostId(id.ghost_id);
      const recv = await lightReceive(index);
      setAddress(recv.address);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  useEffect(() => {
    refresh();
  }, [index]);

  // Watch for a coin landing while this screen is open, so the "received"
  // pill flashes here specifically. Polled more often than the app-wide
  // watcher: somebody is standing in front of this screen waiting.
  useEffect(() => {
    return watchForPayments((p) => setLatestDetect(p), { intervalMs: 5_000 });
  }, []);

  const copy = async (text: string, tag: "ghost" | "address") => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(tag);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">incoming</span>
          <h1>Receive</h1>
          <p className="lead">
            Share a Ghost ID for instant L2 payments, or a fresh
            BIP86 address for L1 deposits. The wallet listens
            continuously — incoming sats land in History
            automatically.
          </p>
        </div>
        <span className="pill pass live" title="BIP-352 listener active">
          listening
        </span>
      </div>

      {err && <div className="card error-card">{err}</div>}

      {latestDetect && (
        <div
          className="card"
          style={{ borderColor: "var(--pass)", borderLeftWidth: 3 }}
        >
          <div className="row" style={{ alignItems: "center", gap: 12 }}>
            <div style={{ fontSize: 24, color: "var(--pass)" }}>✓</div>
            <div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 18 }}>
                +{latestDetect.amount_sats.toLocaleString()}{" "}
                <span className="muted" style={{ fontSize: 13 }}>sats</span>
              </div>
              <div className="muted" style={{ fontSize: 12 }}>
                received · txid {latestDetect.txid.slice(0, 16)}…
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <h2>Ghost ID — instant L2 payments</h2>
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          Share this with senders. Ghost-aware wallets route via
          BIP-352 silent payments — instant, no on-chain transaction,
          no liquidity setup.
        </p>
        {ghostId && (
          <div className="receive-pair">
            <div className="qr-card">
              <QRCodeSVG value={ghostId} size={140} level="M" />
            </div>
            <div className="receive-pair-text">
              <div className="row" style={{ alignItems: "stretch", gap: 6 }}>
                <input readOnly value={ghostId} className="mono" />
                <button
                  className="btn-secondary btn-sm"
                  onClick={() => copy(ghostId, "ghost")}
                >
                  {copied === "ghost" ? "copied" : "Copy"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Bitcoin address — L1 deposits</h2>
          <div className="row" style={{ gap: 6, alignItems: "center" }}>
            <label
              style={{
                margin: 0,
                textTransform: "none",
                letterSpacing: 0,
                fontFamily: "var(--font-sans)",
                fontSize: 13,
                color: "var(--dim)",
              }}
            >
              Index
            </label>
            <input
              type="number"
              min={0}
              value={index}
              onChange={(e) => setIndex(Number(e.target.value) || 0)}
              style={{ width: 80 }}
            />
          </div>
        </div>
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          Fresh BIP86 taproot address. Any Bitcoin wallet can pay it
          directly. Ghost-aware wallets pick up the embedded ghost-id
          from the QR and route via silent payments instead — one QR
          works everywhere.
        </p>
        {address && (
          <div className="receive-pair">
            <div className="qr-card">
              <QRCodeSVG
                value={bip21ReceiveUri(address, ghostId)}
                size={140}
                level="M"
              />
            </div>
            <div className="receive-pair-text">
              <div className="row" style={{ alignItems: "stretch", gap: 6 }}>
                <input readOnly value={address} className="mono" />
                <button
                  className="btn-secondary btn-sm"
                  onClick={() => copy(address, "address")}
                >
                  {copied === "address" ? "copied" : "Copy"}
                </button>
              </div>
              <span
                className="muted"
                style={{ fontSize: 11, marginTop: 4, display: "block", fontFamily: "var(--font-mono)" }}
              >
                m/86'/531'/0'/0/{index}
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
