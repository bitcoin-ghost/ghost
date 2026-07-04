import { useEffect, useMemo, useState } from "react";
import {
  lightBalance,
  lightL1Utxos,
  lightSend,
  psbtBumpFee,
  psbtCreate,
  type LightBalanceResponse,
  type LightL1UtxoEntry,
  type LightSendMode,
  type OutpointRef,
  type PsbtCreateResponse,
} from "../lib/tauri";

/// Send "mode" widening — the daemon exposes exactly one real send
/// mode (`ghostpay`, the instant L2 ledger transfer). The GUI adds a
/// second option, `psbt`, which doesn't go through `lightSend` at all:
/// it builds an unsigned PSBT and lets the user download / sign it
/// elsewhere. This keeps the mode-card UX consistent without
/// pretending PSBT is a daemon send mode.
///
/// The former `wraith`/`confidential` cards were removed: neither had
/// a real Send code path (both silently took the plaintext L2 route),
/// so offering them was a truth-in-advertising defect. Unlinkable L1
/// spends live in the Mix tab; a shielded confidential L2 transfer is
/// post-v1 (needs client-side ZK proving the wallet can't yet do).
type UiSendMode = LightSendMode | "psbt";

interface SendProps {
  activeWallet: string | null;
}

interface ModeOption {
  id: UiSendMode;
  label: string;
  /// Short badge on the card ("recommended" / "advanced") so the
  /// primary path (L2) reads as the default at a glance.
  badge: string;
  /// One-line "what this is / when to use it" — the concise helper
  /// the operator asked for. Sits above the longer `hint`.
  tagline: string;
  hint: string;
}

// Order is load-bearing: Ghost Pay (instant L2) is listed FIRST and is
// the default mode — it's the path most sends should take. PSBT (L1) is
// the secondary, advanced path. Keep L2 first so the UI always leads
// with it.
const MODES = [
  {
    id: "ghostpay",
    label: "Ghost Pay (instant L2)",
    badge: "recommended",
    tagline: "Instant · off-chain · no network fee.",
    hint: "Instant off-chain transfer through the operator. No on-chain tx, no confirmation wait — settles to L1 in batches later. For an unlinkable on-chain spend, use the Mix tab (Wraith CoinJoin).",
  },
  {
    id: "psbt",
    label: "PSBT export (L1)",
    badge: "advanced",
    tagline: "On-chain · you sign & broadcast · for cold storage or multisig.",
    hint: "Builds an unsigned BIP-174 PSBT spending your L1 UTXOs. Sign here, on a hardware wallet, or with cosigners — then broadcast from the Sign tab. Use for cold-storage flows or multisig.",
  },
] as const satisfies readonly ModeOption[];

// Compile-time guard: Send must offer *exactly* the real modes, no
// more. The GUI has no unit-test runner — its check is `tsc --noEmit`
// (the `lint`/`build` scripts) — so this type-level assertion is the
// stand-in. It fails the build if the set of card ids ever drifts from
// `UiSendMode` (`ghostpay` | `psbt`): dropping a real mode, or letting
// a retired one (`wraith`/`confidential`) back in, both break here.
type Equal<A, B> =
  (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2)
    ? true
    : false;
type Expect<T extends true> = T;
// Exported so `noUnusedLocals` doesn't strip it — the export is the
// only reference it needs; the assertion still runs at compile time.
export type _ModesAreExactlyTheRealModes = Expect<
  Equal<(typeof MODES)[number]["id"], UiSendMode>
>;

/// Recipient prefix → human-readable network/format identifier.
/// Surfaced to the user as a "we recognise this as X" hint so a
/// typo in the address surfaces before submit. We DON'T block
/// submit on this — Ghost-id formats may evolve and we shouldn't
/// hard-fail on a prefix we don't yet know.
function recipientShape(s: string): string | null {
  const t = s.trim();
  if (!t) return null;
  if (t.startsWith("ghost1q")) return "Ghost-id (mainnet)";
  if (t.startsWith("tghost1q")) return "Ghost-id (signet/testnet)";
  if (t.startsWith("sghost1q")) return "Ghost-id (signet)";
  if (t.startsWith("rghost1q")) return "Ghost-id (regtest)";
  if (t.startsWith("bc1")) return "Bitcoin address (mainnet, segwit)";
  if (t.startsWith("tb1")) return "Bitcoin address (testnet/signet, segwit)";
  if (t.startsWith("bcrt1")) return "Bitcoin address (regtest, segwit)";
  if (t.startsWith("1") || t.startsWith("3")) return "Bitcoin address (mainnet, legacy)";
  return null;
}

/// localStorage key for recent recipient suggestions, scoped per
/// wallet. Capped at 10 entries; most-recent first.
function recentsKey(wallet: string | null): string {
  return `wraith.send.recents:${wallet ?? "_none_"}`;
}

function loadRecents(wallet: string | null): string[] {
  if (!wallet) return [];
  try {
    const raw = localStorage.getItem(recentsKey(wallet));
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.filter((s): s is string => typeof s === "string").slice(0, 10);
  } catch {
    return [];
  }
}

function pushRecent(wallet: string | null, recipient: string): void {
  if (!wallet) return;
  try {
    const existing = loadRecents(wallet);
    const next = [recipient, ...existing.filter((r) => r !== recipient)].slice(
      0,
      10,
    );
    localStorage.setItem(recentsKey(wallet), JSON.stringify(next));
  } catch {
    /* quota / sandbox */
  }
}

/// Per-UTXO localStorage keys for coin control. Labels and freezes
/// are pure presentation — they don't change daemon behaviour
/// directly; the daemon only sees the resulting `selected_outpoints`
/// list. Frozen UTXOs are simply unchecked by default in the GUI.
function coinControlKey(wallet: string | null): string {
  return `wraith.coincontrol:${wallet ?? "_none_"}`;
}
interface CoinControlEntry {
  label?: string;
  frozen?: boolean;
}
function loadCoinControl(
  wallet: string | null,
): Record<string, CoinControlEntry> {
  if (!wallet) return {};
  try {
    const raw = localStorage.getItem(coinControlKey(wallet));
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}
function saveCoinControl(
  wallet: string | null,
  data: Record<string, CoinControlEntry>,
): void {
  if (!wallet) return;
  try {
    localStorage.setItem(coinControlKey(wallet), JSON.stringify(data));
  } catch {
    /* quota / sandbox */
  }
}
function utxoKey(u: LightL1UtxoEntry): string {
  return `${u.txid}:${u.vout}`;
}

export function Send({ activeWallet }: SendProps) {
  const [balance, setBalance] = useState<LightBalanceResponse | null>(null);
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [memo, setMemo] = useState("");
  const [mode, setMode] = useState<UiSendMode>("ghostpay");
  const [feeRate, setFeeRate] = useState<string>("5");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [psbtResult, setPsbtResult] = useState<PsbtCreateResponse | null>(null);
  const [recents, setRecents] = useState<string[]>(() =>
    loadRecents(activeWallet),
  );
  // Coin control: live UTXO list + per-UTXO selection state +
  // labels + freezes. Only fetched when mode=psbt; the daemon's
  // greedy selector covers the other modes today.
  const [utxos, setUtxos] = useState<LightL1UtxoEntry[]>([]);
  const [utxosLoading, setUtxosLoading] = useState(false);
  const [utxosErr, setUtxosErr] = useState<string | null>(null);
  // Selected = checked = "include in spend". Map keyed by
  // `${txid}:${vout}`. Frozen UTXOs default to unchecked, but the
  // user can override on a per-spend basis.
  const [selectedUtxos, setSelectedUtxos] = useState<Set<string>>(new Set());
  const [coinControl, setCoinControl] = useState<
    Record<string, CoinControlEntry>
  >(() => loadCoinControl(activeWallet));
  const [showCoinControl, setShowCoinControl] = useState(false);

  useEffect(() => {
    setRecents(loadRecents(activeWallet));
    setCoinControl(loadCoinControl(activeWallet));
  }, [activeWallet]);

  // Safety net: if `mode` ever holds a value that is no longer a real
  // mode (e.g. a `wraith`/`confidential` string surviving from an old
  // build's persisted state), fall back to the safe default so the UI
  // never sits on a retired mode. Today `mode` isn't persisted, but
  // this keeps the invariant explicit and future-proof.
  useEffect(() => {
    if (mode !== "psbt" && !MODES.some((m) => m.id === mode)) {
      setMode("ghostpay");
    }
  }, [mode]);

  // Reload UTXOs whenever we enter PSBT mode (or the wallet changes
  // while already in PSBT mode). One-shot — coin control is a
  // pre-spend ritual, not a live dashboard.
  useEffect(() => {
    if (mode !== "psbt" || !activeWallet) return;
    let alive = true;
    setUtxosLoading(true);
    setUtxosErr(null);
    (async () => {
      try {
        const r = await lightL1Utxos(32, 1);
        if (!alive) return;
        setUtxos(r.utxos);
        // Default selection: every NON-frozen UTXO is checked. The
        // user can override per-spend.
        const cc = loadCoinControl(activeWallet);
        const initial = new Set<string>();
        for (const u of r.utxos) {
          const k = utxoKey(u);
          if (!cc[k]?.frozen) initial.add(k);
        }
        setSelectedUtxos(initial);
      } catch (e) {
        if (alive) setUtxosErr((e as Error).message ?? String(e));
      } finally {
        if (alive) setUtxosLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [mode, activeWallet]);

  const refreshUtxos = async () => {
    if (!activeWallet) return;
    setUtxosLoading(true);
    setUtxosErr(null);
    try {
      const r = await lightL1Utxos(32, 1);
      setUtxos(r.utxos);
      const cc = loadCoinControl(activeWallet);
      const refreshed = new Set<string>();
      for (const u of r.utxos) {
        const k = utxoKey(u);
        if (!cc[k]?.frozen) refreshed.add(k);
      }
      setSelectedUtxos(refreshed);
    } catch (e) {
      setUtxosErr((e as Error).message ?? String(e));
    } finally {
      setUtxosLoading(false);
    }
  };

  const toggleUtxoSelected = (k: string) => {
    setSelectedUtxos((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });
  };

  const updateCoinControl = (k: string, patch: Partial<CoinControlEntry>) => {
    setCoinControl((prev) => {
      const next = { ...prev };
      const existing = next[k] ?? {};
      const merged = { ...existing, ...patch };
      // Drop the entry entirely if both fields are empty/undefined
      // — keeps localStorage tidy.
      if (!merged.label && !merged.frozen) {
        delete next[k];
      } else {
        next[k] = merged;
      }
      saveCoinControl(activeWallet, next);
      return next;
    });
  };

  useEffect(() => {
    if (!activeWallet) return;
    let alive = true;
    const tick = async () => {
      try {
        const b = await lightBalance();
        if (alive) setBalance(b);
      } catch {
        /* ignore — daemon may be transiently unavailable */
      }
    };
    tick();
    const id = setInterval(tick, 3000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [activeWallet]);

  const validate = (): string | null => {
    if (!recipient.trim()) return "Recipient is required.";
    const amt = Number(amount);
    if (!Number.isFinite(amt) || amt <= 0 || !Number.isInteger(amt)) {
      return "Amount must be a positive integer (sats).";
    }
    // Soft-warn over balance — daemon will reject anyway, but surface
    // it before the user clicks confirm.
    if (
      balance &&
      balance.confirmed_sats != null &&
      amt > balance.confirmed_sats
    ) {
      return `Amount exceeds confirmed balance (${balance.confirmed_sats.toLocaleString()} sats).`;
    }
    return null;
  };

  const onReview = () => {
    setErr(null);
    setSuccess(null);
    const v = validate();
    if (v) {
      setErr(v);
      return;
    }
    setConfirming(true);
  };

  const onConfirm = async () => {
    const amt = Number(amount);
    setBusy(true);
    setErr(null);
    try {
      if (mode === "psbt") {
        // PSBT export path: no broadcast happens. We build an
        // unsigned PSBT and surface it for the user to copy /
        // download / take to a hardware wallet.
        const fr = Number(feeRate);
        // Coin control: pass the user's checked set. Empty set
        // means "let the daemon pick anything" (no filter); the
        // daemon converts an absent/empty list into the greedy
        // default. We only forward the list when the user actively
        // narrowed below the full set — otherwise stale localStorage
        // freezes shouldn't accidentally constrain a sensible
        // greedy pick.
        const allKeys = utxos.map((u) => utxoKey(u));
        const isNarrowed =
          allKeys.length > 0 &&
          selectedUtxos.size > 0 &&
          selectedUtxos.size < allKeys.length;
        const selected_outpoints: OutpointRef[] | undefined = isNarrowed
          ? utxos
              .filter((u) => selectedUtxos.has(utxoKey(u)))
              .map((u) => ({ txid: u.txid, vout: u.vout }))
          : undefined;
        const result = await psbtCreate({
          recipient_address: recipient.trim(),
          amount_sats: amt,
          fee_rate_sats_per_vb:
            Number.isFinite(fr) && fr > 0 ? fr : 5,
          selected_outpoints,
        });
        setPsbtResult(result);
        setSuccess(
          `Built unsigned PSBT — ${result.input_count} input(s), ${result.fee_sats.toLocaleString()} sat fee.${
            isNarrowed
              ? ` (coin control: ${selected_outpoints!.length} of ${allKeys.length} UTXOs eligible)`
              : ""
          }`,
        );
        pushRecent(activeWallet, recipient.trim());
        setRecents(loadRecents(activeWallet));
        setConfirming(false);
      } else {
        await lightSend(
          recipient.trim(),
          amt,
          mode,
          memo.trim() || undefined,
        );
        setSuccess(
          `Sent ${amt.toLocaleString()} sats to ${recipient.slice(0, 18)}…`,
        );
        pushRecent(activeWallet, recipient.trim());
        setRecents(loadRecents(activeWallet));
        setRecipient("");
        setAmount("");
        setMemo("");
        setConfirming(false);
      }
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onCopyPsbt = async () => {
    if (!psbtResult) return;
    try {
      await navigator.clipboard.writeText(psbtResult.psbt);
      setSuccess("PSBT copied to clipboard.");
    } catch {
      setErr("Clipboard unavailable — use Download instead.");
    }
  };

  const onDownloadPsbt = () => {
    if (!psbtResult) return;
    const blob = new Blob([psbtResult.psbt], {
      type: "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const stamp = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `wraith-${stamp}.psbt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  };

  const onCancel = () => {
    setConfirming(false);
  };

  if (!activeWallet) {
    return (
      <div className="screen">
        <h1>Send</h1>
        <div className="card muted">
          Select a wallet first to send L2 payments.
        </div>
      </div>
    );
  }

  const shape = recipientShape(recipient);
  const modeOption = MODES.find((m) => m.id === mode) ?? MODES[0];
  const amtNum = Number(amount);

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">outgoing</span>
          <h1>Send</h1>
          <p className="lead">
            Default is <strong>Ghost Pay</strong> — an instant, off-chain
            L2 transfer with no network fee. Need a plain on-chain spend
            instead? Switch to PSBT export (L1) and sign it yourself. For
            an unlinkable on-chain spend, use the Mix tab. The recipient
            field accepts both a ghost-id and any Bitcoin address.
          </p>
        </div>
      </div>

      <div className="card">
        <h2>Available balance</h2>
        <div className="kv">
          <div className="k">Confirmed</div>
          <div className="v">
            {balance?.confirmed_sats?.toLocaleString() ?? "—"} sats
          </div>
          <div className="k">Pending</div>
          <div className="v">
            {balance?.unconfirmed_sats?.toLocaleString() ?? "—"} sats
          </div>
          {balance?.locked_sats != null && balance.locked_sats > 0 && (
            <>
              <div className="k">In locks</div>
              <div className="v">
                {balance.locked_sats.toLocaleString()} sats
              </div>
            </>
          )}
        </div>
      </div>

      {confirming ? (
        // Confirmation step — full review of what's about to go out.
        // Prevents a slip of the finger from sending the wrong amount
        // to the wrong recipient.
        <div className="card" style={{ borderColor: "var(--accent, var(--border))" }}>
          <h2>Confirm payment</h2>
          {err && (
            <div
              className="pill fail"
              style={{ alignSelf: "flex-start", marginBottom: 8 }}
            >
              {err}
            </div>
          )}
          <div className="kv">
            <div className="k">Mode</div>
            <div className="v">
              <strong>{modeOption.label}</strong>
              <div
                className="muted"
                style={{ fontSize: 12, marginTop: 4 }}
              >
                {modeOption.hint}
              </div>
            </div>
            <div className="k">Amount</div>
            <div className="v">
              <strong style={{ fontSize: 18 }}>
                {amtNum.toLocaleString()} sats
              </strong>
            </div>
            <div className="k">Recipient</div>
            <div className="v mono" style={{ wordBreak: "break-all" }}>
              {recipient}
              {shape && (
                <div
                  className="muted"
                  style={{ fontFamily: "var(--font-base, sans-serif)", fontSize: 12, marginTop: 4 }}
                >
                  {shape}
                </div>
              )}
            </div>
            {memo && (
              <>
                <div className="k">Memo</div>
                <div className="v">{memo}</div>
              </>
            )}
          </div>
          <div className="row" style={{ marginTop: 16 }}>
            <button
              className="secondary"
              onClick={onCancel}
              disabled={busy}
              style={{ marginRight: 8 }}
            >
              Back
            </button>
            <button
              className="primary"
              onClick={onConfirm}
              disabled={busy}
            >
              {busy ? "Sending…" : "Confirm send"}
            </button>
          </div>
        </div>
      ) : (
        <div className="card">
          <h2>New payment</h2>
          {err && (
            <div className="pill fail" style={{ alignSelf: "flex-start" }}>
              {err}
            </div>
          )}
          {success && (
            <div className="pill pass" style={{ alignSelf: "flex-start" }}>
              {success}
            </div>
          )}
          <div className="col">
            <label>Recipient (Ghost ID or Bitcoin address)</label>
            <input
              className="mono"
              placeholder="ghost1q… / tghost1q… / bc1q…"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              disabled={busy}
              list="send-recents"
            />
            {recents.length > 0 && (
              <datalist id="send-recents">
                {recents.map((r) => (
                  <option key={r} value={r} />
                ))}
              </datalist>
            )}
            {shape && (
              <span className="muted" style={{ fontSize: 12 }}>
                {shape}
              </span>
            )}
          </div>
          <div className="row">
            <div className="col" style={{ flex: 1 }}>
              <label>Amount (sats)</label>
              <input
                type="number"
                min={1}
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                disabled={busy}
              />
            </div>
            <div className="col" style={{ flex: 2 }}>
              <label>Memo (optional, ≤59 chars)</label>
              <input
                maxLength={59}
                value={memo}
                onChange={(e) => setMemo(e.target.value)}
                disabled={busy}
              />
            </div>
          </div>
          <div className="col">
            <label>Mode</label>
            {/* TODO(design): richer infographic — a small illustrated
                diagram per mode (L2 = phone→phone instant; L1 = coin→
                block on-chain) would land the difference faster than
                text. For now we lead with clear labels, a recommended/
                advanced badge, and a one-line tagline + detail. */}
            <div className="tier-grid">
              {MODES.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  className={`tier-card${mode === m.id ? " active" : ""}`}
                  onClick={() => !busy && setMode(m.id)}
                  disabled={busy}
                >
                  <div
                    className="tier-label"
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      flexWrap: "wrap",
                    }}
                  >
                    {m.label.split(" (")[0]}
                    <span
                      className={`pill ${m.id === "ghostpay" ? "pass" : "mute"}`}
                      style={{ fontSize: 9, textTransform: "uppercase" }}
                    >
                      {m.badge}
                    </span>
                  </div>
                  <div
                    className="tier-meta"
                    style={{ marginTop: 6, fontWeight: 500 }}
                  >
                    {m.tagline}
                  </div>
                  <div
                    className="tier-meta muted"
                    style={{ marginTop: 4, lineHeight: 1.45 }}
                  >
                    {m.hint}
                  </div>
                </button>
              ))}
            </div>
          </div>
          {mode === "psbt" && (
            <>
              <div className="col">
                <label>Fee rate (sats/vB)</label>
                <input
                  type="number"
                  min={1}
                  value={feeRate}
                  onChange={(e) => setFeeRate(e.target.value)}
                  disabled={busy}
                  style={{ maxWidth: 120 }}
                />
                <span className="muted" style={{ fontSize: 11 }}>
                  Conservative default 5 sats/vB. Bump for faster
                  confirmation; the wallet won't broadcast — that's
                  still your decision.
                </span>
              </div>

              {/* Coin selection — collapsed by default. Most users
                  never need it; coin control matters most for
                  privacy-conscious or multi-account flows. */}
              <div className="col">
                <button
                  type="button"
                  className="btn-secondary btn-sm"
                  onClick={() => setShowCoinControl((s) => !s)}
                  style={{ alignSelf: "flex-start" }}
                  disabled={busy}
                >
                  {showCoinControl ? "▼" : "▶"} Coin selection
                  {utxos.length > 0 && (
                    <span className="muted" style={{ marginLeft: 8 }}>
                      ({selectedUtxos.size} / {utxos.length} eligible ·{" "}
                      {utxos
                        .filter((u) => selectedUtxos.has(utxoKey(u)))
                        .reduce((acc, u) => acc + u.amount_sats, 0)
                        .toLocaleString()}{" "}
                      sats)
                    </span>
                  )}
                </button>
                {showCoinControl && (
                  <CoinControlPanel
                    utxos={utxos}
                    selected={selectedUtxos}
                    coinControl={coinControl}
                    loading={utxosLoading}
                    err={utxosErr}
                    onToggle={toggleUtxoSelected}
                    onLabel={(k, label) => updateCoinControl(k, { label })}
                    onFreeze={(k, frozen) => {
                      updateCoinControl(k, { frozen });
                      // Freezing also unchecks; unfreezing re-checks.
                      setSelectedUtxos((prev) => {
                        const next = new Set(prev);
                        if (frozen) next.delete(k);
                        else next.add(k);
                        return next;
                      });
                    }}
                    onSelectAll={() => {
                      const all = new Set(utxos.map((u) => utxoKey(u)));
                      setSelectedUtxos(all);
                    }}
                    onSelectNonFrozen={() => {
                      const set = new Set<string>();
                      for (const u of utxos) {
                        const k = utxoKey(u);
                        if (!coinControl[k]?.frozen) set.add(k);
                      }
                      setSelectedUtxos(set);
                    }}
                    onRefresh={refreshUtxos}
                  />
                )}
              </div>
            </>
          )}
          <div className="row">
            <button className="btn-primary" onClick={onReview} disabled={busy}>
              Review →
            </button>
          </div>
        </div>
      )}

      {psbtResult && !confirming && (
        <div className="card">
          <div className="card-header">
            <h2>Unsigned PSBT</h2>
            <span className="pill mute" style={{ fontSize: 10 }}>
              {psbtResult.input_count} input(s)
            </span>
          </div>
          <div className="kv">
            <div className="k">Recipient</div>
            <div className="v mono">
              {psbtResult.recipient_sats.toLocaleString()} sats
            </div>
            <div className="k">Change</div>
            <div className="v mono">
              {psbtResult.change_sats > 0
                ? `${psbtResult.change_sats.toLocaleString()} sats (idx ${psbtResult.change_bip86_index})`
                : "absorbed into fee (residual was below dust)"}
            </div>
            <div className="k">Fee</div>
            <div className="v mono">
              {psbtResult.fee_sats.toLocaleString()} sats
            </div>
            <div className="k">Total in</div>
            <div className="v mono">
              {psbtResult.total_input_sats.toLocaleString()} sats
            </div>
          </div>
          <textarea
            readOnly
            value={psbtResult.psbt}
            rows={3}
            spellCheck={false}
            style={{ fontFamily: "var(--font-mono)", fontSize: 10 }}
          />
          <div className="row" style={{ gap: 8 }}>
            <button className="btn-secondary btn-sm" onClick={onCopyPsbt}>
              Copy
            </button>
            <button className="btn-secondary btn-sm" onClick={onDownloadPsbt}>
              Download
            </button>
            <button
              className="btn-secondary btn-sm"
              onClick={async () => {
                if (!psbtResult) return;
                const cur = Number(feeRate) || 5;
                const promptVal = window.prompt(
                  `Bump fee rate (sats/vB). Current rate ~${cur}, new must be strictly higher.`,
                  String(cur + 5),
                );
                if (!promptVal) return;
                const newRate = Number(promptVal);
                if (!Number.isFinite(newRate) || newRate <= 0) {
                  setErr("Fee rate must be a positive number.");
                  return;
                }
                setBusy(true);
                setErr(null);
                try {
                  const r = await psbtBumpFee({
                    psbt: psbtResult.psbt,
                    new_fee_rate_sats_per_vb: newRate,
                  });
                  setPsbtResult({
                    psbt: r.psbt,
                    input_count: r.input_count,
                    total_input_sats: psbtResult.total_input_sats,
                    recipient_sats: psbtResult.recipient_sats,
                    change_sats: r.new_change_sats,
                    fee_sats: r.new_fee_sats,
                    change_bip86_index: psbtResult.change_bip86_index,
                  });
                  setSuccess(
                    `Fee bumped from ${r.old_fee_sats.toLocaleString()} to ${r.new_fee_sats.toLocaleString()} sats. Re-sign and broadcast the new PSBT.`,
                  );
                  setFeeRate(String(newRate));
                } catch (e) {
                  setErr((e as Error).message ?? String(e));
                } finally {
                  setBusy(false);
                }
              }}
              disabled={busy}
              title="BIP-125 fee-bump — reduces change to absorb the higher fee, returns a fresh unsigned PSBT"
            >
              Bump fee
            </button>
            <span className="spacer" />
            <span
              className="muted"
              style={{ fontSize: 11, alignSelf: "center" }}
            >
              Sign in the Sign tab, with a hardware wallet, or pass to
              cosigners — then broadcast.
            </span>
            <button
              className="btn-secondary btn-sm"
              onClick={() => setPsbtResult(null)}
            >
              Done
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

interface CoinControlPanelProps {
  utxos: LightL1UtxoEntry[];
  selected: Set<string>;
  coinControl: Record<string, CoinControlEntry>;
  loading: boolean;
  err: string | null;
  onToggle: (k: string) => void;
  onLabel: (k: string, label: string) => void;
  onFreeze: (k: string, frozen: boolean) => void;
  onSelectAll: () => void;
  onSelectNonFrozen: () => void;
  onRefresh: () => void;
}

/// Coin selection table — UTXO rows with per-UTXO checkbox, label,
/// and freeze. Labels persist across reloads (privacy hint: "this
/// is from KYC exchange X, don't combine with this one"). Freeze
/// just defaults the checkbox to unchecked on reload — no daemon-
/// side enforcement, since the daemon only sees the resulting
/// `selected_outpoints`.
function CoinControlPanel({
  utxos,
  selected,
  coinControl,
  loading,
  err,
  onToggle,
  onLabel,
  onFreeze,
  onSelectAll,
  onSelectNonFrozen,
  onRefresh,
}: CoinControlPanelProps) {
  const sorted = useMemo(() => {
    // Sort by descending value so the most useful UTXOs sit at the
    // top — matches how the daemon's greedy selector picks.
    return [...utxos].sort((a, b) => b.amount_sats - a.amount_sats);
  }, [utxos]);

  const totalSelected = sorted
    .filter((u) => selected.has(utxoKey(u)))
    .reduce((acc, u) => acc + u.amount_sats, 0);

  return (
    <div
      className="card"
      style={{ marginTop: 6, padding: 12, gap: 8 }}
    >
      {err && (
        <div className="pill fail" style={{ alignSelf: "flex-start" }}>
          {err}
        </div>
      )}
      <div className="row" style={{ gap: 8, flexWrap: "wrap" }}>
        <button
          className="btn-secondary btn-sm"
          onClick={onRefresh}
          disabled={loading}
        >
          {loading ? "Scanning…" : "Refresh"}
        </button>
        <button
          className="btn-secondary btn-sm"
          onClick={onSelectAll}
          disabled={loading || sorted.length === 0}
        >
          Select all
        </button>
        <button
          className="btn-secondary btn-sm"
          onClick={onSelectNonFrozen}
          disabled={loading || sorted.length === 0}
        >
          Select non-frozen
        </button>
        <span className="spacer" />
        <span className="muted" style={{ fontSize: 11, alignSelf: "center" }}>
          {selected.size} of {sorted.length} ·{" "}
          <strong style={{ color: "var(--fg)" }}>
            {totalSelected.toLocaleString()}
          </strong>{" "}
          sats eligible
        </span>
      </div>
      {sorted.length === 0 ? (
        <p className="muted" style={{ fontSize: 12, margin: 0 }}>
          {loading
            ? "Scanning ghost-pay's UTXO set for the wallet's BIP86 receive addresses…"
            : "No L1 UTXOs at this wallet's receive chain. Receive some funds first, or widen the BIP86 scan range."}
        </p>
      ) : (
        <table className="table" style={{ marginTop: 0 }}>
          <thead>
            <tr>
              <th style={{ width: 32 }}></th>
              <th>UTXO</th>
              <th>Label</th>
              <th style={{ width: 60 }}>Conf</th>
              <th style={{ width: 110, textAlign: "right" }}>Sats</th>
              <th style={{ width: 70 }}></th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((u) => {
              const k = utxoKey(u);
              const cc = coinControl[k] ?? {};
              const isSelected = selected.has(k);
              const isFrozen = !!cc.frozen;
              return (
                <tr
                  key={k}
                  style={{ opacity: isFrozen && !isSelected ? 0.55 : 1 }}
                >
                  <td>
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => onToggle(k)}
                    />
                  </td>
                  <td className="mono" style={{ fontSize: 10 }}>
                    {u.txid.slice(0, 12)}…:{u.vout}
                    {u.address && (
                      <div
                        className="muted"
                        style={{ fontSize: 9, wordBreak: "break-all" }}
                      >
                        {u.address}
                      </div>
                    )}
                  </td>
                  <td>
                    <input
                      value={cc.label ?? ""}
                      onChange={(e) => onLabel(k, e.target.value)}
                      placeholder="—"
                      style={{
                        width: "100%",
                        fontSize: 11,
                        padding: "2px 6px",
                      }}
                    />
                  </td>
                  <td className="mono muted" style={{ fontSize: 11 }}>
                    {u.confirmations}
                  </td>
                  <td
                    className="mono"
                    style={{ textAlign: "right", fontSize: 12 }}
                  >
                    {u.amount_sats.toLocaleString()}
                  </td>
                  <td>
                    <label
                      className="muted"
                      style={{
                        fontSize: 10,
                        display: "flex",
                        alignItems: "center",
                        gap: 4,
                        cursor: "pointer",
                      }}
                      title="Frozen UTXOs default to unchecked on reload — useful for ring-fencing coins you don't want to spend by accident"
                    >
                      <input
                        type="checkbox"
                        checked={isFrozen}
                        onChange={(e) => onFreeze(k, e.target.checked)}
                      />
                      freeze
                    </label>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
