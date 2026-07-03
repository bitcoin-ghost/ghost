import { useEffect, useState } from "react";
import {
  daemonEnv,
  lightBalance,
  lightHistory,
  walletDelete,
  walletList,
  walletSelect,
  walletShowMnemonic,
  walletUnlock,
  walletGhostId,
  type LightBalanceResponse,
  type LightHistoryEntry,
  type WalletEntry,
} from "../lib/tauri";
import { Onboarding } from "./Onboarding";
import { PassphraseModal } from "../components/PassphraseModal";
import { Logo } from "../components/Logo";

interface WalletProps {
  /// Bumped by App when the daemon pushes a `PaymentDetected`
  /// event. Used as a refetch trigger so the dashboard's balance
  /// + recent activity update immediately on a new receive.
  paymentTick?: number;
}

export function Wallet({ paymentTick = 0 }: WalletProps) {
  const [wallets, setWallets] = useState<WalletEntry[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [ghostId, setGhostId] = useState<string | null>(null);
  const [network, setNetwork] = useState<string | null>(null);
  const [balance, setBalance] = useState<LightBalanceResponse | null>(null);
  const [recent, setRecent] = useState<LightHistoryEntry[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  /// Mnemonic to display once after a "show backup phrase" action.
  /// The freshly-created path goes through the Onboarding wizard
  /// instead of this modal.
  const [mnemonicReveal, setMnemonicReveal] = useState<{
    name: string;
    mnemonic: string;
    reason: "backup_request";
  } | null>(null);
  /// Onboarding wizard mode — set on "+ New wallet" or
  /// "Import from mnemonic" click. null when no wizard is open.
  const [onboarding, setOnboarding] = useState<"create" | "import" | null>(
    null,
  );
  /// PassphraseModal state. The wallet name being acted on tells
  /// us which IPC to call when the user submits their passphrase.
  const [passModal, setPassModal] = useState<
    | { kind: "unlock" | "show_mnemonic"; wallet: string; error?: string }
    | null
  >(null);
  /// Delete-confirmation modal. Deleting a wallet erases its keystore
  /// from disk, so we require the user to type the wallet name back
  /// before the action is armed.
  const [deleteModal, setDeleteModal] = useState<{
    wallet: string;
    confirm: string;
    error?: string;
  } | null>(null);

  const refresh = async () => {
    setErr(null);
    try {
      const list = await walletList();
      setWallets(list.wallets);
      setActive(list.active);
      try {
        const env = await daemonEnv();
        setNetwork(env.network);
      } catch {
        /* network is best-effort; keep prior value on transient failure */
      }
      if (list.active) {
        try {
          const id = await walletGhostId();
          setGhostId(id.ghost_id);
        } catch {
          setGhostId(null);
        }
      } else {
        setGhostId(null);
        setBalance(null);
        setRecent([]);
      }
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  // Refetch balance + recent activity when an active wallet is set
  // and on each `paymentTick` push from the daemon's watch loop. The
  // 6s interval is the top-up — pushes drive the immediate update.
  useEffect(() => {
    if (!active) return;
    let alive = true;
    const tick = async () => {
      try {
        const [b, h] = await Promise.all([
          lightBalance(),
          lightHistory(5, 0),
        ]);
        if (!alive) return;
        setBalance(b);
        setRecent(h.transactions);
      } catch {
        /* daemon may be transiently unavailable; keep prior values */
      }
    };
    tick();
    const id = setInterval(tick, 6000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [active, paymentTick]);

  const onCreate = () => setOnboarding("create");
  const onImport = () => setOnboarding("import");
  const onWizardClose = async () => {
    setOnboarding(null);
    await refresh();
  };

  const onShowMnemonic = (name: string) => {
    setPassModal({ kind: "show_mnemonic", wallet: name });
  };

  const onSelect = async (name: string) => {
    setBusy(true);
    setErr(null);
    try {
      await walletSelect(name);
      await refresh();
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const onUnlock = (name: string) => {
    setPassModal({ kind: "unlock", wallet: name });
  };

  const onDelete = (name: string) => {
    setDeleteModal({ wallet: name, confirm: "" });
  };

  const onConfirmDelete = async () => {
    if (!deleteModal) return;
    if (deleteModal.confirm !== deleteModal.wallet) {
      setDeleteModal({
        ...deleteModal,
        error: "Type the wallet name exactly to confirm.",
      });
      return;
    }
    setBusy(true);
    try {
      await walletDelete(deleteModal.wallet);
      setDeleteModal(null);
      await refresh();
    } catch (e) {
      setDeleteModal({
        ...deleteModal,
        error: (e as Error).message ?? String(e),
      });
    } finally {
      setBusy(false);
    }
  };

  const onPassSubmit = async (passphrase: string) => {
    if (!passModal) return;
    const { kind, wallet } = passModal;
    setBusy(true);
    try {
      if (kind === "unlock") {
        await walletUnlock(wallet, passphrase);
        setPassModal(null);
        await refresh();
      } else {
        const r = await walletShowMnemonic(wallet, passphrase);
        setPassModal(null);
        setMnemonicReveal({
          name: r.name,
          mnemonic: r.mnemonic,
          reason: "backup_request",
        });
      }
    } catch (e) {
      // Keep the modal open with the error inline so the user can
      // retry without losing the modal context.
      setPassModal({
        ...passModal,
        error: (e as Error).message ?? String(e),
      });
    } finally {
      setBusy(false);
    }
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable in some webview sandboxes */
    }
  };

  const fmtAmount = (sats: number) => {
    const sign = sats > 0 ? "+" : "";
    return `${sign}${sats.toLocaleString()}`;
  };
  const fmtTime = (unix: number) => new Date(unix * 1000).toLocaleString();

  return (
    <div className="screen">
      {onboarding && (
        <Onboarding mode={onboarding} onClose={onWizardClose} />
      )}

      {passModal && (
        <PassphraseModal
          title={
            passModal.kind === "unlock"
              ? `Unlock ${passModal.wallet}`
              : `Reveal backup phrase for ${passModal.wallet}`
          }
          description={
            passModal.kind === "unlock"
              ? "Decrypts the keystore so the daemon can sign and derive addresses."
              : "Decrypts the keystore and displays the BIP-39 backup phrase. Required for off-device backups."
          }
          submitLabel={
            passModal.kind === "unlock" ? "Unlock" : "Reveal"
          }
          error={passModal.error}
          busy={busy}
          onSubmit={onPassSubmit}
          onCancel={() => setPassModal(null)}
        />
      )}

      {deleteModal && (
        <div className="modal-overlay">
          <div className="modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="card-header">
              <h2 style={{ margin: 0 }}>Delete wallet</h2>
              <span className="eyebrow eyebrow-dim">irreversible</span>
            </div>
            <p style={{ margin: 0 }}>
              This permanently removes the keystore for{" "}
              <strong>{deleteModal.wallet}</strong> from disk. If you
              have not written down its backup phrase,{" "}
              <strong>any funds in this wallet will be lost forever.</strong>
            </p>
            {deleteModal.error && (
              <div className="pill fail" style={{ alignSelf: "flex-start" }}>
                {deleteModal.error}
              </div>
            )}
            <div className="col">
              <label>
                Type <span className="mono">{deleteModal.wallet}</span> to
                confirm
              </label>
              <input
                className="mono"
                value={deleteModal.confirm}
                onChange={(e) =>
                  setDeleteModal({
                    ...deleteModal,
                    confirm: e.target.value,
                    error: undefined,
                  })
                }
                disabled={busy}
                autoFocus
                onKeyDown={(e) => {
                  if (
                    e.key === "Enter" &&
                    deleteModal.confirm === deleteModal.wallet
                  )
                    onConfirmDelete();
                }}
              />
            </div>
            <div
              className="row"
              style={{ justifyContent: "flex-end", gap: 8 }}
            >
              <button
                className="btn-secondary"
                onClick={() => setDeleteModal(null)}
                disabled={busy}
              >
                Cancel
              </button>
              <button
                className="btn-danger"
                onClick={onConfirmDelete}
                disabled={busy || deleteModal.confirm !== deleteModal.wallet}
              >
                {busy ? "Deleting…" : "Delete wallet"}
              </button>
            </div>
          </div>
        </div>
      )}

      {err && <div className="card" style={{ borderColor: "var(--fail)" }}>{err}</div>}

      {mnemonicReveal && (
        <div
          className="card"
          style={{
            borderColor: "var(--warn, #d97706)",
            borderWidth: 2,
            background: "var(--bg)",
          }}
        >
          <h2 style={{ marginTop: 0 }}>
            {`Backup phrase: ${mnemonicReveal.name}`}
          </h2>
          <p style={{ margin: 0 }}>
            <strong>Write these 24 words down on paper.</strong> Anyone
            with this phrase can spend funds in this wallet. The
            daemon does not keep it in plaintext — without it, fund
            recovery is impossible if the keystore file or its
            passphrase are lost.
          </p>
          <div className="mnemonic-block" style={{ marginTop: 12 }}>
            {mnemonicReveal.mnemonic
              .trim()
              .split(/\s+/)
              .map((w, i) => (
                <div className="mnemonic-word" key={i}>
                  <span className="mnemonic-idx">{i + 1}</span>
                  <span className="mnemonic-text">{w}</span>
                </div>
              ))}
          </div>
          <div className="row" style={{ marginTop: 12 }}>
            <button
              className="secondary"
              onClick={() => copy(mnemonicReveal.mnemonic)}
              style={{ marginRight: 8 }}
            >
              {copied ? "copied" : "Copy to clipboard"}
            </button>
            <button
              className="primary"
              onClick={() => setMnemonicReveal(null)}
            >
              I have written it down
            </button>
          </div>
        </div>
      )}

      {/* Dashboard hero — only shown when a wallet is active. The
          big-balance, copy-id, recent-activity layout is the
          first-impression screen the user sees on app open. */}
      {active && ghostId && (
        <div className="card" style={{ paddingBottom: 8 }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "baseline",
              marginBottom: 12,
            }}
          >
            <div>
              <div className="muted" style={{ fontSize: 13 }}>
                {active}
                {network && (
                  <span className="pill mute" style={{ marginLeft: 8 }}>
                    {network}
                  </span>
                )}
              </div>
              <div
                style={{
                  fontSize: 36,
                  fontWeight: 600,
                  letterSpacing: "-0.02em",
                  marginTop: 4,
                }}
              >
                {balance == null || balance.confirmed_sats == null
                  ? "—"
                  : balance.confirmed_sats.toLocaleString()}{" "}
                <span
                  className="muted"
                  style={{ fontSize: 18, fontWeight: 400 }}
                >
                  sats
                </span>
              </div>
              {balance != null &&
                balance.unconfirmed_sats != null &&
                balance.unconfirmed_sats > 0 && (
                  <div
                    className="muted"
                    style={{ fontSize: 13, marginTop: 2 }}
                  >
                    +{balance.unconfirmed_sats.toLocaleString()} pending
                  </div>
                )}
              {balance != null &&
                balance.locked_sats != null &&
                balance.locked_sats > 0 && (
                  <div
                    className="muted"
                    style={{ fontSize: 13, marginTop: 2 }}
                  >
                    {balance.locked_sats.toLocaleString()} in active locks
                  </div>
                )}
            </div>
          </div>

          <div className="kv">
            <div className="k">Ghost ID</div>
            <div
              className="v mono"
              style={{
                display: "flex",
                gap: 8,
                alignItems: "center",
                wordBreak: "break-all",
              }}
            >
              <span style={{ flex: 1 }}>{ghostId}</span>
              <button
                className="secondary"
                onClick={() => copy(ghostId)}
                style={{ flexShrink: 0 }}
              >
                {copied ? "copied" : "Copy"}
              </button>
            </div>
          </div>

          {recent.length > 0 && (
            <>
              <h2 style={{ marginTop: 18 }}>Recent activity</h2>
              <table className="table">
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Type</th>
                    <th>Amount</th>
                    <th>Memo</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.map((e) => (
                    <tr key={e.txid + e.timestamp}>
                      <td className="muted">{fmtTime(e.timestamp)}</td>
                      <td>
                        <span
                          className={`pill ${
                            e.tx_type === "receive" ? "pass" : "mute"
                          }`}
                        >
                          {e.tx_type}
                        </span>
                      </td>
                      <td
                        className="mono"
                        style={{
                          color:
                            e.amount_sats > 0
                              ? "var(--pass)"
                              : e.amount_sats < 0
                                ? "var(--fail)"
                                : "var(--fg)",
                        }}
                      >
                        {fmtAmount(e.amount_sats)}
                      </td>
                      <td className="muted">{e.memo ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </div>
      )}

      {wallets.length === 0 ? (
        <div className="welcome-hero">
          <Logo size={48} className="welcome-ghost" />
          <span className="eyebrow">welcome to wraith</span>
          <h1 className="welcome-title">
            Your private Bitcoin wallet on{" "}
            <span style={{ color: "var(--accent)" }}>Bitcoin Ghost</span>.
          </h1>
          <p className="welcome-lead">
            Self-custodial. Open source. Create a new wallet to
            receive your first sats, or restore an existing one from
            its 24-word backup phrase.
          </p>
          <div className="row" style={{ gap: 8, marginTop: 12 }}>
            <button
              className="btn-primary"
              onClick={onCreate}
              disabled={busy}
              style={{ padding: "12px 24px", fontSize: 15 }}
            >
              + Create new wallet
            </button>
            <button
              className="btn-secondary"
              onClick={onImport}
              disabled={busy}
              style={{ padding: "12px 24px", fontSize: 15 }}
            >
              I have a backup phrase
            </button>
          </div>
        </div>
      ) : (
      <div className="card">
        <div className="card-header">
          <h2>Wallets</h2>
          <div className="row" style={{ gap: 8 }}>
            <button
              className="btn-secondary"
              onClick={onImport}
              disabled={busy}
            >
              Import from mnemonic
            </button>
            <button className="btn-primary" onClick={onCreate} disabled={busy}>
              + New wallet
            </button>
          </div>
        </div>
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>State</th>
                <th>Ghost ID</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {wallets.map((w) => (
                <tr key={w.name}>
                  <td>{w.name}</td>
                  <td>
                    {w.is_active && (
                      <span className="pill pass" style={{ marginRight: 6 }}>
                        active
                      </span>
                    )}
                    <span className={`pill ${w.is_unlocked ? "pass" : "mute"}`}>
                      {w.is_unlocked ? "unlocked" : "locked"}
                    </span>
                  </td>
                  <td className="mono muted">
                    {w.ghost_id ? `${w.ghost_id.slice(0, 18)}…` : "—"}
                  </td>
                  <td style={{ textAlign: "right" }}>
                    {!w.is_active && (
                      <button
                        className="btn-secondary btn-sm"
                        onClick={() => onSelect(w.name)}
                        disabled={busy}
                        style={{ marginRight: 6 }}
                      >
                        Select
                      </button>
                    )}
                    {!w.is_unlocked && (
                      <button
                        className="btn-secondary btn-sm"
                        onClick={() => onUnlock(w.name)}
                        disabled={busy}
                        style={{ marginRight: 6 }}
                      >
                        Unlock
                      </button>
                    )}
                    <button
                      className="btn-secondary btn-sm"
                      onClick={() => onShowMnemonic(w.name)}
                      disabled={busy}
                      title="Decrypt and display the BIP-39 backup phrase"
                      style={{ marginRight: 6 }}
                    >
                      Backup
                    </button>
                    <button
                      className="btn-danger btn-sm"
                      onClick={() => onDelete(w.name)}
                      disabled={busy}
                      title="Permanently delete this wallet from disk"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
      </div>
      )}
    </div>
  );
}
