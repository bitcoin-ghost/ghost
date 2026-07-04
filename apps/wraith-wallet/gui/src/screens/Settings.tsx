import { useEffect, useState } from "react";
import {
  daemonEnv,
  daemonHealth,
  walletList,
  walletExport,
  walletRestore,
  checkForUpdate,
  connectionStatus,
  setNodeEndpoints,
  OWN_NODE_GHOST_PAY_DEFAULT,
  OWN_NODE_GSP_DEFAULT,
  type DaemonEnvResponse,
  type HealthResponse,
  type WalletEntry,
  type WalletBackupResult,
  type CheckForUpdateResult,
  type ConnectionStatusResponse,
} from "../lib/tauri";
import { ConnectionStatus } from "../components/ConnectionStatus";

interface SettingsProps {
  /// GUI-side kiosk toggle (per-install, persisted in localStorage).
  /// Hides the nav and locks the GUI to Merchant. The daemon
  /// itself stays unrestricted, so this is a UX shortcut not a
  /// hard security barrier — see `daemonKiosk` for that.
  guiKiosk: boolean;
  /// Daemon-side kiosk lock from `WRAITHD_KIOSK_MODE`. Read-only
  /// here: the daemon refuses wallet-management ops until it
  /// restarts without the env var. The "real" till lock.
  daemonKiosk: boolean;
  onToggleGuiKiosk: (next: boolean) => void;
  /// Re-open the skippable first-run tour. The "seen" flag lives in
  /// localStorage; replaying just re-shows the tour without clearing it.
  onReplayTour: () => void;
}

/// Read-only inspection of the daemon's environment + endpoints,
/// plus a small set of GUI-only tunables (kiosk lock, theme via
/// header). Daemon-side knobs (Tor proxy, ghost-pay URLs, GSP
/// URLs, idle-lock, shroud window) are set via env vars at
/// wraithd boot — this screen surfaces what's currently active so
/// you can confirm what the daemon is using vs what you intended.
export function Settings({ guiKiosk, daemonKiosk, onToggleGuiKiosk, onReplayTour }: SettingsProps) {
  const [env, setEnv] = useState<DaemonEnvResponse | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);

  // Keystore backup / restore.
  const [wallets, setWallets] = useState<WalletEntry[]>([]);
  const [backupWallet, setBackupWallet] = useState("");
  const [backupPath, setBackupPath] = useState("");
  const [restoreName, setRestoreName] = useState("");
  const [restorePath, setRestorePath] = useState("");
  const [keystoreBusy, setKeystoreBusy] = useState(false);
  const [keystoreErr, setKeystoreErr] = useState<string | null>(null);
  const [exportResult, setExportResult] = useState<WalletBackupResult | null>(
    null,
  );
  const [restoreResult, setRestoreResult] = useState<WalletBackupResult | null>(
    null,
  );

  // Node connection selector.
  const [conn, setConn] = useState<ConnectionStatusResponse | null>(null);
  const [nodePreset, setNodePreset] = useState<"public" | "custom">("public");
  const [customPay, setCustomPay] = useState(OWN_NODE_GHOST_PAY_DEFAULT);
  const [customGsp, setCustomGsp] = useState(OWN_NODE_GSP_DEFAULT);
  const [nodeBusy, setNodeBusy] = useState(false);
  const [nodeErr, setNodeErr] = useState<string | null>(null);
  const [nodeSaved, setNodeSaved] = useState(false);
  // Populate the form from the daemon's live config exactly once, so typing
  // isn't clobbered by the 8s env poll. Only the setter is used — the flag
  // lives inside the functional updater below.
  const [, setNodeFormInit] = useState(false);

  // Update check.
  const [updateUrl, setUpdateUrl] = useState("");
  const [updateBusy, setUpdateBusy] = useState(false);
  const [updateErr, setUpdateErr] = useState<string | null>(null);
  const [updateResult, setUpdateResult] = useState<CheckForUpdateResult | null>(
    null,
  );

  const refreshWallets = async () => {
    try {
      const list = await walletList();
      setWallets(list.wallets);
      // Default the backup selector to the active wallet, if any.
      setBackupWallet((cur) => {
        if (cur && list.wallets.some((w) => w.name === cur)) return cur;
        const active = list.wallets.find((w) => w.is_active);
        return active?.name ?? list.wallets[0]?.name ?? "";
      });
    } catch {
      // Wallet management may be unavailable (e.g. kiosk mode); leave
      // the list empty so the card shows the "no wallets" hint.
    }
  };

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const [e, h] = await Promise.all([daemonEnv(), daemonHealth()]);
        if (!alive) return;
        setEnv(e);
        setHealth(h);
        setErr(null);
        // Seed the node-selector form from the daemon's live config, but only
        // once — after that the user owns the fields and the poll must not
        // overwrite what they're typing.
        setNodeFormInit((done) => {
          if (!done) {
            const preset = e.node_preset === "custom" ? "custom" : "public";
            setNodePreset(preset);
            if (preset === "custom") {
              if (e.ghost_pay_urls.length) setCustomPay(e.ghost_pay_urls.join(", "));
              if (e.gsp_urls.length) setCustomGsp(e.gsp_urls.join(", "));
            }
          }
          return true;
        });
      } catch (e) {
        if (!alive) return;
        setErr((e as Error).message ?? String(e));
      }
      // Live reachability of whatever node is currently configured. Never
      // throws for an unreachable backend — a red pill is a real answer.
      try {
        const c = await connectionStatus();
        if (alive) setConn(c);
      } catch {
        /* daemon dropped mid-tick — the env error above covers it */
      }
    };
    tick();
    refreshWallets();
    const id = setInterval(tick, 8000);
    return () => {
      alive = false;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const envLocked = !!env?.ghost_pay_env_override || !!env?.gsp_env_override;

  const onSaveNode = async () => {
    setNodeBusy(true);
    setNodeErr(null);
    setNodeSaved(false);
    try {
      if (nodePreset === "custom") {
        await setNodeEndpoints("custom", customPay.trim(), customGsp.trim());
      } else {
        await setNodeEndpoints("public");
      }
      setNodeSaved(true);
      // Pull the fresh config + reachability straight away so the card
      // reflects the change without waiting for the next 8s poll.
      const [e, c] = await Promise.all([daemonEnv(), connectionStatus()]);
      setEnv(e);
      setConn(c);
    } catch (e) {
      setNodeErr((e as Error).message ?? String(e));
    } finally {
      setNodeBusy(false);
    }
  };

  const onBackup = async () => {
    const name = backupWallet.trim();
    const path = backupPath.trim();
    if (!name) {
      setKeystoreErr("Pick a wallet to back up.");
      return;
    }
    if (!path) {
      setKeystoreErr("Enter a destination file path for the backup.");
      return;
    }
    setKeystoreBusy(true);
    setKeystoreErr(null);
    setExportResult(null);
    try {
      const r = await walletExport(name, path);
      setExportResult(r);
      setBackupPath("");
    } catch (e) {
      setKeystoreErr((e as Error).message ?? String(e));
    } finally {
      setKeystoreBusy(false);
    }
  };

  const onRestore = async () => {
    const name = restoreName.trim();
    const path = restorePath.trim();
    if (!name) {
      setKeystoreErr("Enter a name for the restored wallet.");
      return;
    }
    if (!path) {
      setKeystoreErr("Enter the path to the keystore file to restore.");
      return;
    }
    setKeystoreBusy(true);
    setKeystoreErr(null);
    setRestoreResult(null);
    try {
      const r = await walletRestore(name, path);
      setRestoreResult(r);
      setRestoreName("");
      setRestorePath("");
      await refreshWallets();
    } catch (e) {
      setKeystoreErr((e as Error).message ?? String(e));
    } finally {
      setKeystoreBusy(false);
    }
  };

  const onCheckUpdate = async () => {
    setUpdateBusy(true);
    setUpdateErr(null);
    setUpdateResult(null);
    try {
      const url = updateUrl.trim();
      const r = await checkForUpdate(url.length > 0 ? url : undefined);
      setUpdateResult(r);
    } catch (e) {
      setUpdateErr((e as Error).message ?? String(e));
    } finally {
      setUpdateBusy(false);
    }
  };

  const fmtUptime = (secs: number | undefined): string => {
    if (secs == null) return "—";
    const m = Math.floor(secs / 60);
    const h = Math.floor(m / 60);
    if (h > 0) return `${h}h ${m % 60}m`;
    return `${m}m ${secs % 60}s`;
  };

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">configuration</span>
          <h1>Settings</h1>
          <p className="lead">
            Choose which node the wallet talks to, and inspect the daemon
            environment the running wraithd picked up at boot.
          </p>
        </div>
      </div>

      {err && (
        <div className="card error-card">
          <strong>Couldn't reach the daemon.</strong>
          <pre className="error-details">{err}</pre>
        </div>
      )}

      <div className="card">
        <h2>Daemon</h2>
        <div className="kv">
          <div className="k">Version</div>
          <div className="v mono">
            {health?.version ? `Wraith ${health.version}` : "—"}
          </div>
          <div className="k">Uptime</div>
          <div className="v">{fmtUptime(health?.uptime_secs)}</div>
          <div className="k">Network</div>
          <div className="v">
            <span className="pill mute">{env?.network ?? "—"}</span>
          </div>
          {env?.kiosk_mode && (
            <>
              <div className="k">Mode</div>
              <div className="v">
                <span className="pill warn">kiosk</span>
                <span className="muted" style={{ marginLeft: 8 }}>
                  wallet management is disabled
                </span>
              </div>
            </>
          )}
        </div>
      </div>

      <div className="card">
        <h2>Storage</h2>
        <div className="kv">
          <div className="k">Wallets dir</div>
          <div className="v mono">{env?.wallets_dir ?? "—"}</div>
          <div className="k">IPC socket</div>
          <div className="v mono">{env?.socket_path ?? "—"}</div>
        </div>
      </div>

      <div className="card">
        <h2>Keystore backup &amp; restore</h2>
        <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
          Wallets are stored as Argon2id + AES-256-GCM encrypted
          keystores. A backup is a straight copy of that encrypted file —
          it never leaves the daemon as plaintext, and it still requires
          the wallet passphrase to unlock after a restore. Keep it
          somewhere safe; anyone who also learns the passphrase can spend
          from it.
        </p>

        {keystoreErr && (
          <div className="card error-card" style={{ marginBottom: 12 }}>
            {keystoreErr}
          </div>
        )}

        <h3 style={{ marginBottom: 4 }}>Back up</h3>
        {wallets.length === 0 ? (
          <p className="muted" style={{ fontSize: 13 }}>
            No wallets available to back up.
          </p>
        ) : (
          <>
            <div className="col">
              <label>Wallet</label>
              <select
                value={backupWallet}
                onChange={(e) => setBackupWallet(e.target.value)}
                disabled={keystoreBusy}
              >
                {wallets.map((w) => (
                  <option key={w.name} value={w.name}>
                    {w.name}
                    {w.is_active ? " (active)" : ""}
                  </option>
                ))}
              </select>
            </div>
            <div className="col">
              <label>Destination file path</label>
              <input
                className="mono"
                value={backupPath}
                onChange={(e) => setBackupPath(e.target.value)}
                placeholder="/home/you/backups/wallet.keystore"
                disabled={keystoreBusy}
              />
              <span className="muted" style={{ fontSize: 12 }}>
                Absolute path the daemon writes to. It refuses to
                overwrite an existing file.
              </span>
            </div>
            <div className="row" style={{ marginTop: 8 }}>
              <button
                className="btn-primary"
                onClick={onBackup}
                disabled={keystoreBusy}
              >
                {keystoreBusy ? "Working…" : "Back up keystore"}
              </button>
            </div>
            {exportResult && (
              <div className="kv" style={{ marginTop: 12 }}>
                <div className="k">Backed up</div>
                <div className="v mono" style={{ fontSize: 12 }}>
                  {exportResult.name}
                </div>
                <div className="k">Wrote</div>
                <div className="v mono" style={{ fontSize: 12 }}>
                  {exportResult.path}
                </div>
                <div className="k">Size</div>
                <div className="v">
                  {exportResult.bytes.toLocaleString()} bytes
                </div>
              </div>
            )}
          </>
        )}

        <h3 style={{ marginTop: 16, marginBottom: 4 }}>Restore</h3>
        <div className="col">
          <label>New wallet name</label>
          <input
            value={restoreName}
            onChange={(e) => setRestoreName(e.target.value)}
            placeholder="restored-wallet"
            disabled={keystoreBusy}
          />
        </div>
        <div className="col">
          <label>Keystore file path</label>
          <input
            className="mono"
            value={restorePath}
            onChange={(e) => setRestorePath(e.target.value)}
            placeholder="/home/you/backups/wallet.keystore"
            disabled={keystoreBusy}
          />
          <span className="muted" style={{ fontSize: 12 }}>
            The daemon refuses to overwrite a wallet that already exists
            under this name. Unlock it afterwards with its original
            passphrase.
          </span>
        </div>
        <div className="row" style={{ marginTop: 8 }}>
          <button
            className="btn-primary"
            onClick={onRestore}
            disabled={keystoreBusy}
          >
            {keystoreBusy ? "Working…" : "Restore keystore"}
          </button>
        </div>
        {restoreResult && (
          <div className="kv" style={{ marginTop: 12 }}>
            <div className="k">Restored</div>
            <div className="v mono" style={{ fontSize: 12 }}>
              {restoreResult.name}
            </div>
            <div className="k">Installed at</div>
            <div className="v mono" style={{ fontSize: 12 }}>
              {restoreResult.path}
            </div>
            <div className="k">Size</div>
            <div className="v">
              {restoreResult.bytes.toLocaleString()} bytes
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Updates</h2>
          <span className="pill mute">
            {health?.version ? `Wraith ${health.version}` : "—"}
          </span>
        </div>
        <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
          Asks the daemon to fetch a signed release manifest and compare
          its version against the running daemon. Nothing is downloaded
          or installed — this only tells you whether a newer build
          exists.
        </p>
        <div className="col">
          <label>Manifest URL (optional)</label>
          <input
            className="mono"
            value={updateUrl}
            onChange={(e) => setUpdateUrl(e.target.value)}
            placeholder={
              env?.network
                ? "leave blank to use the daemon's configured channel"
                : "https://…/manifest.json"
            }
            disabled={updateBusy}
          />
          <span className="muted" style={{ fontSize: 12 }}>
            Leave blank to use the daemon's{" "}
            <code>WRAITHD_UPDATE_MANIFEST_URL</code> default. The daemon
            errors if neither is set.
          </span>
        </div>
        <div className="row" style={{ marginTop: 8 }}>
          <button
            className="btn-primary"
            onClick={onCheckUpdate}
            disabled={updateBusy}
          >
            {updateBusy ? "Checking…" : "Check for updates"}
          </button>
        </div>
        {updateErr && (
          <div className="card error-card" style={{ marginTop: 12 }}>
            {updateErr}
          </div>
        )}
        {updateResult && (
          <div style={{ marginTop: 12 }}>
            <div className="row" style={{ marginBottom: 8 }}>
              <span
                className={`pill ${updateResult.up_to_date ? "pass" : "warn"}`}
              >
                {updateResult.up_to_date
                  ? "up to date"
                  : "update available"}
              </span>
            </div>
            <div className="kv">
              <div className="k">Current</div>
              <div className="v mono">{updateResult.current_version}</div>
              <div className="k">Latest</div>
              <div className="v mono">
                {updateResult.latest_version ?? "—"}
              </div>
              <div className="k">Manifest</div>
              <div className="v mono" style={{ fontSize: 12 }}>
                {updateResult.manifest_url}
              </div>
              {updateResult.tarball && (
                <>
                  <div className="k">Tarball</div>
                  <div className="v mono" style={{ fontSize: 12 }}>
                    {updateResult.tarball}
                  </div>
                </>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Node connection</h2>
          <ConnectionStatus conn={conn} />
        </div>
        <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
          Like choosing a server in other wallets: use the public Ghost nodes
          (works out of the box, no node required) or point the wallet at a
          node you run yourself. The pills above show whether the current
          choice is reachable.
        </p>

        {envLocked ? (
          <div className="card surface" style={{ marginBottom: 12 }}>
            <p style={{ margin: 0, fontSize: 13 }}>
              The node endpoints are pinned by environment variables (
              <code>WRAITHD_GHOST_PAY</code> / <code>WRAITHD_GSP</code>). To
              manage the node from here, unset them and restart wraithd.
            </p>
          </div>
        ) : null}

        <fieldset
          disabled={envLocked || nodeBusy}
          style={{ border: 0, padding: 0, margin: 0 }}
        >
          <label className="radio-row">
            <input
              type="radio"
              name="node-preset"
              checked={nodePreset === "public"}
              onChange={() => {
                setNodePreset("public");
                setNodeSaved(false);
              }}
            />
            <span>
              <strong>Public Ghost nodes</strong>{" "}
              <span className="pill mute" style={{ fontSize: 11 }}>
                recommended
              </span>
              <br />
              <span className="muted" style={{ fontSize: 12 }}>
                The Bitcoin Ghost fleet at <code>pool.bitcoinghost.org</code>.
                A fresh install uses this so the wallet just works.
              </span>
            </span>
          </label>

          <label className="radio-row" style={{ marginTop: 8 }}>
            <input
              type="radio"
              name="node-preset"
              checked={nodePreset === "custom"}
              onChange={() => {
                setNodePreset("custom");
                setNodeSaved(false);
              }}
            />
            <span>
              <strong>My own node</strong>
              <br />
              <span className="muted" style={{ fontSize: 12 }}>
                Point the wallet at a ghost-pay + GSP you run yourself.
              </span>
            </span>
          </label>

          {nodePreset === "custom" && (
            <div style={{ marginTop: 12 }}>
              <div className="col">
                <label>ghost-pay URL</label>
                <input
                  className="mono"
                  value={customPay}
                  onChange={(e) => {
                    setCustomPay(e.target.value);
                    setNodeSaved(false);
                  }}
                  placeholder={OWN_NODE_GHOST_PAY_DEFAULT}
                />
                <span className="muted" style={{ fontSize: 12 }}>
                  <code>http://</code> or <code>https://</code>. Comma-separate
                  for failover.
                </span>
              </div>
              <div className="col">
                <label>GSP URL</label>
                <input
                  className="mono"
                  value={customGsp}
                  onChange={(e) => {
                    setCustomGsp(e.target.value);
                    setNodeSaved(false);
                  }}
                  placeholder={OWN_NODE_GSP_DEFAULT}
                />
                <span className="muted" style={{ fontSize: 12 }}>
                  <code>ws://</code> or <code>wss://</code>. Comma-separate for
                  failover.
                </span>
              </div>
            </div>
          )}

          <div className="row" style={{ marginTop: 12 }}>
            <button
              className="btn-primary"
              onClick={onSaveNode}
              disabled={envLocked || nodeBusy}
            >
              {nodeBusy ? "Applying…" : "Save & connect"}
            </button>
            {nodeSaved && (
              <span className="pill pass" style={{ marginLeft: 8 }}>
                applied
              </span>
            )}
          </div>
        </fieldset>

        {nodeErr && (
          <div className="card error-card" style={{ marginTop: 12 }}>
            {nodeErr}
          </div>
        )}

        <div className="kv" style={{ marginTop: 12 }}>
          <div className="k">Active ghost-pay</div>
          <div className="v mono">{env?.ghost_pay_urls.join(", ") ?? "—"}</div>
          <div className="k">Active GSP</div>
          <div className="v mono">{env?.gsp_urls.join(", ") ?? "—"}</div>
          <div className="k">Tor proxy</div>
          <div className="v mono">{env?.tor_proxy ?? "—"}</div>
        </div>
      </div>

      <div className="card">
        <h2>Privacy + lock</h2>
        <div className="kv">
          <div className="k">Idle auto-lock</div>
          <div className="v">
            {env == null
              ? "—"
              : env.idle_lock_secs === 0
                ? "disabled"
                : `${env.idle_lock_secs}s`}
          </div>
          <div className="k">Shroud window</div>
          <div className="v">
            {env == null
              ? "—"
              : env.shroud_max_ms === 0
                ? "disabled"
                : `0–${env.shroud_max_ms}ms`}
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Merchant kiosk mode</h2>
          {(guiKiosk || daemonKiosk) && (
            <span className={`pill ${daemonKiosk ? "warn" : "warn"}`}>
              {daemonKiosk ? "daemon-locked" : "active"}
            </span>
          )}
        </div>
        <p>
          Locks the GUI to the Merchant screen, hides the
          wallet-management nav. Use this on a machine running as a
          dedicated till — staff can take payments but can't
          create / unlock / switch wallets.
        </p>
        <div className="kv">
          <div className="k">Daemon lock</div>
          <div className="v">
            <span className={`pill ${daemonKiosk ? "warn" : "mute"}`}>
              {daemonKiosk ? "active" : "off"}
            </span>
            <span
              className="muted"
              style={{ marginLeft: 8, fontSize: 12 }}
            >
              set via <code>WRAITHD_KIOSK_MODE</code>; daemon refuses
              wallet-management ops while it's set. Exit by
              restarting wraithd without the env var.
            </span>
          </div>
          <div className="k">GUI lock</div>
          <div className="v">
            <button
              className={guiKiosk ? "btn-secondary" : "btn-primary"}
              onClick={() => onToggleGuiKiosk(!guiKiosk)}
              disabled={daemonKiosk}
              title={
                daemonKiosk
                  ? "Daemon kiosk is already active — its lock supersedes the GUI toggle"
                  : guiKiosk
                    ? "Click to leave kiosk mode"
                    : "Click to enter kiosk mode (per-install, persisted)"
              }
            >
              {guiKiosk ? "Leave kiosk mode" : "Enter kiosk mode"}
            </button>
            <span
              className="muted"
              style={{ marginLeft: 8, fontSize: 12 }}
            >
              GUI-only — daemon stays unrestricted. Persisted in
              localStorage so it survives reload. For a real
              till deployment, also set the daemon lock above.
            </span>
          </div>
        </div>
      </div>

      <div className="card">
        <h2>Help &amp; guidance</h2>
        <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
          New here, or showing someone else the ropes? Replay the short
          guided tour of the wallet's four sections. You can skip it at
          any point. Every screen also has a small <strong>?</strong> that
          explains what it does.
        </p>
        <div className="row" style={{ marginTop: 8 }}>
          <button className="btn-secondary" onClick={onReplayTour}>
            Show tour
          </button>
        </div>
      </div>

      <div className="card surface">
        <h2>About</h2>
        <p className="mono" style={{ marginTop: 0 }}>
          Ghost Wallet — Version: Wraith{" "}
          {health?.version ?? "—"}
        </p>
        <p>
          Ghost Wallet is the desktop interface for{" "}
          <strong>Bitcoin Ghost</strong> — incentivised nodes,
          decentralised mining, private payments. Open source,
          self-custodial, ossifying.
        </p>
        <div className="row" style={{ marginTop: 8 }}>
          <a
            className="btn-secondary"
            href="https://bitcoinghost.org"
            target="_blank"
            rel="noreferrer noopener"
          >
            bitcoinghost.org
          </a>
          <a
            className="btn-secondary"
            href="https://github.com/bitcoin-ghost/ghost"
            target="_blank"
            rel="noreferrer noopener"
          >
            GitHub
          </a>
          <a
            className="btn-secondary"
            href="https://bitcoinghost.org/docs/"
            target="_blank"
            rel="noreferrer noopener"
          >
            Docs
          </a>
        </div>
      </div>
    </div>
  );
}

export interface DaemonEnvResponseExtended extends DaemonEnvResponse {
  idle_lock_secs: number;
  shroud_max_ms: number;
}
