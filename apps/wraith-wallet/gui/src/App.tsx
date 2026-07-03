import { useEffect, useRef, useState } from "react";
import {
  chainStatus,
  daemonEnv,
  gspAuth,
  gspSessionStatus,
  onPaymentDetected,
  onWatchError,
  startWatch,
  walletStatus,
  type ChainStatusResponse,
  type DetectedPayment,
} from "./lib/tauri";
import { Wallet } from "./screens/Wallet";
import { Receive } from "./screens/Receive";
import { Send } from "./screens/Send";
import { Sign } from "./screens/Sign";
import { Cosigner } from "./screens/Cosigner";
import { Mix } from "./screens/Mix";
import { Glyph } from "./screens/Glyph";
import { Merchant } from "./screens/Merchant";
import { Reports } from "./screens/Reports";
import { Locks } from "./screens/Locks";
import { History } from "./screens/History";
import { Network } from "./screens/Network";
import { Settings } from "./screens/Settings";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Logo } from "./components/Logo";
import { ThemeToggle } from "./components/ThemeToggle";
import { SyncIndicator } from "./components/SyncIndicator";

type Screen =
  | "wallet"
  | "receive"
  | "send"
  | "sign"
  | "cosigner"
  | "mix"
  | "glyph"
  | "merchant"
  | "reports"
  | "locks"
  | "history"
  | "network"
  | "settings";

// Sidebar navigation grouped into a few plain-language categories.
// Keep the grouping shallow — end users scan headings, not a flat
// list of thirteen links. Every existing route is preserved; only
// the presentation changes.
const NAV_GROUPS: Array<{
  heading: string;
  items: Array<{ id: Screen; label: string }>;
}> = [
  {
    heading: "Wallet",
    items: [
      { id: "wallet", label: "Wallet" },
      { id: "history", label: "History" },
      { id: "locks", label: "Locks" },
    ],
  },
  {
    heading: "Payments",
    items: [
      { id: "receive", label: "Receive" },
      { id: "send", label: "Send" },
      { id: "sign", label: "Sign" },
      { id: "cosigner", label: "Cosigner" },
      { id: "mix", label: "Mix" },
      { id: "glyph", label: "Glyph" },
    ],
  },
  {
    heading: "Merchant",
    items: [
      { id: "merchant", label: "Merchant" },
      { id: "reports", label: "Reports" },
    ],
  },
  {
    heading: "System",
    items: [
      { id: "network", label: "Network" },
      { id: "settings", label: "Settings" },
    ],
  },
];

export default function App() {
  const [screen, setScreen] = useState<Screen>("wallet");
  const [networkLabel, setNetworkLabel] = useState<string | null>(null);
  const [walletState, setWalletState] = useState<{
    active: string | null;
    unlocked: boolean;
  }>({ active: null, unlocked: false });
  const [paymentTick, setPaymentTick] = useState(0);
  const [lastDetect, setLastDetect] = useState<DetectedPayment | null>(null);
  const [watchErr, setWatchErr] = useState<string | null>(null);
  const [hasSession, setHasSession] = useState(false);
  const [daemonOffline, setDaemonOffline] = useState(false);
  const [chain, setChain] = useState<ChainStatusResponse | null>(null);
  // Two layers of kiosk mode:
  //   - daemonKiosk: WRAITHD_KIOSK_MODE on the daemon. Hard lock —
  //     daemon refuses wallet-management ops, can only be exited by
  //     restarting wraithd. Used for permanent till deployments.
  //   - guiKiosk: a per-install GUI-only toggle, persisted in
  //     localStorage. Hides the nav and snaps to Merchant, but the
  //     daemon stays unrestricted, so staff with shell access could
  //     still poke it. Use for soft "treat this session as a till"
  //     — coffee shops where the operator trusts the host.
  // The effective kiosk state is the OR: either flag locks the GUI.
  const [daemonKiosk, setDaemonKiosk] = useState(false);
  const [guiKiosk, setGuiKiosk] = useState<boolean>(() => {
    return localStorage.getItem("wraith.kiosk") === "1";
  });
  const kioskMode = daemonKiosk || guiKiosk;

  const autoAuthInFlight = useRef<string | null>(null);

  // Header status tick — daemon + wallet status, kiosk-mode detection,
  // auto-gsp-auth on first unlock. Best-effort: every error path here
  // either falls through silently or surfaces via the "daemon offline"
  // pill — never crashes the shell.
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const env = await daemonEnv();
        const w = await walletStatus();
        if (!alive) return;
        setDaemonOffline(false);
        setNetworkLabel(env.network);
        setWalletState({ active: w.active, unlocked: w.unlocked });
        // Best-effort chain probe — if ghost-pay is down we leave
        // the previous chain state and don't flip the offline pill.
        chainStatus()
          .then((c) => {
            if (alive) setChain(c);
          })
          .catch(() => {});
        const wasDaemonKiosk = daemonKiosk;
        const isDaemonKiosk = !!env.kiosk_mode;
        if (isDaemonKiosk !== wasDaemonKiosk) {
          setDaemonKiosk(isDaemonKiosk);
          if (isDaemonKiosk) setScreen("merchant");
        }
        if (w.active && w.unlocked) {
          try {
            const session = await gspSessionStatus();
            if (!alive) return;
            setHasSession(session.have_token);
            if (
              !session.have_token &&
              autoAuthInFlight.current !== w.active
            ) {
              autoAuthInFlight.current = w.active;
              gspAuth().catch(() => {
                if (alive) autoAuthInFlight.current = null;
              });
            }
          } catch {
            /* transient — try again next tick */
          }
        } else {
          setHasSession(false);
          if (!w.active) autoAuthInFlight.current = null;
        }
      } catch {
        if (alive) setDaemonOffline(true);
      }
    };
    tick();
    const id = setInterval(tick, 4000);
    return () => {
      alive = false;
      clearInterval(id);
    };
    // kioskMode dep intentionally omitted — we read it inside the
    // closure via the latest captured value, and adding it would
    // re-create the interval on every kiosk transition.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Live BIP-352 receive notifications — register the event listeners
  // once at mount. startWatch() itself is deferred to the effect below,
  // which waits for a GSP session (the watch needs one to run).
  useEffect(() => {
    let alive = true;
    let unlistenDetect: (() => void) | undefined;
    let unlistenError: (() => void) | undefined;
    (async () => {
      unlistenDetect = await onPaymentDetected((p) => {
        if (!alive) return;
        setLastDetect(p);
        setPaymentTick((n) => n + 1);
      });
      unlistenError = await onWatchError((e) => {
        if (!alive) return;
        setWatchErr(e.message);
      });
    })();
    return () => {
      alive = false;
      if (unlistenDetect) unlistenDetect();
      if (unlistenError) unlistenError();
    };
  }, []);

  // Start (or restart) the push-watch once a GSP session is live. The
  // watch needs a session — calling startWatch() before one exists just
  // fails with "no active sessions". startWatch() is idempotent, so
  // re-calling it whenever a session appears is safe.
  useEffect(() => {
    if (!hasSession) {
      setWatchErr(null); // no session yet — not an error state
      return;
    }
    let alive = true;
    startWatch()
      .then(() => {
        if (alive) setWatchErr(null);
      })
      .catch((e) => {
        if (alive) setWatchErr((e as Error).message ?? String(e));
      });
    return () => {
      alive = false;
    };
  }, [hasSession]);

  // Active-screen renderer wrapped in the boundary so a screen's
  // crash doesn't blank the whole app.
  const activeScreen = () => {
    switch (screen) {
      case "wallet":
        return <Wallet paymentTick={paymentTick} />;
      case "receive":
        return <Receive paymentTick={paymentTick} />;
      case "send":
        return <Send activeWallet={walletState.active} />;
      case "sign":
        return <Sign activeWallet={walletState.active} />;
      case "cosigner":
        return <Cosigner activeWallet={walletState.active} />;
      case "mix":
        return <Mix activeWallet={walletState.active} />;
      case "glyph":
        return <Glyph activeWallet={walletState.active} />;
      case "merchant":
        return (
          <Merchant
            activeWallet={walletState.active}
            paymentTick={paymentTick}
            guiKiosk={guiKiosk}
            onEnterKiosk={() => toggleGuiKiosk(true)}
          />
        );
      case "reports":
        return <Reports activeWallet={walletState.active} />;
      case "locks":
        return <Locks />;
      case "history":
        return <History paymentTick={paymentTick} />;
      case "network":
        return <Network />;
      case "settings":
        return (
          <Settings
            guiKiosk={guiKiosk}
            daemonKiosk={daemonKiosk}
            onToggleGuiKiosk={toggleGuiKiosk}
          />
        );
    }
  };

  const openExternal = (url: string) => {
    // Tauri webview blocks raw window.open in some configs; the
    // anchor href fallback handles it. Kept as a function so we
    // can swap to the @tauri-apps/api/shell.open later.
    window.open(url, "_blank", "noopener,noreferrer");
  };

  const toggleGuiKiosk = (next: boolean) => {
    setGuiKiosk(next);
    localStorage.setItem("wraith.kiosk", next ? "1" : "0");
    if (next) setScreen("merchant");
  };

  return (
    <div className={kioskMode ? "app kiosk" : "app"}>
      <header className="app-header">
        <div className="title">
          <Logo className="logo-ghost" size={28} />
          <span className="wordmark">ghost wallet</span>
        </div>

        <div className="spacer" />

        {daemonKiosk && (
          <span
            className="pill warn"
            title="Daemon kiosk mode (WRAITHD_KIOSK_MODE) — wallet management disabled at the daemon. Exit by restarting wraithd without the env var."
          >
            kiosk · daemon-locked
          </span>
        )}
        {!daemonKiosk && guiKiosk && (
          <button
            className="pill warn"
            onClick={() => toggleGuiKiosk(false)}
            title="Click to exit kiosk mode and re-show the nav. Daemon stays unrestricted in this mode."
            style={{ cursor: "pointer", border: 0 }}
          >
            kiosk · exit
          </button>
        )}

        {lastDetect && (
          <span
            className="pill pass live"
            title={`txid ${lastDetect.txid.slice(0, 12)}…  vout ${lastDetect.vout}`}
          >
            +{lastDetect.amount_sats.toLocaleString()} sats
          </span>
        )}

        {hasSession && watchErr && (
          <span className="pill fail" title={watchErr}>
            watch offline
          </span>
        )}

        {daemonOffline ? (
          <span className="pill fail live">daemon offline</span>
        ) : (
          <SyncIndicator chain={chain} compact />
        )}

        {!daemonOffline && (
          <span className="status">
            {networkLabel && <span className="net">{networkLabel}</span>}
            {walletState.active && (
              <>
                <span className="sep">·</span>
                <span className="wallet-name">{walletState.active}</span>
                {!walletState.unlocked && (
                  <span style={{ color: "var(--warn)" }}> (locked)</span>
                )}
              </>
            )}
          </span>
        )}

        <div className="utils">
          <button
            className="icon-btn"
            onClick={() => openExternal("https://bitcoinghost.org")}
            title="bitcoinghost.org"
            aria-label="Website"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <path d="M2 12h20" />
              <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
            </svg>
          </button>
          <button
            className="icon-btn"
            onClick={() => openExternal("https://github.com/bitcoin-ghost/ghost")}
            title="GitHub"
            aria-label="GitHub"
          >
            <svg viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
            </svg>
          </button>
          <button
            className="icon-btn"
            onClick={() => openExternal("https://bitcoinghost.org/docs/")}
            title="Docs"
            aria-label="Docs"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9.5 9a3 3 0 0 1 5.5 1.5c0 2-3 3-3 3" />
              <circle cx="12" cy="17" r=".5" />
              <circle cx="12" cy="12" r="10" />
            </svg>
          </button>
          <button
            className={`icon-btn ${screen === "settings" ? "active" : ""}`}
            onClick={() => setScreen("settings")}
            title="Settings"
            aria-label="Settings"
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
              <circle cx="12" cy="12" r="3" />
            </svg>
          </button>
          <ThemeToggle />
        </div>
      </header>

      {!kioskMode && (
        <aside className="app-sidebar">
          <nav>
            {NAV_GROUPS.map((group) => (
              <div className="nav-group" key={group.heading}>
                <div className="nav-heading">{group.heading}</div>
                {group.items.map((item) => (
                  <button
                    key={item.id}
                    className={screen === item.id ? "active" : ""}
                    onClick={() => setScreen(item.id)}
                  >
                    {item.label}
                  </button>
                ))}
              </div>
            ))}
          </nav>
        </aside>
      )}

      <main className="app-main">
        <ErrorBoundary key={screen}>{activeScreen()}</ErrorBoundary>
      </main>
    </div>
  );
}
