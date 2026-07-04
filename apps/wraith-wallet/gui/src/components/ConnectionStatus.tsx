import type { ConnectionStatusResponse } from "../lib/tauri";

interface ConnectionStatusProps {
  conn: ConnectionStatusResponse | null;
  /// Where to send the user for the full diagnostics view. Clicking any
  /// pill jumps to the Network screen.
  onOpenDiagnostics?: () => void;
}

/// Persistent header connectivity bar: three compact pills — Ghost Pay,
/// GSP, and chain sync. The whole point is that a user whose laptop has
/// no local ghost-pay / GSP sees a clear "unreachable" state (with a
/// hint) rather than a spinner that never resolves. The backing
/// `connectionStatus()` call never throws for an unreachable endpoint,
/// so a red pill here is a real, actionable answer.
export function ConnectionStatus({ conn, onOpenDiagnostics }: ConnectionStatusProps) {
  if (!conn) {
    // Daemon replied to nothing yet — brief, resolves on the next tick.
    return <span className="pill mute live">connecting…</span>;
  }

  const jump = onOpenDiagnostics
    ? { onClick: onOpenDiagnostics, style: { cursor: "pointer", border: 0 } as const }
    : {};

  // ----- Ghost Pay -----
  const ghostPay = conn.ghost_pay_reachable ? (
    <span
      className="pill pass"
      title={`Ghost Pay reachable${
        conn.ghost_pay_version ? ` · v${conn.ghost_pay_version}` : ""
      }`}
      {...jump}
    >
      Ghost Pay
    </span>
  ) : (
    <span
      className="pill fail"
      title={`Ghost Pay unreachable${
        conn.ghost_pay_error ? ` — ${conn.ghost_pay_error}` : ""
      }. Set the ghost-pay URL (WRAITHD_GHOST_PAY_URL) or start a local ghost-pay, then check the Network screen.`}
      {...jump}
    >
      Ghost Pay · unreachable
    </span>
  );

  // ----- GSP websocket -----
  let gsp;
  if (conn.gsp_connected) {
    gsp = (
      <span className="pill pass" title="GSP websocket connected and authenticated" {...jump}>
        GSP
      </span>
    );
  } else if (conn.gsp_have_token) {
    gsp = (
      <span
        className="pill warn"
        title={`GSP session present but not live (phase: ${conn.gsp_phase ?? "unknown"})`}
        {...jump}
      >
        GSP · {conn.gsp_phase ?? "connecting"}
      </span>
    );
  } else {
    gsp = (
      <span
        className="pill mute"
        title="No GSP session — unlock a wallet, or configure the GSP URL (WRAITHD_GSP_URL) if this laptop has no local node."
        {...jump}
      >
        GSP · off
      </span>
    );
  }

  // ----- Chain sync -----
  let sync;
  if (!conn.ghost_pay_reachable) {
    sync = (
      <span
        className="pill mute"
        title="Sync unknown — the chain height comes from ghost-pay, which is unreachable."
        {...jump}
      >
        sync · —
      </span>
    );
  } else if (conn.chain_synced) {
    sync = (
      <span
        className="pill pass live"
        title={`Synced with ${conn.network}${
          conn.l2_height != null ? ` · L2 #${conn.l2_height}` : ""
        }`}
        {...jump}
      >
        synced · #{conn.chain_height?.toLocaleString() ?? "—"}
      </span>
    );
  } else {
    const behind =
      conn.chain_headers != null && conn.chain_height != null
        ? conn.chain_headers - conn.chain_height
        : null;
    sync = (
      <span
        className="pill warn live"
        title={`Syncing ${conn.network} — ${conn.chain_height?.toLocaleString() ?? "?"} of ${
          conn.chain_headers?.toLocaleString() ?? "?"
        }`}
        {...jump}
      >
        syncing · #{conn.chain_height?.toLocaleString() ?? "—"}
        {behind != null && behind > 0 ? ` · ${behind.toLocaleString()} left` : ""}
      </span>
    );
  }

  return (
    <span className="conn-status" style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
      {ghostPay}
      {gsp}
      {sync}
    </span>
  );
}
