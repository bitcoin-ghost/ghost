import type { ConnectionStatusResponse } from "../lib/tauri";

interface ConnectionStatusProps {
  conn: ConnectionStatusResponse | null;
  /// Where to send the user for the full diagnostics view. Clicking any
  /// pill jumps to the Network screen.
  onOpenDiagnostics?: () => void;
}

/// Persistent header connectivity bar: two compact pills — the node, and
/// chain sync.
///
/// The point is that a user gets a clear, actionable answer instead of a
/// spinner that never resolves, and that the three states stay distinct:
/// no node set, node set but silent, node answering. They have different
/// fixes, and merging them into one "unreachable" sends people hunting for
/// a fault when what is missing is a setting.
///
/// The backing `connectionStatus()` call never throws for an unreachable
/// node, so a red pill here is a real answer rather than a failed request.
export function ConnectionStatus({ conn, onOpenDiagnostics }: ConnectionStatusProps) {
  if (!conn) {
    // Daemon replied to nothing yet — brief, resolves on the next tick.
    return <span className="pill mute live">connecting…</span>;
  }

  const jump = onOpenDiagnostics
    ? { onClick: onOpenDiagnostics, style: { cursor: "pointer", border: 0 } as const }
    : {};

  // ----- The node -----
  let node;
  if (!conn.node_configured) {
    node = (
      <span
        className="pill mute"
        title="No node configured. The wallet reads and writes the chain through your own ghostd — set it in Settings."
        {...jump}
      >
        node · not set
      </span>
    );
  } else if (conn.node_reachable) {
    node = (
      <span
        className="pill pass"
        title={`Node reachable${conn.node_version ? ` · ${conn.node_version}` : ""}`}
        {...jump}
      >
        node
      </span>
    );
  } else {
    node = (
      <span
        className="pill fail"
        title={`Node unreachable${
          conn.node_error ? ` — ${conn.node_error}` : ""
        }. Check it is running and that the URL and credentials are right, on the Network screen.`}
        {...jump}
      >
        node · unreachable
      </span>
    );
  }

  // ----- Chain sync -----
  let sync;
  if (!conn.node_reachable) {
    sync = (
      <span
        className="pill mute"
        title={
          conn.node_configured
            ? "Sync unknown — the chain height comes from your node, which is not answering."
            : "Sync unknown — no node is configured."
        }
        {...jump}
      >
        sync · —
      </span>
    );
  } else if (conn.chain_synced) {
    sync = (
      <span className="pill pass live" title={`Synced with ${conn.network}`} {...jump}>
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
      {node}
      {sync}
    </span>
  );
}
