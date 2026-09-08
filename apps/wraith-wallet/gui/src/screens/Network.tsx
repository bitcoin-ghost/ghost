import { useEffect, useState } from "react";
import {
  chainStatus,
  daemonHealth,
  daemonEnv,
  daemonDoctor,
  type ChainStatusResponse,
  type DaemonEnvResponse,
  type DoctorResponse,
  type HealthResponse,
} from "../lib/tauri";
import { SyncIndicator } from "../components/SyncIndicator";

export function Network() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [env, setEnv] = useState<DaemonEnvResponse | null>(null);
  const [doctor, setDoctor] = useState<DoctorResponse | null>(null);
  const [doctorTs, setDoctorTs] = useState<number | null>(null);
  const [doctorErr, setDoctorErr] = useState<string | null>(null);
  const [chain, setChain] = useState<ChainStatusResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    setErr(null);
    try {
      setHealth(await daemonHealth());
      setEnv(await daemonEnv());
      try {
        setChain(await chainStatus());
      } catch {
        /* chain probe is best-effort */
      }
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    }
  };

  const runDoctor = async () => {
    setBusy(true);
    setDoctorErr(null);
    try {
      const r = await daemonDoctor();
      setDoctor(r);
      setDoctorTs(Date.now());
    } catch (e) {
      setDoctorErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  // Auto-run doctor on mount so the user lands on a populated
  // dashboard. Refresh every 8s for the lighter env/health/session.
  useEffect(() => {
    refresh();
    runDoctor();
    const id = setInterval(refresh, 8000);
    return () => clearInterval(id);
    // runDoctor + refresh are stable in scope — intentionally empty
    // dep so the interval doesn't churn on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fmtUptime = (secs: number | undefined) => {
    if (!secs && secs !== 0) return "—";
    const m = Math.floor(secs / 60);
    const h = Math.floor(m / 60);
    if (h > 0) return `${h}h ${m % 60}m`;
    return `${m}m ${secs % 60}s`;
  };

  // Top-level health rollup: green if doctor.all_pass, red if any
  // fails, yellow if some skip and rest pass. Surfaces alongside
  // each card's own status so the user sees the summary even
  // before scrolling.
  const overallStatus = (() => {
    if (!doctor) return { label: "checking…", className: "mute" };
    if (doctor.all_pass) return { label: "healthy", className: "pass" };
    return { label: "issues", className: "fail" };
  })();

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">diagnostics</span>
          <h1>Network</h1>
          <p className="lead">
            Connectivity health to the daemon, your node and the
            wraith-coordinator. Auto-runs on mount; refresh on demand.
          </p>
        </div>
        <span className={`pill ${overallStatus.className} live`}>
          {overallStatus.label}
        </span>
      </div>
      {err && (
        <div className="card" style={{ borderColor: "var(--fail)" }}>
          {err}
        </div>
      )}

      <div className="card">
        <h2>Chain sync</h2>
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          L1 = the operator's bitcoind. L2 = ghost-pay's finalized
          checkpoints. Sync indicator updates every 8s; ETA is
          estimated from blocks-per-second on the trailing 90s
          window.
        </p>
        <SyncIndicator chain={chain} />
      </div>

      {/* Doctor — headline "is everything OK" view. Per-row table
          beats the JSON dump for at-a-glance parsing. */}
      <div className="card">
        <div className="card-header">
          <h2>Health checks</h2>
          <div className="row" style={{ gap: 8, alignItems: "center" }}>
            {doctorTs && (
              <span className="muted" style={{ fontSize: 12 }}>
                last run {new Date(doctorTs).toLocaleTimeString()}
              </span>
            )}
            <button className="secondary" onClick={runDoctor} disabled={busy}>
              {busy ? "Checking…" : "Re-run"}
            </button>
          </div>
        </div>
        {doctorErr && (
          <div
            className="pill fail"
            style={{ alignSelf: "flex-start", marginTop: 8 }}
          >
            {doctorErr}
          </div>
        )}
        {doctor && (
          <table className="table">
            <thead>
              <tr>
                <th style={{ width: 40 }} />
                <th>Component</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {doctor.checks.map((c) => (
                <tr key={c.name}>
                  <td>
                    <span
                      className={`pill ${
                        c.status === "pass"
                          ? "pass"
                          : c.status === "skip"
                            ? "mute"
                            : "fail"
                      }`}
                      style={{ fontSize: 11 }}
                    >
                      {c.status}
                    </span>
                  </td>
                  <td className="mono">{c.name}</td>
                  <td className="muted" style={{ fontSize: 13 }}>
                    {c.detail}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!doctor && !doctorErr && (
          <div className="muted" style={{ marginTop: 8 }}>
            Running connectivity sweep…
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Daemon</h2>
          <span className={`pill ${health ? "pass" : "fail"}`}>
            {health ? "ok" : "offline"}
          </span>
        </div>
        <div className="kv">
          <div className="k">Status</div>
          <div className="v">{health?.status ?? "—"}</div>
          <div className="k">Version</div>
          <div className="v">{health?.version ?? "—"}</div>
          <div className="k">Uptime</div>
          <div className="v">{fmtUptime(health?.uptime_secs)}</div>
          <div className="k">Network</div>
          <div className="v">{env?.network ?? "—"}</div>
          {env?.kiosk_mode && (
            <>
              <div className="k">Mode</div>
              <div className="v">
                <span className="pill mute">kiosk</span>{" "}
                <span className="muted" style={{ fontSize: 12 }}>
                  wallet management disabled
                </span>
              </div>
            </>
          )}
          <div className="k">Socket</div>
          <div className="v mono" style={{ fontSize: 12 }}>
            {env?.socket_path ?? "—"}
          </div>
          <div className="k">Wallets dir</div>
          <div className="v mono" style={{ fontSize: 12 }}>
            {env?.wallets_dir ?? "—"}
          </div>
        </div>
      </div>

      <div className="card">
        <h2>Node</h2>
        <div className="kv">
          <div className="k">RPC</div>
          <div className="v mono" style={{ fontSize: 12 }}>
            {env?.ghostd_url ?? "(none configured)"}
          </div>
          <div className="k">Auth</div>
          <div className="v">{env?.ghostd_auth ?? "—"}</div>
          {env?.ghostd_env_override && (
            <>
              <div className="k">Pinned</div>
              <div className="v muted">
                set by WRAITHD_GHOSTD_URL — change it there, not here
              </div>
            </>
          )}
        </div>
        {!env?.ghostd_url && (
          <div className="muted" style={{ marginTop: 8 }}>
            The wallet reads and writes the chain through your own node. Until
            one is set it will refuse those operations rather than ask somebody
            else — set it in Settings.
          </div>
        )}
      </div>
    </div>
  );
}
