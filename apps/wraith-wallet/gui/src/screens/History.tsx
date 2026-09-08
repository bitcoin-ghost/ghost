import { useEffect, useMemo, useState } from "react";
import { lightHistory, type LightHistoryEntry } from "../lib/tauri";

interface HistoryProps {
  /// Bumped by App when the daemon pushes a `PaymentDetected`
  /// event. Used as a dep so a new receive triggers an immediate
  /// re-fetch instead of waiting for the next 5s poll tick.
  paymentTick?: number;
}

type Filter = "all" | "send" | "receive";
const PAGE_SIZE = 25;

export function History({ paymentTick = 0 }: HistoryProps) {
  const [entries, setEntries] = useState<LightHistoryEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [copiedTxid, setCopiedTxid] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        // Fetch a generous window — server-side pagination would be
        // an extra IPC round-trip per page. For the volumes a
        // single wallet generates, 500 rows in memory is fine and
        // lets the client filter + search without re-querying.
        const h = await lightHistory(500, 0);
        if (!alive) return;
        setEntries(h.transactions);
        setTotal(h.total_count);
        setErr(null);
      } catch (e) {
        if (!alive) return;
        setErr((e as Error).message ?? String(e));
      }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [paymentTick]);

  // Reset to page 0 whenever the filter or search changes — the
  // current page might not have any rows after the filter applies.
  useEffect(() => {
    setPage(0);
  }, [filter, search]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return entries.filter((e) => {
      if (filter === "send" && e.tx_type !== "send") return false;
      if (filter === "receive" && e.tx_type !== "receive") return false;
      if (q) {
        const haystack = `${e.memo ?? ""} ${e.txid}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [entries, filter, search]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageEntries = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const fmtTime = (unix: number) => new Date(unix * 1000).toLocaleString();
  // A dash, not a zero: the wallet not knowing what moved and the wallet
  // knowing nothing moved are different answers.
  const fmtAmount = (sats: number | null) => {
    if (sats === null || sats === undefined) return "—";
    const sign = sats > 0 ? "+" : "";
    return `${sign}${sats.toLocaleString()}`;
  };

  const copyTxid = async (txid: string) => {
    try {
      await navigator.clipboard.writeText(txid);
      setCopiedTxid(txid);
      setTimeout(() => setCopiedTxid(null), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">ledger</span>
          <h1>History</h1>
          <p className="lead">
            All sent and received L2 transactions. Filter by direction,
            search by memo or txid, click a txid to copy.
          </p>
        </div>
      </div>
      {err && <div className="card error-card">{err}</div>}
      <div className="card">
        <div className="card-header">
          <h2>
            {filtered.length === 0
              ? entries.length === 0
                ? "No transactions yet"
                : "No matches"
              : "Activity"}
          </h2>
          <span className="muted">
            {filtered.length === entries.length
              ? `${total} total`
              : `${filtered.length} of ${total}`}
          </span>
        </div>

        <div className="row" style={{ gap: 8, alignItems: "center" }}>
          <div className="row" style={{ gap: 4 }}>
            {(["all", "send", "receive"] as Filter[]).map((f) => (
              <button
                key={f}
                className={filter === f ? "primary" : "secondary"}
                onClick={() => setFilter(f)}
                style={{ fontSize: 12, padding: "4px 10px" }}
              >
                {f === "all" ? "All" : f === "send" ? "Sent" : "Received"}
              </button>
            ))}
          </div>
          <input
            placeholder="Search memo or txid…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ flex: 1 }}
          />
        </div>

        {pageEntries.length > 0 && (
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>Type</th>
                <th>Amount (sats)</th>
                <th>Memo</th>
                <th>Conf</th>
                <th>Txid</th>
              </tr>
            </thead>
            <tbody>
              {pageEntries.map((e) => (
                <tr key={e.txid + e.timestamp}>
                  <td className="muted" style={{ fontSize: 13 }}>
                    {fmtTime(e.timestamp)}
                  </td>
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
                        (e.amount_sats ?? 0) > 0
                          ? "var(--pass)"
                          : (e.amount_sats ?? 0) < 0
                            ? "var(--fail)"
                            : "var(--fg)",
                    }}
                  >
                    {fmtAmount(e.amount_sats)}
                  </td>
                  <td className="muted">{e.memo ?? "—"}</td>
                  <td>{e.confirmations ?? "—"}</td>
                  <td>
                    <button
                      className="secondary"
                      onClick={() => copyTxid(e.txid)}
                      style={{
                        fontSize: 11,
                        padding: "2px 8px",
                        fontFamily: "var(--mono, monospace)",
                      }}
                      title={e.txid}
                    >
                      {copiedTxid === e.txid
                        ? "copied"
                        : `${e.txid.slice(0, 8)}…`}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {pageCount > 1 && (
          <div
            className="row"
            style={{ justifyContent: "space-between", marginTop: 8 }}
          >
            <button
              className="secondary"
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
            >
              ← Previous
            </button>
            <span className="muted" style={{ fontSize: 13 }}>
              Page {page + 1} of {pageCount}
            </span>
            <button
              className="secondary"
              onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}
              disabled={page >= pageCount - 1}
            >
              Next →
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
