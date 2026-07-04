import { useEffect, useRef, useState } from "react";
import { QRCodeSVG } from "qrcode.react";
import {
  daemonEnv,
  lightL1Utxos,
  lightReceive,
  walletGhostId,
  type DetectedPayment,
  type LightL1UtxoEntry,
  onPaymentDetected,
  startWatch,
} from "../lib/tauri";
import { Numpad } from "../components/Numpad";
import { ProductCatalog, useProducts, type Product } from "../components/ProductCatalog";
import { printReceipt, emailReceipt, receiptPlainText } from "../lib/receipt";

interface MerchantProps {
  activeWallet: string | null;
  paymentTick?: number;
  guiKiosk?: boolean;
  onEnterKiosk?: () => void;
}

interface CartLine {
  /// Stable id per line — lets us delete a single quantity row even
  /// when products with the same name appear twice.
  line_id: string;
  /// Source product id, or null for a custom-amount entry.
  product_id: string | null;
  label: string;
  emoji?: string;
  unit_sats: number;
  qty: number;
}

interface OpenInvoice {
  id: number;
  amount_sats: number;
  memo: string;
  address: string;
  ghost_id: string;
  bip86_index: number;
  opened_at: number;
  /// Snapshot of the cart at invoice-creation time. Kept so the
  /// PaidReceipt that follows a successful payment can persist the
  /// per-line breakdown for reports/reprints, even though the live
  /// cart auto-clears on `markPaid`.
  lines: PaidLine[];
}

/// Frozen cart line as it appears on a printed/persisted receipt.
/// Distinct from `CartLine` because cart entries can be edited up
/// until the invoice is created — once paid, the line is immutable
/// historical data.
export interface PaidLine {
  label: string;
  emoji?: string;
  unit_sats: number;
  qty: number;
}

export interface PaidReceipt {
  invoice_id: number;
  amount_sats: number;
  memo: string;
  method: "silent_payment" | "direct";
  txid: string;
  paid_at: number;
  /// Wallet that took the payment. Lets reports keyed across many
  /// wallets stay attributable, and ends up on the printed receipt
  /// header without an extra prop.
  wallet_name?: string;
  /// Frozen line items from the cart at sale time. Optional only
  /// because legacy receipts written before this field exists are
  /// silently tolerated by the loader.
  lines?: PaidLine[];
}

const MERCHANT_INDEX_BASE = 5000;
const SAT = 100_000_000;

export function takingsKey(wallet: string | null): string {
  return `wraith.merchant.takings:${wallet ?? "_none_"}`;
}

export function startOfLocalDay(at: number = Date.now()): number {
  const d = new Date(at);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/// Loads ALL persisted receipts for a wallet — the historical
/// log. The pre-2026-05 build filtered to "today" inside the
/// loader so the till didn't show stale info, but that meant
/// yesterday's sales were silently dropped on reload. Reports
/// need the full history; the till's "Today's takings" pill row
/// just filters at render time. Tolerates rows missing the newer
/// `lines`/`wallet_name` fields so old data stays readable.
export function loadTakings(wallet: string | null): PaidReceipt[] {
  if (!wallet) return [];
  try {
    const raw = localStorage.getItem(takingsKey(wallet));
    if (!raw) return [];
    const parsed = JSON.parse(raw) as PaidReceipt[];
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (r) => r && typeof r.paid_at === "number" && typeof r.amount_sats === "number",
    );
  } catch {
    return [];
  }
}

export function saveTakings(wallet: string | null, takings: PaidReceipt[]): void {
  if (!wallet) return;
  try {
    localStorage.setItem(takingsKey(wallet), JSON.stringify(takings));
  } catch {
    /* quota / sandbox */
  }
}

/// CSV header includes per-line item info as a JSON column so a
/// single CSV row stays one logical "sale". Spreadsheets that want
/// per-item rows can pivot the JSON, while a quick eyeball still
/// works without unrolling.
export function takingsToCsv(takings: PaidReceipt[]): string {
  const header =
    "paid_at_iso,wallet,amount_sats,method,memo,txid,invoice_id,line_count,lines_json";
  const csvEscape = (s: string): string => {
    if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
    return s;
  };
  const rows = takings.map((r) => {
    const lines = r.lines ?? [];
    const linesJson = lines.length > 0 ? JSON.stringify(lines) : "";
    return [
      new Date(r.paid_at).toISOString(),
      csvEscape(r.wallet_name ?? ""),
      String(r.amount_sats),
      r.method,
      csvEscape(r.memo),
      r.txid,
      String(r.invoice_id),
      String(lines.length),
      csvEscape(linesJson),
    ].join(",");
  });
  return [header, ...rows].join("\n");
}

export function downloadText(
  filename: string,
  content: string,
  mime: string = "text/csv;charset=utf-8",
): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

function bip21Uri(
  address: string,
  amount_sats: number,
  memo: string,
  ghost_id: string,
): string {
  const params = new URLSearchParams();
  params.set("amount", (amount_sats / SAT).toFixed(8));
  if (memo) params.set("message", memo);
  if (ghost_id) params.set("ghost", ghost_id);
  return `bitcoin:${address}?${params.toString()}`;
}

function freshLineId(): string {
  return Math.random().toString(36).slice(2, 9);
}

export function Merchant({
  activeWallet,
  paymentTick = 0,
  guiKiosk,
  onEnterKiosk,
}: MerchantProps) {
  const [ghostId, setGhostId] = useState<string | null>(null);
  const [networkLabel, setNetworkLabel] = useState<string | null>(null);

  // Cart state — line items + a custom-amount keypad scratch value.
  const [cart, setCart] = useState<CartLine[]>([]);
  const [keypad, setKeypad] = useState("");
  const [memoInput, setMemoInput] = useState("");
  const [invoiceIndex, setInvoiceIndex] = useState(MERCHANT_INDEX_BASE);

  // Right-pane state: idle / open / paid.
  const [open, setOpen] = useState<OpenInvoice | null>(null);
  const [paid, setPaid] = useState<PaidReceipt | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // Transient positive feedback for receipt actions (email / copy).
  const [notice, setNotice] = useState<string | null>(null);

  // Persisted catalog + takings.
  const { products, setProducts } = useProducts(activeWallet);
  const [takings, setTakings] = useState<PaidReceipt[]>(() =>
    loadTakings(activeWallet),
  );
  useEffect(() => {
    saveTakings(activeWallet, takings);
  }, [activeWallet, takings]);
  useEffect(() => {
    setTakings(loadTakings(activeWallet));
  }, [activeWallet]);

  // Latest open invoice for the listener — see Detect listeners below.
  const openRef = useRef<OpenInvoice | null>(null);
  useEffect(() => {
    openRef.current = open;
  }, [open]);

  // Bootstrap: ghost_id + network label + watch loop.
  useEffect(() => {
    if (!activeWallet) return;
    let alive = true;
    (async () => {
      try {
        const id = await walletGhostId();
        if (alive) setGhostId(id.ghost_id);
        const env = await daemonEnv();
        if (alive) setNetworkLabel(env.network);
        await startWatch();
      } catch (e) {
        if (alive) setErr((e as Error).message ?? String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [activeWallet]);

  // Detect: BIP-352 push.
  useEffect(() => {
    let alive = true;
    let unlisten: (() => void) | undefined;
    (async () => {
      try {
        unlisten = await onPaymentDetected((p: DetectedPayment) => {
          if (!alive) return;
          const inv = openRef.current;
          if (!inv) return;
          const detect_ms = p.received_at * 1000;
          if (detect_ms < inv.opened_at - 5_000) return;
          if (p.amount_sats < inv.amount_sats) return;
          markPaid({
            invoice_id: inv.id,
            amount_sats: p.amount_sats,
            memo: inv.memo,
            method: "silent_payment",
            txid: p.txid,
            paid_at: Date.now(),
            wallet_name: activeWallet ?? undefined,
            lines: inv.lines,
          });
        });
      } catch (e) {
        if (alive) setErr((e as Error).message ?? String(e));
      }
    })();
    return () => {
      alive = false;
      if (unlisten) unlisten();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Detect: direct deposit poll.
  useEffect(() => {
    if (!open) return;
    let alive = true;
    const tick = async () => {
      try {
        const r = await lightL1Utxos(open.bip86_index + 1, 0);
        if (!alive) return;
        const match: LightL1UtxoEntry | undefined = r.utxos.find(
          (u) =>
            u.address === open.address && u.amount_sats >= open.amount_sats,
        );
        if (match) {
          markPaid({
            invoice_id: open.id,
            amount_sats: match.amount_sats,
            memo: open.memo,
            method: "direct",
            txid: match.txid,
            paid_at: Date.now(),
            wallet_name: activeWallet ?? undefined,
            lines: open.lines,
          });
        }
      } catch {
        /* best-effort */
      }
    };
    tick();
    const id = setInterval(tick, 4000);
    return () => {
      alive = false;
      clearInterval(id);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, paymentTick]);

  const cartTotal = cart.reduce((acc, l) => acc + l.unit_sats * l.qty, 0);
  const keypadAmount = (() => {
    const n = Number(keypad);
    return Number.isFinite(n) && n > 0 ? n : 0;
  })();
  const sendableTotal = cartTotal + keypadAmount;

  const addProductToCart = (p: Product) => {
    setCart((prev) => {
      const existing = prev.find(
        (l) => l.product_id === p.id && l.unit_sats === p.price_sats,
      );
      if (existing) {
        return prev.map((l) =>
          l.line_id === existing.line_id ? { ...l, qty: l.qty + 1 } : l,
        );
      }
      return [
        ...prev,
        {
          line_id: freshLineId(),
          product_id: p.id,
          label: p.name,
          emoji: p.emoji,
          unit_sats: p.price_sats,
          qty: 1,
        },
      ];
    });
  };

  const addKeypadAmount = () => {
    if (keypadAmount <= 0) return;
    setCart((prev) => [
      ...prev,
      {
        line_id: freshLineId(),
        product_id: null,
        label: "Custom",
        unit_sats: keypadAmount,
        qty: 1,
      },
    ]);
    setKeypad("");
  };

  const removeLine = (line_id: string) => {
    setCart((prev) => prev.filter((l) => l.line_id !== line_id));
  };

  const clearCart = () => {
    setCart([]);
    setKeypad("");
    setMemoInput("");
  };

  const buildMemo = (): string => {
    if (memoInput.trim()) return memoInput.trim();
    if (cart.length === 0) return "";
    const itemized = cart
      .map((l) => (l.qty > 1 ? `${l.label} ×${l.qty}` : l.label))
      .join(", ");
    return itemized.length > 59 ? itemized.slice(0, 56) + "…" : itemized;
  };

  const onCreateInvoice = async () => {
    setErr(null);
    if (!ghostId) {
      setErr("Ghost ID not loaded yet — try again in a second.");
      return;
    }
    // Fold the keypad's pending amount into the cart total at submit time.
    let amount = cartTotal;
    if (keypadAmount > 0) amount += keypadAmount;
    if (amount <= 0) {
      setErr("Add a product or punch in an amount before taking payment.");
      return;
    }
    setBusy(true);
    try {
      const recv = await lightReceive(invoiceIndex);
      const id = invoiceIndex;
      // Freeze a snapshot of the cart now. The numpad's pending
      // amount becomes a "Custom" line so customer printouts and
      // reports always reflect the full sale, not just the named
      // products.
      const lines: PaidLine[] = cart.map((l) => ({
        label: l.label,
        emoji: l.emoji,
        unit_sats: l.unit_sats,
        qty: l.qty,
      }));
      if (keypadAmount > 0) {
        lines.push({
          label: "Custom",
          unit_sats: keypadAmount,
          qty: 1,
        });
      }
      setOpen({
        id,
        amount_sats: amount,
        memo: buildMemo(),
        address: recv.address,
        ghost_id: ghostId,
        bip86_index: id,
        opened_at: Date.now(),
        lines,
      });
      setPaid(null);
      setInvoiceIndex(invoiceIndex + 1);
    } catch (e) {
      setErr((e as Error).message ?? String(e));
    } finally {
      setBusy(false);
    }
  };

  const cancelInvoice = () => {
    setOpen(null);
  };

  const markPaid = (receipt: PaidReceipt) => {
    if (paid) return;
    setPaid(receipt);
    setTakings((prev) => [receipt, ...prev]);
    setOpen(null);
    // Cart auto-clears on a successful sale.
    clearCart();
  };

  const onNextSale = () => {
    setPaid(null);
  };

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      /* ignore */
    }
  };

  // Today's takings is a derived view — the underlying store is
  // all-time so reports can pull the full history. Filter happens
  // here rather than in the loader.
  const todayStart = startOfLocalDay();
  const todayTakings = takings.filter((r) => r.paid_at >= todayStart);

  const onExportCsv = () => {
    const stamp = new Date().toISOString().slice(0, 10);
    downloadText(`takings-today-${stamp}.csv`, takingsToCsv(todayTakings));
  };

  const onPrintReceipt = (r: PaidReceipt) => {
    printReceipt(r, {
      wallet: activeWallet ?? r.wallet_name ?? null,
      network: networkLabel,
    });
  };

  const flashNotice = (msg: string) => {
    setNotice(msg);
    window.setTimeout(() => setNotice(null), 3000);
  };

  const receiptOpts = (r: PaidReceipt) => ({
    wallet: activeWallet ?? r.wallet_name ?? null,
    network: networkLabel,
  });

  const onEmailReceipt = (r: PaidReceipt) => {
    // mailto hand-off — opens the operator's own mail client with the
    // receipt prefilled. No SMTP dependency in the daemon.
    emailReceipt(r, receiptOpts(r));
    flashNotice("Opening your mail app… no mail client? Use Copy instead.");
  };

  const onCopyReceipt = async (r: PaidReceipt) => {
    try {
      await navigator.clipboard.writeText(receiptPlainText(r, receiptOpts(r)));
      flashNotice("Receipt copied to clipboard.");
    } catch {
      setErr("Clipboard unavailable — try Print or Email instead.");
    }
  };

  if (!activeWallet) {
    return (
      <div className="screen">
        <div className="page-head">
          <div>
            <span className="eyebrow">point of sale</span>
            <h1>Merchant</h1>
          </div>
        </div>
        <div className="card muted">
          Select and unlock a wallet first to take payments.
        </div>
      </div>
    );
  }

  // ----- Render -----
  return (
    <div className="screen">
      <div className="page-head">
        <div>
          <span className="eyebrow">point of sale</span>
          <h1>Merchant</h1>
          <p className="lead">
            Tap products, punch a custom amount, take the payment.
            Customer scans the QR — terminal flips to PAID when the
            funds land.
          </p>
        </div>
        {!guiKiosk && onEnterKiosk && (
          <button
            className="btn-secondary"
            onClick={onEnterKiosk}
            title="Hide the wallet nav and lock this session to the Merchant screen. Click the kiosk pill in the header to exit."
          >
            Lock as till →
          </button>
        )}
      </div>

      {err && (
        <div className="card error-card">{err}</div>
      )}

      <div className="till-grid">
        {/* ===== COL 1: PRODUCTS (fills) + TODAY'S TAKINGS (stub) ===== */}
        <div className="till-col">
          <div className="till-card-fill">
            <div className="till-scroll">
              <ProductCatalog
                products={products}
                onPick={addProductToCart}
                onChange={setProducts}
              />
            </div>
          </div>
          {todayTakings.length > 0 && (
            <div className="till-card">
              <div className="card-header">
                <h3>Today's takings</h3>
                <span className="muted" style={{ fontSize: 11 }}>
                  {todayTakings.length} ·{" "}
                  <strong style={{ color: "var(--fg)" }}>
                    {todayTakings
                      .reduce((acc, r) => acc + r.amount_sats, 0)
                      .toLocaleString()}
                  </strong>{" "}
                  sats
                </span>
              </div>
              <div className="row" style={{ gap: 8, marginTop: 4 }}>
                {todayTakings.slice(0, 4).map((r) => (
                  <button
                    key={r.invoice_id + ":" + r.txid}
                    className="pill mute"
                    onClick={() => onPrintReceipt(r)}
                    title={`${new Date(r.paid_at).toLocaleTimeString()} · ${r.memo || "—"} — click to reprint receipt`}
                    style={{ cursor: "pointer", border: 0 }}
                  >
                    +{r.amount_sats.toLocaleString()}
                  </button>
                ))}
                {todayTakings.length > 4 && (
                  <span className="muted" style={{ fontSize: 11 }}>
                    +{todayTakings.length - 4} more
                  </span>
                )}
              </div>
              <div className="row">
                <button
                  className="btn-secondary btn-sm"
                  onClick={onExportCsv}
                  title="Download today's sales as a CSV"
                >
                  Export CSV
                </button>
                <button
                  className="btn-secondary btn-sm"
                  onClick={() => {
                    if (
                      window.confirm(
                        `Clear today's ${todayTakings.length} sale(s) from the local takings log? Older history (Reports) is unaffected. Export to CSV first if you need a record — chain history isn't affected either way.`,
                      )
                    ) {
                      setTakings((prev) =>
                        prev.filter((r) => r.paid_at < todayStart),
                      );
                    }
                  }}
                >
                  Clear today
                </button>
              </div>
            </div>
          )}
        </div>

        {/* ===== COL 2: TILL (cart [grows] + numpad + actions) ===== */}
        <div className="till-col">
          <div className="till-card till-card-fill">
            <div className="card-header">
              <h3>Sale</h3>
              {networkLabel && (
                <span className="pill mute">{networkLabel}</span>
              )}
            </div>
            <div
              className={`till-amount-display${sendableTotal === 0 ? " zero" : ""}`}
            >
              {sendableTotal.toLocaleString()}
              <span className="unit">sats</span>
            </div>
            {cart.length === 0 && keypadAmount === 0 ? (
              <div className="cart-empty">
                Tap a product or punch in an amount.
              </div>
            ) : (
              <div className="till-scroll">
                <div className="cart-list">
                  {cart.map((l) => (
                    <div className="cart-item" key={l.line_id}>
                      <div className="cart-item-name">
                        {l.emoji && (
                          <span style={{ marginRight: 6 }}>{l.emoji}</span>
                        )}
                        {l.label}
                        {l.qty > 1 && (
                          <span className="qty">× {l.qty}</span>
                        )}
                      </div>
                      <div className="cart-item-price">
                        {(l.unit_sats * l.qty).toLocaleString()}
                      </div>
                      <button
                        className="cart-item-remove"
                        title="Remove"
                        onClick={() => removeLine(l.line_id)}
                      >
                        ×
                      </button>
                    </div>
                  ))}
                  {keypadAmount > 0 && (
                    <div className="cart-item" style={{ opacity: 0.7 }}>
                      <div className="cart-item-name">Pending</div>
                      <div className="cart-item-price">
                        {keypadAmount.toLocaleString()}
                      </div>
                      <button
                        className="cart-item-remove"
                        title="Add to cart as a custom line"
                        onClick={addKeypadAmount}
                        style={{ color: "var(--accent)" }}
                      >
                        +
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="till-card tight">
            <h3>Custom amount</h3>
            <Numpad
              value={keypad}
              onChange={setKeypad}
              disabled={busy || open != null}
            />
          </div>

          <div className="till-card tight">
              <input
                maxLength={59}
                value={memoInput}
                onChange={(e) => setMemoInput(e.target.value)}
                placeholder={
                  cart.length > 0
                    ? cart
                        .map((l) =>
                          l.qty > 1 ? `${l.label} ×${l.qty}` : l.label,
                        )
                        .join(", ")
                        .slice(0, 50)
                    : "Memo (optional)"
                }
                disabled={busy || open != null}
              />
              <div className="row">
                <button
                  className="btn-secondary btn-sm"
                  onClick={clearCart}
                  disabled={
                    cart.length === 0 && keypad === "" && memoInput === ""
                  }
                >
                  Clear
                </button>
                <span className="spacer" />
                <button
                  className="btn-primary"
                  onClick={onCreateInvoice}
                  disabled={busy || sendableTotal <= 0 || open != null}
                  style={{ padding: "10px 18px" }}
                >
                {busy
                  ? "Building…"
                  : open
                    ? "Awaiting payment"
                    : "Take payment →"}
              </button>
            </div>
          </div>
        </div>

        {/* ===== COL 3: PAYMENT PANE ===== */}
        <div className="till-col">
          {paid ? (
            <div
              className="payment-pane"
              style={{
                borderColor: "var(--pass)",
                borderLeftWidth: 3,
                flex: 1,
                minHeight: 0,
              }}
            >
              <div className="success-hero">
                <div className="check">✓</div>
                <div className="label">paid</div>
                <div className="amount">
                  {paid.amount_sats.toLocaleString()}
                  <span className="unit"> sats</span>
                </div>
                {paid.memo && (
                  <div className="muted" style={{ fontSize: 14 }}>
                    {paid.memo}
                  </div>
                )}
                {paid.lines && paid.lines.length > 0 && (
                  <div
                    className="muted"
                    style={{
                      fontSize: 11,
                      marginTop: 6,
                      lineHeight: 1.4,
                    }}
                  >
                    {paid.lines
                      .map((l) =>
                        l.qty > 1 ? `${l.label} ×${l.qty}` : l.label,
                      )
                      .join(" · ")}
                  </div>
                )}
                <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>
                  via{" "}
                  {paid.method === "silent_payment"
                    ? "Ghost silent payment"
                    : "direct deposit"}{" "}
                  · {new Date(paid.paid_at).toLocaleTimeString()}
                </div>
                <div
                  className="mono muted"
                  style={{
                    fontSize: 10,
                    marginTop: 4,
                    wordBreak: "break-all",
                  }}
                >
                  {paid.txid}
                </div>
              </div>
              <div
                className="row"
                style={{ justifyContent: "center", flexWrap: "wrap", gap: 8 }}
              >
                <button
                  className="btn-secondary btn-sm"
                  onClick={() => onPrintReceipt(paid)}
                  title="Open the printable receipt in a new window"
                >
                  Print receipt
                </button>
                <button
                  className="btn-secondary btn-sm"
                  onClick={() => onEmailReceipt(paid)}
                  title="Open your mail app with the receipt prefilled (mailto)"
                >
                  Email receipt
                </button>
                <button
                  className="btn-secondary btn-sm"
                  onClick={() => onCopyReceipt(paid)}
                  title="Copy the receipt as plain text"
                >
                  Copy
                </button>
                <button
                  className="btn-primary"
                  onClick={onNextSale}
                  style={{ padding: "12px 24px", fontSize: 15 }}
                >
                  Next sale
                </button>
              </div>
              {notice && (
                <div
                  className="pill pass"
                  style={{ alignSelf: "center", marginTop: 4 }}
                >
                  {notice}
                </div>
              )}
            </div>
          ) : open ? (
            <div
              className="payment-pane"
              style={{ flex: 1, minHeight: 0 }}
            >
              <div
                className="row"
                style={{
                  alignItems: "baseline",
                  justifyContent: "space-between",
                }}
              >
                <div>
                  <span className="eyebrow eyebrow-dim" style={{ fontSize: 10 }}>
                    invoice #{open.id}
                  </span>
                  <div
                    style={{
                      fontFamily: "var(--font-mono)",
                      fontSize: 26,
                      fontWeight: 500,
                      letterSpacing: "-0.02em",
                      lineHeight: 1.1,
                      marginTop: 4,
                    }}
                  >
                    {open.amount_sats.toLocaleString()}
                    <span
                      style={{
                        fontSize: 13,
                        color: "var(--dim)",
                        marginLeft: 8,
                        fontWeight: 400,
                      }}
                    >
                      sats
                    </span>
                  </div>
                </div>
                <span className="pill warn live">waiting</span>
              </div>
              {open.memo && (
                <div className="muted" style={{ fontSize: 12 }}>
                  {open.memo}
                </div>
              )}
              <div style={{ display: "flex", justifyContent: "center" }}>
                <div className="qr-card">
                  <QRCodeSVG
                    value={bip21Uri(
                      open.address,
                      open.amount_sats,
                      open.memo,
                      open.ghost_id,
                    )}
                    size={200}
                    level="M"
                  />
                </div>
              </div>
              <div className="row" style={{ justifyContent: "center" }}>
                <button
                  className="btn-secondary btn-sm"
                  onClick={() =>
                    copy(
                      bip21Uri(
                        open.address,
                        open.amount_sats,
                        open.memo,
                        open.ghost_id,
                      ),
                    )
                  }
                >
                  Copy URI
                </button>
                <button
                  className="btn-secondary btn-sm"
                  onClick={cancelInvoice}
                >
                  Cancel
                </button>
              </div>
              <div
                className="muted"
                style={{
                  fontSize: 11,
                  fontStyle: "italic",
                  textAlign: "center",
                }}
              >
                Watching silent-payment and direct deposit.
              </div>
            </div>
          ) : (
            <div
              className="payment-pane idle"
              style={{ flex: 1, minHeight: 0 }}
            >
              <div className="placeholder">
                <div className="icon">⌁</div>
                <div style={{ fontSize: 13 }}>
                  Build a sale on the left.<br />
                  The QR code lands here once you take payment.
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

    </div>
  );
}
