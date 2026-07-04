import type { PaidReceipt } from "../screens/Merchant";

interface PrintReceiptOptions {
  /// Wallet name printed in the header. Falls back to the receipt's
  /// own `wallet_name` if absent.
  wallet?: string | null;
  /// Network label ("mainnet" / "signet" / "regtest"). Printed in
  /// small grey text — handy for testing, ignored on a real till.
  network?: string | null;
  /// "Receipt" by default; `Reprint` for re-issued copies.
  title?: string;
}

interface EmailReceiptOptions extends PrintReceiptOptions {
  /// Optional recipient to prefill. Usually left blank — the merchant
  /// types the customer's address in their own mail client.
  to?: string;
}

const SAT = 100_000_000;

/// Renders a single paid receipt to a print-only popup window and
/// invokes the OS print dialog. Self-contained: ships its own CSS
/// so it works whether or not the host page has print styles.
///
/// Why a popup and not the existing window:
///   - the till layout is dense; switching it to "print mode" via
///     @media print and a hidden printable section means every
///     screen needs to be print-tested.
///   - thermal-printer drivers love a tiny standalone document.
///   - cancelling print just closes the popup, no state reset.
export function printReceipt(
  receipt: PaidReceipt,
  opts: PrintReceiptOptions = {},
): void {
  const html = receiptHtml(receipt, opts);
  // `noopener` would null `w.opener` — fine — but some webviews
  // reject scripts written to about:blank if the opener was
  // detached. Stick to opener-attached + same-origin.
  const w = window.open("", "wraith-receipt", "width=380,height=640");
  if (!w) {
    // Popup-blocked. Fall back to a data: URL the user can save.
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank", "noopener,noreferrer");
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    return;
  }
  w.document.open();
  w.document.write(html);
  w.document.close();
  // Defer print until the document has parsed; webkit fires it
  // synchronously otherwise and the body is empty.
  w.addEventListener("load", () => {
    try {
      w.focus();
      w.print();
    } catch {
      /* the user can hit Ctrl-P themselves */
    }
  });
}

export function receiptHtml(
  receipt: PaidReceipt,
  opts: PrintReceiptOptions = {},
): string {
  const wallet = opts.wallet ?? receipt.wallet_name ?? "";
  const title = opts.title ?? "Receipt";
  const ts = new Date(receipt.paid_at);
  const date = ts.toLocaleDateString();
  const time = ts.toLocaleTimeString();
  const lines = receipt.lines ?? [];
  const linesHtml = lines.length
    ? lines
        .map(
          (l) => `
          <tr>
            <td class="qty">${l.qty}×</td>
            <td class="name">${escapeHtml(l.emoji ? l.emoji + " " : "")}${escapeHtml(l.label)}</td>
            <td class="amt">${(l.unit_sats * l.qty).toLocaleString()}</td>
          </tr>`,
        )
        .join("")
    : `<tr><td colspan="3" class="muted">No itemised lines.</td></tr>`;

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>${escapeHtml(title)} #${receipt.invoice_id}</title>
<style>
  @page { margin: 8mm; }
  body {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
    color: #111;
    margin: 0;
    padding: 16px;
    width: 280px;
  }
  h1 { font-size: 14px; margin: 0 0 4px; letter-spacing: 0.04em; text-transform: uppercase; }
  .sub { font-size: 10px; color: #666; margin-bottom: 12px; }
  .meta { font-size: 11px; line-height: 1.5; margin-bottom: 12px; }
  .meta .row { display: flex; justify-content: space-between; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0; }
  th, td {
    padding: 4px 0;
    font-weight: normal;
    text-align: left;
    vertical-align: top;
    border-bottom: 1px dashed #ccc;
  }
  th { font-size: 10px; text-transform: uppercase; color: #666; letter-spacing: 0.05em; }
  td.qty { width: 28px; color: #666; }
  td.amt, th.amt { text-align: right; white-space: nowrap; }
  td.name { word-break: break-word; }
  .total {
    margin-top: 8px;
    display: flex;
    justify-content: space-between;
    font-size: 14px;
    font-weight: bold;
    border-top: 2px solid #111;
    padding-top: 8px;
  }
  .memo {
    margin-top: 12px;
    font-size: 11px;
    color: #444;
    font-style: italic;
  }
  .footer {
    margin-top: 16px;
    font-size: 9px;
    color: #888;
    word-break: break-all;
    line-height: 1.5;
  }
  .footer .label { color: #666; text-transform: uppercase; letter-spacing: 0.05em; }
  .muted { color: #888; font-style: italic; text-align: center; }
  @media screen {
    body { background: #fff; box-shadow: 0 0 0 1px #ddd; margin: 24px auto; }
  }
</style>
</head>
<body>
  <h1>${escapeHtml(wallet || "wraith")}</h1>
  <div class="sub">${escapeHtml(title)} · paid in bitcoin${opts.network ? ` · ${escapeHtml(opts.network)}` : ""}</div>
  <div class="meta">
    <div class="row"><span>Date</span><span>${escapeHtml(date)}</span></div>
    <div class="row"><span>Time</span><span>${escapeHtml(time)}</span></div>
    <div class="row"><span>Invoice</span><span>#${receipt.invoice_id}</span></div>
    <div class="row"><span>Method</span><span>${
      receipt.method === "silent_payment" ? "silent payment" : "direct"
    }</span></div>
  </div>
  <table>
    <thead>
      <tr>
        <th></th>
        <th>Item</th>
        <th class="amt">Sats</th>
      </tr>
    </thead>
    <tbody>${linesHtml}</tbody>
  </table>
  <div class="total">
    <span>Total</span>
    <span>${receipt.amount_sats.toLocaleString()} sats</span>
  </div>
  <div class="meta" style="margin-top:4px;">
    <div class="row"><span>≈ BTC</span><span>${(receipt.amount_sats / SAT).toFixed(8)}</span></div>
  </div>
  ${
    receipt.memo
      ? `<div class="memo">"${escapeHtml(receipt.memo)}"</div>`
      : ""
  }
  <div class="footer">
    <div class="label">txid</div>
    <div>${escapeHtml(receipt.txid)}</div>
  </div>
  <div class="footer" style="margin-top:12px; text-align:center;">
    Thank you · powered by Ghost Wallet
  </div>
</body>
</html>`;
}

/// Plain-text rendering of a receipt — the email body and the
/// "copy receipt" fallback. Mail clients and clipboards want text, not
/// the print HTML, so this is a separate, dependency-free renderer.
export function receiptPlainText(
  receipt: PaidReceipt,
  opts: PrintReceiptOptions = {},
): string {
  const wallet = opts.wallet ?? receipt.wallet_name ?? "wraith";
  const ts = new Date(receipt.paid_at);
  const lines = receipt.lines ?? [];
  const out: string[] = [];
  out.push(wallet.toUpperCase());
  out.push(
    `${opts.title ?? "Receipt"} #${receipt.invoice_id} · paid in bitcoin${
      opts.network ? ` · ${opts.network}` : ""
    }`,
  );
  out.push("");
  out.push(`Date:    ${ts.toLocaleDateString()} ${ts.toLocaleTimeString()}`);
  out.push(
    `Method:  ${receipt.method === "silent_payment" ? "silent payment" : "direct"}`,
  );
  out.push("");
  if (lines.length) {
    for (const l of lines) {
      const name = (l.emoji ? l.emoji + " " : "") + l.label;
      out.push(`${l.qty}x ${name}  -  ${(l.unit_sats * l.qty).toLocaleString()} sats`);
    }
  } else {
    out.push("(no itemised lines)");
  }
  out.push("");
  out.push(
    `TOTAL: ${receipt.amount_sats.toLocaleString()} sats (${(
      receipt.amount_sats / SAT
    ).toFixed(8)} BTC)`,
  );
  if (receipt.memo) {
    out.push("");
    out.push(`Memo: ${receipt.memo}`);
  }
  out.push("");
  out.push(`txid: ${receipt.txid}`);
  out.push("");
  out.push("Thank you · powered by Ghost Wallet");
  return out.join("\n");
}

/// Open the user's mail client with a receipt prefilled (subject +
/// plain-text body) via a `mailto:` link. No SMTP and no daemon mail
/// transport — the OS hands off to whatever mail app is registered.
/// This is the pragmatic v1: the merchant's own client sends it, and
/// there's a "Copy receipt" fallback in the UI when no mail handler is
/// registered. Returns the composed `mailto:` URL.
export function emailReceipt(
  receipt: PaidReceipt,
  opts: EmailReceiptOptions = {},
): string {
  const wallet = opts.wallet ?? receipt.wallet_name ?? "wraith";
  const subject = `${opts.title ?? "Receipt"} #${receipt.invoice_id} — ${receipt.amount_sats.toLocaleString()} sats · ${wallet}`;
  const body = receiptPlainText(receipt, opts);
  const url = `mailto:${
    opts.to ? encodeURIComponent(opts.to) : ""
  }?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  // Anchor-click is the most webview-friendly way to trigger the OS
  // mailto handler — `window.location` is blocked in some Tauri configs.
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener noreferrer";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  return url;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/// Print a multi-row sales report. Same popup pattern as the
/// individual receipt — keep both on the same printable surface.
export function printSalesReport(
  receipts: PaidReceipt[],
  opts: { wallet?: string | null; title?: string; rangeLabel?: string } = {},
): void {
  const html = salesReportHtml(receipts, opts);
  const w = window.open("", "wraith-report", "width=720,height=900");
  if (!w) {
    const blob = new Blob([html], { type: "text/html;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    window.open(url, "_blank", "noopener,noreferrer");
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    return;
  }
  w.document.open();
  w.document.write(html);
  w.document.close();
  w.addEventListener("load", () => {
    try {
      w.focus();
      w.print();
    } catch {
      /* user can hit Ctrl-P */
    }
  });
}

export function salesReportHtml(
  receipts: PaidReceipt[],
  opts: { wallet?: string | null; title?: string; rangeLabel?: string } = {},
): string {
  const total = receipts.reduce((acc, r) => acc + r.amount_sats, 0);
  const title = opts.title ?? "Sales report";
  const wallet = opts.wallet ?? "";
  const generated = new Date().toLocaleString();
  const rows = receipts
    .map((r) => {
      const ts = new Date(r.paid_at);
      const itemSummary = (r.lines ?? [])
        .map((l) => (l.qty > 1 ? `${l.label} ×${l.qty}` : l.label))
        .join(", ");
      return `
      <tr>
        <td>${ts.toLocaleDateString()} ${ts.toLocaleTimeString()}</td>
        <td>#${r.invoice_id}</td>
        <td>${escapeHtml(r.memo || itemSummary || "—")}</td>
        <td>${r.method === "silent_payment" ? "silent" : "direct"}</td>
        <td class="amt">${r.amount_sats.toLocaleString()}</td>
      </tr>`;
    })
    .join("");

  return `<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<title>${escapeHtml(title)}</title>
<style>
  @page { margin: 16mm; }
  body {
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    font-size: 12px;
    color: #111;
    margin: 0;
    padding: 24px;
  }
  h1 { font-size: 18px; margin: 0 0 4px; }
  .sub { font-size: 11px; color: #666; margin-bottom: 16px; }
  .summary {
    display: flex;
    gap: 24px;
    margin-bottom: 16px;
    padding: 12px;
    background: #f7f7f5;
    border: 1px solid #e0ddd5;
  }
  .summary .stat { font-size: 11px; color: #666; }
  .summary .stat strong {
    display: block;
    color: #111;
    font-size: 15px;
    margin-top: 2px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  table { width: 100%; border-collapse: collapse; }
  th, td {
    padding: 6px 8px;
    text-align: left;
    border-bottom: 1px solid #eee;
    font-size: 11px;
  }
  th {
    background: #fafaf8;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    font-size: 10px;
    color: #444;
  }
  td.amt, th.amt { text-align: right; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  tfoot td {
    font-weight: bold;
    border-top: 2px solid #111;
    border-bottom: none;
    padding-top: 8px;
    font-size: 13px;
  }
  .empty { color: #888; font-style: italic; padding: 24px; text-align: center; }
  @media screen {
    body { background: #fff; box-shadow: 0 0 0 1px #ddd; margin: 24px auto; max-width: 720px; }
  }
</style>
</head>
<body>
  <h1>${escapeHtml(title)}</h1>
  <div class="sub">
    ${escapeHtml(wallet || "wraith")}${opts.rangeLabel ? ` · ${escapeHtml(opts.rangeLabel)}` : ""} ·
    generated ${escapeHtml(generated)}
  </div>
  <div class="summary">
    <div class="stat">Sales<strong>${receipts.length}</strong></div>
    <div class="stat">Total<strong>${total.toLocaleString()} sats</strong></div>
    <div class="stat">≈ BTC<strong>${(total / SAT).toFixed(8)}</strong></div>
    <div class="stat">Average<strong>${
      receipts.length ? Math.round(total / receipts.length).toLocaleString() : 0
    } sats</strong></div>
  </div>
  ${
    receipts.length
      ? `<table>
          <thead>
            <tr>
              <th>When</th>
              <th>Invoice</th>
              <th>Item / memo</th>
              <th>Method</th>
              <th class="amt">Sats</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
          <tfoot>
            <tr>
              <td colspan="4">Total</td>
              <td class="amt">${total.toLocaleString()}</td>
            </tr>
          </tfoot>
        </table>`
      : `<div class="empty">No sales in this range.</div>`
  }
</body>
</html>`;
}
