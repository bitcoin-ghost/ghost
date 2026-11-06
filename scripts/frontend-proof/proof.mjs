#!/usr/bin/env node
// Drive every front-end page against a live node pool in a real headless Chromium, and check
// what it shows against the API's own JSON. Run by scripts/frontend-proof/run.sh, which brings
// the pool, the website and the dashboard up; see there for the whole flow.
//
//   node proof.mjs --serve <work>/serve.json --dashboard http://127.0.0.1:43901 \
//        --password <dashboard password> --site http://127.0.0.1:43900 --shots <dir> \
//        [--playwright <dir holding node_modules/playwright>]
//
// Every page, at 1280 px and at 390 px, in the light and the dark theme:
//   - no console error, no uncaught exception, no failed request, no HTTP error answer (except
//     the ones a failure case asks for);
//   - no "NaN", "undefined", "[object Object]", and no "unknown"/"unavailable" outside the
//     phrases a page uses on purpose for data the API does not have (UNKNOWN_OK, with the API
//     reading that justifies each);
//   - no horizontal scroll;
//   - a full-page screenshot.
// Then the numbers: balances, payouts, blocks (subsidy, miners, treasury base and change,
// finder surplus, against the coinbase on the Bitcoin node), expected wait, the pool's block
// interval and worker hashrate, each as the page shows it against the API.
// The miners are paused (SIGSTOP) while the numbers are read, so the chain holds still, and
// resumed at the end. Exit 1 on any failure; a JSON report is written beside the screenshots.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const A = {};
for (let i = 2; i < process.argv.length; i += 2) A[process.argv[i].replace(/^--/, "")] = process.argv[i + 1];
for (const k of ["serve", "dashboard", "password", "site", "shots"]) if (!A[k]) throw new Error(`missing --${k}`);
const require = createRequire(path.join(path.resolve(A.playwright || "."), "noop.js"));
const { chromium } = require("playwright");

const SERVE = JSON.parse(fs.readFileSync(A.serve, "utf8"));
fs.mkdirSync(A.shots, { recursive: true });
const FAIL = [];
const PASS = [];
const NOTES = [];
// A tile for a figure the API does not report at all: not a rendering fault, but reported.
const GAPS = [];
function fail(where, what) { FAIL.push(`${where}: ${what}`); console.log(`  FAIL ${where}: ${what}`); }
function pass(where, what) { PASS.push(`${where}: ${what}`); }
function note(where, what) { NOTES.push(`${where}: ${what}`); console.log(`  note ${where}: ${what}`); }

// ---------------------------------------------------------------- the API, read directly

async function getJson(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(15_000) });
  let body = null;
  try { body = await r.json(); } catch { /* not JSON */ }
  return { status: r.status, body };
}
async function rpc(node, method, ...params) {
  const r = await fetch(`http://127.0.0.1:${node.rpc_port}/`, {
    method: "POST",
    headers: { authorization: "Basic " + Buffer.from(`${SERVE.rpc_user}:${SERVE.rpc_password}`).toString("base64") },
    body: JSON.stringify({ jsonrpc: "1.0", id: "p", method, params }),
    signal: AbortSignal.timeout(30_000),
  });
  const j = await r.json();
  if (j.error) throw new Error(`${method}: ${JSON.stringify(j.error)}`);
  return j.result;
}
const api = (node, p) => getJson(`http://127.0.0.1:${node.http}${p}`);

// Every miner process of the run, paused or resumed (process groups: the harness starts each
// process in a session of its own).
function signalMiners(sig) {
  for (const n of SERVE.nodes)
    for (const [name, pid] of Object.entries(n.pids))
      if (name.startsWith("miner")) try { process.kill(-pid, sig); } catch { /* gone */ }
}

async function quiet(timeoutMs = 240_000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeoutMs) {
    try {
      const tips = new Set(await Promise.all(SERVE.nodes.map((n) => rpc(n, "getbestblockhash"))));
      const height = await rpc(SERVE.nodes[0], "getblockcount");
      const st = await Promise.all(SERVE.nodes.map((n) => api(n, "/api/v1/node-pool/status")));
      const anchors = new Set(st.map((s) => s.body?.share_chain?.tip));
      const settled = st.every((s) => s.body?.settlement?.caught_up && s.body.settlement.synced_height === height);
      if (tips.size === 1 && anchors.size === 1 && settled) return height;
    } catch { /* not yet */ }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error("the nodes did not agree on one tip within the timeout");
}

// ---------------------------------------------------------------- formatting, as the pages do

const en = (v) => v.toLocaleString("en-US");
// dashboard/src/lib/nodePool/view.ts
const D = {
  sats: (v) => `${en(v)} sats`,
  int: (v) => en(v),
  duration(s) {
    const d = Math.floor(s / 86_400);
    if (d >= 730) return `${en(Math.round(s / (365.25 * 86_400)))} years`;
    const h = Math.floor((s % 86_400) / 3_600);
    const m = Math.floor((s % 3_600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m`;
    return `${Math.floor(s)}s`;
  },
  hashrate(hs) {
    for (const [f, u] of [[1e18, "EH/s"], [1e15, "PH/s"], [1e12, "TH/s"], [1e9, "GH/s"], [1e6, "MH/s"], [1e3, "KH/s"]])
      if (hs >= f) return `${(hs / f).toFixed(2)} ${u}`;
    return `${hs.toFixed(0)} H/s`;
  },
};
// ghost-web/miner.js
const W = {
  sats: (s) => (Math.abs(s) < 100000 ? `${en(Number(s))}sats` : `${(s / 1e8).toFixed(8)}BTC`),
  duration(s) {
    if (s < 90) return Math.max(1, Math.round(s)) + " s";
    if (s < 5400) return Math.round(s / 60) + " min";
    if (s < 2 * 86400) return (s / 3600).toFixed(1) + " hours";
    if (s < 60 * 86400) return (s / 86400).toFixed(1) + " days";
    return (s / (30.44 * 86400)).toFixed(1) + " months";
  },
  hashrate(hs) {
    const units = ["H/s", "kH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s"];
    let i = 0, v = hs;
    while (Math.abs(v) >= 1000 && i < units.length - 1) { v /= 1000; i++; }
    return (v === 0 ? "0" : v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0)) + units[i];
  },
};
const squash = (s) => s.replace(/\s+/g, "");
const bestRate = (r) => { for (const k of ["1h", "15m", "24h"]) if (Number.isFinite(r?.[k])) return r[k]; return null; };

// ---------------------------------------------------------------- the browser

// Words a page may show on purpose, with what must be true of the API for each. A page showing
// "unknown" or "unavailable" anywhere else fails.
const UNKNOWN_OK = [
  // The sensing loop's own model name for a user agent it has no entry for (cpuminer, the
  // probes' agent): the API's value, shown as given.
  /unknown model/i, /unknown agent/i,
  // The expected wait when the pool has too few blocks: the API says known:false with a reason.
  /expected wait: unknown/i, /\bunknown: \S/i,
  // Explanatory prose on the miner page and docs, not a value.
  /we would rather say so than show a made-up number/i, /unknown, not zero/i,
  // A Rust target triple in a file name (downloads page).
  /-unknown-linux-gnu/,
];

function badWords(text) {
  const out = [];
  for (const line of text.split("\n")) {
    const l = line.trim();
    if (!l) continue;
    if (/\bNaN\b|\bundefined\b|\[object Object\]/.test(l)) out.push(l.slice(0, 160));
    else if (/\b(unknown|unavailable)\b/i.test(l) && !UNKNOWN_OK.some((r) => r.test(l))) out.push(l.slice(0, 160));
  }
  return out;
}

const VIEWPORTS = [
  { name: "desktop", width: 1280, height: 900 },
  { name: "mobile", width: 390, height: 844, isMobile: true, hasTouch: true },
];
const THEMES = ["light", "dark"];
// What a regtest harness node does not run, unlike an installed node: the mempool explorer's
// backend behind /mempool-app/api, and the installer's off-site backup helper behind
// /api/backup-offsite (/opt/ghost/bin/ghost-backup-offsite). Their failures are not the page's.
// The website's Hazync page reads the Hazync coordinator's board (/hazync/api/), a separate
// service the site's host proxies to.
const ENV_MISSING = ["/mempool-app/api/", "/api/backup-offsite", "/hazync/api/"];
// The website's live regions: status tiles, the node list, the miner page's sections.
// The miner page's "next payment" tile shows a bare "unknown" when the API says the wait is not
// known; the reason is its sub-line and the queue section's sentence.
const MINER_PAGE_WORDS = [/^unknown$/, /unavailable/i];
const SITE_VALUES = ["[data-np-field]", "#np-list-status", "#np-list-body", "#np-list-meta", "[id^=mp-]", "#error-msg"];
// Every other page in the dashboard's sidebar (dashboard/src/components/layout/Sidebar.tsx).
const OTHER_DASHBOARD_PAGES = ["/home", "/sync", "/block-template", "/mempool", "/network", "/shroud",
  "/ghost-mode", "/filtering", "/filtering/basic", "/filtering/advanced", "/storage", "/haze", "/address",
  "/zero-sync", "/system", "/swarm", "/connect", "/watchdog", "/logs", "/settings"];

async function newContext(browser, vp, theme) {
  const ctx = await browser.newContext({
    viewport: { width: vp.width, height: vp.height }, isMobile: !!vp.isMobile, hasTouch: !!vp.hasTouch,
    colorScheme: theme, deviceScaleFactor: 1,
  });
  await ctx.addInitScript((t) => { try { localStorage.setItem("ghost-theme", t); } catch { /* none */ } }, theme);
  return ctx;
}

// Load `url` in `page`, wait for it to settle, and run the generic checks. `expectErrors`:
// request URL substrings allowed to fail or answer >= 400 (a failure case).
// `values`: CSS selectors of the elements that carry live data. When given, "unknown" and
// "unavailable" are looked for only there (the website's prose uses both words in its
// explanations); NaN, undefined and [object Object] are looked for everywhere.
async function visit(page, url, label, { expectErrors = [], settle, allowWords = [], values = null } = {}) {
  const problems = [];
  const allowed = (u) => expectErrors.some((e) => u.includes(e));
  const onConsole = (m) => {
    if (m.type() !== "error") return;
    const loc = m.location()?.url || "";
    if (allowed(loc) || allowed(m.text())) return;
    // The browser's own line for an expected failed request names the URL only in location.
    if (/Failed to load resource/.test(m.text()) && allowed(loc)) return;
    problems.push(`console error: ${m.text().slice(0, 200)} ${loc}`);
  };
  const onPageError = (e) => problems.push(`uncaught: ${String(e).slice(0, 200)}`);
  // A prefetch Next.js cancels when the page moves on (`?_rsc=`) is not a failure.
  const onFailed = (r) => {
    if (allowed(r.url()) || /fonts\.(googleapis|gstatic)/.test(r.url())) return;
    // Any request the browser cancels because the page moved on (a poll, a prefetch) is
    // ERR_ABORTED: not a failure of the page. A refused, reset or timed-out request still is.
    if (r.failure()?.errorText === "net::ERR_ABORTED") return;
    problems.push(`request failed: ${r.url()} ${r.failure()?.errorText}`);
  };
  // The JSON the page itself fetched, by URL path (last answer wins): time-windowed figures
  // (hashrate, expected wait) move between a direct API read and the page's own, so the page is
  // checked against what it was given, and that against the direct read within a tolerance.
  const seen = [];
  const onResponse = (r) => {
    if (r.status() >= 400 && !allowed(r.url())) problems.push(`HTTP ${r.status()}: ${r.url()}`);
    if (/\/api\/(v1|pool|proxy)\//.test(r.url()) && r.status() === 200)
      seen.push(r.json().then((b) => [new URL(r.url()).pathname, b], () => null));
  };
  page.on("console", onConsole); page.on("pageerror", onPageError); page.on("requestfailed", onFailed); page.on("response", onResponse);
  try {
    await page.goto(url, { waitUntil: "networkidle", timeout: 60_000 });
    if (settle) await settle(page);
    await page.waitForTimeout(800);
    const text = await page.evaluate(() => document.body.innerText);
    const valueText = values
      ? await page.evaluate((sels) => sels.flatMap((q) => [...document.querySelectorAll(q)].map((e) => e.innerText)).join("\n"), values)
      : text;
    const words = [...badWords(valueText), ...(values ? badWords(text).filter((w) => /\bNaN\b|\bundefined\b|\[object Object\]/.test(w)) : [])];
    for (const w of new Set(words)) if (!allowWords.some((r) => r.test(w))) problems.push(`shows: "${w}"`);
    const scroll = await page.evaluate(() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]);
    if (scroll[0] > scroll[1] + 1) problems.push(`horizontal scroll: page ${scroll[0]} px wide in a ${scroll[1]} px viewport`);
    const theme = await page.evaluate(() => document.documentElement.getAttribute("data-theme"));
    const file = path.join(A.shots, `${label.replace(/[^a-z0-9]+/gi, "_")}.png`);
    await page.screenshot({ path: file, fullPage: true });
    const json = {};
    for (const e of await Promise.all(seen)) if (e) json[e[0]] = e[1];
    return { text, problems, theme, file, json };
  } finally {
    page.off("console", onConsole); page.off("pageerror", onPageError); page.off("requestfailed", onFailed); page.off("response", onResponse);
  }
}

function report(label, r, theme) {
  if (theme && r.theme && r.theme !== theme) r.problems.push(`theme is ${r.theme}, asked ${theme}`);
  if (r.problems.length) for (const p of r.problems) fail(label, p);
  else pass(label, "no console error, failed request, bad word or horizontal scroll");
}

// The text of the value cell beside a dashboard Kv label.
async function kv(page, label) {
  // A Kv (dashboard/src/components/nodePool/parts.tsx) is a label div followed by its value.
  return page.evaluate((l) => {
    for (const e of document.querySelectorAll("div.text-xs.mb-1")) {
      if (e.textContent.trim() === l && e.nextElementSibling) return e.nextElementSibling.innerText.trim();
    }
    return null;
  }, label);
}
// A hashrate as the dashboard prints it, against the API's: the windows slide between the two
// reads, so within 2%.
function expectRate(where, label, got, hs) {
  if (hs == null) return expectKv(where, label, got, "unknown");
  const m = /^([\d.]+) (EH|PH|TH|GH|MH|KH|H)\/s$/.exec(got || "");
  const f = { EH: 1e18, PH: 1e15, TH: 1e12, GH: 1e9, MH: 1e6, KH: 1e3, H: 1 };
  const v = m ? Number(m[1]) * f[m[2]] : NaN;
  if (Number.isFinite(v) && Math.abs(v - hs) <= 0.02 * hs) pass(where, `${label} ${got} ~ ${D.hashrate(hs)}`);
  else fail(where, `${label} shows ${JSON.stringify(got)}, the API says ${D.hashrate(hs)}`);
}
function expectKv(where, label, got, want) {
  if (got === want) pass(where, `${label} = ${want}`);
  else fail(where, `${label} shows ${JSON.stringify(got)}, the API says ${JSON.stringify(want)}`);
}

const dashSettle = async (page) => {
  await page.waitForFunction(() => !/Loading /.test(document.body.innerText), null, { timeout: 30_000 }).catch(() => {});
};

async function login(ctx) {
  const page = await ctx.newPage();
  await page.goto(`${A.dashboard}/login`, { waitUntil: "networkidle" });
  await page.fill('input[type="password"]', A.password);
  await Promise.all([page.waitForURL((u) => !u.pathname.startsWith("/login"), { timeout: 30_000 }), page.click('button[type="submit"]')]);
  await page.waitForLoadState("networkidle");
  // The login fetch's body can still be open when the app navigates; leave the page here, before
  // any check listens, so its abort is not charged to the first page checked.
  await page.goto("about:blank");
  return page;
}

// ---------------------------------------------------------------- the checks

async function main() {
  const browser = await chromium.launch();
  const nodes = SERVE.nodes;
  const n0 = nodes[0];
  const allMiners = nodes.flatMap((n) => n.miners.map((m) => ({ ...m, node: n })));
  const addresses = [...new Set(allMiners.map((m) => m.address))];
  console.log(`== pausing ${allMiners.length} miners and waiting for one tip`);
  signalMiners("SIGSTOP");
  try {
    const height = await quiet();
    console.log(`   quiet at Bitcoin height ${height}`);

    // The API's answers, read once the chain holds still.
    const status = (await api(n0, "/api/v1/node-pool/status")).body;
    const ledgers = {}, minersBy = {};
    for (const a of addresses) {
      ledgers[a] = (await api(n0, `/api/v1/ledger/${a}`)).body;
      const own = allMiners.find((m) => m.address === a).node;
      minersBy[a] = (await api(own, `/api/v1/miner/${a}`)).body;
    }
    // The ledger is the share chain's: every node answers it the same.
    for (const a of addresses) {
      for (const n of nodes.slice(1)) {
        const l = (await api(n, `/api/v1/ledger/${a}`)).body;
        if (l?.balance?.units !== ledgers[a]?.balance?.units) fail("api", `node${n.index} ledger for ${a} ${l?.balance?.units} != node0 ${ledgers[a]?.balance?.units}`);
      }
    }
    pass("api", `ledger for ${addresses.length} addresses identical on ${nodes.length} nodes`);

    // Blocks: the API against the coinbase on the Bitcoin node, and the run's preconditions.
    const blocks = status.recent_blocks;
    let changeBlocks = 0, surplusBlocks = 0, paying = 0;
    for (const b of blocks) {
      const where = `api block ${b.height}`;
      const sum = b.treasury_base_sats + b.treasury_change_sats + b.miners_paid_sats + b.finder_surplus_sats;
      if (sum !== b.subsidy_sats) fail(where, `base+change+miners+surplus ${sum} != subsidy ${b.subsidy_sats}`);
      if (b.treasury_sats !== b.treasury_base_sats + b.treasury_change_sats) fail(where, "treasury != base + change");
      if (b.payouts.reduce((x, p) => x + p.sats, 0) !== b.miners_paid_sats) fail(where, "sum of payouts != miners paid");
      if (b.treasury_change_sats > 0 && b.finder_surplus_sats > 0) fail(where, "both change and surplus");
      const blk = await rpc(n0, "getblock", b.block_hash, 2);
      const vout = blk.tx[0].vout.map((v) => [Math.round(v.value * 1e8), v.scriptPubKey.hex]);
      if (vout[0][1] !== SERVE.treasury_script || vout[0][0] !== b.treasury_sats) fail(where, `coinbase treasury output ${vout[0][0]} to ${vout[0][1].slice(0, 12)}…, API ${b.treasury_sats}`);
      const minerVouts = vout.slice(1, 1 + b.payouts.length).map((v) => v[0]);
      if (JSON.stringify(minerVouts) !== JSON.stringify(b.payouts.map((p) => p.sats))) fail(where, `coinbase miner outputs ${minerVouts} != API payouts`);
      const fees = vout.reduce((x, v) => x + v[0], 0) - b.subsidy_sats;
      const finder = vout.length > 3 + b.payouts.length ? vout[1 + b.payouts.length][0] : 0;
      if (finder !== fees + b.finder_surplus_sats) fail(where, `finder output ${finder} != fees ${fees} + surplus ${b.finder_surplus_sats}`);
      if (b.treasury_change_sats > 0) changeBlocks++;
      if (b.finder_surplus_sats > 0) surplusBlocks++;
      if (b.payouts.length) paying++;
    }
    pass("api", `${blocks.length} recent blocks match their coinbases: ${paying} paid miners, ${changeBlocks} left change, ${surplusBlocks} paid a finder surplus`);
    if (!changeBlocks) fail("precondition", "no recent block left change to the treasury");
    if (!surplusBlocks) fail("precondition", "no recent block paid a cleared-ledger finder surplus");
    const paid = addresses.filter((a) => ledgers[a]?.payouts?.length);
    if (!paid.length) note("precondition", "no running miner's address has a payout yet; payouts are checked on paid genesis addresses");
    // Addresses the listed blocks paid that no running miner mines to (the genesis table's):
    // their payout rows are checked on both front ends too.
    const paidOnly = [...new Set(blocks.flatMap((b) => b.payouts.map((x) => x.address)))]
      .filter((a) => !addresses.includes(a)).slice(0, 2);
    for (const a of paidOnly) ledgers[a] = (await api(n0, `/api/v1/ledger/${a}`)).body;
    if (!paid.length && !paidOnly.length) fail("precondition", "no address has a payout in the listed blocks");

    // ---------------- dashboard
    for (const vp of VIEWPORTS) for (const theme of THEMES) {
      const tag = `${vp.name}-${theme}`;
      console.log(`== dashboard ${tag}`);
      const ctx = await newContext(browser, vp, theme);
      const page = await login(ctx);
      // The dashboard's other pages (the Bitcoin node, privacy, filtering, storage, system):
      // not the node pool's, so no numbers, but no console error, failed request or overflow.
      // Their words are noted, not failed: a regtest node legitimately lacks some of their data.
      for (const p of OTHER_DASHBOARD_PAGES) {
        const r = await visit(page, `${A.dashboard}${p}`, `dash-other${p}-${tag}`, { settle: dashSettle, allowWords: [/./], expectErrors: ENV_MISSING });
        const words = badWords(r.text);
        if (words.length && vp.name === "desktop" && theme === "dark") note(`dashboard ${p}`, `shows ${words.slice(0, 4).map((w) => JSON.stringify(w)).join(", ")}`);
        report(`dashboard ${p} ${tag}`, r, theme);
      }
      const pages = [
        ["/", "overview"], ["/miners", "miners"], ["/blocks", "blocks"], ["/share-chain", "share-chain"],
        ["/mining", "connect-miners"],
        ...addresses.map((a, i) => [`/miners/${encodeURIComponent(a)}`, `miner-${i}`]),
      ];
      for (const [p, name] of pages) {
        const label = `dashboard ${name} ${tag}`;
        const r = await visit(page, `${A.dashboard}${p}`, `dash-${name}-${tag}`, { settle: dashSettle });
        report(label, r, theme);
        if (vp.name !== "desktop" || theme !== "dark") continue;
        // Numbers, once per page (desktop, dark).
        if (name === "overview") {
          expectKv(label, "Anchor height", await kv(page, "Anchor height"), D.int(status.share_chain.anchor_height));
          expectKv(label, "Relay peers", await kv(page, "Relay peers"), D.int(status.peers));
          expectKv(label, "Pool blocks listed", await kv(page, "Pool blocks listed"), D.int(status.recent_blocks.length));
          expectKv(label, "Ledger rows", await kv(page, "Ledger rows"), D.int(status.ledger_rows));
          expectKv(label, "Open channels", await kv(page, "Open channels"), D.int(status.miners.length));
          expectKv(label, "Fee address", await kv(page, "Fee address (finder output)"), status.fee_address);
          if (!/Healthy/.test(r.text)) fail(label, "health is not Healthy");
        }
        if (name === "blocks") {
          const rows = await page.$$eval('[data-testid="block-row"]', (trs) => trs.map((tr) => [...tr.children].map((td) => td.innerText.trim())));
          if (rows.length !== blocks.length) fail(label, `${rows.length} block rows, API ${blocks.length}`);
          rows.forEach((cells, i) => {
            const b = blocks[i];
            const want = [D.int(b.height), null, b.status, D.sats(b.subsidy_sats), D.sats(b.miners_paid_sats), String(b.payouts.length),
              D.sats(b.treasury_base_sats), D.sats(b.treasury_change_sats), D.sats(b.finder_surplus_sats), D.sats(b.treasury_sats)];
            want.forEach((w, k) => { if (w !== null && cells[k] !== w) fail(label, `block ${b.height} column ${k}: ${cells[k]} != ${w}`); });
          });
          pass(label, `${rows.length} block rows match the API`);
        }
        if (name === "miners") {
          const rows = await page.$$eval('[data-testid="miner-row"]', (trs) => trs.map((tr) => [...tr.children].map((td) => td.innerText.trim())));
          const connected = [...new Set(status.miners.map((m) => m.address))];
          if (rows.length !== connected.length) fail(label, `${rows.length} address rows, ${connected.length} connected addresses`);
          for (const a of connected) {
            const short = a.length <= 21 ? a : `${a.slice(0, 10)}…${a.slice(-10)}`;
            const row = rows.find((c) => c[0] === short);
            if (!row) { fail(label, `no row for ${a}`); continue; }
            const m = r.json[`/api/proxy/api/v1/miner/${a}`] || (await api(n0, `/api/v1/miner/${a}`)).body;
            const l = ledgers[a];
            expectKv(label, `${short} balance`, row[4], l.known ? D.sats(l.balance.sats) : "no balance yet");
            const hr = bestRate(m.summary.hashrate_hs);
            expectRate(label, `${short} hashrate`, row[2], hr);
          }
        }
        if (name.startsWith("miner-")) {
          const a = addresses[Number(name.slice(6))];
          const l = ledgers[a];
          const own = allMiners.find((m) => m.address === a).node;
          const m = r.json[`/api/proxy/api/v1/miner/${a}`] || minersBy[a];
          expectKv(label, "Balance owed", await kv(page, "Balance owed"), D.sats(l.balance.sats));
          const rows = await page.$$eval('[data-testid="payout-row"]', (trs) => trs.map((tr) => [...tr.children].map((td) => td.innerText.trim())));
          if (rows.length !== l.payouts.length) fail(label, `${rows.length} payout rows, API ${l.payouts.length}`);
          rows.forEach((c, i) => { if (c[2] !== D.sats(l.payouts[i].sats)) fail(label, `payout ${i}: ${c[2]} != ${D.sats(l.payouts[i].sats)}`); });
          if (own === n0) {
            // The dashboard is node0's: only its own miners have workers here.
            const ew = m.expected_wait;
            const want = !ew.known ? (ew.reason ? `unknown: ${ew.reason}` : "unknown")
              : [Number.isFinite(ew.seconds) ? `about ${D.duration(ew.seconds)}` : null,
                Number.isFinite(ew.blocks_needed) ? `${ew.blocks_needed} pool block${ew.blocks_needed === 1 ? "" : "s"}` : null].filter(Boolean).join(", ");
            expectKv(label, "Expected wait", await kv(page, "Expected wait"), want);
            const iv = ew.pool_expected_block_interval_secs;
            expectKv(label, "Pool block interval", await kv(page, "Pool finds a block about every"), Number.isFinite(iv) ? D.duration(iv) : "unknown");
            const wrows = await page.$$eval('[data-testid="worker-row"]', (trs) => trs.map((tr) => [...tr.children].map((td) => td.innerText.trim())));
            if (wrows.length !== m.workers.length) fail(label, `${wrows.length} worker rows, API ${m.workers.length}`);
            for (const w of m.workers) {
              const row = wrows.find((c) => c[0] === (w.name || "(no worker name)"));
              const hr = bestRate(w.hashrate_hs);
              if (!row) fail(label, `no row for worker ${w.name}`);
              else expectRate(label, `worker ${w.name} hashrate`, row[2], hr);
            }
          }
        }
        if (name === "share-chain") {
          expectKv(label, "Tip anchor", await kv(page, "Tip anchor"), status.share_chain.tip);
          expectKv(label, "Anchor height", await kv(page, "Anchor height"), D.int(status.share_chain.anchor_height));
        }
      }
      await ctx.close();
    }

    // ---------------- website
    const sitePages = ["/", "/index.html", "/pool.html", "/endpoints.html", "/nodes.html", "/miners.html", "/downloads.html",
      "/security.html", "/hazync.html", "/docs/", "/miner.html", "/no-such-page"];
    const docs = fs.readdirSync(path.join(path.dirname(new URL(import.meta.url).pathname), "../../ghost-web/docs")).filter((f) => f.endsWith(".md"));
    const listed = JSON.parse(await (await fetch(`${A.site}/node-list.json`)).text());
    const linkChecked = new Set();
    for (const vp of VIEWPORTS) for (const theme of THEMES) {
      const tag = `${vp.name}-${theme}`;
      console.log(`== website ${tag}`);
      const ctx = await newContext(browser, vp, theme);
      const page = await ctx.newPage();
      for (const p of sitePages) {
        const label = `site ${p} ${tag}`;
        const r = await visit(page, `${A.site}${p}`, `site-${p}-${tag}`, {
          expectErrors: [...(p === "/no-such-page" ? ["/no-such-page"] : []), ...ENV_MISSING],
          values: SITE_VALUES,
        });
        report(label, r, theme);
        if ((p === "/pool.html" || p === "/index.html") && vp.name === "desktop" && theme === "dark") {
          // The status tiles, read after the miners were paused: the chain holds still.
          const v = await page.$$eval("[data-np-field]", (els) => Object.fromEntries(els.map((e) => [e.getAttribute("data-np-field"), e.innerText.replace(/\s+/g, " ").trim()])));
          const want = {
            tip_height: en(status.share_chain.anchor_height),
            btc_height: en(status.settlement.bitcoin_tip),
            network_tier: en(status.share_chain.t_net),
            peers: en(status.peers),
            miners: en(status.miners.length),
            blocks_found: status.pool_blocks_found === undefined ? undefined : en(status.pool_blocks_found),
          };
          for (const [k, t] of Object.entries(v)) {
            if (t === "unavailable") fail(label, `tile ${k} shows unavailable`);
            else if (t === "—") GAPS.push(`${label}: tile ${k} reads "—": the status API does not report it`);
            else if (want[k] !== undefined) expectKv(label, `tile ${k}`, t, want[k]);
          }
        }
        if (p === "/endpoints.html" && vp.name === "desktop" && theme === "dark") {
          const rows = await page.$$eval("#np-list-body tr", (trs) => trs.length);
          expectKv(label, "listed nodes", rows, listed.nodes.length);
        }
        if (vp.name === "desktop" && theme === "dark" && p !== "/no-such-page") {
          // Every link to another page of the site must lead somewhere.
          const links = await page.$$eval("a[href]", (as) => as.map((a) => a.href));
          for (const l of links) {
            const u = new URL(l);
            if (u.origin !== new URL(A.site).origin) continue;
            const key = u.pathname;
            if (linkChecked.has(key)) continue;
            linkChecked.add(key);
            const st = (await fetch(`${A.site}${key}`)).status;
            if (st !== 200) fail(label, `links to ${key}, which answers ${st}`);
          }
        }
      }
      if (vp.name === "mobile") for (const d of docs) {
        const label = `site docs ${d} ${tag}`;
        report(label, await visit(page, `${A.site}/docs/#${d.replace(/\.md$/, "")}`, `site-docs-${d}-${tag}`, { allowWords: [/./] }), theme);
      }
      // The miner page, for every miner address.
      for (const [i, a] of addresses.entries()) {
        const label = `site miner ${i} ${tag}`;
        const r = await visit(page, `${A.site}/miner.html?address=${a}`, `site-miner-${i}-${tag}`, {
          allowWords: MINER_PAGE_WORDS,
          values: SITE_VALUES,
          settle: (pg) => pg.waitForFunction(() => /Checked|Updated/.test(document.getElementById("mp-updated")?.innerText || "") || document.getElementById("error-mode")?.hidden === false, null, { timeout: 60_000 }),
        });
        report(label, r, theme);
        if (vp.name !== "desktop" || theme !== "dark") continue;
        const l = ledgers[a];
        const tiles = squash(await page.$eval("#mp-tiles", (e) => e.innerText));
        if (!tiles.includes(W.sats(l.balance.sats))) fail(label, `balance tile does not show ${W.sats(l.balance.sats)}: ${tiles.slice(0, 200)}`);
        else pass(label, `balance ${W.sats(l.balance.sats)}`);
        const paidSum = l.payouts.reduce((x, p) => x + p.sats, 0);
        if (!tiles.includes(W.sats(paidSum))) fail(label, `paid tile does not show ${W.sats(paidSum)}`);
        const pay = squash(await page.$eval("#mp-payouts", (e) => e.innerText));
        for (const p of l.payouts) if (!pay.includes(W.sats(p.sats))) fail(label, `payout at ${p.height} (${W.sats(p.sats)}) missing`);
        const own = allMiners.find((m) => m.address === a).node;
        const mine = r.json[`/api/pool/${own.ip}/api/v1/miner/${a}`] || minersBy[a];
        const wait = mine.expected_wait;
        const q = squash(await page.$eval("#mp-queue", (e) => e.innerText));
        const wantWait = wait.known ? squash(`Expected wait: about ${W.duration(wait.seconds)}`) : squash("Expected wait: unknown.");
        if (!q.includes(wantWait)) fail(label, `queue does not say ${wantWait}`);
        const workers = squash(await page.$eval("#mp-workers", (e) => e.innerText));
        for (const w of mine.workers) {
          const hr = w.hashrate_hs?.["1h"];
          if (Number.isFinite(hr) && !workers.includes(W.hashrate(hr))) fail(label, `worker ${w.name} hashrate ${W.hashrate(hr)} missing (node${own.index})`);
          if (!workers.includes(squash(`node ${own.ip}`))) fail(label, `worker ${w.name} does not name its node ${own.ip}`);
        }
      }
      await ctx.close();
    }

    // ---------------- paid addresses no running miner mines to
    {
      const ctx = await newContext(browser, VIEWPORTS[0], "dark");
      const dpage = await login(ctx);
      const spage = await ctx.newPage();
      for (const [i, a] of paidOnly.entries()) {
        const l = ledgers[a];
        let label = `dashboard paid address ${i}`;
        let r = await visit(dpage, `${A.dashboard}/miners/${a}`, `dash-paid-${i}`, { settle: dashSettle });
        report(label, r, "dark");
        expectKv(label, "Balance owed", await kv(dpage, "Balance owed"), D.sats(l.balance.sats));
        const rows = await dpage.$$eval('[data-testid="payout-row"]', (trs) => trs.map((tr) => [...tr.children].map((td) => td.innerText.trim())));
        if (rows.length !== l.payouts.length) fail(label, `${rows.length} payout rows, API ${l.payouts.length}`);
        rows.forEach((c, k) => { if (c[0] !== D.int(l.payouts[k].height) || c[2] !== D.sats(l.payouts[k].sats)) fail(label, `payout ${k}: ${c[0]} ${c[2]} != ${l.payouts[k].height} ${D.sats(l.payouts[k].sats)}`); });
        if (rows.length === l.payouts.length) pass(label, `${rows.length} payout row(s) match the ledger`);
        label = `site paid address ${i}`;
        r = await visit(spage, `${A.site}/miner.html?address=${a}`, `site-paid-${i}`, {
          allowWords: MINER_PAGE_WORDS,
          values: SITE_VALUES,
          settle: (pg) => pg.waitForFunction(() => /Checked|Updated/.test(document.getElementById("mp-updated")?.innerText || ""), null, { timeout: 60_000 }),
        });
        report(label, r, "dark");
        const pay = squash(await spage.$eval("#mp-payouts", (e) => e.innerText));
        const missing = l.payouts.filter((x) => !pay.includes(W.sats(x.sats)) || !pay.includes(String(x.height)));
        if (missing.length) fail(label, `payouts not shown: ${missing.map((x) => x.height).join(", ")}`);
        else pass(label, `${l.payouts.length} payout(s) shown with height and amount`);
        if (!squash(await spage.$eval("#mp-tiles", (e) => e.innerText)).includes(W.sats(l.balance.sats))) fail(label, `balance ${W.sats(l.balance.sats)} not shown`);
      }
      await ctx.close();
    }

    // ---------------- failure behaviour
    console.log("== failure cases");
    {
      const ctx = await newContext(browser, VIEWPORTS[0], "dark");
      const page = await ctx.newPage();
      // An address with no history.
      // P2WPKH of sha256("frontend-proof/no-history")[..20]: nobody mines to it. (The lister's
      // address is not fresh: its probes open channels.)
      const fresh = "bcrt1q8987qe7sm0v04xe8kgacpny64zmd37u6tq498j";
      let r = await visit(page, `${A.site}/miner.html?address=${fresh}`, "fail-site-fresh-address", {
          allowWords: MINER_PAGE_WORDS,
        values: SITE_VALUES,
        settle: (pg) => pg.waitForFunction(() => /Checked|Updated/.test(document.getElementById("mp-updated")?.innerText || "") || document.getElementById("error-mode")?.hidden === false, null, { timeout: 60_000 }),
      });
      report("site miner, an address with no history", r);
      // An invalid address: the ledger answers 400 and the page must say why, without NaN.
      r = await visit(page, `${A.site}/miner.html?address=notanaddress`, "fail-site-invalid-address", {
        values: SITE_VALUES,
        expectErrors: ["/api/pool/"],
        settle: (pg) => pg.waitForFunction(() => /Checked|Updated/.test(document.getElementById("mp-updated")?.innerText || "") || document.getElementById("error-mode")?.hidden === false, null, { timeout: 60_000 }),
        allowWords: [/unavailable/i],
      });
      report("site miner, an invalid address", r);
      note("site miner, an invalid address", `shows: ${r.text.split("\n").filter((l) => /address|invalid|not a/i.test(l)).slice(0, 3).join(" | ")}`);
      const dpage = await login(ctx);
      r = await visit(dpage, `${A.dashboard}/miners/notanaddress`, "fail-dash-invalid-address", { settle: dashSettle, expectErrors: ["/api/proxy/"], allowWords: [/unavailable/i] });
      report("dashboard miner, an invalid address", r);
      note("dashboard miner, an invalid address", `shows: ${r.text.split("\n").filter((l) => /unavailable|invalid|address/i.test(l)).slice(0, 3).join(" | ")}`);
      r = await visit(dpage, `${A.dashboard}/miners/${fresh}`, "fail-dash-fresh-address", { settle: dashSettle });
      report("dashboard miner, an address with no history", r);

      // A node down: node1's pool_sv2 stopped (SIGSTOP: it holds its connections and answers
      // nothing). The website's miner page must still show the ledger from another node and
      // say which node is not answering; node1's own dashboard would say unavailable.
      const n1 = nodes[1];
      const down = n1.pids.pool_sv2;
      process.kill(-down, "SIGSTOP");
      try {
        const a = n1.miners[0].address;
        r = await visit(page, `${A.site}/miner.html?address=${a}`, "fail-site-node1-down", {
          allowWords: MINER_PAGE_WORDS,
        values: SITE_VALUES,
          expectErrors: [`/api/pool/${n1.ip}/`],
          settle: (pg) => pg.waitForFunction(() => /Checked|Updated/.test(document.getElementById("mp-updated")?.innerText || "") || document.getElementById("error-mode")?.hidden === false, null, { timeout: 90_000 }),
        });
        report("site miner, its node down", r);
        if (!squash(r.text).includes(W.sats(ledgers[a].balance.sats))) fail("site miner, its node down", "balance not shown from another node");
        if (!r.text.includes(n1.ip)) fail("site miner, its node down", `does not name ${n1.ip} as not answering`);
        note("site miner, its node down", r.text.split("\n").filter((l) => l.includes(n1.ip) || /not answering|unavailable/i.test(l)).slice(0, 4).join(" | "));
      } finally {
        process.kill(-down, "SIGCONT");
      }
      await ctx.close();
    }
  } finally {
    signalMiners("SIGCONT");
    await browser.close();
  }
  fs.writeFileSync(path.join(A.shots, "report.json"), JSON.stringify({ pass: PASS, fail: FAIL, gaps: [...new Set(GAPS)], notes: NOTES }, null, 1));
  for (const g of new Set(GAPS)) console.log(`  gap  ${g}`);
  console.log(`\n== ${PASS.length} passed, ${FAIL.length} failed; report and screenshots in ${A.shots}`);
  process.exit(FAIL.length ? 1 : 0);
}

main().catch((e) => { console.error(e); signalMiners("SIGCONT"); process.exit(2); });
