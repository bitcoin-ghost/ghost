"use strict";

// W2.14: the node pool pages, rendered from the REAL view components with sample JSON shaped as
// pool_sv2 serves it (`bins/pool-sv2/src/lib/node_pool_api.rs`, `node_pool_miner_api.rs`), and
// from a failed API. What must hold: every page shows what the node reported, and when the node
// pool service does not answer, nothing reads as healthy or as zero.

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");

const tsx = require("./helpers/tsx.js");

const FIX = path.join(__dirname, "fixtures");
const fixture = (name) => JSON.parse(fs.readFileSync(path.join(FIX, name), "utf8"));
const NOW = 1_800_000_000;

let React;
let render;
let views;
let canLoad = tsx.register();
test.before(() => {
  if (!canLoad) return;
  try {
    React = require("react");
    ({ renderToStaticMarkup: render } = require("react-dom/server"));
    views = {
      ...tsx.load("@/components/nodePool/OverviewView"),
      ...tsx.load("@/components/nodePool/MinersView"),
      ...tsx.load("@/components/nodePool/MinerDetailView"),
      ...tsx.load("@/components/nodePool/BlocksView"),
      ...tsx.load("@/components/nodePool/ShareChainView"),
      ...tsx.load("@/components/nodePool/NodePoolSettingsView"),
      view: tsx.load("@/lib/nodePool/view"),
      api: tsx.load("@/lib/api/nodePool"),
    };
  } catch (e) {
    canLoad = false;
    console.error(`cannot load the dashboard modules: ${e.stack}`);
  }
});

// A test that cannot load what it tests must FAIL, not skip: a skipped test is green.
function need() {
  assert.ok(canLoad, "this Node cannot load the dashboard's TSX modules (needs module.registerHooks)");
}

function html(Component, props) {
  return render(React.createElement(Component, props));
}

/** The visible text, tags stripped, whitespace collapsed. */
function text(markup) {
  return markup.replace(/<[^>]+>/g, " ").replace(/&#x27;/g, "'").replace(/&amp;/g, "&").replace(/\s+/g, " ");
}

function count(markup, testid) {
  return (markup.match(new RegExp(`data-testid="${testid}"`, "g")) || []).length;
}

const FAILED = new Error("the node pool service (pool_sv2) did not answer: connection refused");

/** Words a failed page must never show for a value it does not have. */
function assertNothingHealthy(t) {
  assert.doesNotMatch(t, /\bHealthy\b/);
  assert.doesNotMatch(t, /caught up/);
  assert.doesNotMatch(t, /\b0 sats\b/);
}

// ---------------------------------------------------------------- overview

test("overview: renders the status, health checks and start values", () => {
  need();
  const status = fixture("node-pool-status.json");
  const m = html(views.OverviewView, {
    status,
    node: { is_synced: true, block_height: 999, sync_height: 999, version: "1.0.0", uptime_seconds: 3700 },
  });
  const t = text(m);
  // One provisional block and one unseen anchor: attention, not healthy.
  assert.match(t, /Needs attention/);
  assert.match(t, /Relay peers 2 connected/);
  assert.match(t, /Settlement caught up to Bitcoin 999/);
  assert.match(t, /Provisional blocks 1 retired from their coinbase/);
  assert.match(t, /Share-chain sync 1 anchor\(s\) held without their batch/);
  assert.match(t, /Anchor height 7/);
  assert.match(t, /bcrt1qfeeaddressexample0000000000000000000/);
  assert.match(t, /Pinned table digest none pinned/);
  assert.match(t, /Source default/);
  assert.match(t, /Payout addresses 2/);
  assert.match(t, /Firmware warnings 1/);
  assert.match(t, /Synced/);
  assert.match(t, /Uptime 1h 1m/);
  // Pool-wide: every block since genesis, not the listed few, and the credited work's rate.
  assert.match(t, /Pool blocks found 41/);
  assert.match(t, /Pool finds a block about every 14h 26m/);
  // The credited work's hashrate and the ledger's total, as pool_sv2 reports them.
  assert.match(t, /Pool hashrate 101\.81 MH\/s/);
  assert.match(m, /job heights 856 to 999 \(2 shares\), over 144 Bitcoin blocks/);
  assert.match(t, /Total owed to miners 30,500 sats/);
});

test("overview: a hashrate the node cannot measure says why; an older pool_sv2's missing figures read unknown", () => {
  need();
  const status = fixture("node-pool-status.json");
  status.pool_hashrate = {
    hashes_per_sec: null, from_job_height: null, to_job_height: null, window_blocks: 0,
    credited_shares: 0, unavailable: "settlement has not seen a Bitcoin tip yet",
  };
  let t = text(html(views.OverviewView, { status }));
  assert.match(t, /Pool hashrate not measured: settlement has not seen a Bitcoin tip yet/);
  assert.doesNotMatch(t, /Pool hashrate 0/);
  delete status.pool_hashrate;
  delete status.total_owed;
  t = text(html(views.OverviewView, { status }));
  assert.match(t, /Pool hashrate unknown/);
  assert.match(t, /Total owed to miners unknown/);
});

test("overview: pool-wide figures an older pool_sv2 does not send read unknown; none credited says so", () => {
  need();
  const status = fixture("node-pool-status.json");
  delete status.pool_blocks_found;
  delete status.pool_expected_block_interval_secs;
  let t = text(html(views.OverviewView, { status }));
  assert.match(t, /Pool blocks found unknown/);
  assert.match(t, /Pool finds a block about every unknown/);
  status.pool_expected_block_interval_secs = null;
  t = text(html(views.OverviewView, { status }));
  assert.match(t, /Pool finds a block about every no work credited yet/);
});

test("overview: a healthy status reads healthy", () => {
  need();
  const status = fixture("node-pool-status.json");
  status.settlement.provisional = [];
  status.share_chain.unseen_anchors = 0;
  const t = text(html(views.OverviewView, { status }));
  assert.match(t, /Healthy/);
  assert.doesNotMatch(t, /Needs attention/);
});

test("overview: no relay peers is a warning, a mismatched block an error", () => {
  need();
  const status = fixture("node-pool-status.json");
  status.peers = 0;
  status.settlement.mismatched = 2;
  const h = views.view.nodePoolHealth(status, undefined);
  assert.equal(h.level, "error");
  assert.equal(h.checks.find((c) => c.label === "Relay peers").level, "warn");
  assert.equal(h.checks.find((c) => c.label === "Mismatched blocks").level, "error");
});

test("overview: work before the first earning height is flagged, and only then", () => {
  need();
  const status = fixture("node-pool-status.json");
  status.settlement.provisional = [];
  status.share_chain.unseen_anchors = 0;
  status.earning = {
    first_earning_height: 21,
    job_height: 12,
    earns: false,
    notice: "Work on this node earns nothing until Bitcoin height 21.",
  };
  const h = views.view.nodePoolHealth(status, undefined);
  assert.equal(h.level, "warn");
  assert.equal(h.checks.find((c) => c.label === "Work earns nothing yet").level, "warn");
  assert.match(text(html(views.OverviewView, { status })), /earns nothing until Bitcoin height 21/);
  status.earning = { first_earning_height: 21, job_height: 30, earns: true, notice: null };
  const ok = views.view.nodePoolHealth(status, undefined);
  assert.equal(ok.level, "ok");
  assert.equal(ok.checks.find((c) => c.label === "Work earns nothing yet"), undefined);
});

test("overview: a failed API shows unavailable and unknown, never healthy or zero", () => {
  need();
  const m = html(views.OverviewView, { statusError: FAILED, nodeError: new Error("API error: 502") });
  const t = text(m);
  assert.match(t, /Node pool status unavailable/);
  assert.match(t, /did not answer: connection refused/);
  assert.match(t, /Unhealthy/);
  assert.match(t, /Node status unavailable/);
  assert.match(t, /Sync unknown/);
  assert.match(t, /Anchor height unknown/);
  assert.match(t, /Relay peers unknown/);
  assert.match(t, /Fee address \(finder output\) unknown/);
  assertNothingHealthy(t);
  assert.doesNotMatch(t, /Relay peers 0/);
});

// ---------------------------------------------------------------- miners

test("miners: channels, slot classes, sensing, warnings and per-address ledger/miner data", () => {
  need();
  const status = fixture("node-pool-status.json");
  const ledger = fixture("node-pool-ledger.json");
  const miner = fixture("node-pool-miner.json");
  const one = "bcrt1qminerone000000000000000000000000000";
  const two = "bcrt1qminertwo000000000000000000000000000";
  const m = html(views.MinersView, {
    status,
    ledgers: { [one]: { data: ledger }, [two]: { error: new Error("API error: 503") } },
    miners: { [one]: { data: miner } },
  });
  const t = text(m);
  assert.equal(count(m, "channel-row"), 2);
  assert.equal(count(m, "miner-row"), 2);
  assert.match(t, /settled \(highest passed 9, ceiling 9\)/);
  assert.match(t, /standard channel: header only, full class/);
  assert.match(t, /Stock Antminer 2\.0\.0/);
  assert.match(t, /Stock Antminer firmware carries at most 9 miner outputs/);
  assert.match(t, /6,501 sats/);
  assert.match(t, /#1 oldest, #2 largest of 3/);
  assert.match(t, /110\.00 TH\/s/);
  assert.match(t, /812 \/ 3 \/ 1/);
  assert.match(t, /unknown: fewer than 3 pool blocks in 30 days/);
  // Address two: ledger failed, miner still loading. Neither reads as zero.
  assert.match(t, /unavailable/);
  assert.match(m, /href="\/miners\/bcrt1qminerone000000000000000000000000000"/);
});

test("miners: a channel opened with no worker name says so, not unknown", () => {
  need();
  const status = fixture("node-pool-status.json");
  status.miners[0].worker = "";
  const t = text(html(views.MinersView, { status, ledgers: {}, miners: {} }));
  assert.match(t, /\(no worker name\)/);
});

test("miners: a failed API shows unavailable, no rows and no counts", () => {
  need();
  const m = html(views.MinersView, { statusError: FAILED, ledgers: {}, miners: {} });
  const t = text(m);
  assert.match(t, /Node pool status unavailable/);
  assert.equal(count(m, "channel-row"), 0);
  assert.doesNotMatch(t, /Open channels/);
  assertNothingHealthy(t);
});

test("miners: no miner connected says so", () => {
  need();
  const status = fixture("node-pool-status.json");
  status.miners = [];
  const t = text(html(views.MinersView, { status, ledgers: {}, miners: {} }));
  assert.match(t, /No miner is connected to this node/);
});

// ---------------------------------------------------------------- miner detail

test("miner detail: ledger, queue by class, workers, payouts and shares", () => {
  need();
  const m = html(views.MinerDetailView, {
    address: "bcrt1qminerone000000000000000000000000000",
    ledger: fixture("node-pool-ledger.json"),
    miner: fixture("node-pool-miner.json"),
    now: NOW,
  });
  const t = text(m);
  assert.match(t, /Balance owed 6,501 sats/);
  assert.match(t, /Queued since height 901/);
  assert.match(t, /Carried over at the cutover 500 sats/);
  assert.match(t, /Oldest-queue rank #1/);
  assert.match(t, /Next block height 1,000/);
  assert.equal(count(m, "worker-row"), 1);
  assert.equal(count(m, "payout-row"), 1);
  assert.match(t, /provisional/);
  assert.match(t, /not yet \(100 needed\)/);
  // A null hashrate is unknown, not zero.
  assert.match(t, /Hashrate 24 h unknown/);
  assert.match(t, /Earned, last 24 h 9,000 sats/);
  assert.match(t, /Pool finds a block about every 210 years/);
  assert.match(t, /paid only when the pool finds a block/);
});

test("miner detail: no share seen on this node reads as such, not as unknown", () => {
  need();
  // An address mining on another node: this node answers, and has seen nothing from it.
  const miner = fixture("node-pool-miner.json");
  miner.summary.last_share_at = null;
  miner.workers = miner.workers.map((w) => ({ ...w, last_share_at: null }));
  const t = text(
    html(views.MinerDetailView, {
      address: "bcrt1qminerone000000000000000000000000000",
      ledger: fixture("node-pool-ledger.json"),
      miner,
      now: NOW,
    }),
  );
  assert.match(t, /Last share none on this node/);
  assert.doesNotMatch(t, /Last share unknown/);
});

test("miner detail: a failed API shows unavailable for both halves", () => {
  need();
  const t = text(
    html(views.MinerDetailView, {
      address: "bcrt1qx",
      ledgerError: FAILED,
      minerError: new Error("API error: 503"),
      now: NOW,
    }),
  );
  assert.match(t, /Miner statistics unavailable/);
  assert.match(t, /Ledger unavailable/);
  assert.doesNotMatch(t, /Carried over/);
  assert.match(t, /Payouts unavailable/);
  assert.doesNotMatch(t, /Balance owed/);
  assertNothingHealthy(t);
});

// ---------------------------------------------------------------- blocks

test("blocks: recent pool blocks with payouts, treasury change and settlement", () => {
  need();
  const m = html(views.BlocksView, { status: fixture("node-pool-status.json"), now: NOW });
  const t = text(m);
  assert.equal(count(m, "block-row"), 2);
  assert.equal(count(m, "provisional"), 1);
  assert.match(t, /310,936,500 sats/); // treasury change of block 960
  assert.match(t, /312,499,000 sats/); // its treasury total
  assert.match(t, /1,562,500 sats/); // S\/200
  assert.match(t, /Block 960: 1 payout\(s\)/);
  assert.match(t, /State caught up/);
  assert.match(t, /Matched since start 1/);
});

test("blocks: no block yet says so", () => {
  need();
  const status = fixture("node-pool-status.json");
  status.recent_blocks = [];
  const m = html(views.BlocksView, { status, now: NOW });
  assert.equal(count(m, "no-blocks"), 1);
});

test("blocks: a failed API shows unavailable", () => {
  need();
  const m = html(views.BlocksView, { statusError: FAILED, now: NOW });
  const t = text(m);
  assert.match(t, /Node pool status unavailable/);
  assert.equal(count(m, "block-row"), 0);
  assertNothingHealthy(t);
});

// ---------------------------------------------------------------- share chain

test("share chain: tip, sync, relay counters, checkpoints and pruning", () => {
  need();
  const m = html(views.ShareChainView, { status: fixture("node-pool-status.json"), now: NOW });
  const t = text(m);
  assert.match(t, /Anchor height 7/);
  assert.match(t, /fetching batches for 1 anchor\(s\)/);
  assert.match(t, /Network shares accepted 40/);
  assert.match(t, /Reorgs 1/);
  assert.match(t, /288 Bitcoin blocks below the tip/);
  assert.match(t, /on: batches below the older checkpoint are deleted/);
  assert.equal(count(m, "checkpoint-row"), 1);
});

test("share chain: an older pool_sv2 without counters or retention says not reported", () => {
  need();
  const status = fixture("node-pool-status.json");
  delete status.relay_stats;
  delete status.retention;
  const t = text(html(views.ShareChainView, { status, now: NOW }));
  assert.match(t, /Relay counters unknown: not reported by this pool_sv2/);
  assert.match(t, /Retention unknown: not reported by this pool_sv2/);
  assert.doesNotMatch(t, /Reorgs 0/);
});

test("share chain: a failed API shows unavailable", () => {
  need();
  const t = text(html(views.ShareChainView, { statusError: FAILED, now: NOW }));
  assert.match(t, /Node pool status unavailable/);
  assert.doesNotMatch(t, /Anchor height/);
});

// ---------------------------------------------------------------- settings

test("settings: the fee address is shown read-only, unknown when the API failed", () => {
  need();
  const ok = text(html(views.NodePoolSettingsView, { status: fixture("node-pool-status.json") }));
  assert.match(ok, /bcrt1qfeeaddressexample0000000000000000000/);
  assert.match(ok, /--fee-address/);
  const okMarkup = html(views.NodePoolSettingsView, { status: fixture("node-pool-status.json") });
  assert.doesNotMatch(okMarkup, /<input/);
  const bad = text(html(views.NodePoolSettingsView, { statusError: FAILED }));
  assert.match(bad, /Node pool status unavailable/);
  assert.match(bad, /Fee address \(finder output\) unknown/);
});

// ---------------------------------------------------------------- API client

test("api: the status call goes through the proxy and a 503 is a thrown error", async () => {
  need();
  const calls = [];
  const realFetch = global.fetch;
  global.fetch = async (url) => {
    calls.push(String(url));
    return new Response(JSON.stringify({ error: "the node pool service (pool_sv2) did not answer: refused" }), {
      status: 503,
      headers: { "content-type": "application/json" },
    });
  };
  try {
    await assert.rejects(views.api.getNodePoolStatus(), /pool_sv2\) did not answer: refused/);
    await assert.rejects(views.api.getNodePoolLedger("bc1q x/y"), /did not answer/);
  } finally {
    global.fetch = realFetch;
  }
  assert.equal(calls[0], "http://localhost:3000/api/proxy/api/v1/node-pool/status");
  assert.equal(calls[1], "http://localhost:3000/api/proxy/api/v1/ledger/bc1q%20x%2Fy");
});

// ---------------------------------------------------------------- helpers

test("helpers: unknown is never zero", () => {
  need();
  const v = views.view;
  assert.equal(v.fmtSats(null), "unknown");
  assert.equal(v.fmtSats(0), "0 sats");
  assert.equal(v.fmtInt(undefined), "unknown");
  assert.equal(v.fmtHashrate(null), "unknown");
  assert.equal(v.bestRate({ "15m": null, "1h": null, "24h": null }), null);
  assert.equal(v.waitLabel({ known: true, seconds: 90000, blocks_needed: 2 }), "about 1d 1h, 2 pool blocks");
  assert.equal(v.waitLabel(undefined), "unknown");
  assert.equal(v.nodePoolHealth(undefined, undefined).level, "unknown");
});

// ---------------------------------------------------------------- fixtures match pool_sv2

test("fixtures: every key of the sample JSON is a field pool_sv2 serialises", () => {
  const rs = ["node_pool_api.rs", "node_pool_miner_api.rs"]
    .map((f) => fs.readFileSync(path.join(__dirname, "..", "..", "bins", "pool-sv2", "src", "lib", f), "utf8"))
    .join("\n");
  const fields = new Set();
  for (const m of rs.matchAll(/^\s*pub (\w+):/gm)) fields.add(m[1]);
  for (const m of rs.matchAll(/rename = "([^"]+)"/g)) fields.add(m[1]);
  const free = new Set(["reject_reasons"]); // a map: its keys are reason codes, not fields
  const missing = [];
  const walk = (v, where, parent) => {
    if (Array.isArray(v)) return v.forEach((x) => walk(x, where, parent));
    if (v && typeof v === "object") {
      for (const [k, x] of Object.entries(v)) {
        if (free.has(parent)) continue;
        if (!fields.has(k)) missing.push(`${where}.${k}`);
        walk(x, `${where}.${k}`, k);
      }
    }
  };
  for (const f of ["node-pool-status.json", "node-pool-ledger.json", "node-pool-miner.json"]) walk(fixture(f), f, "");
  assert.deepEqual(missing, []);
});
