"use strict";

// The Ghost Pool pages, rendered from the REAL view components with sample JSON shaped as
// pool_sv2 serves it (the module docs of `bins/pool-sv2/src/lib/solo_api.rs`), and from a failed
// API. What must hold: every page shows what the node reported, and when the pool service does
// not answer, nothing reads as healthy or as zero.

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs");

const tsx = require("./helpers/tsx.js");

const FIX = path.join(__dirname, "fixtures");
const fixture = (name) => JSON.parse(fs.readFileSync(path.join(FIX, name), "utf8"));
const NOW = 1_800_000_000;
const ADDR = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

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
      ...tsx.load("@/components/pool/OverviewView"),
      ...tsx.load("@/components/pool/MinersView"),
      ...tsx.load("@/components/pool/MinerDetailView"),
      ...tsx.load("@/components/pool/BlocksView"),
      ...tsx.load("@/components/pool/PoolSettingsView"),
      view: tsx.load("@/lib/pool/view"),
      api: tsx.load("@/lib/api/pool"),
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
  return markup
    .replace(/<[^>]+>/g, " ")
    .replace(/&#x27;/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/\s+/g, " ");
}

function count(markup, testid) {
  return (markup.match(new RegExp(`data-testid="${testid}"`, "g")) || []).length;
}

const FAILED = new Error("the pool service (pool_sv2) did not answer: connection refused");

/** Words a failed page must never show for a value it does not have. */
function assertNothingHealthy(t) {
  assert.doesNotMatch(t, /\bHealthy\b/);
  assert.doesNotMatch(t, /\b0 H\/s\b/);
  assert.doesNotMatch(t, /\b0 sats\b/);
  assert.doesNotMatch(t, /\bNaN\b|undefined|\[object Object\]/);
}

// ---------------------------------------------------------------- the API client

test("the API client asks the new routes, the address encoded", async () => {
  need();
  const seen = [];
  const orig = global.fetch;
  global.fetch = async (url) => {
    seen.push(String(url));
    return { ok: true, status: 200, json: async () => ({}), headers: { get: () => "application/json" } };
  };
  try {
    await views.api.getPoolStatus().catch(() => {});
    await views.api.getPoolMiner("bc1q/../x").catch(() => {});
    await views.api.getPoolMinerHistory(ADDR, "7d").catch(() => {});
    await views.api.getPoolMinerList().catch(() => {});
  } finally {
    global.fetch = orig;
  }
  assert.ok(seen.some((u) => u.endsWith("/api/proxy/api/v1/pool/status")), seen.join(" "));
  assert.ok(seen.some((u) => u.endsWith("/api/proxy/api/v1/miner/bc1q%2F..%2Fx")), seen.join(" "));
  assert.ok(seen.some((u) => u.endsWith(`/api/proxy/api/v1/miner/${ADDR}/history?window=7d`)), seen.join(" "));
  assert.ok(seen.some((u) => u.endsWith("/api/proxy/api/v1/pool/miners")), seen.join(" "));
  assert.ok(!seen.some((u) => /ledger|node-pool/.test(u)), "no removed route is asked");
});

// ---------------------------------------------------------------- overview

test("overview: renders the status, health checks, the payout rule and the other node", () => {
  need();
  const m = html(views.OverviewView, {
    status: fixture("pool-status.json"),
    node: { is_synced: true, block_height: 974899, sync_height: 974899, version: "1.0.0", uptime_seconds: 3700 },
  });
  const t = text(m);
  assert.match(t, /Ghost Pool health Healthy/);
  assert.match(t, /Templates building jobs at height 974,900/);
  assert.match(t, /Backup submission found blocks are also sent to http:\/\/10\.0\.0\.2:8332/);
  assert.match(t, /Pool hashrate, 1 hour 290\.00 TH\/s/);
  assert.match(t, /Miners connected 3/);
  assert.match(t, /Worker connections 5/);
  assert.match(t, /Best share ever 99\.00 G/);
  assert.match(t, /Blocks found 2/);
  assert.match(t, /Latest height 974,800/);
  assert.match(t, /Latest paid its miner 3\.1099 BTC/);
  assert.match(t, /Network difficulty 110\.00 T/);
  assert.match(t, /Synced/);
  assert.match(t, /Uptime 1h 1m/);
  // 1.1e14 * 2^32 / 2.9e14 s, about 51 years.
  assert.match(t, /This node finds a block every ~5\d years/);
  assert.match(t, /http:\/\/10\.0\.0\.2:8332 Reachable reachable, height 974,899, checked 30s ago · last block: accepted/);
  assert.match(t, /Treasury address bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k/);
  assert.match(t, /Treasury share 0\.5% of the subsidy/);
  assert.match(t, /Next block: treasury 0\.015625 BTC/);
  assert.match(t, /Next block: miner, before fees 3\.109375 BTC/);
  assert.match(t, /Transaction fees go to the miner who found the block/);
  assert.match(t, /Ports SV1 3333, 4444 · SV2 34255/);
  assert.match(t, /SV2 authority key 9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72/);
  assert.doesNotMatch(t, /share chain|ledger|slot class|genesis|relay/i);
});

test("overview: no other node, no template, a failed coinbase check: each is flagged", () => {
  need();
  const s = fixture("pool-status.json");
  s.submit_nodes = [];
  s.bitcoin.job_height = null;
  s.blocks_found[1].check = "treasury output 1562499 != 1562500";
  const t = text(html(views.OverviewView, { status: s }));
  assert.match(t, /Ghost Pool health Unhealthy/);
  assert.match(t, /Templates no template yet: miners have no work/);
  assert.match(t, /Backup submission no other node configured/);
  assert.match(t, /Coinbase check 1 found block\(s\) failed the post-submit coinbase check: treasury output 1562499 != 1562500/);
  assert.match(t, /None configured\. A block found here reaches the network through this node only/);
});

test("overview: another node refused a block: needs attention", () => {
  need();
  const s = fixture("pool-status.json");
  s.blocks_found[1].submitted = [{ node: "http://10.0.0.2:8332", result: "connection refused" }];
  const t = text(html(views.OverviewView, { status: s }));
  assert.match(t, /Needs attention/);
  assert.match(t, /Other node 1 found block\(s\) were not accepted by another node/);
  assert.match(t, /last block: connection refused/);
});

test("overview: an unreachable other node needs attention and says why", () => {
  need();
  const s = fixture("pool-status.json");
  s.submit_nodes = [
    { node: "http://10.0.0.2:8332", reachable: false, last_checked_at: NOW - 5, last_ok_at: NOW - 3600, height: 974890, error: "connection refused" },
  ];
  const t = text(html(views.OverviewView, { status: s, now: NOW }));
  assert.match(t, /Needs attention/);
  assert.match(t, /Other node reachable http:\/\/10\.0\.0\.2:8332 did not answer the last check: connection refused/);
  assert.match(t, /Unreachable NOT reachable: connection refused \(last answered 1h 0m ago\)/);
});

test("overview: an older pool_sv2's bare node names read as not checked, never reachable", () => {
  need();
  const s = fixture("pool-status.json");
  s.submit_nodes = ["http://10.0.0.2:8332"];
  delete s.ports.sv2_authority_public_key;
  const t = text(html(views.OverviewView, { status: s }));
  assert.match(t, /Backup submission found blocks are also sent to http:\/\/10\.0\.0\.2:8332/);
  assert.match(t, /Not checked not checked yet/);
  assert.doesNotMatch(t, /Reachable reachable/);
  assert.match(t, /SV2 authority key not reported by this pool_sv2/);
});

test("overview: a hashrate or tip the pool has not measured is unknown, never zero", () => {
  need();
  const s = fixture("pool-status.json");
  s.pool_hashrate_hs = { "15m": null, "1h": null, "24h": null };
  s.bitcoin = { tip_height: null, tip_hash: null, job_height: null, network_difficulty: null };
  s.best_share = { ever: 0, "24h": 0 };
  s.blocks_found = [];
  const t = text(html(views.OverviewView, { status: s }));
  assert.match(t, /Pool hashrate, 1 hour unknown/);
  assert.match(t, /This node finds a block every unknown: needs hashrate and a tip/);
  assert.match(t, /Best share ever none yet/);
  assert.match(t, /Latest none yet/);
  assert.match(t, /Blocks found 0/, "a count of found blocks is a real zero");
  assert.doesNotMatch(t, /0 H\/s/);
});

test("overview: the pool service down: unavailable, nothing healthy, nothing zero", () => {
  need();
  const t = text(html(views.OverviewView, { statusError: FAILED, nodeError: FAILED }));
  assert.match(t, /Pool status unavailable/);
  assert.match(t, /connection refused/);
  assert.match(t, /Unhealthy/);
  assertNothingHealthy(t);
  assert.doesNotMatch(t, /Blocks found 0/);
});

// ---------------------------------------------------------------- miners

test("miners: the active list names every connected address with its workers and hashrate", () => {
  need();
  const status = fixture("pool-status.json");
  const list = fixture("pool-miners.json");
  const addresses = views.view.addressesFromBlocks(status.blocks_found);
  const m = html(views.MinersView, {
    status,
    list,
    addresses,
    miners: { [ADDR]: { data: fixture("pool-miner.json") } },
    now: NOW,
  });
  assert.equal(count(m, "active-miner-row"), 2);
  // The finder already in the active list is not repeated below; the other finder is.
  assert.equal(count(m, "miner-row"), 1);
  const t = text(m);
  assert.match(t, /2 payout address\(es\) connected or seen in the last 24 hours/);
  assert.match(t, /bc1p5d7r…usxg3297 yes 2 \/ 1 \/ 0 180\.00 TH\/s 1,500 99\.00 G 5s ago 1/);
  assert.match(t, /bc1qar0s…zzwf5mdq no 0 \/ 0 \/ 1 2\.00 TH\/s 40 3\.00 M 13h 53m ago 0/);
  assert.match(m, /href="\/miners\/bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"/);
  assert.match(t, /never shows it/);
  assert.doesNotMatch(t, /No address to list|only block finders/);
});

test("miners: the active list unavailable says so; empty says none", () => {
  need();
  let t = text(html(views.MinersView, { status: fixture("pool-status.json"), listError: FAILED, addresses: [], miners: {}, now: NOW }));
  assert.match(t, /Miner list unavailable/);
  assertNothingHealthy(t);
  const list = fixture("pool-miners.json");
  list.miners = [];
  t = text(html(views.MinersView, { status: fixture("pool-status.json"), list, addresses: [], miners: {}, now: NOW }));
  assert.match(t, /No miner is connected, and none sent a share in the last 24 hours/);
});

test("miners: lists the addresses with their answers; a failed one says unavailable", () => {
  need();
  const status = fixture("pool-status.json");
  const addresses = views.view.addressesFromBlocks(status.blocks_found);
  assert.deepEqual(addresses, ["bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297", ADDR], "newest finder first, once each");
  const m = html(views.MinersView, {
    status,
    addresses,
    miners: { [ADDR]: { data: fixture("pool-miner.json") }, [addresses[0]]: { error: FAILED } },
    now: NOW,
  });
  assert.equal(count(m, "miner-row"), 2);
  const t = text(m);
  assert.match(t, /Miners \(payout addresses\) 3/);
  assert.match(t, /Worker connections 5/);
  assert.match(t, /1 of 2/);
  assert.match(t, /110\.00 TH\/s/);
  assert.match(t, /812/);
  assert.match(t, /4\.10 G/);
  assert.match(t, /~13\d years|~136 years/);
  assert.match(t, /unavailable/);
  assert.match(m, new RegExp(`href="/miners/${ADDR}"`));
});

test("miners: nothing to list yet, and the pool down", () => {
  need();
  let t = text(html(views.MinersView, { status: fixture("pool-status.json"), addresses: [], miners: {}, now: NOW }));
  assert.match(t, /No other address to list/);
  t = text(html(views.MinersView, { statusError: FAILED, addresses: [], miners: {}, now: NOW }));
  assert.match(t, /Pool status unavailable/);
  assertNothingHealthy(t);
});

// ---------------------------------------------------------------- miner detail

test("miner detail: summary, odds, workers, history and blocks", () => {
  need();
  const m = html(views.MinerDetailView, {
    address: ADDR,
    miner: fixture("pool-miner.json"),
    history: fixture("pool-history.json"),
    now: NOW,
  });
  const t = text(m);
  assert.match(t, /Workers online 1 of 2/);
  assert.match(t, /Idle \/ offline 0 \/ 1/);
  assert.match(t, /Hashrate, 15 min 120\.00 TH\/s/);
  assert.match(t, /Shares, 24 hours 812 accepted · 3 stale · 1 rejected/);
  assert.match(t, /Last share 10s ago/);
  assert.match(t, /Best share ever 4\.10 G/);
  assert.match(t, /Blocks found 1/);
  assert.match(t, /Rejected, by reason: duplicate-share 1/);
  // seconds = 2^32: about 136 years.
  assert.match(t, /Average wait ~136 years/);
  assert.match(t, /Chance within a day about 1 in 50,000/);
  assert.match(t, /Chance within a year about 1 in 137/);
  assert.match(t, /Hashrate assumed 110\.00 TH\/s \(1h\)/);
  assert.equal(count(m, "worker-row"), 2);
  assert.match(t, /rig2 offline/);
  assert.match(t, /extended/);
  assert.match(t, /Accepted shares 60/);
  assert.match(t, /Rejected shares 12/);
  assert.match(t, /Best share in the window 100\.00 M/);
  assert.match(t, /974,000/);
  assert.match(t, /3\.11 BTC/);
  assert.match(t, /http:\/\/10\.0\.0\.2:8332: duplicate/);
});

test("miner detail: no estimate says why; failures say unavailable", () => {
  need();
  const miner = fixture("pool-miner.json");
  miner.expected_time_to_block = {
    known: false, seconds: null, hashrate_hs: null, hashrate_window: null, network_difficulty: null,
    reason: "the pool has no Bitcoin tip yet, so the difficulty is not known",
  };
  let t = text(html(views.MinerDetailView, { address: ADDR, miner, historyError: FAILED, now: NOW }));
  assert.match(t, /Average wait unknown: the pool has no Bitcoin tip yet/);
  assert.match(t, /Chance within a day unknown/);
  assert.match(t, /History unavailable/);
  t = text(html(views.MinerDetailView, { address: ADDR, minerError: FAILED, now: NOW }));
  assert.match(t, /Miner unavailable/);
  assertNothingHealthy(t);
});

// ---------------------------------------------------------------- blocks

test("blocks: newest first, with what each paid, its check and the other node's answer", () => {
  need();
  const m = html(views.BlocksView, { status: fixture("pool-status.json"), now: NOW });
  assert.equal(count(m, "block-row"), 2);
  const t = text(m);
  assert.ok(t.indexOf("974,800") < t.indexOf("974,000"), "newest first");
  assert.match(t, /3\.1099 BTC/);
  assert.match(t, /0\.015625 BTC/);
  assert.match(t, /http:\/\/10\.0\.0\.2:8332: accepted/);
  assert.match(t, /\.rig1/);
  assert.match(m, /https:\/\/mempool\.space\/block\/000000000000000000022222/);
  assert.match(t, /100 more blocks/);
});

test("blocks: none yet, a check not run yet, and the pool down", () => {
  need();
  const s = fixture("pool-status.json");
  s.blocks_found[0].check = null;
  assert.match(text(html(views.BlocksView, { status: s, now: NOW })), /not checked yet/);
  s.blocks_found = [];
  const m = html(views.BlocksView, { status: s, now: NOW });
  assert.equal(count(m, "no-blocks"), 1);
  assert.match(text(m), /Solo mining is a lottery/);
  const t = text(html(views.BlocksView, { statusError: FAILED, now: NOW }));
  assert.match(t, /Blocks found unavailable/);
  assertNothingHealthy(t);
});

// ---------------------------------------------------------------- settings

test("settings: read-only pool settings from the status", () => {
  need();
  let t = text(html(views.PoolSettingsView, { status: fixture("pool-status.json") }));
  assert.match(t, /SV1 ports 3333, 4444/);
  assert.match(t, /SV2 port 34255/);
  assert.match(t, /Found blocks also sent to http:\/\/10\.0\.0\.2:8332/);
  assert.match(t, /SV2 authority key 9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72/);
  assert.match(t, /\[solo\]/);
  t = text(html(views.PoolSettingsView, { statusError: FAILED, statusLoading: false }));
  assert.match(t, /Pool status unavailable/);
});

// ---------------------------------------------------------------- formatting

test("formatting: BTC is exact, durations and odds read plainly", () => {
  need();
  const v = views.view;
  assert.equal(v.fmtBtc(310937500), "3.109375 BTC");
  assert.equal(v.fmtBtc(100000000), "1.0 BTC");
  assert.equal(v.fmtBtc(null), "unknown");
  assert.equal(v.fmtDifficulty(0), "none yet");
  assert.equal(v.fmtHashrate(null), "unknown");
  assert.equal(v.expectedSeconds(1.1e14, 0), null);
  assert.equal(v.fmtChance(v.chanceWithin(86400, 86400)), "63%");
  assert.equal(v.fmtChance(0.999), "over 99%");
});
