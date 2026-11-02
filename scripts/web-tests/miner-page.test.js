// Renders the miner page (ghost-web/miner.js) from sample API answers, and from failed ones,
// under plain node: no browser, no dependencies. Run by scripts/check-miner-page.sh.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const web = path.join(__dirname, '..', '..', 'ghost-web');
const MP = require(path.join(web, 'miner.js'));

const ADDR = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
const NOW = 1800000000;
const T0 = NOW - (NOW % 300) - 287 * 300;
const buckets = Array.from({ length: 288 }, (_, i) => T0 + i * 300);
const known = (v) => buckets.map((_, i) => (i < 276 ? null : v));

let failures = 0;
function test(name, f) {
  try { f(); console.log('ok   ' + name); } catch (e) { failures++; console.log('FAIL ' + name + '\n     ' + e.message); }
}

function ledger() {
  return {
    address: ADDR, network: 'mainnet', script_hex: '0014', known: true, message: null,
    balance: { units: '27917287424000', sats: 6500 }, queue_since: 901, min_payout_sats: 1000, units_per_sat: 4294967296,
    queue: {
      next_block_height: 1000, snapshot_height: 980, parent_anchor: 'aa', owed: { units: '1', sats: 6500 },
      eligible: true, eligible_count: 3, is_top: false, age_rank: 2, size_rank: 2,
      next_block: [{ slot_class: 3, oldest_slots: 2, in_oldest: true, sats: 6500 }, { slot_class: 500, oldest_slots: 250, in_oldest: true, sats: 6500 }]
    },
    queue_unavailable: null, recent_shares: [],
    payouts: [{ height: 960, block_hash: 'b2'.repeat(32), sats: 1000, units: '1', status: 'provisional', confirmations: 40, mature: false, applied_at: 2300 }],
    settlement: { caught_up: true, synced_height: 999, bitcoin_tip: 999, provisional_blocks: 1 }
  };
}

function minerBody(node, workers, wait) {
  return {
    address: ADDR, network: 'mainnet', script_hex: '0014', node_id: node + 'id', generated_at: NOW, collecting_since: NOW - 3600,
    summary: {
      workers: workers.length, online: workers.filter((w) => w.status === 'online').length,
      idle: workers.filter((w) => w.status === 'idle').length, offline: workers.filter((w) => w.status === 'offline').length,
      hashrate_hs: { '15m': 7e14, '1h': 7.1e14, '24h': 7.1e14 },
      shares_24h: { accepted: 600, stale: 1, rejected: 2, reject_reasons: { 'duplicate-share': 2 } }, last_share_at: NOW - 6
    },
    workers,
    expected_wait: wait || { known: false, reason: 'the pool has found 2 blocks in the last 30 days; at least 3 are needed to estimate how often it finds one', seconds: null, blocks_needed: null, pool_blocks_counted: 2, assumptions: [] }
  };
}

function worker(name, status, extra) {
  return Object.assign({
    name, status, last_share_at: NOW - 6, last_submit_at: NOW - 6,
    hashrate_hs: { '15m': 7e14, '1h': 7.1e14, '24h': 7.1e14 },
    shares_24h: { accepted: 600, stale: 1, rejected: 2, reject_reasons: { 'duplicate-share': 2 } },
    slot_class: 9, firmware_warning: 'Stock Antminer firmware carries at most 9 miner outputs',
    connections: [{ downstream_id: 4, channel_id: 1, kind: 'extended', slot_class: 9, model: 'Stock Antminer', firmware: '2.0.0', ceiling_class: 9, settled: true, firmware_warning: 'x' }]
  }, extra || {});
}

function historyBody(node, workers) {
  const series = (h) => ({ hashrate_hs: known(h), accepted: known(5), stale: known(0), rejected: known(1) });
  return {
    address: ADDR, network: 'mainnet', node_id: node, window: '24h', bucket_seconds: 300, generated_at: NOW, collecting_since: NOW - 3600,
    buckets,
    total: series(7e14),
    workers: workers.map((n) => ({ name: n, series: series(7e14 / workers.length) })),
    workers_omitted: 0, reject_reasons: { 'duplicate-share': 2 },
    balance: {
      start_sats: 0, end_sats: buckets.map((_, i) => (i < 100 ? 0 : 6500)), credited_sats: buckets.map((_, i) => (i === 100 ? 9000 : 0)),
      paid_sats: buckets.map((_, i) => (i === 150 ? 2500 : 0)),
      payouts: [{ time: T0 + 150 * 300 + 10, height: 960, sats: 2500, block_hash: 'b2'.repeat(32) }], time_basis: 'x'
    }
  };
}

const LISTED = ['203.0.113.10', '203.0.113.20'];

function goodState(query) {
  const miners = MP.mergeMiners([
    { node: '203.0.113.10', ok: true, status: 200, body: minerBody('203.0.113.10', [worker('rig1', 'online'), worker('rig2', 'offline', { slot_class: null, firmware_warning: null, connections: [] })]) },
    { node: '203.0.113.20', ok: true, status: 200, body: minerBody('203.0.113.20', [worker('rig2', 'online', { slot_class: 500, firmware_warning: null })]) },
    { node: '203.0.113.30', ok: false, status: 503, body: { error: 'down' } },
    { node: '203.0.113.40', ok: false, status: 0, body: null }
  ]);
  const history = MP.mergeHistories([
    { node: '203.0.113.10', ok: true, status: 200, body: historyBody('203.0.113.10', ['rig1']) },
    { node: '203.0.113.20', ok: true, status: 200, body: historyBody('203.0.113.20', ['rig2']) },
    { node: '203.0.113.30', ok: false, status: 503, body: null }
  ]);
  return { query: query || MP.parseQuery('?address=' + ADDR), ledger: { ok: true, status: 200, body: ledger(), node: '203.0.113.10' }, miners, history, now: NOW };
}

function noJunk(html, where) {
  for (const bad of ['NaN', 'undefined', '[object Object]', 'Infinity']) {
    assert(!html.includes(bad), where + ' contains ' + bad);
  }
}

test('the URL: ?address, ?id=address.worker and the window', () => {
  assert.deepStrictEqual(MP.parseQuery('?address=' + ADDR), { address: ADDR, worker: '', window: '24h' });
  assert.deepStrictEqual(MP.parseQuery('?id=' + ADDR + '.rig1'), { address: ADDR, worker: 'rig1', window: '24h' });
  assert.deepStrictEqual(MP.parseQuery('?address=' + ADDR + '&worker=a&window=7d'), { address: ADDR, worker: 'a', window: '7d' });
  assert.strictEqual(MP.parseQuery('?address=x&window=1y').window, '24h');
  assert.strictEqual(MP.queryString({ address: ADDR, worker: 'rig 1', window: '30d' }), '?address=' + ADDR + '&worker=rig%201&window=30d');
});

test('workers from every node are merged, tagged with their node, offline duplicates dropped', () => {
  const m = goodState().miners;
  assert.deepStrictEqual(m.answered, ['203.0.113.10', '203.0.113.20']);
  assert.deepStrictEqual(m.failed, ['203.0.113.30', '203.0.113.40']);
  assert.deepStrictEqual(m.workers.map((w) => w.name + '@' + w.node + ':' + w.status), ['rig1@203.0.113.10:online', 'rig2@203.0.113.20:online']);
  assert.strictEqual(m.summary.shares_24h.accepted, 1200);
  assert.strictEqual(m.summary.hashrate_hs['1h'], 2 * 7.1e14);
  assert.strictEqual(m.wait.known, false);
});

test('histories are summed per bucket and unknown stays unknown', () => {
  const h = goodState().history;
  assert.deepStrictEqual(h.answered, ['203.0.113.10', '203.0.113.20']);
  assert.strictEqual(h.total.accepted[0], null, 'before collection: null, not 0');
  assert.strictEqual(h.total.accepted[287], 10);
  assert.strictEqual(h.total.hashrate_hs[287], 1.4e15);
  assert.deepStrictEqual(Object.keys(h.workers).sort(), ['rig1', 'rig2']);
  assert.strictEqual(h.reasons['duplicate-share'], 4);
  assert.strictEqual(h.balance.end_sats[287], 6500, 'balance from one node, not summed');
});

test('the page renders every section from sample answers', () => {
  const out = MP.renderAll(goodState(), 640);
  for (const k of Object.keys(out)) noJunk(out[k], k);
  assert(out.tiles.includes('6,500'), 'balance tile');
  assert(out.tiles.includes('1.42<span class="unit">PH/s'), 'hashrate tile: ' + out.tiles);
  assert(out.tiles.includes('unknown'), 'the wait is unknown, said so');
  assert(out.workers.includes('rig1') && out.workers.includes('node 203.0.113.20'));
  assert(out.workers.includes('Stock Antminer firmware carries at most 9'), 'firmware warning');
  assert(out.workers.includes('stock Antminer S19'), 'slot class in words');
  assert(out.workers.includes('Not answering: 203.0.113.30, 203.0.113.40'));
  assert(out.hashrate.includes('<svg') && out.hashrate.includes('class="mpc-line s1"'));
  assert(out.hashrate.includes('not collected yet'), 'the unknown stretch is marked');
  assert(out.shares.includes('mpc-bar s1') && out.shares.includes('duplicate-share'));
  assert(out.balance.includes('mpc-marker'), 'payout marker');
  assert(out.payouts.includes('https://mempool.space/block/' + 'b2'.repeat(32)), 'block link');
  assert(out.queue.includes('#2 in the oldest-first queue'));
  assert(out.queue.includes('Expected wait: unknown') && out.queue.includes('2 blocks in the last 30 days'));
  assert(out.settlement.includes('caught up'));
});

test('a known wait shows the estimate with its assumptions', () => {
  const st = goodState();
  st.miners.wait = { known: true, seconds: 3 * 86400, blocks_needed: 2, assumptions: ['the pool keeps finding blocks at its recent rate'] };
  const out = MP.renderAll(st, 640);
  assert(out.tiles.includes('~3.0 days'));
  assert(out.queue.includes('about 3.0 days') && out.queue.includes('2 pool blocks') && out.queue.includes('recent rate'));
});

test('a selected worker gets its own chart and row highlight', () => {
  const st = goodState(MP.parseQuery('?id=' + ADDR + '.rig2'));
  const out = MP.renderAll(st, 640);
  assert(out.hashrate.includes('worker rig2'));
  assert(out.workers.includes('mpw-row mpw-selected'));
  assert(out.header.includes('.rig2'));
  assert(MP.tipHtml(st, 'shares', 287).includes('5 accepted'));
  assert(MP.tipHtml(st, 'hashrate', 0).includes('not collected'));
  assert(MP.tipHtml(st, 'balance', 287).includes('6,500'));
});

test('a failed API shows unavailable everywhere and invents nothing', () => {
  const st = {
    query: MP.parseQuery('?address=' + ADDR),
    ledger: { ok: false },
    miners: MP.mergeMiners(LISTED.map((n) => ({ node: n, ok: false, status: 0, body: null }))),
    history: MP.mergeHistories(LISTED.map((n) => ({ node: n, ok: false, status: 503, body: { error: 'x' } }))),
    now: NOW
  };
  const out = MP.renderAll(st, 640);
  for (const k of Object.keys(out)) noJunk(out[k], k);
  assert.strictEqual((out.tiles.match(/>unavailable</g) || []).length, 6, out.tiles);
  assert(!/\d[\d,]* ?(sats|H\/s|PH\/s|TH\/s)/.test(out.tiles), 'no numbers in the tiles');
  for (const k of ['workers', 'hashrate', 'shares', 'balance', 'queue', 'payouts']) {
    assert(/unavailable/.test(out[k]), k + ' says unavailable');
    assert(!out[k].includes('<svg'), k + ' draws no chart');
  }
  assert(out.header.includes('ledger unavailable'));
});

test('a node pool that has seen nothing yet says so plainly', () => {
  const st = goodState();
  st.ledger.body = Object.assign(ledger(), { known: false, message: 'This address has no balance', balance: { units: '0', sats: 0 }, payouts: [] });
  st.miners = MP.mergeMiners([{ node: '203.0.113.10', ok: true, status: 200, body: minerBody('203.0.113.10', []) }]);
  st.history = MP.mergeHistories([{ node: '203.0.113.10', ok: true, status: 200, body: Object.assign(historyBody('203.0.113.10', []), {
    total: { hashrate_hs: buckets.map(() => null), accepted: buckets.map(() => null), stale: buckets.map(() => null), rejected: buckets.map(() => null) }
  }) }]);
  const out = MP.renderAll(st, 360);
  assert(out.workers.includes('No node has seen a worker'));
  assert(out.payouts.includes('No payouts yet'));
  assert(out.hashrate.includes('No shares in this window'));
  assert(out.header.includes('not on the ledger yet'));
});

test('the nodes asked come from node-list.json, never a fixed list', () => {
  const list = { schema: 'ghost-audit/node-list/v1', nodes: [
    { host: '203.0.113.20' }, { host: '2a01:4f8::1' }, { host: '203.0.113.10' }, { host: '203.0.113.10' },
    { host: '../../admin' }, { host: 'evil.example' }, { host: null }, {}
  ] };
  assert.deepStrictEqual(MP.nodesFromList(list), ['203.0.113.10', '203.0.113.20', '2a01:4f8::1'],
    'listed IP hosts only, sorted, once each');
  for (const bad of [null, undefined, {}, { nodes: null }, { nodes: [] }, 'x', { placeholder: true, nodes: [] }]) {
    assert.deepStrictEqual(MP.nodesFromList(bad), [], 'no list means no nodes: ' + JSON.stringify(bad));
  }
  assert(!('NODES' in MP), 'no hard-coded node list is exported');
  const src = fs.readFileSync(path.join(web, 'miner.js'), 'utf8');
  assert(!/\bvm[1-8]\b/.test(src), 'miner.js names no old-fleet node');
});

test('with no node listed the page says so and asks nobody', () => {
  const out = MP.renderAll({ query: MP.parseQuery('?address=' + ADDR), noNodes: true, ledger: null, miners: null, history: null, now: NOW }, 640);
  for (const k of ['header', 'workers', 'hashrate', 'shares', 'balance', 'queue', 'payouts']) {
    assert(out[k].includes('No node is listed yet'), k + ' says no node is listed');
  }
  for (const k of Object.keys(out)) assert(!/NaN|undefined/.test(out[k]), k + ' invents nothing');
});

test('charts fit a phone and only link blocks on mainnet', () => {
  const svg = MP.chartSvg({ id: 'x', buckets: [1, 2, 3], bucketSeconds: 300, kind: 'line', series: [{ values: [1, null, 3], cls: 's1' }], yFmt: String, width: 200 });
  assert(svg.includes('width="280"'), 'a minimum width');
  assert((svg.match(/M/g) || []).length === 2, 'a null breaks the line');
  assert.strictEqual(MP.blockUrl('regtest', 'ab'), null);
  assert.strictEqual(MP.blockUrl('mainnet', 'ab'), 'https://mempool.space/block/ab');
  assert.strictEqual(MP.fmtDuration(130 * 86400), '4.3 months');
});

test('miner.html has a container for every section miner.js renders', () => {
  const html = fs.readFileSync(path.join(web, 'miner.html'), 'utf8');
  for (const k of Object.keys(MP.renderAll(goodState(), 640))) {
    assert(html.includes('id="mp-' + k + '"'), 'miner.html lacks #mp-' + k);
  }
  for (const id of ['lookup-form', 'lookup-input', 'error-msg', 'miner-body', 'mp-updated', 'mp-tip', 'rl-notice']) {
    assert(html.includes('id="' + id + '"'), 'miner.html lacks #' + id);
  }
  assert(html.includes('NOT READY'), 'the banner stays');
  assert(html.includes('src="/miner.js'));
  assert(!/<script[^>]+src="https?:/.test(html), 'no external scripts');
});

if (failures) { console.log(failures + ' failed'); process.exit(1); }
console.log('all passed');
