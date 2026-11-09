// Renders the miner page (ghost-web/miner.js) from sample API answers shaped as pool_sv2 serves
// them (bins/pool-sv2/src/lib/solo_api.rs), and from failed ones, under plain node: no browser,
// no dependencies. Every section must show its data, or say "unavailable", and never print NaN,
// undefined or a number it was not given. Run by scripts/check-miner-page.sh.
'use strict';
const assert = require('assert');
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
const strip = (h) => h.replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/\s+/g, ' ').trim();
function noJunk(html, where) {
  for (const bad of ['NaN', 'undefined', '[object Object]', 'Infinity', 'null']) {
    assert(!strip(html).includes(bad), where + ' shows ' + bad + ': ' + strip(html).slice(0, 400));
  }
}

const rates = (h) => ({ '15m': h, '1h': h, '24h': h });
const counts = () => ({ accepted: 600, stale: 1, rejected: 2, reject_reasons: { 'duplicate-share': 2 } });

function worker(name, status, extra) {
  return Object.assign({
    name, status, last_share_at: NOW - 6, last_submit_at: NOW - 6,
    hashrate_hs: rates(7e14), shares_24h: counts(), best_share: { ever: 4.1e9, '24h': 2.2e8 },
    connections: status === 'offline' ? [] : [{ downstream_id: 4, channel_id: 1, kind: 'extended' }]
  }, extra || {});
}

function found(height, hash) {
  return { height, hash: hash.repeat(64 / hash.length), address: ADDR, worker: 'rig1', reward_sats: 311000000, treasury_sats: 1562500,
           fees_sats: 62500, found_at: NOW - 3600, check: 'ok', submitted: [{ node: 'http://10.0.0.2:8332', result: 'accepted' }] };
}

function minerBody(workers, extra) {
  const on = workers.filter((w) => w.status === 'online').length;
  return Object.assign({
    address: ADDR, network: 'mainnet', script_hex: '0014', generated_at: NOW, collecting_since: NOW - 3600,
    summary: {
      workers: workers.length, online: on, idle: workers.filter((w) => w.status === 'idle').length,
      offline: workers.filter((w) => w.status === 'offline').length,
      hashrate_hs: rates(7e14), shares_24h: counts(), last_share_at: NOW - 6,
      best_share: { ever: Math.max(0, ...workers.map((w) => w.best_share.ever)), '24h': Math.max(0, ...workers.map((w) => w.best_share['24h'])) }
    },
    workers,
    blocks_found: [],
    expected_time_to_block: { known: true, seconds: 1.1e14 * 4294967296 / 7e14, hashrate_hs: 7e14, hashrate_window: '1h', network_difficulty: 1.1e14, reason: null }
  }, extra || {});
}

function historyBody(workers) {
  const series = (h) => ({ hashrate_hs: known(h), accepted: known(5), stale: known(0), rejected: known(1), best_share: known(1e8) });
  return {
    address: ADDR, network: 'mainnet', window: '24h', bucket_seconds: 300, generated_at: NOW, collecting_since: NOW - 3600,
    buckets, total: series(7e14), workers: workers.map((n) => ({ name: n, series: series(7e14 / workers.length) })),
    workers_omitted: 0, reject_reasons: { 'duplicate-share': 2 }
  };
}

const NAMES = { a: 'Node A', b: 'Node B', c: 'Node C', d: 'Node D' };

function goodState(query) {
  const miners = MP.mergeMiners([
    { node: 'a', ok: true, status: 200, body: minerBody([worker('rig1', 'online'), worker('rig2', 'offline')], { blocks_found: [found(974000, 'aa')] }) },
    { node: 'b', ok: true, status: 200, body: minerBody([worker('rig2', 'online', { best_share: { ever: 9e9, '24h': 1e8 } })], { blocks_found: [found(974000, 'aa'), found(974500, 'bb')] }) },
    { node: 'c', ok: false, status: 502, body: { error: 'down' } }
  ]);
  const history = MP.mergeHistories([
    { node: 'a', ok: true, status: 200, body: historyBody(['rig1']) },
    { node: 'b', ok: true, status: 200, body: historyBody(['rig2']) },
    { node: 'c', ok: false, status: 502, body: null }
  ]);
  return { query: query || MP.parseQuery('?address=' + ADDR), miners, history, now: NOW, names: NAMES };
}

test('the URL: ?address, ?id=address.worker and the window', () => {
  assert.deepStrictEqual(MP.parseQuery('?address=' + ADDR), { address: ADDR, worker: '', window: '24h' });
  assert.deepStrictEqual(MP.parseQuery('?id=' + ADDR + '.rig1'), { address: ADDR, worker: 'rig1', window: '24h' });
  assert.deepStrictEqual(MP.parseQuery('?address=' + ADDR + '&worker=a&window=7d'), { address: ADDR, worker: 'a', window: '7d' });
  assert.strictEqual(MP.parseQuery('?address=x&window=1y').window, '24h');
  assert.strictEqual(MP.queryString({ address: ADDR, worker: 'rig 1', window: '30d' }), '?address=' + ADDR + '&worker=rig%201&window=30d');
});

test('every node is merged: workers tagged with their node, offline duplicates dropped, blocks once', () => {
  const m = goodState().miners;
  assert.deepStrictEqual([m.answered, m.failed], [['a', 'b'], ['c']]);
  assert.deepStrictEqual(m.workers.map((w) => w.name + '@' + w.node + ':' + w.status), ['rig1@a:online', 'rig2@b:online']);
  assert.strictEqual(m.summary.shares_24h.accepted, 1200);
  assert.strictEqual(m.summary.hashrate_hs['1h'], 1.4e15);
  assert.strictEqual(m.summary.best_share.ever, 9e9, 'the best of any node');
  assert.deepStrictEqual(m.blocks.map((b) => b.height), [974500, 974000]);
});

test('the expected time is worked out again from the hashrate on every node together', () => {
  const w = goodState().miners.wait;
  assert.strictEqual(w.known, true);
  assert.strictEqual(w.hashrate, 1.4e15);
  assert(Math.abs(w.seconds - 1.1e14 * 4294967296 / 1.4e15) < 1);
  assert(w.day > 0 && w.day < w.month && w.month < w.year && w.year < 1);
  // No hashrate: unknown, with why.
  const idle = MP.mergeMiners([{ node: 'a', ok: true, status: 200, body: minerBody([], { summary: Object.assign(minerBody([]).summary, { hashrate_hs: rates(null) }) }) }]);
  assert.deepStrictEqual([idle.wait.known, idle.wait.reason], [false, 'no accepted shares in the last 24 hours, so no hashrate']);
  // No tip: the node's own reason.
  const notip = MP.mergeMiners([{ node: 'a', ok: true, status: 200, body: minerBody([worker('rig1', 'online')], {
    expected_time_to_block: { known: false, seconds: null, network_difficulty: null, reason: 'the pool has no Bitcoin tip yet, so the difficulty is not known' } }) }]);
  assert.strictEqual(notip.wait.reason, 'the pool has no Bitcoin tip yet, so the difficulty is not known');
});

test('histories are summed per bucket, the best share is the higher, unknown stays unknown', () => {
  const h = goodState().history;
  assert.deepStrictEqual([h.answered, h.failed], [['a', 'b'], ['c']]);
  assert.strictEqual(h.total.accepted[0], null, 'before collection: null, not 0');
  assert.strictEqual(h.total.accepted[287], 10);
  assert.strictEqual(h.total.hashrate_hs[287], 1.4e15);
  assert.strictEqual(h.total.best_share[287], 1e8);
  assert.deepStrictEqual(Object.keys(h.workers).sort(), ['rig1', 'rig2']);
  assert.strictEqual(h.reasons['duplicate-share'], 4);
});

test('a node one bucket ahead is lined up; one further out is left out', () => {
  const ahead = historyBody(['rig2']);
  ahead.buckets = buckets.map((t) => t + 300);
  const far = historyBody(['rig3']);
  far.buckets = buckets.map((t) => t + 900);
  const h = MP.mergeHistories([
    { node: 'a', ok: true, status: 200, body: historyBody(['rig1']) },
    { node: 'b', ok: true, status: 200, body: ahead },
    { node: 'd', ok: true, status: 200, body: far }
  ]);
  assert.deepStrictEqual([h.answered, h.failed], [['a', 'b'], ['d']]);
  assert.strictEqual(h.total.accepted[276], 5, "b's first known bucket lands one later on a's grid");
  assert.strictEqual(h.total.accepted[287], 10, "b's newest bucket is past a's grid and dropped");
});

test('the page renders every section from sample answers', () => {
  const out = MP.renderAll(goodState(), 640);
  for (const k of Object.keys(out)) noJunk(out[k], k);
  const tiles = strip(out.tiles);
  assert(out.tiles.includes('1.40<span class="unit">PH/s'), 'hashrate tile: ' + out.tiles);
  assert(tiles.includes('Workers online 2 of 2'), tiles);
  assert(tiles.includes('Shares, 24 hours 1,200'), tiles);
  assert(tiles.includes('Best share 9.00 G'), tiles);
  assert(tiles.includes('Blocks found 2 latest at height 974,500'), tiles);
  assert(/Expected time to a block ~1[01]\.\d years an average, not a promise/.test(tiles), tiles);
  const odds = strip(out.odds);
  assert(/Within a day about 1 in [\d,]+/.test(odds), odds);
  assert(/Within a year \d+(\.\d)?%/.test(odds), odds);
  assert(odds.includes('Most small miners never find a block'), odds);
  assert(out.workers.includes('rig1') && strip(out.workers).includes('Node B'), 'workers name their node');
  assert(strip(out.workers).includes('Not answering: Node C'));
  assert(out.hashrate.includes('<svg') && out.hashrate.includes('class="chart-line s1"'));
  assert(out.hashrate.includes('not collected yet'), 'the unknown stretch is marked');
  assert(out.shares.includes('chart-bar s1') && strip(out.shares).includes('2 the same share sent twice') === false);
  assert(strip(out.shares).includes('4 the same share sent twice'), strip(out.shares));
  const blocks = strip(out.blocks);
  assert(blocks.includes('974,500') && blocks.includes('3.11 BTC') && blocks.includes('fees 0.000625 BTC') && blocks.includes('treasury 0.015625 BTC'), blocks);
  assert(blocks.includes('backup node: accepted'), blocks);
  assert(out.blocks.includes('https://mempool.space/block/' + 'bb'.repeat(32)));
  assert(blocks.includes('100 more blocks'), 'coinbase maturity is stated');
  assert(strip(out.header).includes('mining') && strip(out.header).includes('From Node A, Node B'), strip(out.header));
});

test('one worker selected: its own charts, its row marked', () => {
  const out = MP.renderAll(goodState(MP.parseQuery('?id=' + ADDR + '.rig2')), 640);
  assert(out.workers.includes('<tr class="selected">'), 'the row is marked');
  assert(out.hashrate.includes('aria-label="Hashrate of worker rig2"'));
  assert(out.header.includes('.rig2'));
});

test('no node answered: every section says unavailable, nothing reads as zero', () => {
  const st = {
    query: MP.parseQuery('?address=' + ADDR), now: NOW, names: NAMES,
    miners: MP.mergeMiners([{ node: 'a', ok: false, status: 0, body: null }, { node: 'b', ok: false, status: 504, body: { error: 'x' } }]),
    history: MP.mergeHistories([{ node: 'a', ok: false, status: 0, body: null }])
  };
  const out = MP.renderAll(st, 640);
  for (const k of Object.keys(out)) noJunk(out[k], k);
  const t = strip(out.tiles);
  assert(!/\b0\b/.test(t), 'no zero: ' + t);
  assert((t.match(/unavailable/g) || []).length >= 5, t);
  assert(strip(out.workers).includes('unavailable'));
  assert(strip(out.hashrate).includes('unavailable'));
  assert(strip(out.blocks).includes('unavailable'));
  assert(strip(out.header).includes('no node answered'));
});

test('an address the pool cannot pay: the node\'s message is kept', () => {
  const m = MP.mergeMiners([
    { node: 'a', ok: false, status: 400, body: { error: 'P2PKH (1...) addresses are not accepted' } },
    { node: 'b', ok: false, status: 400, body: { error: 'P2PKH (1...) addresses are not accepted' } }
  ]);
  assert.strictEqual(m.refused, 'P2PKH (1...) addresses are not accepted');
  assert.deepStrictEqual(m.answered, []);
});

test('a known address with no workers yet and no blocks', () => {
  const st = {
    query: MP.parseQuery('?address=' + ADDR), now: NOW, names: NAMES,
    miners: MP.mergeMiners([{ node: 'a', ok: true, status: 200, body: minerBody([], {
      summary: { workers: 0, online: 0, idle: 0, offline: 0, hashrate_hs: rates(null), shares_24h: { accepted: 0, stale: 0, rejected: 0, reject_reasons: {} },
                 last_share_at: null, best_share: { ever: 0, '24h': 0 } },
      expected_time_to_block: { known: false, reason: 'no accepted shares in the last 24 hours, so no hashrate', network_difficulty: 1.1e14 } }) }]),
    history: MP.mergeHistories([{ node: 'a', ok: true, status: 200, body: Object.assign(historyBody([]), { total: { hashrate_hs: known(null), accepted: known(null), stale: known(null), rejected: known(null), best_share: known(null) } }) }])
  };
  const out = MP.renderAll(st, 640);
  for (const k of Object.keys(out)) noJunk(out[k], k);
  assert(strip(out.workers).includes('No answering node has seen a worker'));
  assert(strip(out.tiles).includes('Expected time to a block unknown'), strip(out.tiles));
  assert(strip(out.odds).includes('no accepted shares'));
  assert(strip(out.blocks).includes('has not found a block'));
  assert(strip(out.header).includes('not seen'));
  assert(strip(out.hashrate).includes('No shares in this window'));
});

test('the node list could not be loaded', () => {
  const out = MP.renderAll({ query: MP.parseQuery('?address=' + ADDR), noNodes: true, now: NOW }, 640);
  for (const k of Object.keys(out)) noJunk(out[k], k);
  assert(strip(out.tiles).includes('node list could not be loaded'));
});

// The live miner list under the lookup box: /api/v1/pool/miners from every node, as pool_sv2
// serves it (solo_api.rs `miners`).
const ADDR2 = 'bc1q7zvdh3uza6u52uemd3c60g0h0eu9g9yvm2y492';
const listEntry = (address, h, extra) => Object.assign({
  address, connected: true, workers: 2, online: 2, idle: 0, offline: 0, hashrate_hs: rates(h),
  shares_24h: counts(), last_share_at: NOW - 30, best_share: { ever: 5e6, '24h': 5e6 }, blocks_found: 0
}, extra || {});
const lists = () => [
  { node: 'a', ok: true, status: 200, body: { network: 'mainnet', miners: [listEntry(ADDR2, 8e13), listEntry(ADDR, 6e11, { last_share_at: NOW - 90 })] } },
  { node: 'b', ok: true, status: 200, body: { network: 'mainnet', miners: [listEntry(ADDR2, 7e11, { workers: 3, online: 2, best_share: { ever: 9e8, '24h': 9e8 } })] } }
];

test('live list: one row per address over every node, the most hashrate first', () => {
  const m = MP.mergeMinerLists(lists());
  assert.deepStrictEqual(m.answered, ['a', 'b']);
  assert.strictEqual(m.miners.length, 2);
  assert.strictEqual(m.miners[0].address, ADDR2);
  assert.strictEqual(m.miners[0].hashrate, 8e13 + 7e11);
  assert.strictEqual(m.miners[0].workers, 5);
  assert.strictEqual(m.miners[0].online, 4);
  assert.strictEqual(m.miners[0].best, 9e8);
  assert.deepStrictEqual(m.miners[0].nodes, ['a', 'b']);
  assert.strictEqual(m.miners[1].address, ADDR);
});

test('live list: any part of an address, any case, narrows it', () => {
  const m = MP.mergeMinerLists(lists()).miners;
  assert.strictEqual(MP.filterMiners(m, '').length, 2);
  assert.deepStrictEqual(MP.filterMiners(m, '7ZVDH').map((x) => x.address), [ADDR2]);
  assert.deepStrictEqual(MP.filterMiners(m, 'm2y492 ').map((x) => x.address), [ADDR2]);
  assert.deepStrictEqual(MP.filterMiners(m, 'bc1q').length, 2);
  assert.deepStrictEqual(MP.filterMiners(m, 'zzzz'), []);
});

test('live list: renders rows that link to each miner, with a count', () => {
  const m = MP.mergeMinerLists(lists());
  const all = MP.minerListHtml(m, '', NOW);
  noJunk(all, 'list');
  assert(!strip(all).includes(' / '), 'online only: totals over nodes double-count a moved worker');
  assert(strip(all).includes(ADDR2.slice(0, 10)) && /<td class="num">4<\/td>/.test(all));
  assert(all.includes('?address=' + ADDR2));
  assert(strip(all).includes('2 miners'));
  const one = MP.minerListHtml(m, '7zvdh', NOW);
  noJunk(one, 'filtered');
  assert(!one.includes('?address=' + ADDR + '"'));
  assert(strip(one).includes('1 of 2 miners match'));
  const none = MP.minerListHtml(m, '<b>x', NOW);
  assert(strip(none).includes('No live miner'));
  assert(!none.includes('<b>x'), 'the typed text is escaped');
});

test('live list: a node down is named, none answering says unavailable, empty says so', () => {
  const r = lists(); r[1] = { node: 'b', ok: false, status: 0, body: null };
  const part = MP.minerListHtml(MP.mergeMinerLists(r), '', NOW);
  noJunk(part, 'partial');
  assert(strip(part).includes('Not answering: b'));
  const down = MP.minerListHtml(MP.mergeMinerLists([{ node: 'a', ok: false, status: 503, body: null }]), '', NOW);
  assert(strip(down).includes('unavailable'));
  const empty = MP.minerListHtml(MP.mergeMinerLists([{ node: 'a', ok: true, status: 200, body: { miners: [] } }]), '', NOW);
  assert(strip(empty).includes('No miners are connected'));
  assert(strip(MP.minerListHtml(null, '', NOW)).includes('Loading'));
});

if (failures) { console.log(failures + ' failed'); process.exit(1); }
console.log('all passed');
