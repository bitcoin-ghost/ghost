// The shared site script (ghost-web/pool.js) and the pages themselves, under plain node: the node
// list, the connect box, the payout rule, the live status merged from every node, and every
// local link and script a page uses. Run by scripts/check-miner-page.sh.
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const web = path.join(__dirname, '..', '..', 'ghost-web');
const P = require(path.join(web, 'pool.js'));

let failures = 0;
function test(name, f) {
  try { f(); console.log('ok   ' + name); } catch (e) { failures++; console.log('FAIL ' + name + '\n     ' + e.message); }
}
const strip = (h) => h.replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/\s+/g, ' ').trim();
function noJunk(html, where) {
  for (const bad of ['NaN', 'undefined', '[object Object]', 'Infinity', 'null']) {
    assert(!strip(html).includes(bad), where + ' shows ' + bad + ': ' + strip(html));
  }
}

const KEY = '9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72';

function status(over) {
  return Object.assign({
    network: 'mainnet', generated_at: 1800000000, collecting_since: 1799990000,
    bitcoin: { tip_height: 974899, tip_hash: '00'.repeat(32), job_height: 974900, network_difficulty: 1.1e14 },
    miners: { connected: 3, workers: 5 },
    pool_hashrate_hs: { '15m': 3.0e14, '1h': 2.9e14, '24h': 2.5e14 },
    best_share: { ever: 9.9e10, '24h': 1.2e9 },
    blocks_found: [],
    fee_policy: { treasury_address: P.TREASURY, treasury_share_of_subsidy: 0.005, treasury_sats_next_block: 1562500,
                  miner_sats_next_block_before_fees: 310937500, fees_to: 'miner' },
    ports: { sv1: [3333, 4444], sv2: 34255 },
    submit_nodes: ['http://10.0.0.2:8332']
  }, over || {});
}

const block = (h, hash, extra) => Object.assign({ height: h, hash: hash.repeat(64 / hash.length), address: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', worker: 'rig1',
  reward_sats: 311000000, treasury_sats: 1562500, fees_sats: 62500, found_at: 1799999000, check: 'ok', submitted: [] }, extra || {});

test('the payout rule: 0.5% of the subsidy to the treasury, the rest and every fee to the miner', () => {
  const s = P.payoutSplit(312500000, 0);
  assert.deepStrictEqual([s.treasury, s.minerBeforeFees], [1562500, 310937500]);
  assert.strictEqual(P.fmtBtc(s.treasury), '0.015625 BTC');
  assert.strictEqual(P.fmtBtc(s.minerBeforeFees), '3.109375 BTC');
  assert.strictEqual(P.payoutSplit(312500000, 40000).miner, 310977500, 'fees go to the miner, untouched');
  assert.strictEqual(P.payoutSplit(156250001).treasury, 781250, 'rounded down');
  assert.strictEqual(P.payoutSplit(-1), null);
});

test('the home page shows the same worked example the code computes', () => {
  const home = fs.readFileSync(path.join(web, 'index.html'), 'utf8');
  for (const s of ['3.125 BTC', '0.015625 BTC', '3.109375 BTC', P.TREASURY]) assert(home.includes(s), 'home is missing ' + s);
});

test('the next block line is read from fee_policy, and absent without it', () => {
  assert.strictEqual(strip(P.nextBlockHtml(status().fee_policy)),
    'The next block the pool finds pays 3.109375 BTC plus its fees to the miner and 0.015625 BTC to the treasury.');
  assert.strictEqual(P.nextBlockHtml(null), null);
  assert.strictEqual(P.nextBlockHtml({ treasury_sats_next_block: null }), null);
});

test('pool-nodes.json: ids, hosts and keys are checked, anything malformed dropped', () => {
  const shipped = JSON.parse(fs.readFileSync(path.join(web, 'pool-nodes.json'), 'utf8'));
  assert.strictEqual(P.nodesFromConfig(shipped).length, 2, 'the shipped list has both nodes');
  const n = P.nodesFromConfig({ nodes: [
    { id: 'a', name: 'Node A', stratum_host: 'pool-a.example.org', sv2_authority_key: KEY },
    { id: 'a', name: 'dup', stratum_host: 'x.example.org' },
    { id: '../x', stratum_host: 'x.example.org' },
    { id: 'c', stratum_host: 'evil.example.org/"><script>' },
    { id: 'd', stratum_host: 'd.example.org', sv2_authority_key: '<b>' },
    null
  ] });
  assert.deepStrictEqual(n.map((x) => x.id), ['a', 'd']);
  assert.strictEqual(n[0].key, KEY);
  assert.strictEqual(n[1].key, null, 'a malformed key is not shown');
  assert.strictEqual(n[1].name, 'Node d');
  assert.deepStrictEqual(P.nodesFromConfig(null), []);
});

test('the connect box: both nodes, three URLs each, primary and backup, the key when published', () => {
  const nodes = P.nodesFromConfig({ nodes: [
    { id: 'a', name: 'Node A', stratum_host: 'pool-a.example.org', sv2_authority_key: KEY },
    { id: 'b', name: 'Node B', stratum_host: 'pool-b.example.org', sv2_authority_key: null }
  ] });
  const h = P.connectHtml(nodes);
  for (const u of ['stratum+tcp://pool-a.example.org:3333', 'stratum+tcp://pool-a.example.org:4444', 'stratum2+tcp://pool-a.example.org:34255/' + KEY,
                   'stratum+tcp://pool-b.example.org:3333', 'stratum+tcp://pool-b.example.org:4444', 'stratum2+tcp://pool-b.example.org:34255']) {
    assert(h.includes('data-copy="' + u + '"'), 'missing ' + u);
  }
  const t = strip(h);
  assert(/Node A primary/.test(t) && /Node B backup/.test(t), t);
  assert(t.includes('Authority key: not published here yet'));
  assert(t.includes('your Bitcoin address'));
  noJunk(h, 'connect');
  assert(strip(P.connectHtml([])).includes('could not be loaded'));
});

test('live status: every node is added up; a node that did not answer is named and not counted', () => {
  const a = status({ blocks_found: [block(974000, 'aa')] });
  const b = status({ miners: { connected: 1, workers: 1 }, pool_hashrate_hs: { '15m': 1e14, '1h': 1.1e14, '24h': null },
                     best_share: { ever: 2e11, '24h': 1e9 }, bitcoin: { tip_height: 974900, network_difficulty: 1.2e14 },
                     blocks_found: [block(974000, 'aa'), block(974500, 'bb')] });
  const m = P.mergeStatus([
    { node: 'a', ok: true, status: 200, body: a },
    { node: 'b', ok: true, status: 200, body: b },
    { node: 'c', ok: false, status: 502, body: { error: 'down' } }
  ]);
  assert.deepStrictEqual([m.answered, m.failed], [['a', 'b'], ['c']]);
  assert.deepStrictEqual([m.miners, m.workers], [4, 6]);
  assert.strictEqual(m.hashrate['1h'], 4.0e14);
  assert.strictEqual(m.hashrate['24h'], 2.5e14, 'a node without a 24 h figure adds nothing, not zero');
  assert.strictEqual(m.best.ever, 2e11);
  assert.deepStrictEqual([m.tipHeight, m.difficulty], [974900, 1.2e14], 'the higher tip and its difficulty');
  assert.deepStrictEqual(m.blocks.map((e) => [e.block.height, e.seenBy.join('+')]), [[974500, 'b'], [974000, 'a+b']], 'once each, newest first');
  const html = P.statsHtml(m, [{ id: 'a', name: 'Node A' }, { id: 'b', name: 'Node B' }, { id: 'c', name: 'Node C' }]);
  noJunk(html, 'stats');
  const t = strip(html);
  assert(t.includes('400') && t.includes('TH/s'), t);
  assert(t.includes('Miners connected 4'), t);
  assert(t.includes('Blocks found 2 latest at height 974,500'), t);
  assert(t.includes('Best share 200 G'), t);
  assert(t.includes('Bitcoin height 974,900'), t);
  assert(t.includes('From Node A and Node B. Not answering: Node C'), t);
  // 1.2e14 * 2^32 / 4e14 s = about 40.8 years.
  assert(/Pool finds a block every ~40\.\d years/.test(t), t);
  const bl = P.blocksHtml(m, 1800000000);
  noJunk(bl, 'blocks');
  assert(bl.includes('https://mempool.space/block/' + 'bb'.repeat(32)));
  assert(strip(bl).includes('3.11 BTC'));
});

test('no node answering: no figure is shown, and nothing reads as zero', () => {
  const m = P.mergeStatus([{ node: 'a', ok: false, status: 0, body: null }, { node: 'b', ok: false, status: 504, body: null }]);
  const t = strip(P.statsHtml(m, [{ id: 'a', name: 'Node A' }, { id: 'b', name: 'Node B' }]));
  assert(t.includes('No node answered') && t.includes('Node A, Node B'), t);
  assert(!/\b0\b/.test(t), t);
  assert.strictEqual(P.blocksHtml(m, 0), '');
});

test('a node without hashrate or tip yet: unavailable, not zero', () => {
  const s = status({ pool_hashrate_hs: { '15m': null, '1h': null, '24h': null }, bitcoin: { tip_height: null, network_difficulty: null } });
  const t = strip(P.statsHtml(P.mergeStatus([{ node: 'a', ok: true, status: 200, body: s }]), []));
  assert(t.includes('Pool hashrate unavailable'), t);
  assert(t.includes('Bitcoin height unavailable'), t);
  assert(t.includes('Pool finds a block every unavailable'), t);
  assert(t.includes('Blocks found 0 none yet'), 'a count of found blocks is a real zero: ' + t);
});

test('formatting: hashrate, difficulty, BTC, durations and odds', () => {
  assert.strictEqual(P.hashrateText(1.234e15), '1.23 PH/s');
  assert.strictEqual(P.hashrateText(4321.7), '4.32 kH/s');
  assert.strictEqual(P.hashrateText(12.4), '12 H/s');
  assert.strictEqual(P.hashrateText(null), null);
  assert.strictEqual(P.fmtDifficulty(4.1e9), '4.10 G');
  assert.strictEqual(P.fmtDifficulty(0), '0');
  assert.strictEqual(P.fmtBtc(311000000), '3.11 BTC');
  assert.strictEqual(P.fmtBtc(1), '0.00000001 BTC');
  assert.strictEqual(P.fmtBtc(100000000), '1.0 BTC');
  assert.strictEqual(P.fmtDuration(4.7e11), '14,893 years');
  assert.strictEqual(P.fmtDuration(3 * 86400), '3.0 days');
  const mean = P.expectedSeconds(1.1e14, 1e12);
  assert(Math.abs(mean - 1.1e14 * 4294967296 / 1e12) < 1);
  assert.strictEqual(P.expectedSeconds(1.1e14, 0), null);
  assert.strictEqual(P.fmtChance(P.chanceWithin(86400, mean)), 'about 1 in 5,500,000');
  assert.strictEqual(P.fmtChance(P.chanceWithin(86400, 86400)), '63%');
  assert.strictEqual(P.fmtChance(0.999), 'over 99%');
  assert.strictEqual(P.blockUrl('regtest', 'aa'.repeat(32)), null);
  assert.strictEqual(P.blockUrl('mainnet', 'not-a-hash'), null);
});

test('every page: local links and scripts exist, nothing points at a removed page, one title each', () => {
  const pages = fs.readdirSync(web).filter((f) => f.endsWith('.html'));
  assert(pages.length >= 6, pages.join(', '));
  const gone = /node-pool|node-list|share.chain|ledger|hazync|ghost pay|ghost tap|\bmpc\b|elder|bitcoin ghost/i;
  for (const p of pages) {
    const h = fs.readFileSync(path.join(web, p), 'utf8');
    assert.strictEqual((h.match(/<title>/g) || []).length, 1, p + ': one <title>');
    assert(/<title>[^<]*Ghost Pool[^<]*<\/title>/.test(h), p + ': the title names Ghost Pool');
    assert(!gone.test(strip(h)), p + ' still mentions a removed thing: ' + (strip(h).match(gone) || [])[0]);
    for (const m of h.matchAll(/(?:href|src)="(\/[^"#?]*)/g)) {
      let f = m[1] === '/' ? '/index.html' : m[1];
      if (f.endsWith('/')) f += 'index.html';
      assert(fs.existsSync(path.join(web, f)), p + ' links to ' + m[1] + ', which does not exist');
    }
  }
  for (const f of ['pool.js', 'miner.js', 'pool-nodes.json', 'style.css']) assert(fs.existsSync(path.join(web, f)), f);
});

if (failures) { console.log(failures + ' failed'); process.exit(1); }
console.log('all passed');
