// Renders the leaderboard (ghost-web/leaderboard.js) from sample answers shaped as pool_sv2 serves
// /api/v1/pool/leaderboard (bins/pool-sv2/src/lib/solo_api.rs), and from failed ones, under plain
// node. Run by scripts/check-miner-page.sh.
'use strict';
const assert = require('assert');
const path = require('path');

const LB = require(path.join(__dirname, '..', '..', 'ghost-web', 'leaderboard.js'));

const A = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
const B = 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3';

let failures = 0;
function test(name, f) {
  try { f(); console.log('ok   ' + name); } catch (e) { failures++; console.log('FAIL ' + name + '\n     ' + e.message); }
}
const strip = (h) => h.replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();
function noJunk(html) {
  for (const bad of ['NaN', 'undefined', '[object Object]', 'Infinity', 'null']) assert(!strip(html).includes(bad), 'shows ' + bad + ': ' + strip(html));
}

const e = (address, worker, best, active) => ({ address, worker, best, active: !!active });
const board = (lists) => Object.assign({ network: 'mainnet', generated_at: 1, collecting_since: 0, block: [], '24h': [], '30d': [], ever: [] }, lists);

test('every node is merged: a worker on two nodes counts once, with its best on either', () => {
  const m = LB.mergeBoards([
    { node: 'a', ok: true, status: 200, body: board({ block: [e(A, 'rig1', 3e6, false), e(B, 'axe', 1e6, true)], ever: [e(A, 'rig1', 9e9)] }) },
    { node: 'b', ok: true, status: 200, body: board({ block: [e(A, 'rig1', 5e6, true)], ever: [e(A, 'rig1', 2e9), e(B, 'axe', 4e9)] }) },
    { node: 'c', ok: false, status: 502, body: null }
  ]);
  assert.deepStrictEqual([m.answered, m.failed], [['a', 'b'], ['c']]);
  assert.deepStrictEqual(m.lists.block.map((x) => [x.worker, x.best, x.active]), [['rig1', 5e6, true], ['axe', 1e6, true]]);
  assert.deepStrictEqual(m.lists.ever.map((x) => x.worker), ['rig1', 'axe']);
  assert.strictEqual(m.lists.ever[0].best, 9e9);
});

test('the board shows rank, worker, address, best share and how far from a block', () => {
  const m = LB.mergeBoards([{ node: 'a', ok: true, status: 200, body: board({ '24h': [e(A, 'rig1', 1.5e12, true), e(B, '', 2e6)] }) }]);
  const html = LB.boardHtml(m, '24h', 1.5e14);
  noJunk(html);
  const t = strip(html);
  assert(t.includes('1 rig1'), t);
  assert(t.includes('1.0% of a block'), t);
  assert(t.includes('(no worker name)'), t);
  assert(t.includes('1 in 75,000,000'), t);
  assert(t.includes('in the last 24 hours'), t);
  assert(t.includes('A block needs a share of difficulty 150 T'), t);
  assert(html.includes('href="/miner.html?address=' + A + '&amp;worker=rig1"'), html);
  assert(html.includes('class="podium"'));
});

test('empty, unknown and failed boards say so', () => {
  const empty = LB.mergeBoards([{ node: 'a', ok: true, status: 200, body: board({}) }]);
  assert(strip(LB.boardHtml(empty, 'block', null)).includes('A new block resets this list'));
  assert(strip(LB.boardHtml(empty, '30d', null)).includes('No shares in this period yet'));
  const down = LB.mergeBoards([{ node: 'a', ok: false, status: 503, body: { error: 'x' } }]);
  assert(strip(LB.boardHtml(down, 'block', null)).includes('unavailable'));
  assert(strip(LB.boardHtml(null, 'block', null)).includes('Loading'));
  // A node too old to serve the leaderboard answers 404: counted as not answering.
  const old = LB.mergeBoards([{ node: 'a', ok: false, status: 404, body: { error: 'not found' } }]);
  assert.deepStrictEqual(old.failed, ['a']);
  // Without a difficulty there is no "of a block", and no stray text.
  const m = LB.mergeBoards([{ node: 'a', ok: true, status: 200, body: board({ block: [e(A, 'rig1', 3e6)] }) }]);
  const html = LB.boardHtml(m, 'block', null);
  noJunk(html);
  assert(!strip(html).includes('of a block'));
});

test('periods: the URL picks one, anything else is this block', () => {
  assert.strictEqual(LB.parseQuery('?period=30d').period, '30d');
  assert.strictEqual(LB.parseQuery('?period=1y').period, 'block');
  assert.strictEqual(LB.parseQuery('').period, 'block');
  assert(LB.chipsHtml('ever').includes('class="chip on" data-period="ever"'));
});

test('the network difficulty is the highest any node reports', () => {
  assert.strictEqual(LB.networkDifficulty([
    { ok: true, body: { bitcoin: { network_difficulty: 1.4e14 } } },
    { ok: true, body: { bitcoin: { network_difficulty: 1.5e14 } } },
    { ok: false, body: null }
  ]), 1.5e14);
  assert.strictEqual(LB.networkDifficulty([]), null);
});

if (failures) { console.log(failures + ' failed'); process.exit(1); }
console.log('all passed');
