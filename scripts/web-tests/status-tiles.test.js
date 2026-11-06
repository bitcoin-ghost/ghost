// The status tiles (ghost-web/node-pool.js) from a sample /api/v1/node-pool/status answer, under
// plain node: which field each tile reads and how it is shown. Run by scripts/check-miner-page.sh.
'use strict';
const assert = require('assert');
const path = require('path');

const NP = require(path.join(__dirname, '..', '..', 'ghost-web', 'node-pool.js'));

let failures = 0;
function test(name, f) {
  try { f(); console.log('ok   ' + name); } catch (e) { failures++; console.log('FAIL ' + name + '\n     ' + e.message); }
}

function status() {
  return {
    share_chain: { anchor_height: 7, btc_height: 998, t_net: 10 },
    settlement: { bitcoin_tip: 999 },
    peers: 2,
    miners: [{}, {}],
    pool_blocks_found: 41,
    ledger_rows: 3,
    total_owed: { units: '130996625984789', sats: 30500 },
    pool_hashrate: {
      hashes_per_sec: 1.234e15, from_job_height: 856, to_job_height: 999, window_blocks: 144,
      credited_shares: 2, unavailable: null
    }
  };
}

const show = (s, field) => NP.render(field, NP.lookup(s, field));
const strip = (h) => (h === null ? null : h.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim());

test('pool hashrate is read from pool_hashrate.hashes_per_sec, in hashes per second', () => {
  assert.strictEqual(strip(show(status(), 'hashrate')), '1.23 PH/s');
  const s = status();
  s.pool_hashrate.hashes_per_sec = 5e11;
  assert.strictEqual(strip(show(s, 'hashrate')), '500.00 GH/s');
  // A regtest pool's few hashes a second are shown as such, not rounded to zero.
  s.pool_hashrate.hashes_per_sec = 4321.7;
  assert.strictEqual(strip(show(s, 'hashrate')), '4.32 kH/s');
  s.pool_hashrate.hashes_per_sec = 12.4;
  assert.strictEqual(strip(show(s, 'hashrate')), '12 H/s');
  s.pool_hashrate.hashes_per_sec = 0;
  assert.strictEqual(strip(show(s, 'hashrate')), '0 H/s');
});

test('a hashrate the node cannot measure says so, with the reason as its title', () => {
  const s = status();
  s.pool_hashrate = { hashes_per_sec: null, unavailable: 'settlement has not seen a Bitcoin tip yet', window_blocks: 0 };
  const hit = NP.lookup(s, 'hashrate');
  assert.strictEqual(NP.render('hashrate', hit), 'not measured');
  assert.strictEqual(hit.title, 'settlement has not seen a Bitcoin tip yet');
});

test('an older node without the fields reads as not reported, never as zero', () => {
  const s = status();
  delete s.pool_hashrate;
  delete s.total_owed;
  assert.strictEqual(show(s, 'hashrate'), null);
  assert.strictEqual(show(s, 'owed_sats'), null);
});

test('total owed is read from total_owed.sats', () => {
  assert.strictEqual(strip(show(status(), 'owed_sats')), '30,500 sats');
});

test('the other tiles read the fields pool_sv2 sends', () => {
  const s = status();
  assert.strictEqual(show(s, 'tip_height'), '7');
  assert.strictEqual(show(s, 'btc_height'), '999');
  assert.strictEqual(show(s, 'network_tier'), '10');
  assert.strictEqual(show(s, 'peers'), '2');
  assert.strictEqual(show(s, 'miners'), '2');
  assert.strictEqual(show(s, 'blocks_found'), '41');
});

if (failures) { console.log(failures + ' failed'); process.exit(1); }
console.log('all passed');
