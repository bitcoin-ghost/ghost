/* Ghost Pool: the best-share leaderboard (leaderboard.html).
 *
 * Each node ranks its own workers by best share over four periods (pool_sv2's
 * /api/v1/pool/leaderboard): since the last block on the network, the last 24 hours, the last 30
 * days and ever. The page asks every node in /pool-nodes.json through the website's API proxy,
 * merges the lists (a worker that moved node counts once, with its best on either), and shows the
 * top of the chosen period. The network difficulty, from /api/v1/pool/status, says how far the
 * best share is from a block.
 *
 * Rendering is pure, so it is checked under plain node: scripts/web-tests/leaderboard.test.js.
 */
(function (root) {
  'use strict';

  var P = typeof module !== 'undefined' && module.exports ? require('./pool.js') : root.GhostPool;
  var esc = P.esc, isNum = P.isNum, fmtDifficulty = P.fmtDifficulty, fmtInt = P.fmtInt;

  var REFRESH_MS = 60000;
  var SHOWN = 50;
  var PERIODS = [
    { key: 'block', label: 'this block', lead: 'since the last block on the network' },
    { key: '24h', label: '24 h', lead: 'in the last 24 hours' },
    { key: '30d', label: '30 days', lead: 'in the last 30 days' },
    { key: 'ever', label: 'all time', lead: 'since the nodes began keeping each worker' }
  ];

  function period(key) {
    for (var i = 0; i < PERIODS.length; i++) if (PERIODS[i].key === key) return PERIODS[i];
    return PERIODS[0];
  }

  function parseQuery(search) {
    var p = new URLSearchParams(search || '');
    return { period: period(p.get('period')).key };
  }

  // results: [{ node, ok, status, body }] from each node's /api/v1/pool/leaderboard.
  function mergeBoards(results) {
    var out = { answered: [], failed: [], lists: {} };
    var by = {};
    PERIODS.forEach(function (p) { out.lists[p.key] = []; by[p.key] = {}; });
    (results || []).forEach(function (r) {
      var b = r.ok ? r.body : null;
      if (!b || typeof b !== 'object' || !PERIODS.every(function (p) { return Array.isArray(b[p.key]); })) {
        out.failed.push(r.node);
        return;
      }
      out.answered.push(r.node);
      PERIODS.forEach(function (p) {
        b[p.key].forEach(function (e) {
          if (!e || typeof e.address !== 'string' || !e.address || !isNum(e.best) || e.best <= 0) return;
          var worker = typeof e.worker === 'string' ? e.worker : '';
          var id = e.address + '\n' + worker;
          var m = by[p.key][id];
          if (!m) {
            m = by[p.key][id] = { address: e.address, worker: worker, best: e.best, active: !!e.active };
            out.lists[p.key].push(m);
          } else {
            m.best = Math.max(m.best, e.best);
            m.active = m.active || !!e.active;
          }
        });
      });
    });
    PERIODS.forEach(function (p) {
      out.lists[p.key].sort(function (a, b) {
        return b.best - a.best || (a.address < b.address ? -1 : a.address > b.address ? 1 : 0) ||
          (a.worker < b.worker ? -1 : a.worker > b.worker ? 1 : 0);
      });
      out.lists[p.key] = out.lists[p.key].slice(0, SHOWN);
    });
    return out;
  }

  // The highest network difficulty any node reported (they share one chain).
  function networkDifficulty(results) {
    var d = null;
    (results || []).forEach(function (r) {
      var v = r.ok && r.body && r.body.bitcoin ? r.body.bitcoin.network_difficulty : null;
      if (isNum(v) && v > 0) d = d == null ? v : Math.max(d, v);
    });
    return d;
  }

  function shortAddress(a) { return a.length > 20 ? a.slice(0, 10) + '…' + a.slice(-8) : a; }

  function minerHref(e) {
    return '/miner.html?address=' + encodeURIComponent(e.address) + (e.worker ? '&worker=' + encodeURIComponent(e.worker) : '');
  }

  // A share's difficulty as a fraction of the network's: 1 is a block.
  function ofBlock(best, difficulty) {
    if (!isNum(difficulty) || difficulty <= 0) return '';
    var f = best / difficulty;
    if (f >= 1) return 'a block';
    var pct = f * 100;
    return pct >= 0.01 ? pct.toPrecision(2) + '% of a block' : '1 in ' + fmtInt(1 / f);
  }

  function boardHtml(merged, key, difficulty) {
    if (!merged) return '<div class="chart-empty">Loading the leaderboard…</div>';
    if (!merged.answered.length) return '<div class="chart-empty">The leaderboard is unavailable: no node answered.</div>';
    var p = period(key);
    var missing = merged.failed.length ? '<p class="note">Not answering: ' + esc(merged.failed.join(', ')) + '. Workers on it are missing from this list.</p>' : '';
    var list = merged.lists[p.key];
    if (!list.length) {
      var why = p.key === 'block' ? 'No share yet since the last block. A new block resets this list.' : 'No shares in this period yet.';
      return '<div class="chart-empty">' + esc(why) + '</div>' + missing;
    }
    var rows = list.map(function (e, i) {
      return '<tr' + (i < 3 ? ' class="podium"' : '') + '>' +
        '<td class="num rank">' + (i + 1) + '</td>' +
        '<td><a href="' + esc(minerHref(e)) + '">' + esc(e.worker || '(no worker name)') + '</a>' +
          '<div class="sub mono" title="' + esc(e.address) + '">' + esc(shortAddress(e.address)) + '</div></td>' +
        '<td class="num"><strong>' + esc(fmtDifficulty(e.best)) + '</strong>' +
          (ofBlock(e.best, difficulty) ? '<div class="sub">' + esc(ofBlock(e.best, difficulty)) + '</div>' : '') + '</td>' +
        '<td class="opt"><span class="status ' + (e.active ? 'online' : 'offline') + '">' + (e.active ? 'mining' : 'quiet') + '</span></td>' +
        '</tr>';
    }).join('');
    return '<div class="table-wrap"><table class="table leaderboard">' +
      '<thead><tr><th class="num">#</th><th>Worker</th><th class="num">Best share</th><th class="opt" title="Mining: a share in the last 10 minutes">Now</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>' +
      '<p class="note">The best share ' + esc(p.lead) + ', per worker, on every node. ' +
      (isNum(difficulty) ? 'A block needs a share of difficulty ' + esc(fmtDifficulty(difficulty)) + '. ' : '') +
      'Top ' + SHOWN + '.</p>' + missing;
  }

  function chipsHtml(key) {
    return PERIODS.map(function (p) {
      return '<button type="button" class="chip' + (p.key === key ? ' on' : '') + '" data-period="' + p.key + '">' + esc(p.label) + '</button>';
    }).join('');
  }

  function startBrowser(doc, win) {
    var q = parseQuery(win.location.search);
    var chips = doc.getElementById('lb-periods');
    var box = doc.getElementById('lb-board');
    var merged = null, difficulty = null, last = null, loading = false;
    function paint() {
      chips.innerHTML = chipsHtml(q.period);
      var html = boardHtml(merged, q.period, difficulty);
      if (html !== last) { last = html; box.innerHTML = html; }
    }
    chips.addEventListener('click', function (e) {
      var b = e.target.closest ? e.target.closest('[data-period]') : null;
      if (!b) return;
      q.period = period(b.getAttribute('data-period')).key;
      try { win.history.replaceState(null, '', q.period === 'block' ? win.location.pathname : '?period=' + q.period); } catch (err) {}
      paint();
    });
    function load() {
      if (loading) return;
      loading = true;
      P.loadNodes().then(function (nodes) {
        if (!nodes.length) return [[], []];
        return Promise.all([P.askAll(nodes, '/api/v1/pool/leaderboard'), P.askAll(nodes, '/api/v1/pool/status')]);
      }).then(function (r) {
        loading = false;
        var m = mergeBoards(r[0]);
        if (m.answered.length || !merged) merged = m;
        difficulty = networkDifficulty(r[1]) || difficulty;
        paint();
      });
    }
    paint();
    load();
    setInterval(function () { if (!doc.hidden) load(); }, REFRESH_MS);
  }

  var api = {
    parseQuery: parseQuery, mergeBoards: mergeBoards, networkDifficulty: networkDifficulty,
    boardHtml: boardHtml, chipsHtml: chipsHtml, ofBlock: ofBlock
  };
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.Leaderboard = api;
    var go = function () { startBrowser(document, window); };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', go);
    else go();
  }
})(this);
