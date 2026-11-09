/* Ghost Pool: the miner page (miner.html).
 *
 * A miner is its Bitcoin address. Each node sees only the miners connected to it, so the page
 * asks every node in /pool-nodes.json, through the website's API proxy (/api/pool/<id>/...):
 *
 *   /api/v1/miner/{address}                     workers, hashrate, shares, best share, blocks found
 *   /api/v1/miner/{address}/history?window=...  the same over time
 *   /api/v1/pool/miners                          every live miner (the list under the lookup box)
 *
 * and adds the answers up (a worker is shown on the node it is connected to). The expected time
 * to a block is worked out again from the summed hashrate: network difficulty x 2^32 / hashrate.
 * A node that did not answer is named; a figure no node reported says "unavailable", never 0.
 *
 * Rendering is pure (functions of the fetched data returning HTML strings), so it is checked
 * under plain node: scripts/web-tests/miner-page.test.js.
 */
(function (root) {
  'use strict';

  var P = typeof module !== 'undefined' && module.exports ? require('./pool.js') : root.GhostPool;
  var esc = P.esc, isNum = P.isNum, fmtHashrate = P.fmtHashrate, hashrateHtml = P.hashrateHtml;
  var fmtDuration = P.fmtDuration, fmtDifficulty = P.fmtDifficulty, ago = P.ago, fmtInt = P.fmtInt;

  var REFRESH_MS = 60000;
  var WINDOWS = ['24h', '7d', '30d'];
  var SERIES = ['hashrate_hs', 'accepted', 'stale', 'rejected', 'best_share'];
  var REASON_WORDS = {
    'invalid-share': 'the share did not check out',
    'invalid-job-id': 'work on a job the node no longer holds',
    'difficulty-too-low': 'the hash missed the job’s target',
    'duplicate-share': 'the same share sent twice',
    'bad-extranonce-size': 'malformed extranonce',
    'other': 'other errors (the connection was dropped)'
  };

  function plural(n, one, many) { return fmtInt(n) + ' ' + (n === 1 ? one : (many || one + 's')); }

  // ---------------------------------------------------------------- the URL

  // ?address=<addr> (and optionally &worker=<name>); ?id=<address.worker> selects that worker.
  function parseQuery(search) {
    var p = new URLSearchParams(search || '');
    var raw = (p.get('address') || p.get('id') || '').trim();
    var worker = (p.get('worker') || '').trim();
    var address = raw;
    var dot = raw.indexOf('.');
    if (dot >= 0) {
      address = raw.slice(0, dot);
      if (!worker) worker = raw.slice(dot + 1);
    }
    var w = (p.get('window') || '24h').trim();
    if (WINDOWS.indexOf(w) < 0) w = '24h';
    return { address: address, worker: worker, window: w };
  }

  function queryString(q) {
    var s = '?address=' + encodeURIComponent(q.address);
    if (q.worker) s += '&worker=' + encodeURIComponent(q.worker);
    if (q.window && q.window !== '24h') s += '&window=' + encodeURIComponent(q.window);
    return s;
  }

  // ---------------------------------------------------------------- merging nodes

  function addOrNull(a, b) { return isNum(a) ? (isNum(b) ? a + b : a) : (isNum(b) ? b : null); }
  function maxOrNull(a, b) { return isNum(a) ? (isNum(b) ? Math.max(a, b) : a) : (isNum(b) ? b : null); }

  // results: [{ node, ok, status, body }] from each node's /api/v1/miner/{address}.
  function mergeMiners(results) {
    var out = {
      answered: [], failed: [], refused: null, network: null, workers: [], blocks: [], collectingSince: null,
      difficulty: null, waitReason: null,
      summary: { workers: 0, online: 0, idle: 0, offline: 0, hashrate_hs: { '15m': null, '1h': null, '24h': null },
                 shares_24h: { accepted: 0, stale: 0, rejected: 0, reject_reasons: {} }, last_share_at: null,
                 best_share: { ever: null, '24h': null } }
    };
    var seen = {};
    (results || []).forEach(function (r) {
      // 400: not an address this pool can pay. Every node says the same; keep the message.
      if (r.status === 400 && r.body && r.body.error) { out.refused = out.refused || String(r.body.error); out.failed.push(r.node); return; }
      var b = r.ok ? r.body : null;
      if (!b || !Array.isArray(b.workers) || !b.summary) { out.failed.push(r.node); return; }
      out.answered.push(r.node);
      out.network = out.network || b.network || null;
      if (isNum(b.collecting_since)) out.collectingSince = out.collectingSince == null ? b.collecting_since : Math.min(out.collectingSince, b.collecting_since);
      b.workers.forEach(function (w) { out.workers.push(Object.assign({}, w, { node: r.node })); });
      var s = b.summary;
      ['15m', '1h', '24h'].forEach(function (k) {
        out.summary.hashrate_hs[k] = addOrNull(out.summary.hashrate_hs[k], s.hashrate_hs ? s.hashrate_hs[k] : null);
      });
      var sh = s.shares_24h || {};
      ['accepted', 'stale', 'rejected'].forEach(function (k) { out.summary.shares_24h[k] += isNum(sh[k]) ? sh[k] : 0; });
      Object.keys(sh.reject_reasons || {}).forEach(function (k) {
        out.summary.shares_24h.reject_reasons[k] = (out.summary.shares_24h.reject_reasons[k] || 0) + sh.reject_reasons[k];
      });
      out.summary.last_share_at = maxOrNull(out.summary.last_share_at, s.last_share_at);
      if (s.best_share) {
        out.summary.best_share.ever = maxOrNull(out.summary.best_share.ever, s.best_share.ever);
        out.summary.best_share['24h'] = maxOrNull(out.summary.best_share['24h'], s.best_share['24h']);
      }
      var e = b.expected_time_to_block || {};
      out.difficulty = maxOrNull(out.difficulty, e.network_difficulty);
      if (!e.known && e.reason && !out.waitReason) out.waitReason = e.reason;
      (Array.isArray(b.blocks_found) ? b.blocks_found : []).forEach(function (blk) {
        if (!blk || typeof blk.hash !== 'string' || seen[blk.hash]) return;
        seen[blk.hash] = true;
        out.blocks.push(blk);
      });
    });
    out.blocks.sort(function (x, y) { return (y.height || 0) - (x.height || 0); });
    // A worker offline on one node but online on another is shown once, where it is online.
    var rank = { online: 0, idle: 1, offline: 2 };
    var live = {};
    out.workers.forEach(function (w) { if (w.status !== 'offline') live[w.name] = true; });
    out.workers = out.workers.filter(function (w) { return w.status !== 'offline' || !live[w.name]; });
    out.workers.sort(function (a, b) {
      return ((rank[a.status] || 0) - (rank[b.status] || 0)) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) ||
        (a.node < b.node ? -1 : 1);
    });
    // Counted from the merged list, so a worker that moved nodes is one worker.
    out.workers.forEach(function (w) {
      out.summary.workers++;
      if (w.status === 'online' || w.status === 'idle' || w.status === 'offline') out.summary[w.status]++;
    });
    out.wait = expectedWait(out);
    return out;
  }

  // The mean time to a block at the address's hashrate on every node together: the last hour's,
  // else the last day's. Unknown, with why, when there is no difficulty or no hashrate.
  function expectedWait(m) {
    var h = m.summary.hashrate_hs;
    var rate = isNum(h['1h']) && h['1h'] > 0 ? h['1h'] : isNum(h['24h']) && h['24h'] > 0 ? h['24h'] : null;
    var win = rate == null ? null : rate === h['1h'] ? '1h' : '24h';
    if (!m.answered.length) return { known: false, reason: 'no node answered' };
    if (!isNum(m.difficulty) || m.difficulty <= 0) return { known: false, reason: m.waitReason || 'the network difficulty is not known yet' };
    if (rate == null) return { known: false, reason: 'no accepted shares in the last 24 hours, so no hashrate' };
    var secs = P.expectedSeconds(m.difficulty, rate);
    return {
      known: true, seconds: secs, hashrate: rate, window: win, difficulty: m.difficulty,
      day: P.chanceWithin(86400, secs), month: P.chanceWithin(30.44 * 86400, secs), year: P.chanceWithin(365.25 * 86400, secs)
    };
  }

  function addSeries(a, b) {
    return a.map(function (x, i) {
      var y = b ? b[i] : null;
      if (x == null) return y == null ? null : y;
      return y == null ? x : x + y;
    });
  }

  function maxSeries(a, b) {
    return a.map(function (x, i) { return maxOrNull(x, b ? b[i] : null); });
  }

  function combine(k, a, b) { return k === 'best_share' ? maxSeries(a, b) : addSeries(a, b); }

  // Shift a history's series by one bucket (+1: it is one bucket ahead) onto another grid.
  function shiftHistory(b, shift) {
    function sh(arr) {
      if (!Array.isArray(arr)) return arr;
      if (shift === 1) return [null].concat(arr.slice(0, -1));
      return arr.slice(1).concat([null]);
    }
    var c = JSON.parse(JSON.stringify(b));
    c.buckets = b.buckets.map(function (t) { return t - shift * b.bucket_seconds; });
    SERIES.forEach(function (k) { c.total[k] = sh(b.total[k]); });
    (c.workers || []).forEach(function (w) {
      Object.keys(w.series).forEach(function (k) { w.series[k] = sh(w.series[k]); });
    });
    return c;
  }

  // History from every node that answered on the same bucket grid (one bucket out is lined up).
  // Counts and hashrate add up across nodes; the best share is the higher.
  function mergeHistories(results) {
    var out = { answered: [], failed: [], buckets: null, bucket_seconds: null, total: null, workers: {}, reasons: {} };
    (results || []).forEach(function (r) {
      var b = r.ok ? r.body : null;
      if (!b || !Array.isArray(b.buckets) || !b.total) { out.failed.push(r.node); return; }
      if (out.buckets && (b.buckets.length !== out.buckets.length || b.buckets[0] !== out.buckets[0])) {
        var shift = (b.buckets[0] - out.buckets[0]) / out.bucket_seconds;
        if (b.buckets.length !== out.buckets.length || Math.abs(shift) !== 1) { out.failed.push(r.node); return; }
        b = shiftHistory(b, shift);
      }
      out.answered.push(r.node);
      var n = b.buckets.length;
      var fill = function (arr) { return Array.isArray(arr) && arr.length === n ? arr : b.buckets.map(function () { return null; }); };
      if (!out.buckets) {
        out.buckets = b.buckets.slice();
        out.bucket_seconds = b.bucket_seconds;
        out.total = {};
        SERIES.forEach(function (k) { out.total[k] = fill(b.total[k]).slice(); });
      } else {
        SERIES.forEach(function (k) { out.total[k] = combine(k, out.total[k], fill(b.total[k])); });
      }
      (b.workers || []).forEach(function (w) {
        if (!w || !w.series) return;
        var cur = out.workers[w.name];
        if (!cur) {
          cur = out.workers[w.name] = {};
          SERIES.forEach(function (k) { cur[k] = fill(w.series[k]).slice(); });
          return;
        }
        SERIES.forEach(function (k) { cur[k] = combine(k, cur[k], fill(w.series[k])); });
      });
      Object.keys(b.reject_reasons || {}).forEach(function (k) {
        out.reasons[k] = (out.reasons[k] || 0) + b.reject_reasons[k];
      });
    });
    return out;
  }

  // ---------------------------------------------------------------- charts (inline SVG)

  function niceMax(v) {
    if (!(v > 0)) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(v)));
    var m = v / p;
    var n = m <= 1 ? 1 : m <= 2 ? 2 : m <= 2.5 ? 2.5 : m <= 5 ? 5 : 10;
    return n * p;
  }

  function timeLabel(t, bucketSeconds) {
    var d = new Date(t * 1000);
    if (bucketSeconds < 3600) return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
  }

  // opts: { id, label, buckets, bucketSeconds, kind: 'line'|'bars', series: [{ values, cls }],
  // yFmt(v) -> text, width, height, empty }
  function chartSvg(opts) {
    var W = Math.max(280, Math.round(opts.width || 640));
    var H = opts.height || 200;
    var padL = 60, padR = 12, padT = 12, padB = 26;
    var n = opts.buckets.length;
    var plotW = W - padL - padR, plotH = H - padT - padB;
    var stacked = opts.kind === 'bars';
    var max = 0, any = false;
    for (var i = 0; i < n; i++) {
      var sum = 0;
      opts.series.forEach(function (s) {
        var v = s.values[i];
        if (v != null) { any = true; if (stacked) sum += v; else if (v > max) max = v; }
      });
      if (stacked && sum > max) max = sum;
    }
    if (!any) return '<div class="chart-empty">' + esc(opts.empty || 'No data for this window.') + '</div>';
    var yMax = niceMax(max);
    var step = plotW / n;
    function x(k) { return padL + k * step; }
    function y(v) { return padT + plotH - (v / yMax) * plotH; }
    var parts = [];
    parts.push('<svg class="chart-svg" width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H +
      '" role="img" aria-label="' + esc(opts.label || 'chart') + '" data-chart="' + esc(opts.id) + '">');
    [0, 0.5, 1].forEach(function (f) {
      var gy = padT + plotH - f * plotH;
      parts.push('<line class="chart-grid" x1="' + padL + '" x2="' + (W - padR) + '" y1="' + gy.toFixed(1) + '" y2="' + gy.toFixed(1) + '"/>');
      parts.push('<text class="chart-ylab" x="' + (padL - 6) + '" y="' + (gy + 4).toFixed(1) + '" text-anchor="end">' + esc(opts.yFmt(yMax * f)) + '</text>');
    });
    // Before collection began: shaded, so it never reads as zero.
    var firstKnown = -1;
    for (var k = 0; k < n; k++) {
      if (opts.series.some(function (s) { return s.values[k] != null; })) { firstKnown = k; break; }
    }
    if (firstKnown > 0) {
      parts.push('<rect class="chart-unknown" x="' + padL + '" y="' + padT + '" width="' + (firstKnown * step).toFixed(1) + '" height="' + plotH + '"/>');
      if (firstKnown * step > 90) {
        parts.push('<text class="chart-unknown-lab" x="' + (padL + firstKnown * step / 2).toFixed(1) + '" y="' + (padT + plotH / 2).toFixed(1) + '" text-anchor="middle">not collected yet</text>');
      }
    }
    var every = Math.max(1, Math.ceil(n / 5));
    for (var j = 0; j < n; j += every) {
      parts.push('<text class="chart-xlab" x="' + x(j).toFixed(1) + '" y="' + (H - 8) + '">' + esc(timeLabel(opts.buckets[j], opts.bucketSeconds)) + '</text>');
    }
    if (stacked) {
      var bw = Math.max(1, step - (step > 4 ? 2 : 0));
      for (var b = 0; b < n; b++) {
        var base = 0;
        opts.series.forEach(function (s) {
          var v = s.values[b];
          if (!v) return;
          var y0 = y(base), y1 = y(base + v);
          parts.push('<rect class="chart-bar ' + s.cls + '" x="' + (x(b) + (step - bw) / 2).toFixed(1) + '" y="' + y1.toFixed(1) + '" width="' + bw.toFixed(1) + '" height="' + Math.max(1, y0 - y1).toFixed(1) + '"/>');
          base += v;
        });
      }
    } else {
      opts.series.forEach(function (s) {
        var d = '', pen = false;
        for (var i2 = 0; i2 < n; i2++) {
          var v = s.values[i2];
          if (v == null) { pen = false; continue; }
          d += (pen ? 'L' : 'M') + (x(i2) + step / 2).toFixed(1) + ' ' + y(v).toFixed(1);
          pen = true;
        }
        parts.push('<path class="chart-line ' + s.cls + '" d="' + d + '"/>');
      });
    }
    parts.push('</svg>');
    return parts.join('');
  }

  function legend(items) {
    return '<div class="chart-legend">' + items.map(function (it) {
      return '<span class="chart-key"><i class="chart-swatch ' + it.cls + '"></i>' + esc(it.label) + '</span>';
    }).join('') + '</div>';
  }

  // ---------------------------------------------------------------- page sections

  function tile(k, v, sub) {
    return '<div class="stat"><div class="stat-label">' + esc(k) + '</div>' +
      '<div class="stat-value' + (v == null ? ' na' : '') + '">' + (v == null ? 'unavailable' : v) + '</div>' +
      '<div class="stat-sub">' + (sub || '&nbsp;') + '</div></div>';
  }

  function nodeNames(ids, names) {
    return ids.map(function (id) { return (names && names[id]) || id; }).join(', ');
  }

  function renderHeader(st) {
    var a = st.query.address;
    var M = st.miners;
    var on = M && M.summary.online > 0;
    var badge = !M || !M.answered.length ? '<span class="badge off">no node answered</span>'
      : on ? '<span class="badge on">mining</span>' : M.summary.workers ? '<span class="badge idle">not mining now</span>' : '<span class="badge off">not seen</span>';
    var from = M && M.answered.length ? 'From ' + esc(nodeNames(M.answered, st.names)) + (M.network && M.network !== 'mainnet' ? ' · ' + esc(M.network) : '') : '';
    return '<div class="miner-head">' + badge + '<span class="muted">' + from + '</span></div>' +
      '<h1 class="miner-addr">' + esc(a.slice(0, 10) + '…' + a.slice(-6)) + (st.query.worker ? '<span class="miner-worker">.' + esc(st.query.worker) + '</span>' : '') + '</h1>' +
      '<div class="mono muted break">' + esc(a) + '</div>';
  }

  function renderTiles(st) {
    var M = st.miners;
    var s = M && M.answered.length ? M.summary : null;
    var h24 = s ? P.hashrateText(s.hashrate_hs['24h']) : null;
    var acc = s ? s.shares_24h.accepted : 0;
    var bad = s ? s.shares_24h.stale + s.shares_24h.rejected : 0;
    var rate = acc + bad > 0 ? 100 * bad / (acc + bad) : null;
    var w = M ? M.wait : null;
    return '<div class="stats">' +
      tile('Hashrate, last hour', s ? (hashrateHtml(s.hashrate_hs['1h']) || 'not enough data') : null,
        s ? (h24 ? '24 hours: ' + esc(h24) : '24 hours: not enough data') : 'no node answered') +
      tile('Workers online', s ? esc(fmtInt(s.online)) + '<span class="unit">of ' + esc(fmtInt(s.workers)) + '</span>' : null,
        s ? (s.idle ? esc(fmtInt(s.idle)) + ' connected but quiet' : 'last share ' + esc(ago(s.last_share_at, st.now))) : 'no node answered') +
      tile('Shares, 24 hours', s ? esc(fmtInt(acc)) : null,
        s ? (rate == null ? 'none submitted' : esc(rate.toFixed(rate < 1 ? 2 : 1)) + '% stale or rejected') : 'no node answered') +
      tile('Best share', s ? (s.best_share.ever == null ? 'none yet' : esc(fmtDifficulty(s.best_share.ever))) : null,
        s && s.best_share['24h'] != null ? esc(fmtDifficulty(s.best_share['24h'])) + ' in the last 24 hours' : '') +
      tile('Blocks found', M && M.answered.length ? esc(fmtInt(M.blocks.length)) : null, M && M.blocks.length ? 'latest at height ' + esc(fmtInt(M.blocks[0].height)) : 'none yet') +
      tile('Expected time to a block', w && w.known ? '~' + esc(fmtDuration(w.seconds)) : w && M && M.answered.length ? 'unknown' : null,
        w && w.known ? 'an average, not a promise' : w ? esc(w.reason) : 'no node answered') +
      '</div>';
  }

  // The odds, said plainly.
  function renderOdds(st) {
    var M = st.miners;
    var w = M ? M.wait : null;
    if (!w || !w.known) {
      return '<p class="muted">The odds need a hashrate and the network difficulty' + (w && w.reason ? ': ' + esc(w.reason) : '') + '.</p>';
    }
    var hr = P.hashrateText(w.hashrate);
    return '<div class="odds">' +
      '<div class="odds-row"><span>Within a day</span><strong>' + esc(P.fmtChance(w.day)) + '</strong></div>' +
      '<div class="odds-row"><span>Within a month</span><strong>' + esc(P.fmtChance(w.month)) + '</strong></div>' +
      '<div class="odds-row"><span>Within a year</span><strong>' + esc(P.fmtChance(w.year)) + '</strong></div>' +
      '</div>' +
      '<p class="note">At ' + esc(hr) + ' (your ' + (w.window === '1h' ? 'last hour' : 'last 24 hours') + ', on every node) against network difficulty ' +
      esc(fmtDifficulty(w.difficulty)) + ', the average wait for a block is ' + esc(fmtDuration(w.seconds)) +
      '. Every hash is an independent draw: past luck changes nothing, and the real wait can be far shorter or far longer. Most small miners never find a block.</p>';
  }

  function renderWorkers(st) {
    var M = st.miners;
    if (!M || !M.answered.length) return '<div class="chart-empty">Worker details are unavailable: no node answered.</div>';
    var missing = M.failed.length ? '<p class="note">Not answering: ' + esc(nodeNames(M.failed, st.names)) + '. Workers connected there are missing from this list.</p>' : '';
    if (!M.workers.length) {
      return '<div class="chart-empty">No answering node has seen a worker for this address. Workers appear here within a minute of their first accepted share.</div>' + missing;
    }
    var rows = M.workers.map(function (w) {
      var sel = st.query.worker && st.query.worker === w.name ? ' class="selected"' : '';
      var c = w.shares_24h || {};
      var reasons = Object.keys(c.reject_reasons || {}).map(function (k) { return k + ': ' + c.reject_reasons[k]; }).join(', ');
      var best = w.best_share || {};
      return '<tr' + sel + '>' +
        '<td><a href="' + esc(queryString({ address: st.query.address, worker: w.name, window: st.query.window })) + '" data-worker="' + esc(w.name) + '">' + esc(w.name || '(no worker name)') + '</a>' +
          '<div class="sub">' + esc((st.names && st.names[w.node]) || w.node) + '</div></td>' +
        '<td><span class="status ' + esc(w.status) + '">' + esc(w.status) + '</span><div class="sub">last share ' + esc(ago(w.last_share_at, st.now)) + '</div></td>' +
        '<td class="num">' + (hashrateHtml(w.hashrate_hs ? w.hashrate_hs['1h'] : null) || '—') + '</td>' +
        '<td class="num">' + esc(fmtInt(c.accepted || 0)) + '<div class="sub"' + (reasons ? ' title="' + esc(reasons) + '"' : '') + '>' + esc(fmtInt(c.stale || 0)) + ' stale · ' + esc(fmtInt(c.rejected || 0)) + ' rejected</div></td>' +
        '<td class="num">' + (isNum(best.ever) && best.ever > 0 ? esc(fmtDifficulty(best.ever)) : '—') + '</td>' +
        '</tr>';
    }).join('');
    return '<div class="table-wrap"><table class="table">' +
      '<thead><tr><th>Worker</th><th>Status</th><th class="num">Hashrate, 1 h</th><th class="num">Shares, 24 h</th><th class="num">Best share</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>' + missing;
  }

  function selected(st) {
    var H = st.history;
    var w = st.query.worker;
    return w && H.workers[w] ? { s: H.workers[w], label: 'worker ' + w } : { s: H.total, label: 'all workers' };
  }

  function renderHashrateChart(st, width) {
    var H = st.history;
    if (!H || !H.answered.length) return '<div class="chart-empty">Hashrate history is unavailable: no node answered.</div>';
    var sel = selected(st);
    var names = Object.keys(H.workers).sort();
    var chips = '<div class="chips" role="group" aria-label="Worker">' +
      '<button type="button" class="chip' + (sel.label === 'all workers' ? ' on' : '') + '" data-worker="">all workers</button>' +
      names.map(function (n) {
        return '<button type="button" class="chip' + (st.query.worker === n ? ' on' : '') + '" data-worker="' + esc(n) + '">' + esc(n || '(no name)') + '</button>';
      }).join('') + '</div>';
    return chips + chartSvg({
      id: 'hashrate', label: 'Hashrate of ' + sel.label, buckets: H.buckets, bucketSeconds: H.bucket_seconds, kind: 'line',
      series: [{ values: sel.s.hashrate_hs, cls: 's1' }], width: width,
      yFmt: function (v) { return P.hashrateText(v) || ''; },
      empty: 'No shares in this window.'
    });
  }

  function renderSharesChart(st, width) {
    var H = st.history;
    if (!H || !H.answered.length) return '<div class="chart-empty">Share history is unavailable: no node answered.</div>';
    var src = selected(st).s;
    var reasons = Object.keys(H.reasons);
    return legend([{ label: 'accepted', cls: 's1' }, { label: 'stale', cls: 's2' }, { label: 'rejected', cls: 's3' }]) +
      chartSvg({
        id: 'shares', label: 'Shares', buckets: H.buckets, bucketSeconds: H.bucket_seconds, kind: 'bars',
        series: [{ values: src.accepted, cls: 's1' }, { values: src.stale, cls: 's2' }, { values: src.rejected, cls: 's3' }],
        width: width, yFmt: function (v) { return fmtInt(v) || ''; }, empty: 'No shares in this window.'
      }) +
      (reasons.length ? '<p class="note">Rejected in this window (all workers): ' + reasons.map(function (k) {
        return esc(fmtInt(H.reasons[k])) + ' ' + esc(REASON_WORDS[k] || k);
      }).join(', ') + '.</p>' : '');
  }

  function renderBlocks(st) {
    var M = st.miners;
    if (!M || !M.answered.length) return '<div class="chart-empty">Blocks found are unavailable: no node answered.</div>';
    if (!M.blocks.length) {
      return '<p class="muted">This address has not found a block on Ghost Pool' + (M.failed.length ? ' (as far as the answering nodes know)' : '') + '.</p>';
    }
    var rows = M.blocks.map(function (b) {
      var url = P.blockUrl(M.network, b.hash);
      var hash = url ? '<a href="' + esc(url) + '" rel="noopener">' + esc(P.shortHash(b.hash)) + '</a>' : esc(P.shortHash(b.hash));
      var subs = (b.submitted || []).map(function (s) { return s.result; });
      return '<tr><td>' + esc(fmtInt(b.height)) + '</td><td class="mono">' + hash + '</td><td>' + esc(b.worker || '—') + '</td>' +
        '<td class="num">' + esc(P.fmtBtc(b.reward_sats) || '—') + '<div class="sub">fees ' + esc(P.fmtBtc(b.fees_sats) || '—') + ' · treasury ' + esc(P.fmtBtc(b.treasury_sats) || '—') + '</div></td>' +
        '<td>' + esc(ago(b.found_at, st.now)) + (subs.length ? '<div class="sub">backup node: ' + esc(subs.join(', ')) + '</div>' : '') + '</td></tr>';
    }).join('');
    return '<div class="table-wrap"><table class="table"><thead><tr><th>Height</th><th>Block</th><th>Worker</th><th class="num">Paid to you</th><th>Found</th></tr></thead><tbody>' +
      rows + '</tbody></table></div>' +
      '<p class="note">A block is listed when the pool submits it, before the network has its say: check it on a block explorer. The coinbase can be spent after 100 more blocks (about 17 hours).</p>';
  }

  function noNodesHtml() {
    return '<div class="chart-empty">The node list could not be loaded, so there is no node to ask.</div>';
  }

  // Everything the page shows, from the fetched state. Pure.
  function renderAll(st, width) {
    if (st.noNodes) {
      var msg = noNodesHtml();
      return { header: '<div class="mono muted break">' + esc(st.query.address) + '</div>', tiles: msg, odds: '', workers: '', hashrate: '', shares: '', blocks: '' };
    }
    return {
      header: renderHeader(st),
      tiles: renderTiles(st),
      odds: renderOdds(st),
      workers: renderWorkers(st),
      hashrate: renderHashrateChart(st, width),
      shares: renderSharesChart(st, width),
      blocks: renderBlocks(st)
    };
  }

  // ---------------------------------------------------------------- browser

  // ---------------------------------------------------------------- the live miner list

  // results: [{ node, ok, body }] from each node's /api/v1/pool/miners. One row per address, its
  // workers and hashrate added up over the nodes it is connected to, the most hashrate first.
  function mergeMinerLists(results) {
    var out = { answered: [], failed: [], miners: [] };
    var by = {};
    (results || []).forEach(function (r) {
      var list = r.ok && r.body && Array.isArray(r.body.miners) ? r.body.miners : null;
      if (!list) { out.failed.push(r.node); return; }
      out.answered.push(r.node);
      list.forEach(function (e) {
        if (!e || typeof e.address !== 'string' || !e.address) return;
        var m = by[e.address];
        if (!m) {
          m = by[e.address] = { address: e.address, nodes: [], workers: 0, online: 0,
                                hashrate: null, best: null, last_share_at: null, blocks: 0 };
          out.miners.push(m);
        }
        m.nodes.push(r.node);
        m.workers += isNum(e.workers) ? e.workers : 0;
        m.online += isNum(e.online) ? e.online : 0;
        var h = e.hashrate_hs || {};
        m.hashrate = addOrNull(m.hashrate, isNum(h['15m']) ? h['15m'] : null);
        m.best = maxOrNull(m.best, e.best_share ? e.best_share.ever : null);
        m.last_share_at = maxOrNull(m.last_share_at, e.last_share_at);
        m.blocks += isNum(e.blocks_found) ? e.blocks_found : 0;
      });
    });
    out.miners.sort(function (a, b) {
      return (b.hashrate || 0) - (a.hashrate || 0) || (a.address < b.address ? -1 : 1);
    });
    return out;
  }

  // The miners whose address contains `text` (any part of it, any case).
  function filterMiners(miners, text) {
    var t = String(text || '').trim().toLowerCase();
    if (!t) return miners;
    return miners.filter(function (m) { return m.address.toLowerCase().indexOf(t) >= 0; });
  }

  function shortAddress(a) { return a.length > 20 ? a.slice(0, 10) + '…' + a.slice(-8) : a; }

  function minerListHtml(merged, text, now) {
    if (!merged) return '<div class="chart-empty">Loading the live miners…</div>';
    if (!merged.answered.length) return '<div class="chart-empty">The live miner list is unavailable: no node answered.</div>';
    var missing = merged.failed.length ? '<p class="note">Not answering: ' + esc(merged.failed.join(', ')) + '. Miners connected there are missing from this list.</p>' : '';
    if (!merged.miners.length) return '<div class="chart-empty">No miners are connected right now.</div>' + missing;
    var shown = filterMiners(merged.miners, text);
    if (!shown.length) return '<div class="chart-empty">No live miner\'s address contains “' + esc(String(text).trim()) + '”. Enter the whole address to look it up anyway.</div>' + missing;
    var total = merged.miners.reduce(function (s, m) { return s + (m.hashrate || 0); }, 0);
    var rows = shown.map(function (m) {
      return '<tr>' +
        '<td><a class="mono" href="' + esc(queryString({ address: m.address })) + '" title="' + esc(m.address) + '">' + esc(shortAddress(m.address)) + '</a></td>' +
        // Online only: a worker that moved node is still listed (offline) on the node it left for
        // 24 h, so totals over nodes count it twice. A connection is on one node at a time.
        '<td class="num">' + esc(fmtInt(m.online)) + '</td>' +
        '<td class="num">' + (hashrateHtml(m.hashrate) || '—') + '</td>' +
        '<td class="num opt">' + (isNum(m.best) && m.best > 0 ? esc(fmtDifficulty(m.best)) : '—') + '</td>' +
        '<td class="num opt">' + esc(ago(m.last_share_at, now)) + '</td>' +
        '</tr>';
    }).join('');
    var count = shown.length === merged.miners.length
      ? plural(merged.miners.length, 'miner') + ', ' + (P.hashrateText(total) || '0 H/s') + ' in all.'
      : fmtInt(shown.length) + ' of ' + plural(merged.miners.length, 'miner') + ' match.';
    return '<div class="table-wrap"><table class="table miner-list">' +
      '<thead><tr><th>Address</th><th class="num" title="Workers connected and sending shares now">Online</th><th class="num" title="Averaged over the last 15 minutes">Hashrate</th><th class="num opt">Best share</th><th class="num opt">Last share</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div><p class="note">' + esc(count) + '</p>' + missing;
  }

  function startMinerList(doc, win) {
    var input = doc.getElementById('lookup-input');
    var box = doc.getElementById('ml-list');
    var merged = null, last = null, loading = false;
    function paint() {
      var html = minerListHtml(merged, input.value, Date.now() / 1000);
      if (html !== last) { last = html; box.innerHTML = html; }
    }
    function load() {
      if (loading) return;
      loading = true;
      P.loadNodes().then(function (nodes) {
        return nodes.length ? P.askAll(nodes, '/api/v1/pool/miners') : [];
      }).then(function (r) {
        loading = false;
        var m = mergeMinerLists(r);
        if (m.answered.length || !merged) merged = m;
        paint();
      });
    }
    input.addEventListener('input', paint);
    paint();
    load();
    setInterval(function () { if (!doc.hidden) load(); }, REFRESH_MS);
    // Submitting part of an address that only one live miner has opens that miner.
    return function (v) {
      var hits = merged ? filterMiners(merged.miners, v) : [];
      return hits.length === 1 ? hits[0].address : v;
    };
  }

  function startBrowser(doc, win) {
    var q = parseQuery(win.location.search);
    var $ = function (id) { return doc.getElementById(id); };
    var shown = {};
    function put(id, html) {
      if (shown[id] === html) return;   // unchanged: leave the DOM alone, no flicker
      shown[id] = html;
      var el = $(id);
      if (el) el.innerHTML = html;
    }
    function show(id, on) { var el = $(id); if (el) el.hidden = !on; }

    var resolve = function (v) { return v; };
    $('lookup-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var v = resolve($('lookup-input').value.trim());
      if (v) win.location.search = queryString(parseQuery('?address=' + encodeURIComponent(v)));
    });

    if (!q.address) {
      show('lookup-mode', true);
      show('list-mode', true);
      resolve = startMinerList(doc, win);
      return;
    }

    var state = { query: q, miners: null, history: null, now: Date.now() / 1000, names: {} };
    var loading = false;

    function width() {
      var el = $('mp-hashrate');
      return el && el.clientWidth ? el.clientWidth : 640;
    }

    function paint() {
      var html = renderAll(state, width());
      Object.keys(html).forEach(function (k) { put('mp-' + k, html[k]); });
      doc.title = q.address.slice(0, 10) + '… · Ghost Pool';
      doc.querySelectorAll('[data-window]').forEach(function (b) {
        b.classList.toggle('on', b.getAttribute('data-window') === q.window);
      });
    }

    function load() {
      if (loading) return;
      loading = true;
      var addr = encodeURIComponent(q.address);
      P.loadNodes().then(function (nodes) {
        state.noNodes = !nodes.length;
        nodes.forEach(function (n) { state.names[n.id] = n.name; });
        if (state.noNodes) return null;
        return Promise.all([
          P.askAll(nodes, '/api/v1/miner/' + addr),
          P.askAll(nodes, '/api/v1/miner/' + addr + '/history?window=' + q.window)
        ]);
      }).then(function (r) {
        loading = false;
        state.now = Date.now() / 1000;
        if (r) {
          var m = mergeMiners(r[0]);
          if (m.refused && !m.answered.length) {
            show('lookup-mode', true);
            show('error-mode', true);
            show('miner-body', false);
            $('lookup-input').value = q.address;
            $('error-msg').textContent = m.refused;
            return;
          }
          // Keep the last good answer on a failed refresh rather than blanking the page.
          if (m.answered.length || !state.miners) state.miners = m;
          var h = mergeHistories(r[1]);
          if (h.answered.length || !state.history) state.history = h;
        }
        show('miner-body', true);
        $('mp-updated').textContent = 'Updated ' + new Date().toLocaleTimeString() + '. Refreshes every minute.';
        paint();
      });
    }

    function navigate(next) {
      var changedWindow = next.window !== q.window;
      q.worker = next.worker;
      q.window = next.window;
      if (win.history && win.history.replaceState) win.history.replaceState(null, '', queryString(q));
      if (changedWindow) { state.history = null; paint(); load(); } else paint();
    }

    doc.addEventListener('click', function (e) {
      var t = e.target.closest ? e.target.closest('[data-worker],[data-window]') : null;
      if (!t) return;
      e.preventDefault();
      if (t.hasAttribute('data-window')) navigate({ worker: q.worker, window: t.getAttribute('data-window') });
      else navigate({ worker: t.getAttribute('data-worker'), window: q.window });
    });

    var resizeTimer = null;
    win.addEventListener('resize', function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(paint, 150);
    });

    load();
    setInterval(function () { if (!doc.hidden) load(); }, REFRESH_MS);
  }

  var api = {
    parseQuery: parseQuery, queryString: queryString, mergeMiners: mergeMiners, mergeHistories: mergeHistories,
    expectedWait: expectedWait, chartSvg: chartSvg, renderAll: renderAll,
    mergeMinerLists: mergeMinerLists, filterMiners: filterMiners, minerListHtml: minerListHtml
  };
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.MinerPage = api;
    var go = function () { startBrowser(document, window); };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', go);
    else go();
  }
})(this);
