/* Bitcoin Ghost: the miner page (miner.html).
 *
 * Which nodes: the listed ones in /node-list.json, written by `ghost-audit list` (open listing,
 * W2.10). A node is addressed by its listed host, through the website's per-node proxy
 * (/api/pool/<host>/...), which must forward only to hosts in that file. With no listed node
 * the page says so; it never falls back to a fixed list.
 *
 * Reads, from each node:
 *   /api/v1/ledger/{address}                    the share chain's ledger: the same on every node
 *   /api/v1/miner/{address}                     workers on that node, expected wait
 *   /api/v1/miner/{address}/history?window=...  hashrate, shares and balance over time
 *
 * A miner's shares are seen only by the node it is connected to, so the worker and history
 * calls go to every node and are merged; the ledger is asked of the first node that answers.
 * Anything that did not answer shows as "unavailable". Nothing is guessed or filled in.
 *
 * Rendering is pure (functions of the fetched data returning HTML strings), so it can be
 * checked under node without a browser: scripts/web-tests/miner-page.test.js.
 */
(function (root) {
  'use strict';

  var NODE_LIST_URL = '/node-list.json';
  var REFRESH_MS = 60000;
  var TIMEOUT_MS = 10000;
  var WINDOWS = ['24h', '7d', '30d'];
  var SLOT_CLASS_HARDWARE = {
    3: 'NiceHash-size coinbase',
    9: 'stock Antminer S19',
    44: 'Antminer S21',
    143: 'Whatsminer, Avalon, S9/S17',
    364: 'Braiins OS, ePIC',
    500: 'full size: large-coinbase firmware or SV2'
  };
  var REASON_WORDS = {
    'invalid-share': 'the share did not check out',
    'invalid-job-id': 'work on a job the node no longer holds',
    'difficulty-too-low': 'the hash missed the job’s target',
    'duplicate-share': 'the same share sent twice',
    'bad-extranonce-size': 'malformed extranonce',
    'other': 'other errors (the connection was dropped)'
  };

  // ---------------------------------------------------------------- formatting

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function fmtHashrate(hs) {
    if (hs == null || !isFinite(hs)) return null;
    var units = ['H/s', 'kH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s'];
    var i = 0;
    var v = hs;
    while (Math.abs(v) >= 1000 && i < units.length - 1) { v /= 1000; i++; }
    return { v: v === 0 ? '0' : v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0), unit: units[i] };
  }

  function hashrateHtml(hs) {
    var f = fmtHashrate(hs);
    return f ? esc(f.v) + '<span class="unit">' + f.unit + '</span>' : null;
  }

  function fmtSatsText(s) {
    if (s == null || !isFinite(s)) return '—';
    if (Math.abs(s) < 100000) return Number(s).toLocaleString('en-US') + ' sats';
    return (s / 1e8).toFixed(8) + ' BTC';
  }

  function satsHtml(s) {
    if (s == null || !isFinite(s)) return '—';
    if (Math.abs(s) < 100000) return Number(s).toLocaleString('en-US') + '<span class="unit">sats</span>';
    return (s / 1e8).toFixed(8) + '<span class="unit">BTC</span>';
  }

  function fmtDuration(secs) {
    if (secs == null || !isFinite(secs)) return '—';
    if (secs < 90) return Math.max(1, Math.round(secs)) + ' s';
    if (secs < 5400) return Math.round(secs / 60) + ' min';
    if (secs < 2 * 86400) return (secs / 3600).toFixed(1) + ' hours';
    if (secs < 60 * 86400) return (secs / 86400).toFixed(1) + ' days';
    return (secs / (30.44 * 86400)).toFixed(1) + ' months';
  }

  function ago(t, now) {
    if (t == null) return 'never';
    var d = now - t;
    if (d < 5) return 'just now';
    return fmtDuration(d) + ' ago';
  }

  function shortHash(h) { return h ? h.slice(0, 10) + '…' + h.slice(-6) : '—'; }

  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }

  function blockUrl(network, hash) {
    if (!hash) return null;
    if (network === 'mainnet') return 'https://mempool.space/block/' + hash;
    if (network === 'signet') return null; // our own signet is not on mempool.space
    return null;
  }

  // ---------------------------------------------------------------- the URL

  // ?address=<addr> (and optionally &worker=<name>); ?id=<address.worker> still works and
  // selects that worker.
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

  // results: [{ node, ok, status, body }]. Workers from every node that answered, tagged with
  // the node; summary fields added across nodes (a rate is unknown only if no node knows it).
  function mergeMiners(results) {
    var out = {
      answered: [], failed: [], workers: [], wait: null,
      summary: { workers: 0, online: 0, idle: 0, offline: 0, hashrate_hs: { '15m': null, '1h': null, '24h': null },
                 shares_24h: { accepted: 0, stale: 0, rejected: 0, reject_reasons: {} }, last_share_at: null }
    };
    results.forEach(function (r) {
      if (!r.ok || !r.body || !Array.isArray(r.body.workers)) { out.failed.push(r.node); return; }
      out.answered.push(r.node);
      var b = r.body;
      b.workers.forEach(function (w) {
        var copy = Object.assign({}, w, { node: r.node, node_id: b.node_id });
        out.workers.push(copy);
      });
      var s = b.summary || {};
      ['workers', 'online', 'idle', 'offline'].forEach(function (k) { out.summary[k] += s[k] || 0; });
      ['15m', '1h', '24h'].forEach(function (k) {
        var v = s.hashrate_hs ? s.hashrate_hs[k] : null;
        if (v != null) out.summary.hashrate_hs[k] = (out.summary.hashrate_hs[k] || 0) + v;
      });
      var sh = s.shares_24h || {};
      out.summary.shares_24h.accepted += sh.accepted || 0;
      out.summary.shares_24h.stale += sh.stale || 0;
      out.summary.shares_24h.rejected += sh.rejected || 0;
      Object.keys(sh.reject_reasons || {}).forEach(function (k) {
        out.summary.shares_24h.reject_reasons[k] = (out.summary.shares_24h.reject_reasons[k] || 0) + sh.reject_reasons[k];
      });
      if (s.last_share_at != null && (out.summary.last_share_at == null || s.last_share_at > out.summary.last_share_at)) {
        out.summary.last_share_at = s.last_share_at;
      }
      // The wait comes from the share chain; every node computes it alike. Prefer a known one.
      if (b.expected_wait && (!out.wait || (!out.wait.known && b.expected_wait.known))) out.wait = b.expected_wait;
    });
    var rank = { online: 0, idle: 1, offline: 2 };
    // A worker offline on one node but online on another is shown once, where it is online.
    var live = {};
    out.workers.forEach(function (w) { if (w.status !== 'offline') live[w.name] = true; });
    out.workers = out.workers.filter(function (w) { return w.status !== 'offline' || !live[w.name]; });
    out.workers.sort(function (a, b) {
      return (rank[a.status] - rank[b.status]) || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) ||
        (a.node < b.node ? -1 : 1);
    });
    return out;
  }

  function addSeries(a, b) {
    return a.map(function (x, i) {
      var y = b[i];
      if (x == null) return y == null ? null : y;
      return y == null ? x : x + y;
    });
  }

  // History from every node that answered with the same bucket grid. The total and each
  // worker are summed across nodes; the balance (the share chain's) is taken from the first.
  function mergeHistories(results) {
    var out = { answered: [], failed: [], buckets: null, bucket_seconds: null, total: null, workers: {}, reasons: {}, balance: null, collecting_since: null };
    results.forEach(function (r) {
      var b = r.body;
      if (!r.ok || !b || !Array.isArray(b.buckets)) { out.failed.push(r.node); return; }
      if (out.buckets && (b.buckets.length !== out.buckets.length || b.buckets[0] !== out.buckets[0])) {
        // A node whose clock or refresh landed in another bucket: line up on the first answer.
        var shift = (b.buckets[0] - out.buckets[0]) / out.bucket_seconds;
        if (Math.abs(shift) !== 1) { out.failed.push(r.node); return; }
        b = shiftHistory(b, shift);
      }
      out.answered.push(r.node);
      if (!out.buckets) {
        out.buckets = b.buckets.slice();
        out.bucket_seconds = b.bucket_seconds;
        out.balance = b.balance || null;
        out.collecting_since = b.collecting_since;
      } else if (b.collecting_since < out.collecting_since) {
        out.collecting_since = b.collecting_since;
      }
      ['hashrate_hs', 'accepted', 'stale', 'rejected'].forEach(function (k) {
        if (!out.total) out.total = {};
        out.total[k] = out.total[k] ? addSeries(out.total[k], b.total[k]) : b.total[k].slice();
      });
      (b.workers || []).forEach(function (w) {
        var cur = out.workers[w.name];
        if (!cur) { out.workers[w.name] = JSON.parse(JSON.stringify(w.series)); return; }
        Object.keys(cur).forEach(function (k) { cur[k] = addSeries(cur[k], w.series[k]); });
      });
      Object.keys(b.reject_reasons || {}).forEach(function (k) {
        out.reasons[k] = (out.reasons[k] || 0) + b.reject_reasons[k];
      });
    });
    return out;
  }

  // Shift a history's series by one bucket (+1: it is one bucket ahead) onto another grid.
  function shiftHistory(b, shift) {
    function sh(arr) {
      if (shift === 1) return [null].concat(arr.slice(0, -1));
      return arr.slice(1).concat([null]);
    }
    var c = JSON.parse(JSON.stringify(b));
    c.buckets = b.buckets.map(function (t) { return t - shift * b.bucket_seconds; });
    ['hashrate_hs', 'accepted', 'stale', 'rejected'].forEach(function (k) { c.total[k] = sh(b.total[k]); });
    (c.workers || []).forEach(function (w) {
      Object.keys(w.series).forEach(function (k) { w.series[k] = sh(w.series[k]); });
    });
    return c;
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
    if (bucketSeconds < 3600) {
      return ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2);
    }
    return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
  }

  // opts: { id, buckets, bucketSeconds, kind: 'line'|'bars', series: [{ key, label, values,
  // cls }], yFmt(v) -> text, width, height, markers: [{ i, label }], empty: text }
  function chartSvg(opts) {
    var W = Math.max(280, Math.round(opts.width || 640));
    var H = opts.height || 200;
    var padL = 56, padR = 12, padT = 12, padB = 26;
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
    if (!any) {
      return '<div class="mpc-empty">' + esc(opts.empty || 'No data for this window.') + '</div>';
    }
    var yMax = niceMax(max);
    var step = plotW / n;
    function x(i) { return padL + i * step; }
    function y(v) { return padT + plotH - (v / yMax) * plotH; }
    var parts = [];
    parts.push('<svg class="mpc-svg" width="' + W + '" height="' + H + '" viewBox="0 0 ' + W + ' ' + H +
      '" role="img" aria-label="' + esc(opts.label || 'chart') + '" data-chart="' + esc(opts.id) + '">');
    // Grid and y labels: 0, half, max.
    [0, 0.5, 1].forEach(function (f) {
      var gy = padT + plotH - f * plotH;
      parts.push('<line class="mpc-grid" x1="' + padL + '" x2="' + (W - padR) + '" y1="' + gy.toFixed(1) + '" y2="' + gy.toFixed(1) + '"/>');
      parts.push('<text class="mpc-ylab" x="' + (padL - 6) + '" y="' + (gy + 4).toFixed(1) + '" text-anchor="end">' + esc(opts.yFmt(yMax * f)) + '</text>');
    });
    // Unknown stretch (before collection began): shaded, so it never reads as zero.
    var firstKnown = -1;
    for (var k = 0; k < n; k++) {
      if (opts.series.some(function (s) { return s.values[k] != null; })) { firstKnown = k; break; }
    }
    if (firstKnown > 0 && !opts.neverUnknown) {
      parts.push('<rect class="mpc-unknown" x="' + padL + '" y="' + padT + '" width="' + (firstKnown * step).toFixed(1) + '" height="' + plotH + '"/>');
      if (firstKnown * step > 90) {
        parts.push('<text class="mpc-unknown-lab" x="' + (padL + firstKnown * step / 2).toFixed(1) + '" y="' + (padT + plotH / 2).toFixed(1) + '" text-anchor="middle">not collected yet</text>');
      }
    }
    // X labels: about five, at bucket starts.
    var every = Math.max(1, Math.ceil(n / 5));
    for (var j = 0; j < n; j += every) {
      parts.push('<text class="mpc-xlab" x="' + x(j).toFixed(1) + '" y="' + (H - 8) + '">' + esc(timeLabel(opts.buckets[j], opts.bucketSeconds)) + '</text>');
    }
    if (stacked) {
      var bw = Math.max(1, step - (step > 4 ? 2 : 0));
      for (var b = 0; b < n; b++) {
        var base = 0;
        opts.series.forEach(function (s) {
          var v = s.values[b];
          if (!v) return;
          var y0 = y(base), y1 = y(base + v);
          parts.push('<rect class="mpc-bar ' + s.cls + '" x="' + (x(b) + (step - bw) / 2).toFixed(1) + '" y="' + y1.toFixed(1) + '" width="' + bw.toFixed(1) + '" height="' + Math.max(1, y0 - y1).toFixed(1) + '"/>');
          base += v;
        });
      }
    } else {
      opts.series.forEach(function (s) {
        var d = '', pen = false;
        for (var i2 = 0; i2 < n; i2++) {
          var v = s.values[i2];
          if (v == null) { pen = false; continue; }
          var px = x(i2) + step / 2;
          if (opts.step && pen) d += 'H' + (x(i2)).toFixed(1) + 'V' + y(v).toFixed(1) + 'H' + px.toFixed(1);
          else d += (pen ? 'L' : 'M') + px.toFixed(1) + ' ' + y(v).toFixed(1);
          pen = true;
        }
        parts.push('<path class="mpc-line ' + s.cls + '" d="' + d + '"/>');
      });
    }
    (opts.markers || []).forEach(function (m) {
      var mv = opts.series[0].values[m.i];
      if (mv == null) return;
      parts.push('<circle class="mpc-marker" cx="' + (x(m.i) + step / 2).toFixed(1) + '" cy="' + y(mv).toFixed(1) + '" r="5"><title>' + esc(m.label) + '</title></circle>');
    });
    parts.push('<line class="mpc-cross" x1="0" x2="0" y1="' + padT + '" y2="' + (padT + plotH) + '" visibility="hidden"/>');
    parts.push('<rect class="mpc-hit" x="' + padL + '" y="' + padT + '" width="' + plotW + '" height="' + plotH + '" data-n="' + n + '" data-padl="' + padL + '" data-step="' + step.toFixed(4) + '"/>');
    parts.push('</svg>');
    return parts.join('');
  }

  function legend(items) {
    return '<div class="mpc-legend">' + items.map(function (it) {
      return '<span class="mpc-key"><i class="mpc-swatch ' + it.cls + (it.dot ? ' dot' : '') + '"></i>' + esc(it.label) + '</span>';
    }).join('') + '</div>';
  }

  // ---------------------------------------------------------------- page sections

  function tile(k, v, sub, help) {
    return '<div class="mp-tile"><div class="k' + (help ? ' k-help' : '') + '"' + (help ? ' title="' + esc(help) + '"' : '') + '>' + esc(k) + '</div>' +
      '<div class="v' + (v == null ? ' mp-na' : '') + '">' + (v == null ? 'unavailable' : v) + '</div>' +
      '<div class="sub">' + (sub || '&nbsp;') + '</div></div>';
  }

  function waitText(wait) {
    if (!wait) return { v: null, sub: 'no node answered' };
    if (!wait.known) return { v: 'unknown', sub: esc(wait.reason || 'not enough data') };
    return { v: '~' + esc(fmtDuration(wait.seconds)), sub: 'estimate: ' + plural(wait.blocks_needed, 'pool block') };
  }

  function renderTiles(st) {
    var L = st.ledger && st.ledger.ok ? st.ledger.body : null;
    var M = st.miners;
    var have = M && M.answered.length > 0;
    var s = have ? M.summary : null;
    var h1 = s ? hashrateHtml(s.hashrate_hs['1h']) : null;
    var h24 = s ? fmtHashrate(s.hashrate_hs['24h']) : null;
    var acc = s ? s.shares_24h.accepted : 0;
    var bad = s ? s.shares_24h.stale + s.shares_24h.rejected : 0;
    var rate = acc + bad > 0 ? (100 * bad / (acc + bad)) : null;
    var w = waitText(M ? M.wait : null);
    var paid = L ? L.payouts.reduce(function (a, p) { return a + p.sats; }, 0) : null;
    return '<div class="mp-tiles mp2-tiles">' +
      tile('balance', L ? satsHtml(L.balance.sats) : null,
        L ? (L.balance.sats >= (L.min_payout_sats || 1000) ? 'at or over the 1,000-sat floor' : esc(fmtSatsText((L.min_payout_sats || 1000) - L.balance.sats)) + ' to the floor') : 'ledger unavailable',
        'What your credited shares earned, minus what blocks have paid you. The same on every node.') +
      tile('hashrate · 1 h', s ? (h1 || '—') : null,
        s ? (h24 ? '24 h: ' + esc(h24.v) + ' ' + h24.unit : '24 h: not enough data') : 'no node answered',
        'Estimated from the difficulty of the shares the nodes accepted. Shares are random, so short windows are noisy.') +
      tile('workers', s ? esc(s.online) + '<span class="unit">/ ' + esc(s.workers) + ' online</span>' : null,
        s ? (s.idle ? esc(s.idle) + ' connected but quiet' : (s.last_share_at ? 'last share ' + esc(ago(s.last_share_at, st.now)) : 'no shares seen')) : 'no node answered') +
      tile('shares · 24 h', s ? esc(acc.toLocaleString('en-US')) : null,
        s ? (rate == null ? 'none submitted' : esc(rate.toFixed(rate < 1 ? 2 : 1)) + '% stale or rejected') : 'no node answered',
        'Accepted shares at your miners’ own difficulty. Only shares at or above the network tier are credited to the ledger.') +
      tile('next payment', w.v, w.sub,
        'An estimate from your place in the queue and how often the pool has found blocks recently. See below.') +
      tile('paid', L ? satsHtml(paid) : null, L ? esc(plural(L.payouts.length, 'payout')) + ' listed' : 'ledger unavailable') +
      '</div>';
  }

  function slotHtml(c) {
    if (c == null) return '—';
    return esc(c) + '<div class="py-shares-sub">' + esc(SLOT_CLASS_HARDWARE[c] || '') + '</div>';
  }

  function renderWorkers(st) {
    var M = st.miners;
    if (!M || !M.answered.length) {
      return '<div class="mpc-empty">Worker details are unavailable: no node answered.</div>';
    }
    if (!M.workers.length) {
      return '<div class="mpc-empty">No node has seen a worker for this address in the last 30 days. Workers appear here within a minute of their first share.</div>';
    }
    var rows = M.workers.map(function (w) {
      var sel = st.query.worker && st.query.worker === w.name ? ' mpw-selected' : '';
      var c = w.shares_24h || { accepted: 0, stale: 0, rejected: 0 };
      var hr = hashrateHtml(w.hashrate_hs ? w.hashrate_hs['1h'] : null) || '—';
      var reasons = Object.keys(c.reject_reasons || {}).map(function (k) { return k + ': ' + c.reject_reasons[k]; }).join(', ');
      return '<tr class="mpw-row' + sel + '">' +
        '<td class="mpw-name"><a href="' + esc(queryString({ address: st.query.address, worker: w.name, window: st.query.window })) + '" data-worker="' + esc(w.name) + '">' + esc(w.name || '(no worker name)') + '</a>' +
          '<div class="py-shares-sub">node ' + esc(w.node) + '</div></td>' +
        '<td><span class="mpw-status ' + esc(w.status) + '">' + esc(w.status) + '</span>' +
          '<div class="py-shares-sub">last share ' + esc(ago(w.last_share_at, st.now)) + '</div></td>' +
        '<td class="mpw-num">' + hr + '</td>' +
        '<td class="mpw-num">' + esc((c.accepted || 0).toLocaleString('en-US')) +
          '<div class="py-shares-sub"' + (reasons ? ' title="' + esc(reasons) + '"' : '') + '>' + esc(c.stale) + ' stale · ' + esc(c.rejected) + ' rejected</div></td>' +
        '<td class="mpw-num">' + slotHtml(w.slot_class) + '</td>' +
        '</tr>' +
        (w.firmware_warning ? '<tr class="mpw-warn' + sel + '"><td colspan="5">⚠ ' + esc(w.firmware_warning) + '. Your balance is not reduced by this; blocks this worker finds pay fewer balances.</td></tr>' : '');
    }).join('');
    return '<div class="lb-table-wrap mpw-wrap"><table class="lb-table mpw-table">' +
      '<thead><tr><th>worker</th><th>status</th><th class="mpw-num">hashrate 1 h</th><th class="mpw-num">shares 24 h</th><th class="mpw-num">slot class</th></tr></thead>' +
      '<tbody>' + rows + '</tbody></table></div>' +
      (M.failed.length ? '<p class="payout-note">Not answering: ' + esc(M.failed.join(', ')) + '. Workers connected there are missing from this list.</p>' : '');
  }

  function renderHashrateChart(st, width) {
    var H = st.history;
    if (!H || !H.answered.length) return '<div class="mpc-empty">Hashrate history is unavailable: no node answered.</div>';
    var w = st.query.worker;
    var values = w && H.workers[w] ? H.workers[w].hashrate_hs : H.total.hashrate_hs;
    var label = w && H.workers[w] ? 'worker ' + w : 'all workers';
    var names = Object.keys(H.workers).sort();
    var chips = '<div class="mpc-chips" role="group" aria-label="Worker">' +
      '<button type="button" class="mpc-chip' + (!w || !H.workers[w] ? ' on' : '') + '" data-worker="">all workers</button>' +
      names.map(function (n) {
        return '<button type="button" class="mpc-chip' + (w === n ? ' on' : '') + '" data-worker="' + esc(n) + '">' + esc(n || '(no name)') + '</button>';
      }).join('') + '</div>';
    return chips + '<div class="mpc-title">' + esc(label) + '</div>' + chartSvg({
      id: 'hashrate', label: 'Hashrate of ' + label, buckets: H.buckets, bucketSeconds: H.bucket_seconds, kind: 'line',
      series: [{ key: 'h', label: 'hashrate', values: values, cls: 's1' }], width: width,
      yFmt: function (v) { var f = fmtHashrate(v); return f ? f.v + ' ' + f.unit : ''; },
      empty: 'No shares in this window.'
    });
  }

  function renderSharesChart(st, width) {
    var H = st.history;
    if (!H || !H.answered.length) return '<div class="mpc-empty">Share history is unavailable: no node answered.</div>';
    var w = st.query.worker;
    var src = w && H.workers[w] ? H.workers[w] : H.total;
    var reasons = Object.keys(H.reasons);
    return legend([{ cls: 's1', label: 'accepted' }, { cls: 's2', label: 'stale' }, { cls: 's3', label: 'rejected' }]) +
      chartSvg({
        id: 'shares', label: 'Shares per bucket', buckets: H.buckets, bucketSeconds: H.bucket_seconds, kind: 'bars',
        series: [
          { key: 'accepted', label: 'accepted', values: src.accepted, cls: 's1' },
          { key: 'stale', label: 'stale', values: src.stale, cls: 's2' },
          { key: 'rejected', label: 'rejected', values: src.rejected, cls: 's3' }
        ], width: width, yFmt: function (v) { return Math.round(v).toLocaleString('en-US'); },
        empty: 'No shares in this window.'
      }) +
      (reasons.length ? '<div class="payout-note">Rejected in this window (all workers): ' + reasons.map(function (k) {
        return '<code>' + esc(k) + '</code> ' + esc(H.reasons[k]) + ' (' + esc(REASON_WORDS[k] || k) + ')';
      }).join('; ') + '.</div>' : '');
  }

  function renderBalanceChart(st, width) {
    var H = st.history;
    if (!H || !H.balance) return '<div class="mpc-empty">Balance history is unavailable: no node answered.</div>';
    var B = H.balance;
    var markers = [];
    (B.payouts || []).forEach(function (p) {
      var i = Math.floor((p.time - H.buckets[0]) / H.bucket_seconds);
      if (i >= 0 && i < H.buckets.length) markers.push({ i: i, label: 'paid ' + fmtSatsText(p.sats) + ' at block ' + p.height });
    });
    return legend([{ cls: 's1', label: 'balance' }, { cls: 's2', label: 'payout', dot: true }]) + chartSvg({
      id: 'balance', label: 'Balance over time', buckets: H.buckets, bucketSeconds: H.bucket_seconds, kind: 'line', step: true,
      series: [{ key: 'b', label: 'balance', values: B.end_sats, cls: 's1' }], markers: markers, width: width, neverUnknown: true,
      yFmt: function (v) { return v >= 100000 ? (v / 1e8).toFixed(v >= 1e7 ? 2 : 4) + ' BTC' : Math.round(v).toLocaleString('en-US'); }
    });
  }

  function renderQueue(st) {
    var L = st.ledger && st.ledger.ok ? st.ledger.body : null;
    var wait = st.miners ? st.miners.wait : null;
    if (!L) return '<div class="mpc-empty">The ledger is unavailable: no node answered.</div>';
    var q = L.queue;
    var words = [];
    var floor = L.min_payout_sats || 1000;
    if (!q) {
      words.push('Where you stand for the next block is not known right now: ' + esc(L.queue_unavailable || 'the node has no table for it') + '.');
    } else if (!q.eligible) {
      words.push('Your balance on the table the next block pays is ' + esc(fmtSatsText(q.owed.sats)) + '. Balances are paid once they reach ' + esc(floor.toLocaleString('en-US')) + ' sats, so you are not in a payout queue yet.');
    } else if (q.is_top) {
      words.push('You hold the <strong>largest balance</strong> of the ' + esc(q.eligible_count) + ' eligible. The largest is paid last in every block, with whatever the block has left.');
    } else {
      words.push('You are <strong>#' + esc(q.age_rank) + ' in the oldest-first queue</strong> and #' + esc(q.size_rank) + ' by size, of ' + esc(q.eligible_count) + ' eligible balances. Each block pays the oldest half of its outputs first, then the largest.');
    }
    if (q) {
      words.push('The next block (height ' + esc(q.next_block_height) + ') pays balances as they stood at height ' + esc(q.snapshot_height) + ', 20 blocks earlier, so credits from the last few hours are not in it yet.');
    }
    var est;
    if (!wait) {
      est = '<p><strong>Expected wait: unavailable.</strong> No node answered.</p>';
    } else if (!wait.known) {
      est = '<p><strong>Expected wait: unknown.</strong> ' + esc(wait.reason) + '. We would rather say so than show a made-up number.</p>';
    } else {
      est = '<p><strong>Expected wait: about ' + esc(fmtDuration(wait.seconds)) + '</strong> (' + esc(plural(wait.blocks_needed, 'pool block')) + '). This is an estimate. It assumes:</p><ul class="mpq-assume">' +
        (wait.assumptions || []).map(function (a) { return '<li>' + esc(a) + '</li>'; }).join('') + '</ul>';
    }
    var table = '';
    if (q) {
      table = '<div class="lb-table-wrap"><table class="lb-table payout-table mpq-table"><thead><tr><th>outputs</th><th>found by</th><th>your place</th><th class="mpw-num">pays you</th></tr></thead><tbody>' +
        q.next_block.map(function (c) {
          return '<tr><td class="lb-rank">' + esc(c.slot_class) + '</td><td class="py-miner">' + esc(SLOT_CLASS_HARDWARE[c.slot_class] || '') + '</td>' +
            '<td class="py-shares">' + (c.in_oldest ? 'in the oldest ' + esc(c.oldest_slots) : (q.is_top ? 'top' : '—')) + '</td>' +
            '<td class="py-sats">' + satsHtml(c.sats) + '</td></tr>';
        }).join('') + '</tbody></table></div>' +
        '<p class="payout-note">How many balances a block pays depends on the firmware of the miner that finds it. Each row is one size of coinbase.</p>';
    }
    return '<div class="np-prose mpq-words"><p>' + words.join('</p><p>') + '</p>' + est + '</div>' + table;
  }

  function renderPayouts(st) {
    var L = st.ledger && st.ledger.ok ? st.ledger.body : null;
    if (!L) return '<div class="mpc-empty">Payouts are unavailable: no node answered.</div>';
    if (!L.payouts.length) return '<div class="mpc-empty">No payouts yet. A payout appears here when a pool block pays your balance.</div>';
    return '<div class="lb-table-wrap"><table class="lb-table payout-table"><thead><tr><th>block</th><th>hash</th><th>status</th><th class="mpw-num">paid</th></tr></thead><tbody>' +
      L.payouts.map(function (p) {
        var url = blockUrl(L.network, p.block_hash);
        var hash = url ? '<a href="' + esc(url) + '" rel="noopener">' + esc(shortHash(p.block_hash)) + '</a>' : esc(shortHash(p.block_hash));
        return '<tr><td class="lb-rank">' + (url ? '<a href="' + esc(url) + '" rel="noopener">' + esc(p.height) + '</a>' : esc(p.height)) + '</td>' +
          '<td class="py-miner" title="' + esc(p.block_hash) + '">' + hash + '</td>' +
          '<td class="py-shares">' + esc(p.status) + (p.confirmations != null ? '<div class="py-shares-sub">' + esc(p.confirmations) + ' conf' + (p.mature ? ', spendable' : ', spendable at 100') + '</div>' : '') + '</td>' +
          '<td class="py-sats">' + satsHtml(p.sats) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
  }

  function renderSettlement(st) {
    var L = st.ledger && st.ledger.ok ? st.ledger.body : null;
    if (!L) return '';
    var s = L.settlement;
    return s.caught_up
      ? 'Settlement is caught up to Bitcoin block ' + esc(s.bitcoin_tip) + '.'
      : 'Settlement on ' + esc(st.ledger.node) + ' is still catching up (at ' + esc(s.synced_height == null ? '?' : s.synced_height) + ' of ' + esc(s.bitcoin_tip == null ? '?' : s.bitcoin_tip) + '): recent payouts may be missing.';
  }

  function renderHeader(st) {
    var L = st.ledger && st.ledger.ok ? st.ledger.body : null;
    var a = st.query.address;
    var status = !L ? { cls: 'offline', t: 'ledger unavailable' } : L.known ? { cls: 'online', t: 'on the ledger' } : { cls: 'offline', t: 'not on the ledger yet' };
    var nodes = st.miners ? st.miners.answered : [];
    var info = (L ? esc(L.network) + ' · ledger from ' + esc(st.ledger.node) : '') +
      (nodes.length ? ' · workers from ' + esc(nodes.join(', ')) : '');
    return '<div class="mp-status-row"><div class="mp-status ' + status.cls + '">' + esc(status.t) + '</div>' +
      '<div class="mp2-nodeinfo">' + info + '</div></div>' +
      '<h1 class="mp-worker">' + esc(a.slice(0, 8) + '…' + a.slice(-6)) + (st.query.worker ? '<span class="mp2-worker">.' + esc(st.query.worker) + '</span>' : '') + '</h1>' +
      '<div class="mp-full">' + esc(a) + '</div>' +
      (L && !L.known ? '<p class="payout-note">' + esc(L.message || '') + '</p>' : '');
  }

  // Everything the page shows, from the fetched state. Pure.
  // The nodes to ask: every listed node's host, from a parsed /node-list.json. Only IP literals
  // are taken (they go into a URL path), sorted and without repeats. Anything missing or
  // malformed gives an empty list, never a default.
  function nodesFromList(list) {
    var nodes = (list && Array.isArray(list.nodes)) ? list.nodes : [];
    var out = [];
    nodes.forEach(function (n) {
      var h = n && typeof n.host === 'string' ? n.host : '';
      if (/^[0-9A-Fa-f:.]{2,45}$/.test(h) && out.indexOf(h) < 0) out.push(h);
    });
    return out.sort();
  }

  function noNodesHtml() {
    return '<div class="mpc-empty">No node is listed yet, so there is no node to ask. Nodes appear on ' +
      '<a href="/endpoints.html">the node list</a> once they pass the public probe.</div>';
  }

  function renderAll(st, width) {
    if (st.noNodes) {
      var msg = noNodesHtml();
      return {
        header: '<div class="mp-status-row"><div class="mp-status offline">no node listed</div></div>' +
          '<div class="mp-full">' + esc(st.query.address) + '</div>' + msg,
        tiles: '', workers: msg, hashrate: msg, shares: msg, balance: msg, queue: msg, payouts: msg, settlement: ''
      };
    }
    return {
      header: renderHeader(st),
      tiles: renderTiles(st),
      workers: renderWorkers(st),
      hashrate: renderHashrateChart(st, width),
      shares: renderSharesChart(st, width),
      balance: renderBalanceChart(st, width),
      queue: renderQueue(st),
      payouts: renderPayouts(st),
      settlement: renderSettlement(st)
    };
  }

  // ---------------------------------------------------------------- browser

  function fetchJson(url) {
    var ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, TIMEOUT_MS);
    return fetch(url, { cache: 'no-store', signal: ctl ? ctl.signal : undefined }).then(function (r) {
      clearTimeout(timer);
      return r.json().then(function (b) { return { status: r.status, body: b }; }, function () { return { status: r.status, body: null }; });
    }, function () { clearTimeout(timer); return { status: 0, body: null }; });
  }

  function askAll(nodes, path) {
    return Promise.all(nodes.map(function (n) {
      return fetchJson('/api/pool/' + n + path).then(function (r) {
        return { node: n, ok: r.status === 200 && !!r.body, status: r.status, body: r.body };
      });
    }));
  }

  // The ledger from the first node whose answer is the ledger's (200, or 400 for a bad address).
  function askLedger(nodes, address) {
    var path = '/api/v1/ledger/' + encodeURIComponent(address);
    var i = 0;
    var throttled = false;
    function next() {
      if (i >= nodes.length) return Promise.resolve({ ok: false, throttled: throttled });
      var n = nodes[i++];
      return fetchJson('/api/pool/' + n + path).then(function (r) {
        if (r.status === 429) throttled = true;
        if ((r.status === 200 || r.status === 400) && r.body) return { ok: r.status === 200, status: r.status, body: r.body, node: n };
        return next();
      });
    }
    return next();
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

    $('lookup-form').addEventListener('submit', function (e) {
      e.preventDefault();
      var v = $('lookup-input').value.trim();
      if (v) win.location.search = queryString(parseQuery('?address=' + encodeURIComponent(v)));
    });

    if (!q.address) {
      show('lookup-mode', true);
      show('explain', true);
      return;
    }

    var state = { query: q, ledger: null, miners: null, history: null, now: Date.now() / 1000 };
    var loading = false;

    function width() {
      var el = $('mp-hashrate');
      return el && el.clientWidth ? el.clientWidth : 640;
    }

    function paint() {
      var html = renderAll(state, width());
      Object.keys(html).forEach(function (k) { put('mp-' + k, html[k]); });
      win.document.title = q.address.slice(0, 10) + '… · Miner · Bitcoin Ghost';
      doc.querySelectorAll('[data-window]').forEach(function (b) {
        b.classList.toggle('on', b.getAttribute('data-window') === q.window);
      });
    }

    function load() {
      if (loading) return;
      loading = true;
      var addr = encodeURIComponent(q.address);
      fetchJson(NODE_LIST_URL).then(function (l) {
        var nodes = l.status === 200 ? nodesFromList(l.body) : [];
        state.noNodes = !nodes.length;
        if (state.noNodes) return null;
        return Promise.all([
          askLedger(nodes, q.address),
          askAll(nodes, '/api/v1/miner/' + addr),
          askAll(nodes, '/api/v1/miner/' + addr + '/history?window=' + q.window)
        ]);
      }).then(function (r) {
        loading = false;
        if (!r) {
          show('miner-body', true);
          show('explain', true);
          $('mp-updated').textContent = 'Checked ' + new Date().toLocaleTimeString() + '. Refreshes every minute.';
          paint();
          return;
        }
        var rl = $('rl-notice');
        if (rl) rl.classList.toggle('show', !!r[0].throttled);
        if (r[0].status === 400) {
          show('lookup-mode', true);
          show('error-mode', true);
          show('miner-body', false);
          $('lookup-input').value = q.address;
          $('error-msg').textContent = (r[0].body && r[0].body.error) || 'That is not an address the node pool can pay.';
          return;
        }
        // Keep the last good answer on a failed refresh rather than blanking the page.
        state.now = Date.now() / 1000;
        if (r[0].ok || !state.ledger) state.ledger = r[0];
        var m = mergeMiners(r[1]);
        if (m.answered.length || !state.miners) state.miners = m;
        var h = mergeHistories(r[2]);
        if (h.answered.length || !state.history) state.history = h;
        show('miner-body', true);
        show('explain', true);
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

    // Chart hover: a crosshair and the bucket's values, by mouse or touch.
    var tip = $('mp-tip');
    doc.addEventListener('pointermove', function (e) { hover(e); });
    doc.addEventListener('pointerdown', function (e) { hover(e); });
    function hover(e) {
      var svg = e.target.closest ? e.target.closest('svg.mpc-svg') : null;
      doc.querySelectorAll('.mpc-cross').forEach(function (c) { c.setAttribute('visibility', 'hidden'); });
      if (!svg || !state.history || !state.history.buckets) { tip.hidden = true; return; }
      var hit = svg.querySelector('.mpc-hit');
      var box = svg.getBoundingClientRect();
      var px = e.clientX - box.left;
      var step = parseFloat(hit.getAttribute('data-step'));
      var i = Math.floor((px - parseFloat(hit.getAttribute('data-padl'))) / step);
      var H = state.history;
      if (i < 0 || i >= H.buckets.length) { tip.hidden = true; return; }
      var cross = svg.querySelector('.mpc-cross');
      var cx = (parseFloat(hit.getAttribute('data-padl')) + (i + 0.5) * step).toFixed(1);
      cross.setAttribute('x1', cx); cross.setAttribute('x2', cx); cross.setAttribute('visibility', 'visible');
      tip.innerHTML = tipHtml(state, svg.getAttribute('data-chart'), i);
      tip.hidden = false;
      var tx = Math.min(e.clientX + 14, win.innerWidth - tip.offsetWidth - 8);
      tip.style.left = Math.max(8, tx) + 'px';
      tip.style.top = (e.clientY + win.scrollY + 14) + 'px';
    }

    var resizeTimer = null;
    win.addEventListener('resize', function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(paint, 150);
    });

    load();
    setInterval(function () { if (!doc.hidden) load(); }, REFRESH_MS);
  }

  // The tooltip for bucket i of a chart. Pure.
  function tipHtml(st, chart, i) {
    var H = st.history;
    var t = H.buckets[i];
    var head = '<div class="mpt-time">' + esc(new Date(t * 1000).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })) + '</div>';
    var w = st.query.worker && H.workers[st.query.worker] ? H.workers[st.query.worker] : H.total;
    if (chart === 'hashrate') {
      var f = fmtHashrate(w.hashrate_hs[i]);
      return head + (f ? f.v + ' ' + f.unit : 'not collected');
    }
    if (chart === 'shares') {
      if (w.accepted[i] == null) return head + 'not collected';
      return head + esc(w.accepted[i]) + ' accepted<br>' + esc(w.stale[i]) + ' stale<br>' + esc(w.rejected[i]) + ' rejected';
    }
    var B = H.balance;
    return head + 'balance ' + esc(fmtSatsText(B.end_sats[i])) + '<br>credited ' + esc(fmtSatsText(B.credited_sats[i])) +
      (B.paid_sats[i] ? '<br>paid ' + esc(fmtSatsText(B.paid_sats[i])) : '');
  }

  var api = {
    parseQuery: parseQuery, queryString: queryString, mergeMiners: mergeMiners, mergeHistories: mergeHistories,
    chartSvg: chartSvg, renderAll: renderAll, tipHtml: tipHtml, fmtHashrate: fmtHashrate, fmtDuration: fmtDuration,
    blockUrl: blockUrl, nodesFromList: nodesFromList
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
