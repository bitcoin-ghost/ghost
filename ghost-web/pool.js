/* Ghost Pool: what every page of the site shares (pool.js).
 *
 * - The pool's nodes, from /pool-nodes.json: an id (what the website's API proxy knows each node
 *   by, /api/pool/<id>/...), a name, the hostname miners connect to and, when published, the
 *   node's SV2 authority key. Nothing else is trusted from it; a malformed entry is dropped.
 * - The connect box: every node's three stratum URLs.
 * - Live pool figures: each node's /api/v1/pool/status, asked through the proxy and combined
 *   (hashrate and connections added up, best share the highest, found blocks listed once).
 *   A node that does not answer is named; a figure no node reported says "unavailable", never 0.
 * - The payout rule, worked out from a subsidy: treasury = floor(subsidy / 200), the miner the
 *   rest plus every fee.
 *
 * Rendering is pure (functions of the fetched data returning HTML strings), so it is checked
 * under plain node: scripts/web-tests/pool-site.test.js.
 */
(function (root) {
  'use strict';

  var NODES_URL = '/pool-nodes.json';
  var TIMEOUT_MS = 10000;
  var REFRESH_MS = 60000;
  var PORTS = { sv1Small: 3333, sv1Large: 4444, sv2: 34255 };
  var TREASURY = 'bc1qgxg5ywk835c9fp6arz6d6x50xpk6y0ualt900k';

  // ---------------------------------------------------------------- formatting

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  function isNum(v) { return typeof v === 'number' && isFinite(v); }

  function fmtHashrate(hs) {
    if (!isNum(hs)) return null;
    var units = ['H/s', 'kH/s', 'MH/s', 'GH/s', 'TH/s', 'PH/s', 'EH/s'];
    var i = 0;
    var v = hs;
    while (Math.abs(v) >= 1000 && i < units.length - 1) { v /= 1000; i++; }
    return { v: v === 0 ? '0' : v.toFixed(i === 0 ? 0 : v < 10 ? 2 : v < 100 ? 1 : 0), unit: units[i] };
  }

  function hashrateText(hs) {
    var f = fmtHashrate(hs);
    return f ? f.v + ' ' + f.unit : null;
  }

  function hashrateHtml(hs) {
    var f = fmtHashrate(hs);
    return f ? esc(f.v) + '<span class="unit">' + f.unit + '</span>' : null;
  }

  // A share or network difficulty, in difficulty-1 units: 4.1e9 -> "4.10 G".
  function fmtDifficulty(d) {
    if (!isNum(d)) return null;
    if (d === 0) return '0';
    var units = ['', ' k', ' M', ' G', ' T', ' P', ' E'];
    var i = 0;
    var v = d;
    while (Math.abs(v) >= 1000 && i < units.length - 1) { v /= 1000; i++; }
    return (i === 0 ? String(Math.round(v)) : v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0)) + units[i];
  }

  // Exact BTC from sats, trailing zeros trimmed to at least one decimal place.
  function fmtBtc(sats) {
    if (!isNum(sats)) return null;
    var neg = sats < 0;
    var s = Math.abs(Math.round(sats));
    var whole = Math.floor(s / 1e8);
    var frac = String(s % 1e8);
    while (frac.length < 8) frac = '0' + frac;
    frac = frac.replace(/0+$/, '');
    return (neg ? '-' : '') + whole.toLocaleString('en-US') + '.' + (frac || '0') + ' BTC';
  }

  function fmtSats(sats) {
    return isNum(sats) ? Math.round(sats).toLocaleString('en-US') + ' sats' : null;
  }

  function fmtInt(n) { return isNum(n) ? Math.round(n).toLocaleString('en-US') : null; }

  function fmtDuration(secs) {
    if (!isNum(secs) || secs < 0) return null;
    if (secs < 90) return Math.max(1, Math.round(secs)) + ' s';
    if (secs < 5400) return Math.round(secs / 60) + ' min';
    if (secs < 2 * 86400) return (secs / 3600).toFixed(1) + ' hours';
    if (secs < 60 * 86400) return (secs / 86400).toFixed(1) + ' days';
    if (secs < 2 * 365.25 * 86400) return (secs / (30.44 * 86400)).toFixed(1) + ' months';
    var years = secs / (365.25 * 86400);
    return (years < 100 ? years.toFixed(1) : Math.round(years).toLocaleString('en-US')) + ' years';
  }

  function ago(t, now) {
    if (!isNum(t)) return 'never';
    var d = now - t;
    if (d < 5) return 'just now';
    return fmtDuration(d) + ' ago';
  }

  function shortHash(h) { return h ? h.slice(0, 10) + '…' + h.slice(-6) : ''; }

  function blockUrl(network, hash) {
    if (!hash || !/^[0-9a-f]{64}$/.test(hash)) return null;
    if (network === 'mainnet') return 'https://mempool.space/block/' + hash;
    if (network === 'signet') return 'https://mempool.space/signet/block/' + hash;
    return null;
  }

  // ---------------------------------------------------------------- odds

  // The mean seconds to a block at `hashrate` against `difficulty`: difficulty * 2^32 / hashrate.
  function expectedSeconds(difficulty, hashrate) {
    if (!isNum(difficulty) || difficulty <= 0 || !isNum(hashrate) || hashrate <= 0) return null;
    return difficulty * 4294967296 / hashrate;
  }

  // The chance of at least one block within `secs`, given a mean wait: 1 - e^(-secs/mean).
  function chanceWithin(secs, meanSecs) {
    if (!isNum(meanSecs) || meanSecs <= 0) return null;
    return -Math.expm1(-secs / meanSecs);
  }

  // A probability in words a reader can hold: "about 1 in 2,400" below 1%, else a percentage.
  function fmtChance(p) {
    if (!isNum(p)) return null;
    if (p >= 0.995) return 'over 99%';
    if (p >= 0.01) return (p * 100).toFixed(p >= 0.1 ? 0 : 1) + '%';
    if (p <= 0) return 'none';
    var n = 1 / p;
    var r = n < 1000 ? Math.round(n) : Number(n.toPrecision(2));
    return 'about 1 in ' + r.toLocaleString('en-US');
  }

  // ---------------------------------------------------------------- the payout rule

  // What a block pays at `subsidySats`: the treasury takes floor(subsidy / 200), the miner the
  // rest of the subsidy and every fee.
  function payoutSplit(subsidySats, feesSats) {
    if (!isNum(subsidySats) || subsidySats < 0) return null;
    var treasury = Math.floor(subsidySats / 200);
    var fees = isNum(feesSats) && feesSats > 0 ? feesSats : 0;
    return { subsidy: subsidySats, treasury: treasury, minerBeforeFees: subsidySats - treasury, fees: fees, miner: subsidySats - treasury + fees };
  }

  // The live line under the worked example, from a status's fee_policy; null without one.
  function nextBlockHtml(fp) {
    if (!fp || !isNum(fp.treasury_sats_next_block) || !isNum(fp.miner_sats_next_block_before_fees)) return null;
    return 'The next block the pool finds pays <strong>' + esc(fmtBtc(fp.miner_sats_next_block_before_fees)) +
      '</strong> plus its fees to the miner and <strong>' + esc(fmtBtc(fp.treasury_sats_next_block)) + '</strong> to the treasury.';
  }

  // ---------------------------------------------------------------- the nodes

  // The nodes from a parsed pool-nodes.json. Ids are what the proxy knows (they go into a URL
  // path); a hostname must look like one. Anything malformed is dropped, never guessed.
  function nodesFromConfig(cfg) {
    var list = cfg && Array.isArray(cfg.nodes) ? cfg.nodes : [];
    var out = [];
    var seen = {};
    list.forEach(function (n) {
      if (!n || typeof n.id !== 'string' || !/^[a-z0-9][a-z0-9-]{0,31}$/.test(n.id) || seen[n.id]) return;
      var host = typeof n.stratum_host === 'string' && /^[A-Za-z0-9.-]{1,253}$/.test(n.stratum_host) ? n.stratum_host : null;
      if (!host) return;
      var key = validKey(n.sv2_authority_key);
      seen[n.id] = true;
      out.push({ id: n.id, name: typeof n.name === 'string' && n.name ? n.name : 'Node ' + n.id, host: host, key: key, keySource: key ? 'file' : null });
    });
    return out;
  }

  // An SV2 authority key (base58check) as a string, or null.
  function validKey(k) {
    return typeof k === 'string' && /^[1-9A-HJ-NP-Za-km-z]{20,120}$/.test(k) ? k : null;
  }

  // The nodes with each one's SV2 key taken from its own live status (`ports.sv2_authority_public_key`,
  // in mergeStatus's `liveKeys`) where it reports one, else from pool-nodes.json. A node that has
  // not answered keeps the file's key.
  function withLiveKeys(nodes, merged) {
    var live = (merged && merged.liveKeys) || {};
    return (nodes || []).map(function (n) {
      var k = live[n.id];
      if (!k) return n;
      var out = {};
      Object.keys(n).forEach(function (f) { out[f] = n[f]; });
      out.fileKey = n.key;
      out.key = k;
      out.keySource = 'live';
      return out;
    });
  }

  function urlRow(label, url, note) {
    return '<div class="url-row"><div class="url-label">' + esc(label) + '</div>' +
      '<code class="url" data-copy="' + esc(url) + '">' + esc(url) + '</code>' +
      (note ? '<div class="url-note">' + note + '</div>' : '') + '</div>';
  }

  // The connect box: for each node, the two SV1 URLs and the SV2 URL with its key.
  function connectHtml(nodes) {
    if (!nodes || !nodes.length) {
      return '<p class="na">The node list could not be loaded. The pool\'s nodes are listed in ' +
        '<a href="/pool-nodes.json">pool-nodes.json</a>.</p>';
    }
    return '<div class="connect-grid">' + nodes.map(function (n, i) {
      return '<div class="connect-node"><div class="connect-head"><span class="connect-name">' + esc(n.name) + '</span>' +
        '<span class="connect-role">' + (i === 0 ? 'primary' : 'backup') + '</span></div>' +
        urlRow('SV1, small miners (Bitaxe, NerdAxe)', 'stratum+tcp://' + n.host + ':' + PORTS.sv1Small) +
        urlRow('SV1, large miners (Antminer, Whatsminer, Avalon)', 'stratum+tcp://' + n.host + ':' + PORTS.sv1Large) +
        urlRow('SV2', 'stratum2+tcp://' + n.host + ':' + PORTS.sv2 + (n.key ? '/' + n.key : ''),
          n.key ? 'The part after the last <code>/</code> is the node\'s authority key' +
            (n.keySource === 'live' ? ', as the node reports it now' +
              (n.fileKey && n.fileKey !== n.key ? ' (the published list has a different key: ask the operator)' : '') : '') + '.'
            : 'Authority key: not published here yet. Ask the operator before using SV2.') +
        '</div>';
    }).join('') + '</div>' +
      '<div class="connect-cred"><div><span class="url-label">Username</span><code>your Bitcoin address</code> or <code>address.worker</code></div>' +
      '<div><span class="url-label">Password</span><code>x</code> (anything; it is ignored)</div></div>';
  }

  // ---------------------------------------------------------------- live status

  function maxOrNull(a, b) { return isNum(a) ? (isNum(b) ? Math.max(a, b) : a) : (isNum(b) ? b : null); }
  function addOrNull(a, b) { return isNum(a) ? (isNum(b) ? a + b : a) : (isNum(b) ? b : null); }

  // results: [{ node, ok, status, body }] from each node's /api/v1/pool/status. Every miner is
  // connected to one node, so connections and hashrate add up across nodes; a rate is unknown only
  // when no node knows it. A block is listed once, by hash, with what each node said.
  function mergeStatus(results) {
    var out = {
      answered: [], failed: [], network: null, tipHeight: null, difficulty: null,
      miners: null, workers: null, hashrate: { '15m': null, '1h': null, '24h': null },
      best: { ever: null, '24h': null }, blocks: [], feePolicy: null, submitNodes: {}, liveKeys: {}
    };
    var byHash = {};
    (results || []).forEach(function (r) {
      var b = r.ok ? r.body : null;
      if (!b || typeof b !== 'object' || !b.bitcoin) { out.failed.push(r.node); return; }
      out.answered.push(r.node);
      out.network = out.network || b.network || null;
      var bt = b.bitcoin || {};
      if (isNum(bt.tip_height) && !(isNum(out.tipHeight) && out.tipHeight >= bt.tip_height)) {
        out.tipHeight = bt.tip_height;
        if (isNum(bt.network_difficulty)) out.difficulty = bt.network_difficulty;
      }
      if (!isNum(out.difficulty) && isNum(bt.network_difficulty)) out.difficulty = bt.network_difficulty;
      if (b.miners) {
        out.miners = addOrNull(out.miners, b.miners.connected);
        out.workers = addOrNull(out.workers, b.miners.workers);
      }
      ['15m', '1h', '24h'].forEach(function (k) {
        out.hashrate[k] = addOrNull(out.hashrate[k], b.pool_hashrate_hs ? b.pool_hashrate_hs[k] : null);
      });
      if (b.best_share) {
        out.best.ever = maxOrNull(out.best.ever, b.best_share.ever);
        out.best['24h'] = maxOrNull(out.best['24h'], b.best_share['24h']);
      }
      if (!out.feePolicy && b.fee_policy) out.feePolicy = b.fee_policy;
      (Array.isArray(b.submit_nodes) ? b.submit_nodes : []).forEach(function (s) {
        // A bare `scheme://host:port` from an older pool_sv2, or { node, reachable, ... }.
        var name = typeof s === 'string' ? s : s && typeof s.node === 'string' ? s.node : null;
        if (name) out.submitNodes[name] = true;
      });
      var key = b.ports ? validKey(b.ports.sv2_authority_public_key) : null;
      if (key) out.liveKeys[r.node] = key;
      (Array.isArray(b.blocks_found) ? b.blocks_found : []).forEach(function (blk) {
        if (!blk || typeof blk.hash !== 'string') return;
        var cur = byHash[blk.hash];
        if (!cur) {
          cur = byHash[blk.hash] = { block: blk, seenBy: [] };
          out.blocks.push(cur);
        }
        cur.seenBy.push(r.node);
      });
    });
    out.blocks.sort(function (x, y) { return (y.block.height || 0) - (x.block.height || 0); });
    return out;
  }

  function stat(label, valueHtml, sub) {
    return '<div class="stat"><div class="stat-label">' + esc(label) + '</div>' +
      '<div class="stat-value' + (valueHtml == null ? ' na' : '') + '">' + (valueHtml == null ? 'unavailable' : valueHtml) + '</div>' +
      (sub ? '<div class="stat-sub">' + sub + '</div>' : '') + '</div>';
  }

  function bestRate(h) {
    if (!h) return null;
    return isNum(h['1h']) ? h['1h'] : isNum(h['15m']) ? h['15m'] : isNum(h['24h']) ? h['24h'] : null;
  }

  // The home page's live tiles, from mergeStatus. `nodes` gives the names of the ones that failed.
  function statsHtml(m, nodes) {
    var name = {};
    (nodes || []).forEach(function (n) { name[n.id] = n.name; });
    if (!m.answered.length) {
      return '<p class="na">No node answered, so there are no live figures right now.' +
        (m.failed.length ? ' Not answering: ' + esc(m.failed.map(function (id) { return name[id] || id; }).join(', ')) + '.' : '') + '</p>';
    }
    var poolRate = bestRate(m.hashrate);
    var mean = expectedSeconds(m.difficulty, poolRate);
    var tiles = [
      stat('Pool hashrate', hashrateHtml(poolRate), 'all nodes, last hour'),
      stat('Miners connected', m.miners == null ? null : esc(fmtInt(m.miners)), m.workers == null ? '' : esc(fmtInt(m.workers)) + ' worker connections'),
      stat('Blocks found', esc(fmtInt(m.blocks.length)), m.blocks.length ? 'latest at height ' + esc(fmtInt(m.blocks[0].block.height)) : 'none yet'),
      stat('Best share', m.best.ever == null ? null : esc(fmtDifficulty(m.best.ever)), m.best['24h'] == null ? '' : esc(fmtDifficulty(m.best['24h'])) + ' in the last 24 hours'),
      stat('Bitcoin height', m.tipHeight == null ? null : esc(fmtInt(m.tipHeight)), m.difficulty == null ? '' : 'difficulty ' + esc(fmtDifficulty(m.difficulty))),
      stat('Pool finds a block every', mean == null ? null : '~' + esc(fmtDuration(mean)), mean == null ? 'needs hashrate and a difficulty' : 'on average, at this hashrate. Luck decides the real wait.')
    ];
    var foot = 'From ' + esc(m.answered.map(function (id) { return name[id] || id; }).join(' and ')) + '.';
    if (m.failed.length) foot += ' Not answering: ' + esc(m.failed.map(function (id) { return name[id] || id; }).join(', ')) + ' (its miners are not counted).';
    return '<div class="stats">' + tiles.join('') + '</div><p class="stats-foot">' + foot + '</p>';
  }

  // The list of blocks the pool found, newest first, from mergeStatus.
  function blocksHtml(m, now) {
    if (!m.answered.length) return '';
    if (!m.blocks.length) return '<p class="muted">No block found yet.</p>';
    var rows = m.blocks.slice(0, 20).map(function (e) {
      var b = e.block;
      var url = blockUrl(m.network, b.hash);
      var hash = url ? '<a href="' + esc(url) + '" rel="noopener">' + esc(shortHash(b.hash)) + '</a>' : esc(shortHash(b.hash));
      return '<tr><td>' + esc(fmtInt(b.height)) + '</td><td class="mono">' + hash + '</td>' +
        '<td class="mono">' + esc(b.address ? b.address.slice(0, 10) + '…' + b.address.slice(-6) : '') + '</td>' +
        '<td>' + esc(fmtBtc(b.reward_sats) || '') + '</td><td>' + esc(ago(b.found_at, now)) + '</td></tr>';
    }).join('');
    return '<div class="table-wrap"><table class="table"><thead><tr><th>Height</th><th>Block</th><th>Found by</th><th>Paid to the miner</th><th>When</th></tr></thead><tbody>' +
      rows + '</tbody></table></div>';
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

  // Ask every node `path` through the proxy: [{ node, ok, status, body }].
  function askAll(nodes, path) {
    return Promise.all(nodes.map(function (n) {
      return fetchJson('/api/pool/' + n.id + path).then(function (r) {
        return { node: n.id, ok: r.status === 200 && !!r.body, status: r.status, body: r.body };
      });
    }));
  }

  function loadNodes() {
    return fetchJson(NODES_URL).then(function (r) { return r.status === 200 ? nodesFromConfig(r.body) : []; });
  }

  function themeToggle(doc, win) {
    var html = doc.documentElement;
    var btn = doc.getElementById('theme-toggle');
    if (!btn) return;
    var sun = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
    var moon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
    function render() { btn.innerHTML = html.getAttribute('data-theme') === 'dark' ? sun : moon; }
    render();
    btn.addEventListener('click', function () {
      var next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      html.setAttribute('data-theme', next);
      try { win.localStorage.setItem('ghost-theme', next); } catch (e) { /* private window */ }
      render();
    });
  }

  // Click a URL to copy it.
  function copyOnClick(doc, win) {
    doc.addEventListener('click', function (e) {
      var t = e.target.closest ? e.target.closest('[data-copy]') : null;
      if (!t || !win.navigator.clipboard) return;
      win.navigator.clipboard.writeText(t.getAttribute('data-copy')).then(function () {
        t.classList.add('copied');
        setTimeout(function () { t.classList.remove('copied'); }, 1200);
      }, function () { /* clipboard refused: the text is still selectable */ });
    });
  }

  // On a phone the nav scrolls sideways: show the current page's link, and fade the edge that
  // still has links beyond it.
  function navScroll(doc, win) {
    var nav = doc.querySelector('nav.primary');
    if (!nav) return;
    var cur = nav.querySelector('a.current');
    if (cur && cur.offsetLeft + cur.offsetWidth > nav.clientWidth) {
      nav.scrollLeft = cur.offsetLeft - (nav.clientWidth - cur.offsetWidth) / 2;
    }
    function edges() {
      var more = nav.scrollWidth - nav.clientWidth;
      nav.classList.toggle('more-right', more > 1 && nav.scrollLeft < more - 1);
      nav.classList.toggle('more-left', more > 1 && nav.scrollLeft > 1);
    }
    nav.addEventListener('scroll', edges, { passive: true });
    win.addEventListener('resize', edges);
    edges();
  }

  function startBrowser(doc, win) {
    themeToggle(doc, win);
    copyOnClick(doc, win);
    navScroll(doc, win);
    var connect = doc.querySelectorAll('[data-connect]');
    var stats = doc.querySelector('[data-pool-stats]');
    var blocks = doc.querySelector('[data-pool-blocks]');
    var next = doc.querySelector('[data-next-block]');
    if (!connect.length && !stats) return;
    loadNodes().then(function (nodes) {
      connect.forEach(function (el) { el.innerHTML = connectHtml(nodes); });
      // Each node's SV2 key as the node itself reports it replaces the file's.
      function showKeys(m) {
        if (connect.length) connect.forEach(function (el) { el.innerHTML = connectHtml(withLiveKeys(nodes, m)); });
      }
      if (!stats) {
        if (nodes.length) askAll(nodes, '/api/v1/pool/status').then(function (rs) { showKeys(mergeStatus(rs)); });
        return;
      }
      function refresh() {
        if (!nodes.length) { stats.innerHTML = '<p class="na">No node is configured, so there are no live figures.</p>'; return; }
        askAll(nodes, '/api/v1/pool/status').then(function (rs) {
          var m = mergeStatus(rs);
          showKeys(m);
          stats.innerHTML = statsHtml(m, nodes);
          if (blocks) blocks.innerHTML = blocksHtml(m, Date.now() / 1000);
          var nb = nextBlockHtml(m.feePolicy);
          if (next && nb) { next.innerHTML = nb; next.hidden = false; }
        });
      }
      refresh();
      setInterval(function () { if (!doc.hidden) refresh(); }, REFRESH_MS);
    });
  }

  var api = {
    PORTS: PORTS, TREASURY: TREASURY, esc: esc, isNum: isNum, fmtHashrate: fmtHashrate, hashrateText: hashrateText,
    hashrateHtml: hashrateHtml, fmtDifficulty: fmtDifficulty, fmtBtc: fmtBtc, fmtSats: fmtSats, fmtInt: fmtInt,
    fmtDuration: fmtDuration, ago: ago, shortHash: shortHash, blockUrl: blockUrl, expectedSeconds: expectedSeconds,
    chanceWithin: chanceWithin, fmtChance: fmtChance, payoutSplit: payoutSplit, nextBlockHtml: nextBlockHtml,
    nodesFromConfig: nodesFromConfig, validKey: validKey, withLiveKeys: withLiveKeys, connectHtml: connectHtml, mergeStatus: mergeStatus, statsHtml: statsHtml,
    blocksHtml: blocksHtml, bestRate: bestRate, fetchJson: fetchJson, askAll: askAll, loadNodes: loadNodes
  };
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    root.GhostPool = api;
    var go = function () { startBrowser(document, window); };
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', go);
    else go();
  }
})(this);
