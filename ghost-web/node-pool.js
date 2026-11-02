/* Bitcoin Ghost — node pool live status.
 *
 * Reads GET /api/v1/node-pool/status and fills every element marked
 * [data-np-field]. The response shape is not final, so every field is looked
 * up under several candidate names and anything missing shows "—". If the
 * request fails in any way (network, timeout, non-2xx, not JSON) every field
 * shows "unavailable" and nothing is guessed.
 *
 * Markup:
 *   <div data-np-status data-status-url="/api/v1/node-pool/status">
 *     <div class="value" data-np-field="tip_height"></div>
 *     <span data-np-updated></span>
 *     <pre data-np-raw></pre>
 *   </div>
 */
(function () {
  'use strict';

  var DEFAULT_URL = '/api/v1/node-pool/status';
  var POLL_MS = 30000;
  var TIMEOUT_MS = 8000;

  // Candidate paths per displayed field, first match wins. Arrays are shown
  // as their length.
  var FIELDS = {
    tip_height:   ['share_chain.tip_height', 'share_chain.height', 'tip.height', 'anchor_height', 'tip_height', 'anchors'],
    btc_height:   ['btc_height', 'bitcoin_height', 'tip.btc_height', 'share_chain.btc_height', 'block_height'],
    hashrate:     ['pool_hashrate_ths', 'hashrate_ths', 'pool_hashrate_hs', 'hashrate_hs', 'pool_hashrate', 'hashrate'],
    peers:        ['relay.peer_count', 'relay.peers', 'peer_count', 'peers'],
    miners:       ['miners.connected', 'connected_miners', 'active_miners', 'miner_count', 'miners'],
    blocks_found: ['blocks_found', 'pool_blocks', 'blocks.found', 'blocks'],
    network_tier: ['t_net', 'network_tier', 'tier'],
    owed_sats:    ['ledger.total_owed_sats', 'total_owed_sats', 'owed_sats'],
    balances:     ['ledger.balances', 'ledger.eligible', 'balances', 'eligible_balances']
  };

  function get(obj, path) {
    var parts = path.split('.');
    var cur = obj;
    for (var i = 0; i < parts.length; i++) {
      if (cur == null || typeof cur !== 'object' || !(parts[i] in cur)) return undefined;
      cur = cur[parts[i]];
    }
    return cur;
  }

  function lookup(obj, field) {
    var paths = FIELDS[field] || [field];
    for (var i = 0; i < paths.length; i++) {
      var v = get(obj, paths[i]);
      if (v !== undefined && v !== null) return { path: paths[i], value: v };
    }
    return null;
  }

  function formatHashrate(ths) {
    if (!isFinite(ths) || ths <= 0) return '0<span class="unit">TH/s</span>';
    if (ths < 1)    return (ths * 1000).toFixed(1) + '<span class="unit">GH/s</span>';
    if (ths < 1000) return ths.toFixed(2) + '<span class="unit">TH/s</span>';
    if (ths < 1e6)  return (ths / 1000).toFixed(2) + '<span class="unit">PH/s</span>';
    return (ths / 1e6).toFixed(2) + '<span class="unit">EH/s</span>';
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  // Returns HTML for one field, or null when the response has no such field.
  function render(field, hit) {
    if (!hit) return null;
    var v = hit.value;
    if (Array.isArray(v)) v = v.length;
    if (typeof v === 'object') return null;
    if (field === 'hashrate' && typeof v === 'number') {
      if (/_hs$/.test(hit.path)) return formatHashrate(v / 1e12);
      if (/_ths$/.test(hit.path)) return formatHashrate(v);
      return escapeHtml(v.toLocaleString());   // unit unknown: show the number as given
    }
    if (field === 'owed_sats' && typeof v === 'number') {
      return escapeHtml(v.toLocaleString()) + '<span class="unit">sats</span>';
    }
    if (typeof v === 'number') return escapeHtml(v.toLocaleString());
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    return escapeHtml(v);
  }

  function setAll(root, data, ok) {
    var els = root.querySelectorAll('[data-np-field]');
    for (var i = 0; i < els.length; i++) {
      var el = els[i];
      var field = el.getAttribute('data-np-field');
      var html = ok ? render(field, lookup(data, field)) : null;
      if (!ok) {
        el.textContent = 'unavailable';
        el.classList.add('np-na');
      } else if (html === null) {
        el.textContent = '—';
        el.title = 'not reported by this node';
        el.classList.add('np-na');
      } else {
        el.innerHTML = html;
        el.title = '';
        el.classList.remove('np-na');
      }
    }
    var upd = root.querySelectorAll('[data-np-updated]');
    for (var j = 0; j < upd.length; j++) {
      upd[j].textContent = ok
        ? 'Updated ' + new Date().toLocaleTimeString() + '.'
        : 'Live status is unavailable: the status endpoint did not answer. Nothing is shown rather than a guess.';
    }
    var raw = root.querySelectorAll('[data-np-raw]');
    for (var k = 0; k < raw.length; k++) {
      raw[k].textContent = ok ? JSON.stringify(data, null, 2) : '(no response)';
    }
  }

  function fetchStatus(url) {
    var ctl = ('AbortController' in window) ? new AbortController() : null;
    var timer = setTimeout(function () { if (ctl) ctl.abort(); }, TIMEOUT_MS);
    return fetch(url, { cache: 'no-store', signal: ctl ? ctl.signal : undefined })
      .then(function (r) {
        clearTimeout(timer);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      })
      .then(function (d) {
        if (!d || typeof d !== 'object') throw new Error('not an object');
        return d;
      }, function (e) { clearTimeout(timer); throw e; });
  }

  function start(root) {
    var url = root.getAttribute('data-status-url') || DEFAULT_URL;
    function tick() {
      fetchStatus(url).then(
        function (d) { setAll(root, d, true); },
        function () { setAll(root, null, false); }
      );
    }
    tick();
    setInterval(tick, POLL_MS);
  }

  function init() {
    var roots = document.querySelectorAll('[data-np-status]');
    for (var i = 0; i < roots.length; i++) start(roots[i]);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
