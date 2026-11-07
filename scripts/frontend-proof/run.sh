#!/usr/bin/env bash
# Prove the front ends against a live regtest node pool, in a real browser.
#
#   scripts/frontend-proof/run.sh --work DIR [--bin-dir DIR] [--base-port 43000] [--serve-json FILE]
#
# 1. A node pool: scripts/regtest-node-pool/harness.py with --node-ips (a loopback host per
#    node), mined to Bitcoin height 46 on a 300-row synthetic genesis table and held there
#    (--serve-minutes, miners paused). On regtest a share credits more than a block's whole miner
#    share, so from height 41 (the first table holding the miners' own credits) every block pays
#    one miner all of it: blocks that leave change (small slot classes on the genesis rows) and a
#    cleared ledger's finder surplus happen only from 21 to 40. Height 46 puts all three kinds in
#    the 20 blocks the status lists. Or an already running pool: --serve-json <work>/serve.json.
# 2. Open listing as on the real network: a `ghost-audit list` lister per node, writing the list
#    that node's ghost-mining serves at /api/v1/node-pool/node-list, then `ghost-audit merge`
#    over the three over HTTP: the merged list is the website's /node-list.json.
# 3. The website: site-server.mjs serves ghost-web/ and hands /api/pool/<host>/... and
#    /api/v1/node-pool/status to the website's API proxy (scripts/website-proxy/ghost-site-proxy.py,
#    forwarding only to listed hosts), as nginx does on the real site. And the dashboard's
#    standalone build (laid out as the release bundle), pointed at node0.
# 4. proof.mjs drives every page in headless Chromium (Playwright, pinned) and checks it against
#    the API. Screenshots and report.json go to DIR/shots.
#
# Everything started here is stopped on exit, by PID. Needs python3, node >= 18, npm (first run:
# Playwright and its Chromium are installed into DIR/pw), the node pool binaries (--bin-dir:
# ghost-mining, pool_sv2, translator_sv2, ghost-audit, built from this tree) and ghostd (see
# scripts/regtest-node-pool/run.sh --fetch-ghostd). Not run by CI.
set -euo pipefail

# PENDING: this proof drove the node pool's regtest harness (scripts/regtest-node-pool/, the share
# chain, the open-listing lister and merge, and the old website pages), all removed for Ghost
# Pool's solo design (they are kept on the feat/node-pool branch). It needs porting to
# scripts/regtest-solo/ and the new pages before it can run again; until then it refuses to.
if [[ "${FRONTEND_PROOF_FORCE:-}" != "1" ]]; then
  echo "frontend-proof: pending a port to scripts/regtest-solo/ (see docs/SOLO_PROGRESS.md)" >&2
  exit 2
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
PLAYWRIGHT_VERSION=1.56.1
work="" bin_dir="${CARGO_TARGET_DIR:-$repo/target}/debug" base=43000 serve_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --work) work="$2"; shift 2 ;;
    --bin-dir) bin_dir="$2"; shift 2 ;;
    --base-port) base="$2"; shift 2 ;;
    --serve-json) serve_json="$2"; shift 2 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "run.sh: unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ -n "$work" ]] || { echo "run.sh: --work DIR is required" >&2; exit 2; }
mkdir -p "$work"
work="$(cd "$work" && pwd)"
pids=()
harness_pid=""
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
  if [[ -n "$harness_pid" ]]; then
    kill -TERM "$harness_pid" 2>/dev/null || true
    wait "$harness_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT
trap 'exit 143' INT TERM

# -- Playwright, pinned
if [[ ! -d "$work/pw/node_modules/playwright" ]]; then
  mkdir -p "$work/pw"
  ( cd "$work/pw" && npm init -y >/dev/null && npm install --no-audit --no-fund --save-exact "playwright@$PLAYWRIGHT_VERSION" )
  ( cd "$work/pw" && npx playwright install --only-shell chromium )
fi

# -- the node pool
if [[ -z "$serve_json" ]]; then
  [[ ! -e "$work/pool" ]] || { echo "run.sh: $work/pool exists (an earlier run's); remove it" >&2; exit 2; }
  python3 "$repo/scripts/regtest-node-pool/harness.py" --bin-dir "$bin_dir" \
    --ghostd-cache "${XDG_CACHE_HOME:-$HOME/.cache}/ghost-regtest" --base-port "$base" \
    --workdir "$work/pool" --keep --node-ips --mine-to 46 --genesis-rows 300 \
    --only bringup genesis_import mine balances_agree blocks_settle \
    --serve-minutes 240 > "$work/harness.log" 2>&1 &
  harness_pid=$!
  serve_json="$work/pool/serve.json"
  echo "run.sh: harness pid $harness_pid, log $work/harness.log"
  until [[ -f "$serve_json" ]] && grep -q "== serving" "$work/harness.log"; do
    kill -0 "$harness_pid" 2>/dev/null || { echo "run.sh: the harness ended before serving" >&2; tail -20 "$work/harness.log" >&2; exit 1; }
    sleep 5
  done
fi
echo "run.sh: node pool described in $serve_json"
q() { python3 -c "import json,sys; d=json.load(open('$serve_json')); print(eval(sys.argv[1]))" "$1"; }
n_nodes="$(q 'len(d["nodes"])')"

# -- listers, one per node, then the merge
audit="$(q 'd["bin_dir"]')/ghost-audit"
lister_addr="bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"
genesis=()
if [[ "$(q 'd["genesis_export"] or ""')" != "" ]]; then
  genesis=(--genesis-export "$(q 'd["genesis_export"]')" --export-digest "$(q 'd["export_digest"]')"
           --genesis-table-digest "$(q 'd["genesis_table_digest"]')")
fi
# One job per probe: the miners are held still, so new jobs come only from the 30 s re-batch
# (no new blocks), and two within the timeout are often not there.
listers=() lister_pids=()
for ((i = 0; i < n_nodes; i++)); do
  j=$(( (i + 1) % n_nodes ))
  "$audit" list --network regtest "${genesis[@]}" \
    --relay-peer "$(q "d['nodes'][$j]['relay']")" --seed "$(q "d['nodes'][$i]['relay']")" \
    --rpc-port "$(q "d['nodes'][$j]['rpc_port']")" --rpc-user "$(q 'd["rpc_user"]')" \
    --rpc-password "$(q 'd["rpc_password"]')" --data-dir "$work/lister$i" --address "$lister_addr" \
    --allow-private --interval 20 --wait 120 --timeout 90 --jobs 1 \
    --out-json "$(q "d['nodes'][$i]['node_list_path']")" --out-dns "$work/lister$i/pool.zone" \
    > "$work/lister$i.log" 2>&1 &
  pids+=($!)
  lister_pids+=($!)
  listers+=(--lister "http://127.0.0.1:$(q "d['nodes'][$i]['http']")/api/v1/node-pool/node-list")
done
echo "run.sh: listers started; waiting for each to list all $n_nodes nodes (3 passing probes each)"
deadline=$((SECONDS + 1200))
until python3 - "$serve_json" <<'EOF'
import json, sys, urllib.request
d = json.load(open(sys.argv[1]))
for n in d["nodes"]:
    try:
        l = json.load(urllib.request.urlopen(f"http://127.0.0.1:{n['http']}/api/v1/node-pool/node-list", timeout=5))
    except Exception:
        sys.exit(1)
    if len(l.get("nodes", [])) < len(d["nodes"]):
        sys.exit(1)
EOF
do
  (( SECONDS < deadline )) || { echo "run.sh: the listers did not list every node in 20 minutes" >&2; tail -5 "$work"/lister*.log >&2; exit 1; }
  sleep 10
done
"$audit" merge --network regtest "${listers[@]}" --out-json "$work/node-list.json" --out-dns "$work/pool.zone"
echo "run.sh: merged node list in $work/node-list.json"
# The listers' probes are connections too: stopped, so the pages show only the miners.
for p in "${lister_pids[@]}"; do kill "$p" 2>/dev/null || true; done
sleep 5

# -- the website and the dashboard
port_map="$(q '",".join(n["ip"] + "=" + str(n["http"]) for n in d["nodes"])')"
node0_api="http://127.0.0.1:$(q 'd["nodes"][0]["http"]')"
site_port=$((base + 900)) dash_port=$((base + 901)) proxy_port=$((base + 902))
# The proxy as deployed, but on loopback nodes: --allow-private, and each node's own API port.
python3 -I "$repo/scripts/website-proxy/ghost-site-proxy.py" --listen "127.0.0.1:$proxy_port" \
  --node-list "$work/node-list.json" --api-port-map "$port_map" --allow-private > "$work/site-proxy.log" 2>&1 &
pids+=($!)
node "$here/site-server.mjs" --root "$repo/ghost-web" --port "$site_port" --node-list "$work/node-list.json" \
  --api-proxy "http://127.0.0.1:$proxy_port" > "$work/site.log" 2>&1 &
pids+=($!)
# Built every run, so the pages proven are the tree's (an old .next would prove an old dashboard).
[[ -d "$repo/dashboard/node_modules" ]] || ( cd "$repo/dashboard" && npm ci --no-audit --no-fund )
( cd "$repo/dashboard" && NEXT_TELEMETRY_DISABLED=1 npm run build > "$work/dashboard-build.log" 2>&1 ) \
  || { echo "run.sh: the dashboard did not build; see $work/dashboard-build.log" >&2; exit 1; }
"$here/stage-dashboard.sh" "$work/dashboard"
password="proof-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
key="$(python3 -c 'import hashlib; print(hashlib.sha256(b"secret0").hexdigest())')"  # harness node0's internal_api_secret
( cd "$work/dashboard" && NODE_ENV=production PORT="$dash_port" HOSTNAME=127.0.0.1 DASHBOARD_PASSWORD="$password" \
    INTERNAL_AUTH_KEY="$key" NEXT_PUBLIC_API_URL="$node0_api" NEXT_TELEMETRY_DISABLED=1 \
    exec node server.js ) > "$work/dashboard.log" 2>&1 &
pids+=($!)
for url in "http://127.0.0.1:$site_port/" "http://127.0.0.1:$dash_port/login"; do
  for _ in $(seq 60); do curl -fs -o /dev/null "$url" && break; sleep 1; done
done

# -- the browser
status=0
node "$here/proof.mjs" --serve "$serve_json" --dashboard "http://127.0.0.1:$dash_port" --password "$password" \
  --site "http://127.0.0.1:$site_port" --shots "$work/shots" --playwright "$work/pw" \
  --node-list "$work/node-list.json" || status=$?
exit "$status"
