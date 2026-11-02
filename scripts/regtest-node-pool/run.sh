#!/usr/bin/env bash
# Node pool regtest end-to-end harness (plan, Phase 3, first stage). Native processes in one temp
# dir, no Docker: per node a regtest Bitcoin node, ghost-mining (template provider), pool_sv2 with
# [node_pool] + [node_pool.relay] (relays peered), translator_sv2 and a CPU miner.
#
#   scripts/regtest-node-pool/run.sh --build              # debug-build what it needs, then run
#   scripts/regtest-node-pool/run.sh [harness options]    # run on existing debug builds
#   scripts/regtest-node-pool/run.sh --help               # every option
#
# Needs: a Bitcoin node binary that speaks Core's RPC and ZMQ on regtest (BITCOIND= or
# --bitcoind; stock Bitcoin Core works), python3. Optional: MINING_DEVICE= (the SV2
# mining_device from tests/integration-sv2) for a standard channel; --build adds the hostile
# node's pool_sv2 (feature np-fault-injection) under target/hostile/.
#
# Every scenario prints PASS, FAIL or UNMEASURED with its evidence. Exit status: 1 if any FAIL.
# Everything started is stopped on exit, Ctrl-C or SIGTERM, and the teardown is itself checked.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

if [[ "${1:-}" == "--build" ]]; then
  shift
  cd "$repo"
  # Debug builds, two jobs: the harness is meant for a small machine.
  cargo build -j 2 -p pool_sv2 --features np-fault-injection
  mkdir -p target/hostile
  cp target/debug/pool_sv2 target/hostile/pool_sv2
  cargo build -j 2 -p ghost-mining -p pool_sv2 -p translator_sv2 -p ghost-audit
  set -- --hostile-binary "$repo/target/hostile/pool_sv2" "$@"
elif [[ -x "$repo/target/hostile/pool_sv2" ]]; then
  set -- --hostile-binary "$repo/target/hostile/pool_sv2" "$@"
fi

exec python3 "$here/harness.py" "$@"
