#!/usr/bin/env bash
# Regtest-cluster entrypoint: render the per-node config from env, then start
# ghost-pool. Pool1 starts with --genesis (it bootstraps the MPC/elder set);
# pools 2-4 join without it. See README.md for the start ordering.
set -euo pipefail

: "${NODE_NAME:?NODE_NAME required}"
: "${SEED_NODES:?SEED_NODES required (comma-separated \"host:8559\" quoted list)}"
: "${BITCOIN_RPC_USER:?}" "${BITCOIN_RPC_PASSWORD:?}" "${TREASURY_ADDRESS:?}"
GENESIS_ARG="${GENESIS_ARG:-}"

mkdir -p /var/lib/ghost/data
envsubst < /etc/ghost/pool.template.toml > /etc/ghost/config.toml

echo "[$NODE_NAME] starting ghost-pool (genesis='${GENESIS_ARG}') on regtest"
# shellcheck disable=SC2086
exec /usr/local/bin/ghost-pool ${GENESIS_ARG} --config /etc/ghost/config.toml
