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
export SIGNING_KEY="${SIGNING_KEY:-$(head -c 32 /dev/urandom | xxd -p -c 32)}"

# `public_address` must be an IP — hostnames are rejected outright, so the
# container DNS name the template used could never have been accepted. Take the
# address docker assigned this container.
export NODE_IP="$(hostname -i | awk '{print $1}')"
: "${NODE_IP:?could not determine container IP for public_address}"
echo "[$NODE_NAME] public_address=${NODE_IP}"

envsubst < /etc/ghost/pool.template.toml > /etc/ghost/config.toml

# ghost-pool refuses a REMOTE Ghost Core over plain RPC ("TLS required for remote
# Ghost Core connections"), and `bitcoind` is remote from inside this container.
# bitcoind here serves plain RPC/ZMQ, so rather than standing up TLS for a
# throwaway regtest we forward the endpoints onto 127.0.0.1, which the config
# treats as local and therefore exempt. The README already prescribed this socat
# sidecar; nothing implemented it, so every node died before opening its mesh.
#
# Bound to 127.0.0.1 only: these listeners must not be reachable from the docker
# network, or one node's loopback exemption becomes every node's open RPC proxy.
: "${RPC_UPSTREAM_HOST:=bitcoind}"
socat TCP-LISTEN:18443,bind=127.0.0.1,fork,reuseaddr "TCP:${RPC_UPSTREAM_HOST}:18443" &
socat TCP-LISTEN:28332,bind=127.0.0.1,fork,reuseaddr "TCP:${RPC_UPSTREAM_HOST}:28332" &
socat TCP-LISTEN:28333,bind=127.0.0.1,fork,reuseaddr "TCP:${RPC_UPSTREAM_HOST}:28333" &

# Wait for the RPC forwarder to accept before starting the node: ghost-pool exits
# on a failed first connect, and losing the race looked identical to a config bug.
for _ in $(seq 1 30); do
  if (exec 3<>/dev/tcp/127.0.0.1/18443) 2>/dev/null; then break; fi
  sleep 1
done

# Extra flags, per-service. Used to enable the Template Distribution Protocol server on the
# node that fronts the SV2 stack (`EXTRA_ARGS: "--tdp-enabled --tdp-port 8442"`), which is how
# pool_sv2 gets templates. Left empty everywhere else.
EXTRA_ARGS="${EXTRA_ARGS:-}"

echo "[$NODE_NAME] starting ghost-pool (genesis='${GENESIS_ARG}' extra='${EXTRA_ARGS}') on regtest"
# shellcheck disable=SC2086
exec /usr/local/bin/ghost-pool ${GENESIS_ARG} ${EXTRA_ARGS} --config /etc/ghost/config.toml
