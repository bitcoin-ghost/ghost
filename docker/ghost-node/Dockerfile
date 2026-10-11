#|======================================================================================================================|
#|  GHOST NODE - Docker Image                                                                                          |
#|  Contains: ghost-pool, ghost-pay, ghost-coordinator, ghost-gsp                                                     |
#|  Does NOT contain: Any wallet code, key management, or signing capabilities                                         |
#|======================================================================================================================|

FROM rust:1.85-bookworm AS builder

WORKDIR /build

# Build deps: capnproto for the SV2 stratum-core dependency that stratum-apps
# (and thus ghost-pool's TDP provider) pulls in.
RUN apt-get update && apt-get install -y capnproto libcapnp-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only what's needed for node components
COPY Cargo.toml Cargo.lock ./
COPY crates/ghost-common ./crates/ghost-common
COPY crates/ghost-buds ./crates/ghost-buds
COPY crates/ghost-policy ./crates/ghost-policy
COPY crates/ghost-storage ./crates/ghost-storage
COPY crates/ghost-consensus ./crates/ghost-consensus
COPY crates/ghost-accounting ./crates/ghost-accounting
COPY crates/ghost-verification ./crates/ghost-verification
COPY crates/ghost-template ./crates/ghost-template
COPY crates/ghost-keys ./crates/ghost-keys
COPY crates/ghost-locks ./crates/ghost-locks
COPY crates/wraith-protocol ./crates/wraith-protocol
COPY crates/ghost-reconciliation ./crates/ghost-reconciliation
COPY crates/ghost-gsp-proto ./crates/ghost-gsp-proto
COPY crates/ghost-gsp ./crates/ghost-gsp
# SV2 protocol crates ghost-pool's TDP provider depends on
# (formerly the sv2-apps submodule, now amalgamated into the workspace).
COPY crates/stratum-apps ./crates/stratum-apps
COPY crates/bitcoin-core-sv2 ./crates/bitcoin-core-sv2

# Copy node binaries ONLY (no wallet binaries)
COPY bins/ghost-pool ./bins/ghost-pool
COPY bins/ghost-pay ./bins/ghost-pay
COPY bins/ghost-coordinator ./bins/ghost-coordinator
COPY bins/ghost-gsp ./bins/ghost-gsp
COPY bins/ghost-cli ./bins/ghost-cli

# NOTE: We explicitly DO NOT copy:
# - bins/ghost-light-wallet-cli (wallet - users run this locally)
# - crates/ghost-light-wallet (wallet library)

# Build node components only
RUN cargo build --release \
    -p ghost-mining \
    -p ghost-pay \
    -p ghost-coordinator \
    -p ghost-gsp-bin \
    -p ghost-cli

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy only node binaries
COPY --from=builder /build/target/release/ghost-mining /usr/local/bin/
COPY --from=builder /build/target/release/ghost-pay /usr/local/bin/
COPY --from=builder /build/target/release/ghost-coordinator /usr/local/bin/
COPY --from=builder /build/target/release/ghost-gsp /usr/local/bin/
COPY --from=builder /build/target/release/ghost-cli /usr/local/bin/

# Create non-root user
RUN useradd -r -s /bin/false ghost
USER ghost

WORKDIR /data

# No wallet data here - this is a node only
VOLUME ["/data"]

# GSP WebSocket port
EXPOSE 8900
# Ghost Pay RPC
EXPOSE 8800
# Pool API
EXPOSE 8080
# Coordinator
EXPOSE 9000

ENTRYPOINT ["ghost-gsp"]
