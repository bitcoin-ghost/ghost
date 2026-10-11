# Bitcoin Ghost v1.4 - Multi-stage Build
# Builds all binaries in a single image

# ============================================================================
# Build Stage
# ============================================================================
# L-11: Use latest stable Rust version for security patches
FROM rust:1.83-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create build directory
WORKDIR /build

# Copy workspace files first (for dependency caching)
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bins ./bins

# Build release binaries
RUN cargo build --release \
    --bin ghost-mining \
    --bin translator \
    --bin ghost-pay \
    --bin ghost-coordinator

# ============================================================================
# Runtime Stage - ghost-pool
# ============================================================================
FROM debian:bookworm-slim AS ghost-pool

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -r -s /bin/false ghost

# Create directories
RUN mkdir -p /etc/ghost /var/lib/ghost/data /var/log/ghost \
    && chown -R ghost:ghost /etc/ghost /var/lib/ghost /var/log/ghost

# Copy binary
COPY --from=builder /build/target/release/ghost-mining /usr/local/bin/ghost-pool

# Copy default config
COPY docker/config/ghost-pool.toml /etc/ghost/config.toml

# Set ownership
RUN chown ghost:ghost /etc/ghost/config.toml

USER ghost
WORKDIR /var/lib/ghost

# Expose ports
EXPOSE 34255 3333 8080 8555-8562

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/api/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/ghost-pool"]
CMD ["--config", "/etc/ghost/config.toml"]

# ============================================================================
# Runtime Stage - translator
# ============================================================================
FROM debian:bookworm-slim AS translator

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false ghost

COPY --from=builder /build/target/release/translator /usr/local/bin/translator

USER ghost

EXPOSE 3333 34265

ENTRYPOINT ["/usr/local/bin/translator"]

# ============================================================================
# Runtime Stage - ghost-pay
# ============================================================================
FROM debian:bookworm-slim AS ghost-pay

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false ghost
RUN mkdir -p /etc/ghost /var/lib/ghost/data \
    && chown -R ghost:ghost /etc/ghost /var/lib/ghost

COPY --from=builder /build/target/release/ghost-pay /usr/local/bin/ghost-pay
COPY docker/config/ghost-pay.toml /etc/ghost/config.toml
RUN chown ghost:ghost /etc/ghost/config.toml

USER ghost
WORKDIR /var/lib/ghost

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8081/api/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/ghost-pay"]
CMD ["--config", "/etc/ghost/config.toml"]

# ============================================================================
# Runtime Stage - ghost-coordinator
# ============================================================================
FROM debian:bookworm-slim AS ghost-coordinator

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false ghost
RUN mkdir -p /etc/ghost /var/lib/ghost \
    && chown -R ghost:ghost /etc/ghost /var/lib/ghost

COPY --from=builder /build/target/release/ghost-coordinator /usr/local/bin/ghost-coordinator
COPY docker/config/ghost-coordinator.toml /etc/ghost/config.toml
RUN chown ghost:ghost /etc/ghost/config.toml

USER ghost
WORKDIR /var/lib/ghost

EXPOSE 8333

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8333/api/v1/health || exit 1

ENTRYPOINT ["/usr/local/bin/ghost-coordinator"]
CMD ["--config", "/etc/ghost/config.toml"]
