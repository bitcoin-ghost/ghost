# Load balancer

*Miners connect to `pool.bitcoinghost.org` and end up on whichever pool node has the most capacity right now. There's no central proxy in the data path — the SV2 translator on each pool node makes a peer-to-peer routing decision and either keeps the miner local or transparently proxies to another node. The mesh keeps the miner-count map up to date in real time.*

## What gets routed where

DNS resolves `pool.bitcoinghost.org` to all live pool node IPs (round-robin via straight A records — no Cloudflare load balancer, no ghost-registry service). A miner connecting to that hostname picks one of the IPs at the OS DNS level and opens a TCP connection.

```
Miner → DNS  pool.bitcoinghost.org
            └── A 83.136.251.162   ┐
            └── A 85.9.198.212     │  Namecheap A records (round-robin)
            └── A 213.163.207.46   │
            └── A 95.111.221.169   ┘

Miner picks an IP, connects on TCP port 3333 (SV1) or 34255 (SV2).
```

So far this is plain DNS round-robin: 25% chance of landing on each VM. The interesting layer is what happens AFTER the miner connects. The pool node's translator looks at the local miner count and the peers' miner counts (kept fresh by the mesh) and decides whether to keep the miner local or proxy them to a less-loaded peer.

## How peer load info gets around

Every pool node serves a small internal endpoint at `127.0.0.1:8080/api/internal/pool-nodes` that returns:

```json
{
  "this_node": {
    "miner_count": 47,
    "public_address": "83.136.251.162:8559",
    "public_mining": true
  },
  "peers": [
    { "public_address": "85.9.198.212:8559",   "miner_count": 32, "public_mining": true,  "last_seen": 1777123456 },
    { "public_address": "213.163.207.46:8559", "miner_count": 51, "public_mining": true,  "last_seen": 1777123459 },
    { "public_address": "95.111.221.169:8559", "miner_count": 28, "public_mining": true,  "last_seen": 1777123461 }
  ]
}
```

The translator on the same VM polls this endpoint every 10 seconds and caches the result. Source of truth for `peers` data is the BFT mesh's health-ping system — peer entries are refreshed every 10 s by the mesh, the public-mining flag and last_seen timestamps come from there too.

Net effect: each translator has a real-time map of every pool node's miner count, refreshed every 10 s, all without any external service.

## The proxy decision

When a new SV1 miner connects to a pool node's translator on port 3333, the translator runs `should_proxy()` from `bins/translator-sv2/src/lib/load_balancer.rs`:

```rust
async fn should_proxy(
    &self,
    local_downstream_count: usize,
    source_addr: std::net::IpAddr,
) -> Option<SocketAddr> {
    // 1. Cache must be fresh (≤ 30 s old). Stale cache → handle locally.
    if cache.updated_at.elapsed() > Duration::from_secs(self.config.poll_interval_secs * 3) {
        return None;
    }

    // 2. Never re-proxy a connection coming from another pool node.
    //    Without this, peer A could proxy to peer B which proxies back
    //    to peer A — connection-storm loop.
    if from_peer { return None; }

    // 3. Find the least-loaded peer that's accepting public mining.
    let best_peer = cache.peers.iter()
        .filter(|p| p.public_mining && !p.public_address.is_empty())
        .min_by_key(|p| p.miner_count)?;

    // 4. Only proxy if local node is meaningfully more loaded
    //    (avoid flapping when counts are similar).
    if local_count < best_peer.miner_count + self.config.proxy_threshold {
        return None;
    }

    // 5. Build the target address and proxy.
    let target = format!("{}:3333", best_peer_ip).parse().ok()?;
    Some(target)
}
```

The threshold (`proxy_threshold`, default 2) is hysteresis: a node only proxies away if it has at least 2 more miners than the least-loaded peer. Without that buffer, two evenly-loaded nodes would oscillate — node A proxies to node B, node B proxies to node A, traffic ping-pongs.

If `should_proxy` returns `Some(target)`, the translator hands the raw TCP socket off to:

```rust
fn spawn_proxy(self: &Arc<Self>, client: TcpStream, target: SocketAddr) {
    tokio::spawn(async move {
        match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
            Ok(Ok(mut server)) => {
                tokio::io::copy_bidirectional(&mut client, &mut server).await
            }
            // ... error handling drops the client; miner firmware reconnects
        }
    });
}
```

`tokio::io::copy_bidirectional` is a transparent TCP proxy: bytes flow client → server and server → client without inspection. The local translator becomes invisible — the miner thinks it's talking to the local pool node, but the actual SV1/SV2 protocol terminates on the proxied-to node.

## Anti-loop guard

The `from_peer` check is the load balancer's most important safety mechanism. Without it:

```
Time 0:  Miner connects to Node A
         Node A: "I have 50 miners, Node B has 10. Proxy."
         A → B (TCP proxy)
Time 1:  Connection arrives at Node B from Node A's IP.
         Node B's translator checks should_proxy:
         "I have 11 miners now, Node A has 49. Proxy back to A."
         B → A (TCP proxy)
         ...storm.
```

The fix: every pool node knows the IPs of its peers (they're in the mesh peer list with public_address). When a new connection's source IP matches a known peer, `from_peer = true` and `should_proxy` returns `None` — that connection is handled locally, no second hop.

This is why the translator's mesh awareness matters. It's not just for the load balancer's targets — it's for the safety check on inbound connections.

## Health and removal

A peer that's offline drops out of the routing pool naturally:

1. **Mesh health-ping freshness window: 60 s.** Health pings older than 60 s are dropped from the connected-peers list.
2. **The `/api/internal/pool-nodes` endpoint** filters peers by that 60 s window.
3. **The translator's poller** picks up the smaller peer list within 10 s.
4. **`should_proxy` ignores absent peers** — they're not in `cache.peers` at all.

Total time from "peer goes down" to "load balancer stops routing to it": worst case ~70 s (60 s mesh window + 10 s poller). Most failure modes resolve faster because the mesh detects the disconnect via TCP close before the 60 s window elapses.

## Ports

| Protocol | Port | Notes |
|---|---|---|
| Stratum V1 | 3333 | SV1 miners. Translator runs SV1↔SV2 bridge here |
| Stratum V2 (native) | 34255 | Modern SV2 miners. Direct to pool_sv2 |
| Stratum V2 (alt) | 4444 | Alternative SV2 port (some firewalls block 34255) |

Miners can connect via:

```
stratum+tcp://pool.bitcoinghost.org:3333    # Bitaxe, legacy
stratum+tcp://pool.bitcoinghost.org:34255   # Antminer S19/S21, modern
```

The load balancer logic applies to both — the translator handles the SV1 path, the SRI pool_sv2 handles the SV2 path. Both check the same peer-load cache and apply the same proxy rules.

## Configuration

In `pool.toml` (or the translator config, depending on which layer you're tuning):

```toml
[load_balancer]
ghost_pool_url      = "127.0.0.1:8080"   # local pool node's HTTP API
poll_interval_secs  = 10                 # how often to refresh peer load
proxy_threshold     = 2                  # min miner-count delta before proxy
proxy_timeout_ms    = 5000               # TCP connect timeout to peer
```

Defaults are sensible for a 4-node cluster. For larger clusters consider:

- `proxy_threshold = 5` to reduce proxy churn when many nodes are at similar load.
- `poll_interval_secs = 5` for faster reaction to peer-load changes (more API calls, slightly more CPU).

## What the load balancer doesn't do

- **It doesn't health-check directly.** It trusts the mesh's health-ping system. If you want stricter health checks (e.g. probe TCP port liveness, validate Stratum handshake), that's a layer to add separately. Current rule: if the mesh says a peer is alive and serving, the load balancer routes to it.
- **It doesn't do geographic routing.** A miner in Australia connecting via DNS round-robin might land on a European node, which might proxy them to a US node — three transcontinental hops. There's no geo-steering. This is fine for our 4-VM cluster (all in Europe, same region) but would be problematic at larger scale. Geo-aware DNS would be added at the DNS provider level rather than in this code.
- **It doesn't prevent a miner from picking the same node twice.** DNS round-robin is per-resolution; subsequent reconnects pick fresh. That's by design — clients need to be free to retry after a transient failure.
- **It doesn't terminate SSL/TLS.** Stratum V2 is over plain TCP; the load balancer's `copy_bidirectional` is byte-level and doesn't care. SV2 handshake auth happens between the miner and the eventual pool node, end-to-end.
- **It doesn't know about Stratum-internal state.** A proxied connection that disconnects due to a Stratum-protocol error is invisible to the load balancer — only the TCP-level disconnect is. That's fine because Stratum is stateful at the application level only; TCP-level proxying is sufficient.

## Why no Cloudflare / ghost-registry

The protocol's earlier design called for a centralised ghost-registry service that aggregated node metrics and pushed them to a Cloudflare Load Balancer with TCP health checks. That design was abandoned for three reasons:

1. **External dependency.** A Cloudflare account, a separate bootstrap service, and an API token in every node config are all things that can break independently of the network.
2. **Privacy.** Cloudflare sees every miner connection and can correlate IPs to pool nodes. The mesh-driven approach keeps that information internal.
3. **Decentralisation.** A central metrics aggregator is exactly the kind of single-point-of-control the rest of the protocol carefully avoids.

The mesh-driven approach has tradeoffs (no global health probing, no geo-aware routing) but matches the rest of Ghost's no-central-coordinator architecture.

## Source

| File | Purpose |
|---|---|
| `crates/ghost-verification/src/routes.rs` | `/api/internal/pool-nodes` endpoint that exposes the peer list |
| `crates/ghost-consensus/src/peer.rs` | Mesh peer manager that tracks `last_seen` |

The SV2 translator with TLV + load-balancer support began as a downstream fork of the Stratum Reference Implementation. It is now **amalgamated in-tree** in the main `ghost` repo at `bins/translator-sv2/` (the `should_proxy` decision, `spawn_proxy` TCP forwarder, and SV1 connection handler shown above all live under `bins/translator-sv2/src/lib/`), alongside the consensus / mesh side of the load balancer (the peer-list endpoint and mesh peer manager). The only external dependency is the SV2 protocol library (`stratum-core`), pinned by git rev.
