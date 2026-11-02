# Ghost Pool Configuration

Configuration files for Bitcoin Ghost pool nodes.

## Mainnet Configurations

| File | Description |
|------|-------------|
| `mainnet.toml` | Full configuration with all options documented |
| `mainnet-minimal.toml` | Minimal config for quick deployment |
| `mainnet.env.example` | Environment variables template |

## Quick Start

### 1. Generate Required Keys

```bash
# Generate node identity key
ghost-admin key generate --output /etc/ghost/node.key

# Generate signing key (64 hex chars)
export SIGNING_KEY=$(openssl rand -hex 32)

# Generate API secret (64 hex chars)
export INTERNAL_API_SECRET=$(openssl rand -hex 32)
```

### 2. Configure Environment

```bash
# Copy and edit environment file
cp mainnet.env.example mainnet.env
nano mainnet.env

# Required variables:
#   BITCOIN_RPC_PASSWORD - Your Bitcoin Core RPC password
#   PUBLIC_ADDRESS       - Public IP/hostname for miners
#   SIGNING_KEY          - 64 hex char message signing key
#   INTERNAL_API_SECRET  - 64 hex char API authentication secret
```

### 3. Start the Pool

```bash
source mainnet.env && ghost-mining --config mainnet.toml
```

## Mining

Every node is a node pool node. There are no solo or private modes; `mining_mode`,
`private_mining_password` and `solo_payout_address` in an older pool.toml are read and ignored.
What a block pays is the node pool's canonical coinbase (see `docs/NODE_POOL_SPEC.md`).

## Policy Profiles

| Profile | Tiers | Description |
|---------|-------|-------------|
| `bitcoin_pure` | T0+T1 | Financial transactions only |
| `permissive` | T0+T1+T2 | Adds small OP_RETURN (default) |
| `full_open` | T0+T1+T2+T3 | Includes inscriptions/runes |
| `custom` | Configurable | Custom rules |

## Required Firewall Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 3333 | TCP | Stratum V1 — hobby tier (miners) |
| 4444 | TCP | Stratum V1 — farm/rental tier (public mining nodes only) |
| 34255 | TCP | Stratum V2 (miners) |
| 8080 | TCP | HTTP API |
| 8555-8562 | TCP | P2P consensus mesh |

## Configuration Mutability

Settings are classified as **immutable** (set once at deployment) or **mutable** (changeable via dashboard API with graceful restart).

### Immutable Settings

These settings cannot be changed via the dashboard API. They require direct config file access and a manual restart. Changing these settings has security or economic implications.

| Setting | Section | Reason |
|---------|---------|--------|
| `internal_api_secret` | `[network]` | Security - can't change own auth |
| `key_path` | `[identity]` | Identity - changing would change node_id |
| `signing_key` | `[network]` | Identity |
| `network` | `[bitcoin]` | Network - changing networks is catastrophic |
| `seed_nodes` | `[network]` | Security - prevents peer poisoning |

### Mutable Settings (Dashboard API)

These settings can be changed via `POST /api/v1/admin/config` with proper authentication. Changes trigger a graceful restart (5-10 seconds).

| Setting | Section | Use Case |
|---------|---------|----------|
| `profile` | `[policy]` | Switch policy profile |

### Graceful Restart Behavior

When configuration changes via the dashboard API:

1. **Preserved across restart:**
   - Node ID (same key file)
   - Miner balances (the node pool share chain)

2. **Temporarily interrupted:**
   - Active miner connections (~5-10 seconds reconnect)
   - P2P mesh connections (auto-reconnect)
   - In-flight share submissions (miners retry)

## Security Requirements (Mainnet)

These settings are **mandatory** for mainnet and cannot be disabled:

1. **Noise Protocol Encryption** (`noise_enabled = true`)
   - Encrypts all P2P traffic
   - Prevents eavesdropping and MITM attacks

2. **Internal API Authentication** (`internal_api_secret` configured)
   - Protects admin endpoints with HMAC-SHA256
   - Prevents unauthorized share injection

The node will refuse to start on mainnet without these configured.

## Dashboard Configuration API

### Endpoint

```
POST /api/v1/admin/config
Authorization: Bearer <internal_api_secret>
Content-Type: application/json
```

### Request Body

```json
{
  "policy_profile": "bitcoin_pure"
}
```

All fields are optional - only include settings you want to change.

### Response

```json
{
  "success": true,
  "changes": ["policy_profile"],
  "restart_required": true,
  "restart_in_seconds": 5
}
```

### Validation Rules

- `policy_profile`: Must be `bitcoin_pure`, `permissive`, `full_open`, or `custom`

### Error Response

```json
{
  "success": false,
  "error": "Invalid policy_profile 'x'. Valid values: bitcoin_pure, permissive, full_open, custom"
}
```

## SRI (Stratum Reference Implementation)

SRI pool and translator configs are in `sri/` subdirectory:

- `sri/pool-config.toml` - SRI Pool (SV2 server)
- `sri/translator-config.toml` - SRI Translator (SV1↔SV2 bridge)
