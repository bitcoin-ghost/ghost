# Ghost Pool Configuration

Configuration files for Bitcoin Ghost pool nodes.

## Mainnet Configurations

| File | Description |
|------|-------------|
| `mainnet.toml` | Full configuration with all options documented |
| `mainnet-minimal.toml` | Minimal config for quick deployment |
| `mainnet-solo.toml` | Private solo mining configuration |
| `mainnet.env.example` | Environment variables template |

## Quick Start

### 1. Generate Required Keys

```bash
# Generate node identity key
ghost-cli key generate --output /etc/ghost/node.key

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
#   TREASURY_ADDRESS     - Pool fee destination (bc1p... recommended)
#   SIGNING_KEY          - 64 hex char message signing key
#   INTERNAL_API_SECRET  - 64 hex char API authentication secret
```

### 3. Start the Pool

```bash
source mainnet.env && ghost-pool --config mainnet.toml
```

## Mining Modes

| Mode | DNS | Password | Rewards | Use Case |
|------|-----|----------|---------|----------|
| `public_pool` | Yes | No | Pool split | Public mining pool |
| `private_pool` | No | Yes | Pool split | Friends/family pool |
| `private_solo` | No | Yes | 99% to operator | Own mining hardware |

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
| `treasury_address` | `[pool]` | Economic - prevents redirect attacks |
| `internal_api_secret` | `[network]` | Security - can't change own auth |
| `key_path` | `[identity]` | Identity - changing would change node_id |
| `signing_key` | `[network]` | Identity - tied to DNS registration |
| `network` | `[bitcoin]` | Network - changing networks is catastrophic |
| `seed_nodes` | `[network]` | Security - prevents peer poisoning |

### Mutable Settings (Dashboard API)

These settings can be changed via `POST /api/v1/admin/config` with proper authentication. Changes trigger a graceful restart (5-10 seconds).

| Setting | Section | Use Case |
|---------|---------|----------|
| `mining_mode` | `[network]` | Switch public/private/solo |
| `private_mining_password` | `[network]` | Set/change private mode password |
| `solo_payout_address` | `[network]` | Set destination for solo mode |
| `profile` | `[policy]` | Switch policy profile |
| `enabled` | `[ghost_pay]` | Toggle Ghost Pay L2 on/off |

### Graceful Restart Behavior

When configuration changes via the dashboard API:

1. **Preserved across restart:**
   - Node ID (same key file)
   - Elder status (stored in database)
   - Verification history (stored in database)
   - Miner balances (stored in database)

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
  "mining_mode": "private_solo",
  "private_mining_password": "your-password",
  "solo_payout_address": "bc1p...",
  "policy_profile": "bitcoin_pure",
  "ghost_pay_enabled": true
}
```

All fields are optional - only include settings you want to change.

### Response

```json
{
  "success": true,
  "changes": ["mining_mode", "policy_profile"],
  "restart_required": true,
  "restart_in_seconds": 5
}
```

### Validation Rules

- `mining_mode`: Must be `public_pool`, `private_pool`, or `private_solo`
- `private_mining_password`: Required when switching to private modes (min 8 chars)
- `solo_payout_address`: Required when switching to `private_solo` (valid bech32)
- `policy_profile`: Must be `bitcoin_pure`, `permissive`, `full_open`, or `custom`

### Error Response

```json
{
  "success": false,
  "error": "solo_payout_address required for private_solo mode"
}
```

## SRI (Stratum Reference Implementation)

SRI pool and translator configs are in `sri/` subdirectory:

- `sri/pool-config.toml` - SRI Pool (SV2 server)
- `sri/translator-config.toml` - SRI Translator (SV1↔SV2 bridge)
