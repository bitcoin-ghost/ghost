# Light wallet CLI

*A lightweight command-line wallet that connects to Ghost nodes via the GSP protocol. No blockchain download required.*

:::warning Superseded by the Wraith wallet
The standalone `ghost-light-wallet` binary described below has been **retired**. The light/CLI wallet is now part of the **Wraith wallet** (`apps/wraith-wallet/`), which ships a CLI, a background daemon and a desktop GUI from one core:

- **Crate:** `wraith-wallet-cli` &nbsp;→&nbsp; **binary:** `wraith`
- **Build:** `cargo build --release -p wraith-wallet-cli`

The command examples further down reflect the older `ghost-light-wallet` interface and may not match the `wraith` CLI one-for-one. Treat this page as conceptual (GSP connection, Ghost Keys, no full node) until it's rewritten against the `wraith` command set.
:::

## Overview

The light wallet is a self-custody Bitcoin wallet designed for users who don't want to run a full node. It connects to Ghost Service Provider (GSP) servers via WebSocket to query balances, submit transactions, and interact with Ghost Pay.

:::info Key Features
- No blockchain download - connects via GSP WebSocket
- Ghost Keys (BIP-352 Silent Payments) for privacy
- Ghost Locks for timelocked outputs
- Ghost Pay L2 integration
- Wraith Protocol entry points
- Self-custody - keys never leave your device
:::

## Installation

### Quick Install

```bash
# Install via the Ghost installer
curl -sSL https://get.bitcoinghost.org/wallet.sh | bash
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/bitcoin-ghost/ghost
cd ghost

# Build the Wraith wallet CLI (crate is `wraith-wallet-cli`, binary is `wraith`)
cargo build --release -p wraith-wallet-cli

# Binary is at:
./target/release/ghost-light-wallet
```

### Verify Installation

```bash
ghost-light-wallet --version
ghost-light-wallet 1.4.0
```

## Getting Started

### Create a New Wallet

```bash
ghost-light-wallet wallet create

Creating new wallet...

Your recovery phrase (write this down!):
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about

Wallet created successfully.
Default GSP server: wss://pool.bitcoinghost.org:8900/gsp
```

:::warning Backup Your Recovery Phrase
Write down your 12-word recovery phrase and store it securely. This is the only way to recover your wallet if your device is lost.
:::

### Restore from Recovery Phrase

```bash
ghost-light-wallet wallet restore

Enter your 12-word recovery phrase:
> abandon abandon abandon ...

Wallet restored successfully.
```

### Connect to a GSP Server

```bash
# Use the default server
ghost-light-wallet

# Or specify a server
ghost-light-wallet --server wss://pool.bitcoinghost.org:8900/gsp

# Connect to a specific node
ghost-light-wallet --server wss://192.168.1.100:8900/gsp
```

## Command Reference

| Command | Description |
| --- | --- |
| wallet create | Create a new wallet with a fresh recovery phrase |
| wallet restore | Restore wallet from a 12-word recovery phrase |
| balance | Show current wallet balance (on-chain + Ghost Pay) |
| key generate | Generate a new Ghost Key (Silent Payment address) |
| key list | List all generated Ghost Keys |
| send <address> <sats> | Send Bitcoin to an address |
| receive | Generate a receive address (or Ghost Key) |
| lock create | Create a Ghost Lock (timelocked output) |
| lock list | List all Ghost Locks |
| lock claim <id> | Claim a matured Ghost Lock |
| history | Show transaction history |
| pay send <address> <sats> | Send via Ghost Pay L2 (fast, private) |
| pay receive | Generate Ghost Pay invoice |
| wraith enter <sats> | Enter Wraith Protocol mixing pool |

## Ghost Keys

Ghost Keys are based on BIP-352 Silent Payments. They allow you to receive payments without revealing your public key or reusing addresses.

### Generate a Ghost Key

```bash
ghost-light-wallet key generate

New Ghost Key generated:
sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq...

Share this key with senders. Each payment creates a unique address.
```

### How It Works

1. You share your Ghost Key publicly (like a reusable address)
2. Senders derive a unique one-time address from your Ghost Key
3. Only you can detect and spend payments to these derived addresses
4. No address reuse, no link between payments

## Ghost Locks

Ghost Locks are timelocked P2TR outputs with recovery paths. They're useful for savings vaults, inheritance planning, or scheduled payments.

### Create a Ghost Lock

```bash
# Lock 100,000 sats for 144 blocks (~1 day)
ghost-light-wallet lock create --amount 100000 --blocks 144

Ghost Lock created:
  Lock ID: lock_a1b2c3d4
  Amount: 100,000 sats
  Unlocks at block: 878,234
  Recovery path: After 1008 blocks if primary key is lost
```

### Lock Options

```bash
ghost-light-wallet lock create \
  --amount 500000 \           # Amount in sats
  --blocks 4320 \             # Lock duration (~30 days)
  --recovery-blocks 8640 \   # Recovery path delay
  --recovery-key <pubkey>    # Optional backup key
```

## Ghost Pay Integration

Ghost Pay provides fast, private L2 payments. The light wallet CLI supports sending and receiving via Ghost Pay.

```bash
# Check Ghost Pay balance
ghost-light-wallet balance
On-chain: 0.05000000 BTC
Ghost Pay: 0.01000000 BTC

# Send via Ghost Pay (10-second confirmation)
ghost-light-wallet pay send bc1q... 50000

# Generate Ghost Pay invoice
ghost-light-wallet pay receive --amount 25000
```

## Configuration

The wallet stores configuration in `~/.ghost-wallet/config.toml`.

```bash
# ~/.ghost-wallet/config.toml

[network]
network = "signet"  # mainnet, signet, testnet

[gsp]
default_server = "wss://pool.bitcoinghost.org:8900/gsp"
timeout_ms = 30000

[wallet]
auto_backup = true
backup_path = "~/.ghost-wallet/backups"
```

## Security

:::warning Self-Custody Wallet
Your private keys are stored locally in an encrypted wallet file. The GSP server never sees your keys. However:

- Always backup your recovery phrase offline
- Use a strong password for wallet encryption
- The GSP server sees your balance queries (use Tor for privacy)
- Consider running your own GSP node for maximum privacy
:::

## Troubleshooting

### Connection Failed

```bash
# Check if the GSP server is reachable
ghost-light-wallet --server wss://pool.bitcoinghost.org:8900/gsp status

# Try an alternative server
ghost-light-wallet --server wss://backup.bitcoinghost.org:8900/gsp
```

### Transaction Not Confirming

Check the mempool fee rate and bump the fee if needed:

```bash
ghost-light-wallet tx bump <txid> --fee-rate 50
```
