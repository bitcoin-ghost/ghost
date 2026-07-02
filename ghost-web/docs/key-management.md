# Key management

*The five keys an operator handles, where each one lives, and how to rotate them safely. Includes the gotcha that drives most key-rotation incidents: rotating the node identity changes the node_id, which can affect Elder status if not handled carefully.*

## The five keys

| Key | Purpose | Algorithm | Where stored |
|---|---|---|---|
| **Node identity** | P2P authentication, BFT voting, mesh peer ID | Ed25519 | `~/.ghost/node.key` |
| **Noise keypair** | Encrypted P2P transport (the mesh) | X25519 | `~/.ghost/noise.key` |
| **Treasury address** | Pool fee collection (single-sig or multi-sig) | secp256k1 P2TR | Cold storage / hardware wallet |
| **Internal API secret** | Authenticates internal API calls (dashboard, mesh internal) | HMAC-SHA256 | Env var or config file |
| **Ghost Pay API secret** | Authenticates ghost-pay HTTP API | HMAC-SHA256 | `GHOST_PAY_API_SECRET` env var |

Plus, if running ghost-pay: a SQLCipher key for the L2 database (derived from a password file). And, optionally, a Registry signing key for public-mining registration.

The two that matter most operationally are **node identity** and **treasury**. Lose either and you have problems that take real work to recover from.

## Node identity

An Ed25519 keypair plus a 12-byte proof-of-work that prevents Sybil attacks. Once generated, this key IS your node — peer ID, BFT vote signature, MPC ceremony contributor, the whole identity.

### Generate

```bash
ghost-pool --generate-identity
```

Creates `~/.ghost/node.key`:
- 32 bytes: Ed25519 private key
- 12 bytes: PoW proof (nonce + difficulty)

The PoW takes a few seconds on commodity hardware. If you see the process churning for >30s, the difficulty is set high; you can lower it via `--identity-pow-difficulty=N` for testing (don't lower it for mainnet).

### Inspect

```bash
ghost-pool --show-identity
```

Output:

```
Node ID:   a1b2c3d4e5f6...
Short ID:  a1b2c3d4
Signer:    local
```

The Node ID is what other nodes see in their `nodes` table. The Short ID is the first 4 bytes — used in logs for readability.

### File-based storage (default)

Permissions matter:

```bash
chmod 600 ~/.ghost/node.key
chmod 700 ~/.ghost
```

Things you must not do:

- **Don't commit it to version control.** Even private repos. Even encrypted-at-rest. Just don't.
- **Don't share it between nodes.** Each node has its own identity. Sharing collapses two distinct peers into the same identity, with consensus consequences.
- **Don't copy it over unencrypted channels.** No plaintext SCP from the internet. Use a sealed-box on a USB stick, or encrypt with `age` / GPG before transit.

### HSM-backed storage (production)

For nodes that need stronger guarantees against key extraction, ghost-pool supports PKCS#11 HSMs.

```toml
[identity.signer]
type           = "hsm"
library_path   = "/usr/lib/pkcs11/libsofthsm2.so"
slot           = 0
pin_env        = "HSM_PIN"
key_label      = "ghost-node-key"
```

Supported HSMs:

- PKCS#11-compatible HSMs (Thales, Utimaco, etc.)
- YubiHSM 2
- AWS CloudHSM
- SoftHSM (testing only — not production-grade)

Setup outline (using SoftHSM as a test example):

```bash
# 1. Install PKCS#11 library
sudo apt install softhsm2

# 2. Initialise slot
softhsm2-util --init-token --slot 0 --label "ghost" --pin 1234 --so-pin 0000

# 3. Generate Ed25519 key inside the HSM
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --login --pin 1234 \
  --keypairgen --key-type EC:ed25519 \
  --label "ghost-node-key"

# 4. Configure ghost-pool to use it
export HSM_PIN=1234
ghost-pool --config /etc/ghost/pool.toml
```

The private key never leaves the HSM. ghost-pool sends signing requests over PKCS#11 and gets back signatures.

### KMS-backed storage (cloud)

```toml
[identity.signer]
type     = "kms"
provider = "aws"
key_id   = "arn:aws:kms:us-east-1:123456789:key/abcd-1234"
```

Trade-off: convenient operationally, places the cloud provider in the trust circle. Acceptable for some operators, unacceptable for others. Match it to your threat model.

## Treasury address

Pool fees accumulate to the treasury address until the 21 BTC threshold is reached. After threshold, the share shifts toward node operators per the decay schedule.

This is the highest-value key in the system from an economic angle. Treat it like a long-term cold-storage wallet:

- **Generate offline** on an air-gapped device. A hardware wallet works.
- **Use multisig** if multiple operators share custody (e.g. 2-of-3, 3-of-5). Multisig coordination overhead is real but it's the right answer for shared treasuries.
- **Configure** with a bech32m P2TR address (`bc1p…`). Set in `pool.toml`:
  ```toml
  [pool]
  treasury_address = "bc1p..."
  ```
- **Verify** by sending a small test amount once configured, before opening the floodgates.
- **Document** the recovery path. Multiple sealed-envelope copies of the seed phrase, in geographically separate locations, with clear chain-of-custody for the human(s) who'd need to reconstitute it.

The mainnet validator rejects any non-mainnet treasury address (a `tb1...` or `bcrt...` would fail with C-02 "Address validation rejects non-mainnet addresses"). This is intentional — operators have configured testnet addresses on production by accident before.

## Noise keypair

X25519 used for encrypted P2P traffic on the mesh. There is no dedicated
generation subcommand — ghost-pool creates `<data_dir>/noise.key` on first
start if the file is missing, and reuses it thereafter. Tighten permissions
once it exists:

```bash
chmod 600 /home/ghost/.ghost/noise.key
```

Lower-stakes than the node identity — the noise key only encrypts the transport, it doesn't sign votes or messages. Compromise is contained: an attacker who steals it can decrypt that node's mesh traffic but can't impersonate the node (the identity Ed25519 is what signs).

Rotate any time without consensus impact: stop ghost-pool, delete `noise.key`, restart. A fresh keypair is generated and picked up automatically.

## Internal API secret

Used to authenticate internal API calls between ghost-pool and the dashboard, and between dashboard and admin clients. Generate with:

```bash
openssl rand -hex 32
```

Put it in `pool.toml` (preferred) or as `GHOST_INTERNAL_API_SECRET` in the systemd unit:

```toml
[network]
internal_api_secret = "abcd1234..."   # 64 hex chars
```

Mainnet hard-fails without this set. Rotate on a schedule (every 90 days is a sensible default) — every dashboard / mesh-API client needs to be updated when you rotate.

## Ghost Pay API secret

If running ghost-pay, set in the systemd unit's environment:

```ini
Environment=GHOST_PAY_API_SECRET=<openssl rand -hex 32>
Environment=GHOST_PAY_PASSWORD=<another-secret>
```

Mainnet ghost-pay refuses to start without both. The password is used to derive the SQLCipher encryption key for `ghost-pay.db`; the API secret authenticates HTTP API requests.

Each node should have its own values. Don't reuse across the fleet — if one node's secret leaks, you don't want the others compromised too.

## Rotation

### When to rotate

| Trigger | Rotate |
|---|---|
| Scheduled | Node identity: every 12–24 months. Internal/Ghost Pay secrets: every 90 days. Noise keypair: optional but cheap. |
| Personnel | Anyone with key access leaves your team |
| Backup compromised | Stolen laptop, breached cloud bucket, accidental commit to a public repo |
| Audit recommendation | Acted on within the audit's stated timeline |
| Migration | Moving to a new HSM, new KMS provider, new infrastructure |

**Signs of compromise** that demand immediate rotation:

- Unexpected voting behaviour attributed to your node_id.
- Messages signed by your node that you didn't authorise.
- Peers reporting conflicting signatures from your node_id.

### The Elder gotcha

This is the one that bites operators every time:

> Rotating the node identity changes your `node_id`, and **Elder status is tied to node_id**.

If you're an Elder (one of the first 101 nodes), a fresh node identity is a different peer to the rest of the mesh. The new peer has no Elder slot, no MPC ceremony contribution, no qualification history. Months of pass-rate accumulation reset to zero.

Three responses:

1. **Don't rotate if you don't have to.** Most node identities are fine for years. Plan rotation for a real reason, not a calendar reminder.
2. **Plan for the slot loss.** A non-Elder node is still a useful pool operator — just without the +1 Elder share. If you're past Elder slot 101 anyway (the cap is closed), this doesn't apply.
3. **Coordinate with the mesh.** Notify other operators ahead of time. Provide the new node_id. Coordinate timing to minimise BFT disruption (rotating during a settlement-batch window is bad form).

A future "Elder slot transfer" procedure (committee vote to transfer slot from old → new node_id) is on the roadmap but not implemented as of writing. For now, rotation = new identity = new place in the network.

### Standard rotation procedure (non-Elder, single node)

```bash
# 1. Backup current key
cp ~/.ghost/node.key ~/.ghost/node.key.backup-$(date +%Y%m%d)
chmod 600 ~/.ghost/node.key.backup-*

# 2. Record current node_id (you'll need it for handoff)
ghost-pool --show-identity > /tmp/old-identity.txt

# 3. Stop the node
sudo systemctl stop ghost-pool

# 4. Move old key out of the way
mv ~/.ghost/node.key ~/.ghost/node.key.retired-$(date +%Y%m%d)

# 5. Generate new identity
ghost-pool --generate-identity

# 6. Verify the new key
ghost-pool --show-identity

# 7. Start the node
sudo systemctl start ghost-pool
sudo journalctl -u ghost-pool -f --since "1 min ago"
```

Within ~60 seconds the new identity should appear in peer mesh databases. Check from a peer:

```bash
sqlite3 /home/ghost/.ghost/ghost.db \
  "SELECT peer_id, last_seen FROM nodes ORDER BY last_seen DESC LIMIT 5"
```

The new node_id should be near the top.

### Rotation across the cluster (planned operational change)

If you're rotating multiple nodes (e.g. annual maintenance), spread the rotations:

- Day 1: rotate VM4. Watch for 24h.
- Day 2: rotate VM3. Watch for 24h.
- Day 3: rotate VM2. Watch for 24h.
- Day 4: rotate VM1.

This keeps a stable BFT majority through each step. Don't rotate all nodes the same day — you create a 24-hour window where every peer in the mesh is unfamiliar with every other peer's new identity, and discovery has to re-stabilise.

## Backup posture per key

| Key | Backup approach | Frequency |
|---|---|---|
| Node identity | Encrypted backup of `node.key` to off-host secure storage | After generation, never re-rotate without backing up |
| Noise keypair | Same | After generation |
| Treasury seed | Multiple sealed-envelope copies, geographically separated, never digital | After generation, audited annually |
| Internal API secret | In your secret manager (Vault, 1Password, etc.) | Every rotation |
| Ghost Pay secrets | Same | Every rotation |

The treasury seed is the disaster-recovery scenario you really care about. If every other thing in the system is gone — every node, every database, every backup — the treasury seed is what lets you recover the accumulated pool fees. Treat it accordingly: paper, metal, in a safe, and ideally in two safes.

## What this guide doesn't cover

- **Multisig orchestration software.** If you run a 3-of-5 treasury with hardware wallets across operators, the coordination tooling (Specter, Sparrow, Caravan) is whatever your team already uses. Ghost-pool just consumes the resulting bech32m address.
- **HSM vendor specifics.** Each HSM has its own initialisation, backup, and audit story. The PKCS#11 layer is the standard interface; what's behind it varies.
- **Per-jurisdiction compliance.** Some operators have to file specific paperwork around HSM custody. That's outside this doc's scope.
- **Wallet seed management.** This is operator-side ghost-pool keys, not user-side wallet keys. Wallets (Ghost Tap, Light Wallet) have their own backup model — see [Wallets](#wallets).

## Source

| File | Purpose |
|---|---|
| `crates/ghost-common/src/identity.rs` | Ed25519 keypair, PoW generation, signing |
| `crates/ghost-common/src/signer.rs` | Local / HSM / KMS signer abstractions |
| `bins/ghost-pool/src/main.rs` | `--generate-identity` and `--show-identity` flags, mainnet validation of API secret + treasury address |
| `crates/ghost-storage/src/encryption.rs` | SQLCipher key derivation for ghost-pay |
