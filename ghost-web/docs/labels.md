# Labels

*A privacy-preserving way for recipients to categorise incoming payments. The category number is meaningless to anyone but the recipient. Every payment carries one (so no fingerprint), and the human-readable mapping never leaves the recipient's device.*

## The problem

Receiving payments is half the privacy challenge; the other half is keeping useful records of *what those payments were for*. A user accepts payments to one Ghost ID and wants to track: this 0.05 BTC was a donation, this 0.20 BTC was a salary, this 0.001 BTC was a refund. Without categories, every receipt is just "incoming, value, timestamp".

The naive fix is to give senders different addresses per category. Ghost Keys already encourage this (the static Ghost ID can be tagged with derivation hints). But the more categories you expose, the more the address surface starts to leak: an observer who sees "alice@/donations" and "alice@/salary" can map your professional life. The privacy story is supposed to be that nobody sees that.

Labels solve it cleanly: the category is **encrypted, recipient-local, and meaningless to anyone else**. Every payment carries one (defaulting to `0`), so labelled and unlabelled payments are indistinguishable on the wire. The mapping from the integer label to a human-readable name lives only on the recipient's device.

## How it works

A Ghost ID can be advertised with a label hint:

```
Standard: ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...
Labelled: ghost1qpzry9x8gf2tvdw0s3jn54khce6mua7l...?l=7
```

The `?l=7` is a query-parameter-style hint to the sender: "when you send to this address, include label index 7 in the encrypted metadata". The recipient's wallet has its own local dictionary that maps `7 → "Donations"`. Senders never see the label name.

Multiple labelled addresses pointing at the same Ghost ID:

```
ghost1qpzry...?l=1   →   recipient labels 1 = "Donations"
ghost1qpzry...?l=2   →   recipient labels 2 = "Freelance"
ghost1qpzry...?l=3   →   recipient labels 3 = "Family"
```

To anyone watching the chain, all of these resolve to the same on-chain receive logic. Only the recipient knows which payment landed in which category.

## Four design properties

### 1. Labels never touch cryptography

Labels are *purely metadata*. They don't affect:

- Address derivation
- Spend key computation
- One-time output generation
- Any cryptographic operation

This is critical. Silent Payment v2 (the underlying address scheme — see [Keys](#keys)) gives recipient privacy by deriving fresh outputs per payment using ECDH. If labels were involved in derivation, the address space would partition by label and an observer could tell which label was used by analysing the outputs. By keeping labels strictly metadata-side, the cryptographic privacy of [Keys](#keys) carries through completely.

### 2. Every payment carries a label

The wire format always includes the encrypted label field. Default: `0`.

The reasoning is anti-fingerprinting. If only some payments had a label field, an observer could tell labelled-from-unlabelled at a glance and start partitioning. By making the field universal, "no label" looks identical to "label 0" — there's no signal.

### 3. Recipient-local semantics

The label number `1` means whatever the recipient says it means:

```
Alice's dictionary:        Bob's dictionary:
  1 → "Donations"            1 → "Salary"
  2 → "Freelance"            2 → "Refunds"
  3 → "Family"               3 → "Investments"
```

An observer who somehow saw `label: 1` (which they can't — it's encrypted) would still learn nothing. There's no global registry, no canonical interpretation, no leak.

### 4. Deletion safety

Recipients can delete a label dictionary entry at any time. Old payments retain the numeric `label: 5` but the wallet shows `[unknown 5]` instead of the name. Nothing breaks, no data corruption — just a gap in the categorisation that the user can re-fill if they remember what 5 was.

## The data on the wire

Every payment includes an 80-byte encrypted metadata blob attached to the transaction. The in-memory Rust struct:

```rust
struct PaymentMetadata {
    label:   u32,            // recipient-local index (default 0)
    memo:    Option<String>, // optional sender memo (≤59 bytes UTF-8)
    padding: [u8; 59],       // random padding (private field)
}
```

That struct is never sent over the wire. Before encryption, `to_plaintext()` serialises it into a fixed 64-byte buffer:

- 4 bytes label (big-endian u32)
- 1 byte memo length (0–59)
- 59 bytes memo content (filled from the `Option<String>` if present, otherwise random bytes from `padding`)

= 64 bytes plaintext → ChaCha20-Poly1305 → **80 bytes ciphertext** (64 + 16-byte Poly1305 auth tag). The 80-byte ciphertext is what's attached to the transaction.

**Total wire size: 80 bytes always.** Padded to a constant so a long memo isn't distinguishable from a short one or none at all. The random `padding` bytes also ensure two payments with identical `(label, memo)` produce different ciphertexts.

### Encryption

ChaCha20-Poly1305 AEAD with the key and nonce both derived from the same ECDH shared secret used by [Keys](#keys), via HKDF-SHA256 with domain-separated info strings:

```
encryption_key = HKDF-SHA256(
    ikm:    shared_secret,
    salt:   ephemeral_pubkey,
    info:   "ghost/metadata/key/v1",
    out_len: 32 bytes,
)

nonce = HKDF-SHA256(
    ikm:    shared_secret,
    salt:   ephemeral_pubkey,
    info:   "ghost/metadata/nonce/v1",
    out_len: 12 bytes,
)
```

Two properties to notice:

- **Recipient-only decryption.** Only someone who can compute `shared_secret = scan_secret · E` can decrypt the metadata. That's the same key Ghost Keys uses to detect payments — so if a wallet can find a payment, it can also decrypt its metadata. No additional key material.
- **Deterministic nonce.** Computed from the shared secret and ephemeral pubkey via HKDF; not transmitted. Saves 12 bytes on the wire and removes any nonce-reuse risk (each Silent Payment uses a fresh ephemeral keypair, so the `(salt, info)` pair, and hence the derived `(key, nonce)`, is unique per payment).

## A worked example

Alice runs a website that takes donations. She wants to track donations separately from her freelance income.

**Setup:**

```
Alice creates labels in her wallet:
   dictionary.create("Donations")  → index 1
   dictionary.create("Freelance")  → index 2

Alice generates two labelled addresses for the same Ghost ID:
   donate URL:      ghost1qpzry...?l=1
   freelance URL:   ghost1qpzry...?l=2

Alice posts the donate URL on her website and the freelance URL in invoices.
```

**Bob donates 0.05 BTC:**

```
Bob's wallet sees:  ghost1qpzry...?l=1
Bob composes payment:
   metadata = PaymentMetadata { label: 1, memo: "Loved the post" }
Bob encrypts metadata with shared_secret derived from Alice's scan_pubkey.
Bob broadcasts the L2 transaction with encrypted_metadata attached.
```

**Carol pays 0.2 BTC for freelance work:**

```
Carol's wallet sees:  ghost1qpzry...?l=2
Carol composes payment:
   metadata = PaymentMetadata { label: 2, memo: "Web design Q1" }
Carol encrypts and broadcasts.
```

**Alice's wallet, scanning the L2:**

```
For each transaction:
  derive shared_secret from scan_secret and the transaction's ephemeral_pubkey
  attempt to decrypt encrypted_metadata
  if decryption succeeds → payment is mine

Bob's tx decrypts to:    PaymentMetadata { label: 1, memo: "Loved the post" }
Carol's tx decrypts to:  PaymentMetadata { label: 2, memo: "Web design Q1" }

Alice's wallet displays:
   Received 0.05 BTC [Donations]: Loved the post
   Received 0.20 BTC [Freelance]: Web design Q1
```

To any outside observer, both payments look identical: a fresh P2TR output, an OP_RETURN containing the ephemeral pubkey, an 80-byte encrypted metadata blob. Same shape, same size, indistinguishable.

## Memos vs labels

Both fields are optional from the sender's perspective.

| Field | Purpose | Set by | Visible to |
|---|---|---|---|
| **label** | Recipient-controlled category | Sender (hint from URL) | Recipient only |
| **memo** | Sender-controlled note | Sender directly | Recipient only |

A sender can always include a memo regardless of the recipient's labelling scheme. A recipient can always categorise on receive even if the sender's memo says nothing useful. The two are independent.

The memo cap of 59 bytes is a hard limit (deliberate constant size for fingerprint resistance — see "every payment carries a label" above). For longer notes, senders use external messaging.

## What labels aren't

- **Not visible to senders.** The `?l=N` hint is just an integer; senders don't see "Donations" or "Salary". They see `7`. Recipients keep the human meaning private.
- **Not on chain.** The labelled URL (`ghost1...?l=N`) is the recipient's choice of presentation. The chain only records the encrypted 80-byte blob. The mapping from the URL parameter to the encrypted label happens at sender side; the URL itself isn't on chain.
- **Not unique per payment.** Many payments can share the same label. That's the point — recurring donations all land in the "Donations" bucket.
- **Not enforceable.** A sender can include a wrong or spoofed label index (anyone can put `?l=999` in their broadcast). The recipient's wallet just shows "[unknown label]" for unknown indices and the user decides whether to trust the categorisation. This is fine because labels are organisational, not security-critical.
- **Not a memo replacement.** Labels and memos coexist. Labels are categorical (drop-down list), memos are free-form text.
- **Not transferable.** A user's label dictionary is local-only. Moving a wallet to a new device requires backing up the dictionary along with the keys. Most wallets do this automatically as part of seed-based backup.

## Backup considerations

Because labels are local-only, losing the dictionary loses the human-readable mappings. Old payments still show with their numeric labels (`label: 5`), but `[5]` instead of `[Donations]`.

Wallets handle this two ways:

1. **Dictionary tied to seed.** Encrypt the dictionary under a key derived from the wallet's seed and store it in the wallet's encrypted-database backup. Restoring from seed restores labels too.
2. **Manual export/import.** Some users prefer to back up the dictionary separately, e.g. as a small JSON file in a separate cold-storage location. Wallets support this for users who want explicit control.

Either way, the dictionary never goes through the network, never crosses a boundary that a third party could observe.

## Where labels sit

| Layer | Primitive | What it does |
|---|---|---|
| Identity | [Keys](#keys) | Static Ghost ID; fresh derivation per payment |
| Visual identity | [Glyphs](#glyphs) | 16×16 avatar bound to the Ghost ID |
| Receive categorisation | **Labels** | **Encrypted recipient-local payment categories** |
| Custody | [Locks](#locks) | Hold funds in P2TR with timelocked recovery |

Labels are the smallest piece in the stack — 80 bytes per payment, no cryptographic load — but they're often the difference between "I know what came in this month" and "scrolling through 200 entries that all say 'incoming'".

## Source

| File | Purpose |
|---|---|
| `crates/ghost-keys/src/metadata.rs` | `PaymentMetadata`, encryption, AEAD wire format |
| `crates/ghost-keys/src/labels.rs` | `LabelDictionary` (recipient-side index → name mapping) |
| `crates/ghost-keys/src/scanning.rs` | Decryption during payment scan |
| `bins/ghost-pay/src/main.rs` | HTTP handlers (label-aware scanning routes) |
