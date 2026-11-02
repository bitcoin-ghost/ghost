# Glyphs

*A 16×16-pixel ghost avatar permanently bound to a Ghost ID. Designed once, registered through a Wraith deposit, then displayed everywhere the Ghost ID appears — wallets, merchant terminals, node UIs, transaction receipts. Each pixel pattern is unique across the entire network.*

## The problem

A Ghost ID is a `ghost1...` bech32 string. It's the right shape for software but the wrong shape for humans: 60-something characters of base32, identical-looking from a glance. People can't remember them, can't visually distinguish them at a list, can't easily pick the right contact under stress (paying a merchant, scanning a QR, signing a high-value transfer).

A Glyph is a small visual fingerprint that humans CAN distinguish at a glance. Two Ghost IDs differ by at most 32 bytes; their Glyphs differ by 256 pixels in 26 colours. The eye picks up the difference instantly.

## What a Glyph is

A 16×16 bitmap, where each pixel is one of 26 colours from a ghost-themed palette. 256 pixels total, 256 bytes of data, deterministically committed to a specific Ghost ID via a hash binding.

```
struct GhostGlyph {
    pixels:        [u8; 256],          // 16×16 palette indices, values 0–25
    ghost_id:      String,             // ghost1... bech32m
    commitment:    [u8; 32],           // SHA256 binding pixels to ghost_id
    bitmap_hash:   [u8; 32],           // SHA256 of pixels alone (uniqueness key)
    registered_at: Option<u64>,        // Unix timestamp once funded
    funding_txid:  Option<String>,     // Wraith deposit that triggered registration
}
```

Two hashes: one binds the design to a specific Ghost ID; the other is identity-independent and used for global uniqueness enforcement.

## The 26-colour palette

Five themed groups, calibrated to remain distinguishable at small render sizes:

| Group | Indices | Mood |
|---|---|---|
| Core tones | 0–6 | Black → near-white with cool undertones |
| Spectral blues | 7–10 | Deep ocean → bright sky (the primary ghost colours) |
| Ghostly greens | 11–14 | Dark crypt → luminous spirit |
| Ember / warning | 15–18 | Blood red → warm lantern |
| Purple / arcane | 19–22 | Deep abyss → soft lilac |
| Accents | 23–25 | Soul Gold, Ghost Teal, Banshee Pink |

Each colour has a name. Examples:

| Index | Name | Hex |
|---|---|---|
| 0 | Void Black | `#000000` |
| 1 | Phantom White | `#FFFFFF` |
| 9 | Wraith Blue | `#4064C8` |
| 13 | Poltergeist | `#50C878` |
| 17 | Hellfire | `#DC5028` |
| 21 | Arcane | `#A050DC` |
| 24 | Ghost Teal | `#00C8C8` |

26 colours fits one byte per pixel comfortably (any value `≥ 26` is rejected with `GlyphError::InvalidPixelValue`). The full palette is in `crates/ghost-glyph/src/palette.rs`.

## Registration

Glyphs aren't free, and they're permanent. The registration flow:

1. **Design.** User paints a 16×16 grid in their wallet's Glyph editor (Ghost Tap has one). Result: 256 palette indices.
2. **Validation.** The wallet checks every byte is `< 26` and the array is exactly 256 bytes long. Anything else throws `InvalidPixelValue` or `InvalidSize`.
3. **Hashes.** Two SHA-256 commitments computed:

    ```
    commitment   = SHA256( "GhostGlyph/v1"        ‖ pixels[256] ‖ ghost_id_bytes )
    bitmap_hash  = SHA256( "GhostGlyphBitmap/v1"  ‖ pixels[256] )
    ```

    `commitment` binds the design to the specific Ghost ID. `bitmap_hash` is identity-free and used to enforce global uniqueness — no two Ghost IDs can share a pixel pattern.

4. **Wraith deposit.** Registration is funded via a Wraith mixing session. The funding transaction is what makes the registration real on chain. Until the deposit confirms, the glyph is in a "pending" state — `registered_at` is `None`.
5. **Confirmation.** When the Wraith deposit confirms, the registry checks `bitmap_hash` against existing registrations. If it's already taken, registration fails with `DuplicateBitmap`. Otherwise the glyph is permanently bound; `registered_at` and `funding_txid` are populated.
6. **Permanence.** A Ghost ID that already has a registered glyph cannot register another (`AlreadyRegistered`). Cannot be changed, cannot be transferred, cannot be replaced — the Glyph is part of the Ghost ID's identity for life.

The Wraith deposit requirement is anti-spam: scanning the network for unique 16×16 patterns at zero cost would let attackers squat on the most valuable patterns. A funded deposit makes squatting expensive, and the Wraith mixing means observers can't easily map deposits to identities.

## Why permanence

Two-fold:

**Privacy posture.** A Glyph's value is that it consistently identifies the same Ghost ID over time. If users could change Glyphs, an attacker who'd memorised "the green-eyed ghost is Bob" loses the recognition the moment Bob updates. That's a feature for users wanting to evade specific recognition — but it's hostile to the broader purpose of letting people reliably recognise the entities they regularly transact with. Permanence locks the recognition in.

**Anti-impersonation.** A user can't grab a popular Glyph after a celebrity Ghost ID becomes well known. The registration is first-come-first-served on the unique-bitmap basis. If "the silver crown ghost" is already taken at registration time, you can't claim it later by burning enough satoshis.

The trade-off is real: a user who wants to rebrand their wallet has to start a new Ghost ID. Most wallets handle this by letting users hold multiple Ghost IDs simultaneously.

## Rendering

Glyphs render as raw RGBA buffers at configurable scale. No external image library required — the renderer just writes RGBA bytes you can pass to a framebuffer, a canvas, or an export tool.

| Scale | Output | Buffer | Use case |
|---|---|---|---|
| 1× | 16×16 | 1 KB | Thumbnails, list rows |
| 2× | 32×32 | 4 KB | Standard display |
| 4× | 64×64 | 16 KB | Profile views |
| 8× | 128×128 | 64 KB | Large display |
| 16× | 256×256 | 256 KB | Print / export |
| 32× | 512×512 | 1 MB | High-resolution export |
| 256× | 4096×4096 | 64 MB | Maximum resolution |

Scaling is integer block scaling, not interpolation — each source pixel becomes a `scale × scale` solid block. Sharp edges, no blur, deliberate "bitmap art" aesthetic.

If a stored Glyph somehow contains an out-of-palette pixel value (which validation should have prevented), the renderer outputs magenta `(255, 0, 255)` for that pixel as a visual safety net — easy to spot in QA.

## Where they show up

The wallet, terminal, and node UIs all use the same crate (`ghost-glyph`) for rendering, so the visual identity is consistent across surfaces:

| Context | What's shown |
|---|---|
| Ghost Tap wallet | Contact list, payment screens, address book |
| Merchant terminal | Customer-side identity during payment |
| Node TUI | Peer list, Elder roster, signing-quorum displays |
| Ghost Pay | Transaction receipts, statement views |
| Block explorers (third-party) | Optional decoration on Ghost ID lookups |

Anywhere a Ghost ID is mentioned in a UI, the Glyph renders alongside it. Users build visual recognition over time.

## What Glyphs aren't

- **Not avatars in the social-media sense.** They're identity primitives bound to cryptographic identifiers, not customisable profile pictures. Once registered, the Glyph is the Ghost ID's permanent visual.
- **Not on-chain art.** The pixel data isn't stored on the Bitcoin chain. The chain stores only the Wraith deposit transaction and a small commitment; the Glyph bitmap lives in the L2 / network registry.
- **Not free.** Registration costs the Wraith deposit fee + the commitment burn. Small, but real.
- **Not transferrable.** A Glyph belongs to its Ghost ID forever. Selling a Ghost ID doesn't transfer it (and selling Ghost IDs isn't really a thing — the keys ARE the ID).
- **Not anonymity.** A Glyph makes identity *more* recognisable, not less. A user who wants to remain anonymous can keep a wallet with no registered Glyph; the Ghost ID still works for receiving and spending. Glyphs are opt-in.
- **Not unique-collectible.** No NFT semantics, no marketplace, no scarcity-as-economic-asset. The 16×16×26-colour design space holds 2^218 distinct bitmaps; the uniqueness rule is for human recognisability, not artificial scarcity.

## Errors at a glance

```
GlyphError::InvalidPixelValue { index, value }   pixel byte ≥ 26
GlyphError::InvalidSize       { expected, got }  pixel slice ≠ 256 bytes
GlyphError::DuplicateBitmap                      another Ghost ID has this design
GlyphError::AlreadyRegistered                    this Ghost ID already has a glyph
GlyphError::InvalidScale(scale)                  render scale 0 or > 256
GlyphError::NotFound                             no glyph for that query
GlyphError::StorageError(msg)                    database / storage failure
```

## Source

| File | Purpose |
|---|---|
| `crates/ghost-glyph/src/glyph.rs` | `GhostGlyph` struct, validation, commitment + bitmap hashing |
| `crates/ghost-glyph/src/palette.rs` | The 26-colour palette |
| `crates/ghost-glyph/src/render.rs` | RGBA renderer at integer scales |
| `crates/ghost-glyph/src/error.rs` | `GlyphError` enum |
| `apps/ghost-tap/core/src/glyph.rs` | Wallet-side editor + display integration |
