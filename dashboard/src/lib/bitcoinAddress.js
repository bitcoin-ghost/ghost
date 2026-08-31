"use strict";

/**
 * Single source of truth for validating a Bitcoin payout address in the setup wizards.
 *
 * Ghost runs on Bitcoin MAINNET. All three wizards previously accepted `tb1` and `bcrt1`
 * alongside `bc1`, each with its own copy of the check, so a testnet or regtest address could
 * be saved as a node's payout address. Nothing downstream caught it: the address reaches every
 * consumer through `assume_checked()`, which asserts rather than checks, and the resulting
 * scriptPubKey pays to nothing spendable on mainnet — silently burning the reward (#588).
 *
 * The authoritative check is server-side (`validate_pool`, #799). This is the first line of
 * defence, so the operator is told at the point of entry rather than by a node that will not
 * start.
 *
 * Deliberately NOT widened here: the wizards have only ever accepted bech32, while the backend
 * also accepts P2PKH, P2SH, P2WSH and P2TR. Accepting more is a behaviour change and belongs in
 * its own decision — this change only ever REJECTS more than before.
 *
 * No checksum verification: that needs a bech32 implementation, and a typo that survives this
 * is caught server-side. This catches the wrong-network mistake, which is the one that is
 * silent and costly.
 */

/** Bech32 data-part character set — deliberately excludes `1`, `b`, `i` and `o`. */
const BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/** Mainnet segwit human-readable part. `tb1` (testnet/signet) and `bcrt1` (regtest) are not. */
const MAINNET_PREFIX = "bc1";

/**
 * True if `address` is a plausible MAINNET bech32/bech32m address.
 *
 * @param {string} address
 * @returns {boolean}
 */
function isMainnetBech32Address(address) {
  if (typeof address !== "string") return false;
  const trimmed = address.trim().toLowerCase();

  if (!trimmed.startsWith(MAINNET_PREFIX)) return false;

  // Guard the near-misses explicitly: `bcrt1` also starts with "bc", so a prefix test alone
  // would let every regtest address through.
  if (trimmed.startsWith("bcrt1")) return false;

  // bech32 is capped at 90 characters in total; the shortest real payout address is P2WPKH at 42.
  if (trimmed.length < 42 || trimmed.length > 90) return false;

  const data = trimmed.slice(MAINNET_PREFIX.length);
  if (data.length === 0) return false;

  for (const ch of data) {
    if (!BECH32_CHARS.includes(ch)) return false;
  }

  return true;
}

module.exports = { isMainnetBech32Address, BECH32_CHARS, MAINNET_PREFIX };
