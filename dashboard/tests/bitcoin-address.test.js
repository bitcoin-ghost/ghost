"use strict";

// #588: all three setup wizards accepted `tb1` and `bcrt1` alongside `bc1`, each with its own
// copy of the check. Ghost is Bitcoin MAINNET, so a testnet address saved as a node's payout
// address yields a scriptPubKey that pays to nothing spendable — silently burning the reward.

const test = require("node:test");
const assert = require("node:assert/strict");

const { isMainnetBech32Address } = require("../src/lib/bitcoinAddress.js");

test("mainnet addresses of every bech32 type are accepted", () => {
  // The control. Rejecting an address that pays out correctly today would be worse than not
  // checking at all, so this must keep passing.
  for (const [kind, addr] of [
    ["P2WPKH", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"],
    ["P2WSH", "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"],
    ["P2TR", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"],
  ]) {
    assert.equal(isMainnetBech32Address(addr), true, `${kind} must be accepted`);
  }
});

test("a testnet address is rejected", () => {
  assert.equal(
    isMainnetBech32Address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"),
    false,
  );
});

test("a regtest address is rejected even though it starts with bc", () => {
  // `bcrt1` shares its first two characters with `bc1`, so a naive prefix test lets it through.
  assert.equal(
    isMainnetBech32Address("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
    false,
  );
});

test("case and surrounding whitespace do not change the verdict", () => {
  assert.equal(
    isMainnetBech32Address("  BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4  "),
    true,
  );
});

test("characters outside the bech32 set are rejected", () => {
  // `b`, `i`, `o` and `1` are excluded from the bech32 data part. The old regex used the base58
  // class case-insensitively, which described neither alphabet.
  assert.equal(
    isMainnetBech32Address("bc1qb508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tb"),
    false,
  );
});

test("empty, short and non-string inputs are rejected", () => {
  for (const bad of ["", "bc1", "bc1q", null, undefined, 42, {}]) {
    assert.equal(isMainnetBech32Address(bad), false, `${String(bad)} must be rejected`);
  }
});

test("something longer than bech32 permits is rejected", () => {
  assert.equal(isMainnetBech32Address("bc1q" + "q".repeat(200)), false);
});
