#!/usr/bin/env python3
"""Mine a regtest block whose coinbase carries a Ghost payout tag.

`generatetoaddress` builds its own coinbase and cannot be told to include our scriptSig, so the
settlement path — which keys entirely off that tag — cannot be exercised with it. This assembles
the block by hand instead: template, coinbase with the tag, merkle root, then grind the nonce
(trivial at regtest difficulty) and submit.

The point is to produce a block that is *ours* by the same definition production uses, so the
observer's decision is made on real bytes rather than a fixture.
"""
import hashlib
import json
import struct
import subprocess
import sys

CONF = sys.argv[1]
DATADIR = sys.argv[2]
PAYOUT_ID = bytes.fromhex(sys.argv[3])  # 16 bytes, first half of the proposal hash
NODE_ID = bytes.fromhex(sys.argv[4])  # 20 bytes, sha256(node_id)[..20]

PAYOUT_MAGIC = b"GHPP"
NODE_MAGIC = b"GHNT"


def cli(*args):
    out = subprocess.run(
        ["/home/defenwycke/bin/ghost-cli", f"-conf={CONF}", f"-datadir={DATADIR}", *args],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def push(data):
    """A minimal data push — the same encoding coinbase_tags uses."""
    assert len(data) <= 75
    return bytes([len(data)]) + data


def encode_height(h):
    """BIP34: minimally-encoded, sign-aware little-endian height push."""
    b = b""
    v = h
    while v:
        b += bytes([v & 0xFF])
        v >>= 8
    if b and b[-1] & 0x80:
        b += b"\x00"
    return push(b)


tmpl = cli("getblocktemplate", '{"rules":["segwit"]}')
height = tmpl["height"]
prev = bytes.fromhex(tmpl["previousblockhash"])[::-1]
bits = bytes.fromhex(tmpl["bits"])[::-1]
cur_time = tmpl["curtime"]
version = tmpl["version"]
value = tmpl["coinbasevalue"]

# scriptSig: BIP34 height, then the two Ghost tags, then a pool tag — the production layout.
script_sig = encode_height(height)
script_sig += push(PAYOUT_MAGIC + PAYOUT_ID)
script_sig += push(NODE_MAGIC + NODE_ID)
script_sig += b"GHOST PublicPool"
assert len(script_sig) <= 100, f"scriptSig {len(script_sig)} > 100"

addr = cli("getnewaddress")
spk = bytes.fromhex(cli("getaddressinfo", addr)["scriptPubKey"])

# Non-witness serialisation: the txid that goes into the merkle root excludes witness data.
cb = struct.pack("<I", 2)
cb += varint(1)
cb += b"\x00" * 32 + struct.pack("<I", 0xFFFFFFFF)
cb += varint(len(script_sig)) + script_sig
cb += struct.pack("<I", 0xFFFFFFFF)
cb += varint(1)
cb += struct.pack("<q", value) + varint(len(spk)) + spk
cb += struct.pack("<I", 0)

txid = sha256d(cb)
merkle_root = txid  # coinbase-only block

target = int(tmpl["target"], 16)
nonce = 0
while True:
    header = (
        struct.pack("<i", version) + prev + merkle_root
        + struct.pack("<I", cur_time) + bits + struct.pack("<I", nonce)
    )
    if int.from_bytes(sha256d(header)[::-1], "big") <= target:
        break
    nonce += 1
    if nonce > 20_000_000:
        sys.exit("no solution — unexpected at regtest difficulty")

block = header + varint(1) + cb
res = cli("submitblock", block.hex())
block_hash = sha256d(header)[::-1].hex()
print(json.dumps({
    "submitblock": res or "accepted",
    "height": height,
    "block_hash": block_hash,
    "script_sig_len": len(script_sig),
    "script_sig": script_sig.hex(),
    "nonce": nonce,
}))
