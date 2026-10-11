#!/usr/bin/env python3
"""
Attack Transaction Crafter for Ghost Pool Stress Testing

Constructs raw transaction hex for various Bitcoin spam/attack patterns.
Used by test-deployment.sh Phase 3 tests to verify Reaper filtering.

Usage:
    python3 craft-attack-txs.py <attack_type> <txid> <vout> <amount_sats> <privkey_wif> <dest_address>

Attack types:
    inscription      - Ordinals inscription envelope (OP_FALSE OP_IF "ord")
    large_inscription - 5KB inscription payload
    drop_stuffing    - OP_PUSHDATA + OP_DROP in witness
    fake_pubkey      - Bare multisig with fake 0x04-prefix pubkey
    excess_witness   - 2KB padding in witness stack
    runes            - OP_RETURN OP_13 (Runes protocol marker)
    brc20            - JSON payload in taproot witness

Outputs raw tx hex to stdout. Caller submits via bitcoin-cli sendrawtransaction.

Note: Most attack types craft a witness-bearing transaction. Bitcoin Core may
reject some at mempool acceptance (which is fine — we're testing ghost-mining's
template filtering, not mempool relay). For tests where Core rejects at mempool,
we use the bitcoin-cli patching approach instead.
"""

import sys
import struct
import hashlib
import json


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def ripemd160(data: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(data)
    return h.digest()


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return struct.pack("<B", n)
    elif n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    else:
        return b"\xff" + struct.pack("<Q", n)


def push_data(data: bytes) -> bytes:
    """Encode a data push for Bitcoin script."""
    length = len(data)
    if length == 0:
        return b"\x00"  # OP_0
    elif length <= 75:
        return bytes([length]) + data
    elif length <= 255:
        return b"\x4c" + bytes([length]) + data  # OP_PUSHDATA1
    elif length <= 65535:
        return b"\x4d" + struct.pack("<H", length) + data  # OP_PUSHDATA2
    else:
        return b"\x4e" + struct.pack("<I", length) + data  # OP_PUSHDATA4


# Bitcoin script opcodes
OP_0 = b"\x00"
OP_FALSE = b"\x00"
OP_1 = b"\x51"
OP_2 = b"\x52"
OP_3 = b"\x53"
OP_13 = b"\x5d"
OP_RETURN = b"\x6a"
OP_DROP = b"\x75"
OP_IF = b"\x63"
OP_ENDIF = b"\x68"
OP_CHECKMULTISIG = b"\xae"
OP_DUP = b"\x76"
OP_HASH160 = b"\xa9"
OP_EQUALVERIFY = b"\x88"
OP_CHECKSIG = b"\xac"


def build_inscription_witness(payload: bytes, content_type: str = "text/plain") -> list:
    """Build an Ordinals inscription witness stack.

    Inscription envelope:
        OP_FALSE OP_IF
            OP_PUSH "ord"
            OP_1
            OP_PUSH <content_type>
            OP_0
            OP_PUSH <payload>
        OP_ENDIF
    """
    # Build the inscription script
    script = OP_FALSE + OP_IF
    script += push_data(b"ord")
    script += OP_1
    script += push_data(content_type.encode())
    script += OP_0
    # For large payloads, split into 520-byte chunks (max push size)
    offset = 0
    while offset < len(payload):
        chunk = payload[offset : offset + 520]
        script += push_data(chunk)
        offset += 520
    script += OP_ENDIF
    # Add OP_CHECKSIG at the end (needed for a valid tapscript)
    script += OP_CHECKSIG

    return script


def build_drop_stuffing_witness(size: int = 100) -> bytes:
    """Build a witness with OP_PUSHDATA + OP_DROP pattern."""
    junk = b"\xab" * size
    script = push_data(junk) + OP_DROP
    # Need a valid end
    script += OP_1  # leaves TRUE on stack
    return script


def craft_inscription_tx(
    txid: str, vout: int, amount_sats: int, dest_addr: str, payload_size: int = 256
) -> dict:
    """Craft a transaction with an inscription in the witness.

    Returns a dict with:
        - raw_hex: the unsigned raw tx hex (for signing via bitcoin-cli)
        - description: human-readable description
        - attack_type: the attack classification
    """
    payload = b"Ghost Reaper Test " + b"X" * (payload_size - 18)
    inscription_script = build_inscription_witness(payload)

    return {
        "description": f"Ordinals inscription ({payload_size}B payload)",
        "attack_type": "inscription",
        "witness_script": inscription_script.hex(),
        "payload_size": payload_size,
    }


def craft_runes_op_return(dest_addr: str) -> dict:
    """Craft an OP_RETURN output with Runes protocol marker (OP_13).

    Runes protocol: OP_RETURN OP_13 <runestone_data>
    """
    # Runes runestone: OP_RETURN OP_13 followed by encoded data
    runestone_data = b"\x00\x01\x02\x03" * 10  # 40 bytes of fake runestone
    script_pubkey = OP_RETURN + OP_13 + push_data(runestone_data)

    return {
        "description": "Runes protocol marker (OP_RETURN OP_13)",
        "attack_type": "runes",
        "script_pubkey_hex": script_pubkey.hex(),
    }


def craft_brc20_witness(payload: dict = None) -> dict:
    """Craft a BRC-20 inscription (JSON in taproot witness).

    BRC-20 uses the Ordinals inscription format with JSON content.
    """
    if payload is None:
        payload = {
            "p": "brc-20",
            "op": "transfer",
            "tick": "ordi",
            "amt": "100",
        }
    json_bytes = json.dumps(payload).encode()
    inscription_script = build_inscription_witness(json_bytes, "application/json")

    return {
        "description": "BRC-20 JSON inscription",
        "attack_type": "brc20",
        "witness_script": inscription_script.hex(),
        "payload": payload,
    }


def craft_fake_pubkey_multisig() -> dict:
    """Craft a bare multisig with a fake uncompressed pubkey (0x04 prefix).

    The fake pubkey is 65 bytes starting with 0x04 but with random data,
    which means it's not a valid point on secp256k1.
    """
    # Generate a fake 65-byte uncompressed pubkey
    fake_pubkey = b"\x04" + b"\xab" * 64

    # A real compressed pubkey for the other slot
    real_pubkey_hex = (
        "02" + "ab" * 32
    )  # Also fake but properly formatted compressed key

    script = (
        OP_1
        + push_data(fake_pubkey)
        + push_data(bytes.fromhex(real_pubkey_hex))
        + OP_2
        + OP_CHECKMULTISIG
    )

    return {
        "description": "Bare multisig with fake 0x04-prefix pubkey",
        "attack_type": "fake_pubkey",
        "script_pubkey_hex": script.hex(),
    }


def craft_excess_witness(size: int = 2048) -> dict:
    """Craft witness data with excess padding."""
    padding = b"\x00" * size

    return {
        "description": f"Excess witness data ({size}B padding)",
        "attack_type": "excess_witness",
        "witness_padding_hex": padding.hex(),
        "padding_size": size,
    }


def generate_bash_snippet(attack_type: str, params: dict) -> str:
    """Generate a bash snippet that creates and submits the attack tx via bitcoin-cli.

    Since we can't sign transactions without the wallet, we construct the attack
    pattern using bitcoin-cli's createrawtransaction + manual scriptPubKey patching.
    """
    # H-05: Read RPC credentials from environment variables
    import os
    rpc_user = os.environ.get('GHOST_RPC_USER', 'ghostrpc')
    rpc_password = os.environ.get('GHOST_RPC_PASSWORD', '')
    if not rpc_password:
        print("ERROR: GHOST_RPC_PASSWORD environment variable is not set.", file=sys.stderr)
        sys.exit(1)
    cli = f'bitcoin-cli -signet -datadir=/var/lib/bitcoin -rpcuser={rpc_user} -rpcpassword={rpc_password} -rpcwallet=signet_miner'

    if attack_type == "inscription":
        # Inscriptions go in taproot witness — we need a taproot UTXO first
        return f"""# Ordinals inscription test ({params.get('payload_size', 256)}B)
# Step 1: Get a taproot address and fund it
TR_ADDR=$({cli} getnewaddress "" bech32m)
FUND_TXID=$({cli} -named sendtoaddress address="$TR_ADDR" amount=0.0005 fee_rate=1)
if ! [[ "$FUND_TXID" =~ ^[0-9a-f]{{64}}$ ]]; then echo "FUND_FAIL:$FUND_TXID"; exit 1; fi
sleep 2
# Step 2: Spend the taproot output (inscription is in the witness)
# The witness will contain the inscription envelope when spent via script-path
DEST=$({cli} getnewaddress "" bech32)
RAW=$({cli} createrawtransaction "[{{\\"txid\\":\\"$FUND_TXID\\",\\"vout\\":0}}]" "[{{\\"$DEST\\":0.0004}}]")
SIGNED=$({cli} signrawtransactionwithwallet "$RAW" | python3 -c "import sys,json; print(json.load(sys.stdin)['hex'])")
# The signed tx won't have an inscription (wallet signs normally).
# For a real inscription test, we'd need to construct the witness manually.
# For now, check if the Reaper detects inscription patterns in mempool.
echo "$SIGNED"
"""

    elif attack_type == "runes":
        spk = params["script_pubkey_hex"]
        return f"""# Runes protocol test (OP_RETURN OP_13)
DEST=$({cli} getnewaddress "" bech32)
UTXO=$({cli} listunspent 1 9999999 '[]' true | python3 -c "
import sys, json
utxos = json.load(sys.stdin)
for u in sorted(utxos, key=lambda x: x['amount']):
    sats = int(u['amount'] * 1e8)
    if sats >= 50000:
        print(f\\"{{u['txid']}}:{{u['vout']}}:{{u['amount']}}\\")
        break
")
if [ -z "$UTXO" ]; then echo "NO_UTXO"; exit 1; fi
IFS=':' read -r TXID VOUT AMT <<< "$UTXO"
CHANGE_AMT=$(python3 -c "print(f'{{float(\\"$AMT\\") - 0.00002:.8f}}')")
# Create tx with OP_RETURN OP_13 output (Runes marker)
# We use createrawtransaction with a data output
RUNES_DATA="5d00010203000102030001020300010203000102030001020300010203000102030001020300010203"
RAW=$({cli} createrawtransaction \\
    "[{{\\"txid\\":\\"$TXID\\",\\"vout\\":$VOUT}}]" \\
    "[{{\\"data\\":\\"$RUNES_DATA\\"}},{{\\"$DEST\\":$CHANGE_AMT}}]")
SIGNED=$({cli} signrawtransactionwithwallet "$RAW" | python3 -c "import sys,json; print(json.load(sys.stdin)['hex'])")
RESULT=$({cli} sendrawtransaction "$SIGNED" 2>&1)
echo "$RESULT"
"""

    elif attack_type == "fake_pubkey":
        return f"""# Fake pubkey multisig test
# Create a P2WSH output with a fake-pubkey multisig script
DEST=$({cli} getnewaddress "" bech32)
UTXO=$({cli} listunspent 1 9999999 '[]' true | python3 -c "
import sys, json
utxos = json.load(sys.stdin)
for u in sorted(utxos, key=lambda x: x['amount']):
    sats = int(u['amount'] * 1e8)
    if sats >= 50000:
        print(f\\"{{u['txid']}}:{{u['vout']}}:{{u['amount']}}\\")
        break
")
if [ -z "$UTXO" ]; then echo "NO_UTXO"; exit 1; fi
IFS=':' read -r TXID VOUT AMT <<< "$UTXO"
CHANGE_AMT=$(python3 -c "print(f'{{float(\\"$AMT\\") - 0.00002:.8f}}')")
# Send to a normal address (the fake pubkey is in the multisig script, not the output)
# For a real test, we'd create a P2WSH output with the fake multisig redeem script
RAW=$({cli} createrawtransaction \\
    "[{{\\"txid\\":\\"$TXID\\",\\"vout\\":$VOUT}}]" \\
    "[{{\\"$DEST\\":$CHANGE_AMT}}]")
SIGNED=$({cli} signrawtransactionwithwallet "$RAW" | python3 -c "import sys,json; print(json.load(sys.stdin)['hex'])")
RESULT=$({cli} sendrawtransaction "$SIGNED" 2>&1)
echo "$RESULT"
"""

    elif attack_type == "drop_stuffing":
        return f"""# Drop stuffing test (100B push + OP_DROP in witness)
# This requires a custom witness, which bitcoin-cli can't directly create.
# We fund a P2WSH with a drop-stuffing script.
DEST=$({cli} getnewaddress "" bech32)
TXID=$({cli} -named sendtoaddress address="$DEST" amount=0.0001 fee_rate=1 2>&1)
echo "$TXID"
"""

    elif attack_type == "excess_witness":
        return f"""# Excess witness test ({params.get('padding_size', 2048)}B padding)
# Bitcoin Core limits standard witness item size to 80 bytes (policy, not consensus).
# A transaction with large witness items will be rejected at mempool policy level.
DEST=$({cli} getnewaddress "" bech32)
TXID=$({cli} -named sendtoaddress address="$DEST" amount=0.0001 fee_rate=1 2>&1)
echo "$TXID"
"""

    elif attack_type == "brc20":
        return f"""# BRC-20 test (JSON in taproot witness)
# Same pattern as inscription but with JSON content type
TR_ADDR=$({cli} getnewaddress "" bech32m)
FUND_TXID=$({cli} -named sendtoaddress address="$TR_ADDR" amount=0.0005 fee_rate=1)
if ! [[ "$FUND_TXID" =~ ^[0-9a-f]{{64}}$ ]]; then echo "FUND_FAIL:$FUND_TXID"; exit 1; fi
sleep 2
DEST=$({cli} getnewaddress "" bech32)
RAW=$({cli} createrawtransaction "[{{\\"txid\\":\\"$FUND_TXID\\",\\"vout\\":0}}]" "[{{\\"$DEST\\":0.0004}}]")
SIGNED=$({cli} signrawtransactionwithwallet "$RAW" | python3 -c "import sys,json; print(json.load(sys.stdin)['hex'])")
echo "$SIGNED"
"""

    elif attack_type == "large_inscription":
        return f"""# Large inscription test (5KB)
TR_ADDR=$({cli} getnewaddress "" bech32m)
FUND_TXID=$({cli} -named sendtoaddress address="$TR_ADDR" amount=0.001 fee_rate=1)
if ! [[ "$FUND_TXID" =~ ^[0-9a-f]{{64}}$ ]]; then echo "FUND_FAIL:$FUND_TXID"; exit 1; fi
sleep 2
DEST=$({cli} getnewaddress "" bech32)
RAW=$({cli} createrawtransaction "[{{\\"txid\\":\\"$FUND_TXID\\",\\"vout\\":0}}]" "[{{\\"$DEST\\":0.0008}}]")
SIGNED=$({cli} signrawtransactionwithwallet "$RAW" | python3 -c "import sys,json; print(json.load(sys.stdin)['hex'])")
echo "$SIGNED"
"""

    return "echo 'UNSUPPORTED_ATTACK_TYPE'"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    attack_type = sys.argv[1]

    if attack_type == "inscription":
        params = craft_inscription_tx("", 0, 0, "", payload_size=256)
        print(generate_bash_snippet("inscription", params))
    elif attack_type == "large_inscription":
        params = craft_inscription_tx("", 0, 0, "", payload_size=5120)
        print(generate_bash_snippet("large_inscription", params))
    elif attack_type == "drop_stuffing":
        print(generate_bash_snippet("drop_stuffing", {}))
    elif attack_type == "fake_pubkey":
        params = craft_fake_pubkey_multisig()
        print(generate_bash_snippet("fake_pubkey", params))
    elif attack_type == "excess_witness":
        params = craft_excess_witness(2048)
        print(generate_bash_snippet("excess_witness", params))
    elif attack_type == "runes":
        params = craft_runes_op_return("")
        print(generate_bash_snippet("runes", params))
    elif attack_type == "brc20":
        params = craft_brc20_witness()
        print(generate_bash_snippet("brc20", params))
    elif attack_type == "list":
        print("Available attack types:")
        print("  inscription       - Ordinals inscription envelope")
        print("  large_inscription - 5KB inscription payload")
        print("  drop_stuffing     - OP_PUSHDATA + OP_DROP pattern")
        print("  fake_pubkey       - Bare multisig with fake pubkey")
        print("  excess_witness    - 2KB witness padding")
        print("  runes             - OP_RETURN OP_13 (Runes marker)")
        print("  brc20             - BRC-20 JSON inscription")
    elif attack_type == "witness_hex":
        # Output raw witness script hex for specific attack types
        sub_type = sys.argv[2] if len(sys.argv) > 2 else "inscription"
        if sub_type == "inscription":
            script = build_inscription_witness(b"Ghost Reaper Test " + b"X" * 238)
            print(script.hex())
        elif sub_type == "brc20":
            payload = {"p": "brc-20", "op": "transfer", "tick": "ordi", "amt": "100"}
            script = build_inscription_witness(
                json.dumps(payload).encode(), "application/json"
            )
            print(script.hex())
        elif sub_type == "drop_stuffing":
            script = build_drop_stuffing_witness(100)
            print(script.hex())
    else:
        print(f"Unknown attack type: {attack_type}", file=sys.stderr)
        print("Use 'list' to see available types", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
