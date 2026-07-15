#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Ghost Haze wallet-rescan test on hazed nodes.

A hazed node stores witness-stripped blocks. Its wallet rescan reconstructs
blocks from the stripped archive to match SegWit receives, but the coinbase and
legacy scriptSig transactions cannot be rebuilt from stripped data; rescanblockchain
reports how many it skipped via `unreconstructed_hazed_txs` (with a warning that
points at the address index for the pruned range).

Verifies that on a hazed wallet node:
1. rescanblockchain completes and matches a SegWit receive.
2. The response reports unreconstructed_hazed_txs > 0 (the coinbases in range) and
   a warning steering the operator to scanaddressindex.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.key import ECKey
from test_framework.address import key_to_p2wpkh
from test_framework.descriptors import descsum_create


class GhostHazeRescanTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # node1 keeps its wallet: it is the hazed node whose rescan we exercise.
        self.extra_args = [
            ["-hazemode=full_archive", "-disablewallet"],
            ["-hazemode=hazed", "-debug=haze"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_node(0)
        self.start_node(1)
        self.connect_nodes(0, 1)

    def run_test(self):
        node0, node1 = self.nodes

        mining_key = ECKey()
        mining_key.set(b'\x01' * 32, compressed=True)
        mining_addr = key_to_p2wpkh(mining_key.get_pubkey().get_bytes())

        # A watch-only SegWit descriptor node1's wallet will look for during rescan.
        recv_key = ECKey()
        recv_key.set(b'\x02' * 32, compressed=True)
        recv_pub = recv_key.get_pubkey().get_bytes()
        recv_addr = key_to_p2wpkh(recv_pub)
        recv_desc = descsum_create(f"wpkh({recv_pub.hex()})")

        self.log.info("Mine 120 blocks, then pay the watch-only SegWit address")
        self.generatetoaddress(node0, 120, mining_addr)
        self.sync_blocks()

        cb = node0.getblock(node0.getblockhash(1), 2)["tx"][0]
        cb_val = cb["vout"][0]["value"]
        utxo = node0.gettxout(cb["txid"], 0)
        raw = node0.createrawtransaction(
            [{"txid": cb["txid"], "vout": 0}],
            [{recv_addr: Decimal("5.0")},
             {mining_addr: round(cb_val - Decimal("5.0") - Decimal("0.0001"), 8)}],
        )
        from test_framework.wallet_util import bytes_to_wif
        signed = node0.signrawtransactionwithkey(
            raw, [bytes_to_wif(mining_key.get_bytes(), compressed=True)],
            [{"txid": cb["txid"], "vout": 0,
              "scriptPubKey": utxo["scriptPubKey"]["hex"], "amount": cb["vout"][0]["value"]}])
        recv_txid = node0.sendrawtransaction(signed["hex"])
        self.generatetoaddress(node0, 1, mining_addr)
        self.sync_blocks()

        self.log.info("Import the descriptor watch-only on the hazed node (no auto-rescan)")
        node1.createwallet(wallet_name="hazed_w", disable_private_keys=True)
        w = node1.get_wallet_rpc("hazed_w")
        w.importdescriptors([{"desc": recv_desc, "timestamp": "now", "active": False}])

        self.log.info("Rescan the hazed chain; SegWit receive is matched")
        res = w.rescanblockchain()
        assert_equal(res["start_height"], 0)
        # The SegWit receive at recv_addr must be found by reconstruction.
        assert_equal(w.getreceivedbyaddress(recv_addr, 0), Decimal("5.0"))
        found = any(u["txid"] == recv_txid for u in w.listunspent(0, 9999, [recv_addr]))
        assert found, "hazed rescan did not reconstruct the SegWit receive"

        self.log.info("Rescan reports unreconstructed coinbases + steers to the address index")
        assert "unreconstructed_hazed_txs" in res, "hazed rescan must report the skipped count"
        assert_greater_than(res["unreconstructed_hazed_txs"], 0)
        assert "scanaddressindex" in res.get("warning", "")


if __name__ == "__main__":
    GhostHazeRescanTest(__file__).main()
