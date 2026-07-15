#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Ghost Haze merkle-proof serving test (gettxoutproof on hazed nodes).

A hazed node stores witness-stripped blocks, but a merkle inclusion proof only
needs the block's ordered txids, which the stripped block retains. This test
verifies a hazed node can still build and serve a valid gettxoutproof, and that
verifytxoutproof accepts it — so SPV/light clients can be served from hazed nodes.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.key import ECKey
from test_framework.address import key_to_p2wpkh
from test_framework.wallet_util import bytes_to_wif


class GhostHazeTxoutproofTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            ["-hazemode=full_archive", "-disablewallet", "-txindex"],
            ["-hazemode=hazed", "-disablewallet", "-txindex", "-debug=haze"],
        ]

    def skip_test_if_missing_module(self):
        pass

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        self.start_node(0)
        self.start_node(1)
        self.connect_nodes(0, 1)

    def run_test(self):
        node0, node1 = self.nodes
        key = ECKey()
        key.set(b'\x01' * 32, compressed=True)
        addr = key_to_p2wpkh(key.get_pubkey().get_bytes())
        wif = bytes_to_wif(key.get_bytes(), compressed=True)

        self.log.info("Mine 120 blocks, then create a spend so a block has >1 tx")
        self.generatetoaddress(node0, 120, addr)
        self.sync_blocks()

        coinbase = node0.getblock(node0.getblockhash(1), 2)["tx"][0]
        cb_txid, cb_val = coinbase["txid"], coinbase["vout"][0]["value"]
        utxo = node0.gettxout(cb_txid, 0)
        raw = node0.createrawtransaction(
            [{"txid": cb_txid, "vout": 0}],
            [{addr: round(cb_val - Decimal("0.0001"), 8)}],
        )
        signed = node0.signrawtransactionwithkey(
            raw, [wif],
            [{"txid": cb_txid, "vout": 0,
              "scriptPubKey": utxo["scriptPubKey"]["hex"], "amount": cb_val}])
        spend_txid = node0.sendrawtransaction(signed["hex"])
        block_hash = self.generatetoaddress(node0, 1, addr)[0]
        self.sync_blocks()

        # The block now holds [coinbase, spend]. Prove the non-coinbase tx.
        assert spend_txid in node0.getblock(block_hash)["tx"]

        self.log.info("Hazed node builds a merkle proof from the stripped block")
        proof_full = node0.gettxoutproof([spend_txid])
        proof_hazed = node1.gettxoutproof([spend_txid])

        self.log.info("Each node verifies its own and the peer's proof to the same txid")
        for verifier in (node0, node1):
            assert_equal(verifier.verifytxoutproof(proof_hazed), [spend_txid])
            assert_equal(verifier.verifytxoutproof(proof_full), [spend_txid])

        self.log.info("Hazed proof also works for the block's coinbase txid")
        block_cb_txid = node0.getblock(block_hash)["tx"][0]
        cb_proof_hazed = node1.gettxoutproof([block_cb_txid], block_hash)
        assert_equal(node0.verifytxoutproof(cb_proof_hazed), [block_cb_txid])

        self.log.info("A txid absent from the block is rejected on the hazed node")
        bogus = "00" * 32
        assert_raises_rpc_error(-5, None, node1.gettxoutproof, [bogus], block_hash)


if __name__ == "__main__":
    GhostHazeTxoutproofTest(__file__).main()
