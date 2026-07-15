#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.
"""Ghost Haze address-index serving test.

Covers the trusted-mode wallet/explorer serving RPCs added in the Haze release:
getaddressbalance, getaddressutxos, getaddresstxids and scanaddressindex.

Verifies that:
1. The RPCs report correct balance / received / utxos / txids after funding.
2. Spending an address updates spendable balance while `received` is retained.
3. scanaddressindex aggregates a descriptor's activity from the index alone.
4. A HAZED (witness-stripped) node with -addressindex serves byte-identical
   results to a full-archive node — the address index reads structural data,
   never block files, so it works where a block rescan cannot.
5. scanaddressindex fails closed when the address index is disabled.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.key import ECKey
from test_framework.address import key_to_p2wpkh
from test_framework.wallet_util import bytes_to_wif
from test_framework.descriptors import descsum_create


class GhostHazeAddressIndexTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            # node0: full archive, address index ON — the serving baseline.
            ["-hazemode=full_archive", "-addressindex", "-disablewallet"],
            # node1: hazed (stripped blocks), address index ON — the serving claim.
            ["-hazemode=hazed", "-addressindex", "-disablewallet", "-debug=haze"],
            # node2: full archive, address index OFF — the fail-closed path.
            ["-hazemode=full_archive", "-disablewallet"],
        ]

    def skip_test_if_missing_module(self):
        pass

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        for i in range(self.num_nodes):
            self.start_node(i)
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)

    def wait_index_synced(self, node):
        self.wait_until(lambda: node.getindexinfo().get("addressindex", {}).get("synced", False))

    def make_key(self, seed_byte):
        key = ECKey()
        key.set(bytes([seed_byte]) * 32, compressed=True)
        pub = key.get_pubkey().get_bytes()
        addr = key_to_p2wpkh(pub)
        wif = bytes_to_wif(key.get_bytes(), compressed=True)
        desc = descsum_create(f"wpkh({pub.hex()})")
        return addr, wif, desc

    def fund(self, node, funding_addr, funding_wif, dest_addr, amount):
        """Spend a matured coinbase from funding_addr to dest_addr; return txid."""
        # Find a spendable matured coinbase paying funding_addr.
        for h in range(1, node.getblockcount() - 100):
            block = node.getblock(node.getblockhash(h), 2)
            ctx = block["tx"][0]
            utxo = node.gettxout(ctx["txid"], 0)
            if utxo is None:
                continue
            value = ctx["vout"][0]["value"]
            change = round(value - amount - Decimal("0.0001"), 8)
            raw = node.createrawtransaction(
                [{"txid": ctx["txid"], "vout": 0}],
                [{dest_addr: amount}, {funding_addr: change}],
            )
            signed = node.signrawtransactionwithkey(
                raw, [funding_wif],
                [{"txid": ctx["txid"], "vout": 0,
                  "scriptPubKey": utxo["scriptPubKey"]["hex"], "amount": value}],
            )
            assert signed["complete"]
            return node.sendrawtransaction(signed["hex"])
        raise AssertionError("no spendable coinbase for funding address")

    def run_test(self):
        node0, node1, node2 = self.nodes
        mining_addr, mining_wif, _ = self.make_key(0x01)
        addr_a, wif_a, desc_a = self.make_key(0x02)

        self.log.info("Mine 120 blocks to the funding address for coinbase maturity")
        self.generatetoaddress(node0, 120, mining_addr)
        self.sync_blocks()

        self.log.info("Fund address A (2 BTC) and confirm")
        fund_txid = self.fund(node0, mining_addr, mining_wif, addr_a, Decimal("2.0"))
        self.generatetoaddress(node0, 1, mining_addr)
        self.sync_blocks()
        for n in (node0, node1):
            self.wait_index_synced(n)

        self.log.info("getaddressbalance/utxos/txids correct on the full node")
        bal = node0.getaddressbalance(addr_a)
        assert_equal(bal["balance"], 200000000)
        assert_equal(bal["received"], 200000000)
        utxos = node0.getaddressutxos(addr_a)
        assert_equal(len(utxos), 1)
        assert_equal(utxos[0]["satoshis"], 200000000)
        assert_equal(utxos[0]["txid"], fund_txid)
        assert fund_txid in node0.getaddresstxids(addr_a)

        self.log.info("HAZED node serves byte-identical address-index results")
        assert_equal(node1.getaddressbalance(addr_a), node0.getaddressbalance(addr_a))
        assert_equal(node1.getaddressutxos(addr_a), node0.getaddressutxos(addr_a))
        assert_equal(node1.getaddresstxids(addr_a), node0.getaddresstxids(addr_a))

        self.log.info("scanaddressindex aggregates the descriptor from the index alone")
        for n in (node0, node1):
            scan = n.scanaddressindex(desc_a)
            assert_equal(scan["used"], 1)
            assert_equal(scan["balance"], 200000000)
            assert_equal(scan["received"], 200000000)
            assert_equal(len(scan["utxos"]), 1)
            assert_equal(scan["utxos"][0]["satoshis"], 200000000)
            assert fund_txid in scan["txids"]

        self.log.info("Spend from A: balance clears, received retained, spend txid recorded")
        # A's funds are a regular output (fund_txid:0), not a coinbase, so spend it directly.
        utxo_a = node0.gettxout(fund_txid, 0)
        raw = node0.createrawtransaction(
            [{"txid": fund_txid, "vout": 0}],
            [{mining_addr: Decimal("1.99")}],
        )
        signed = node0.signrawtransactionwithkey(
            raw, [wif_a],
            [{"txid": fund_txid, "vout": 0,
              "scriptPubKey": utxo_a["scriptPubKey"]["hex"], "amount": Decimal("2.0")}])
        assert signed["complete"]
        spend_txid = node0.sendrawtransaction(signed["hex"])
        self.generatetoaddress(node0, 1, mining_addr)
        self.sync_blocks()
        for n in (node0, node1):
            self.wait_index_synced(n)
        for n in (node0, node1):
            bal = n.getaddressbalance(addr_a)
            assert_equal(bal["balance"], 0)
            assert_equal(bal["received"], 200000000)
            assert_equal(n.getaddressutxos(addr_a), [])
            txids = n.getaddresstxids(addr_a)
            assert fund_txid in txids and spend_txid in txids

        self.log.info("scanaddressindex fails closed without -addressindex")
        assert_raises_rpc_error(-1, "Address index is not enabled",
                                node2.scanaddressindex, desc_a)


if __name__ == "__main__":
    GhostHazeAddressIndexTest(__file__).main()
