#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Ghost Mode local egress (own-tx broadcast).

Ghost Mode suppresses the P2P transaction-relay path entirely. Local egress is
a sub-mode that keeps a node's OWN (locally-submitted) transactions flowing to
peers so a connected wallet can reach miners, while transactions received from
other peers stay fully suppressed.

Topology (node A is the ghost node, in the centre of a star):

        node1 (B, normal) ----> node0 (A, ghost+egress) <---- node2 (C, normal)

B and C are NOT connected to each other, so any transaction that reaches C must
transit A.

Assertions:
  (a) A transaction submitted LOCALLY on A (sendrawtransaction) propagates to
      both B's and C's mempools — local egress works.
  (b) A transaction originated on B does NOT propagate through A: it never
      reaches A's or C's mempool (peer-received txs are black-holed). A also
      advertises tx_relay=false, so it never asked B for txs in the first place.
  (c) If a peer force-sends a raw tx to A anyway, A rejects it (disconnects the
      peer, transaction never enters A's mempool) — RejectIncomingTxs is
      unchanged by local egress.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import msg_tx
from test_framework.p2p import P2PInterface
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet


class GhostModeLocalEgressTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.extra_args = [
            # node0 (A): ghost mode + local egress. -shroud=0 removes the random
            # relay delay so announcements are deterministic for the test.
            ["-ghostmode", "-ghostmodelocalegress", "-shroud=0"],
            # node1 (B): normal relaying node.
            [],
            # node2 (C): normal relaying node.
            [],
        ]

    def setup_network(self):
        self.setup_nodes()
        # Star topology centred on A. Deliberately do NOT connect B and C, so a
        # transaction can only reach C by transiting A.
        self.connect_nodes(0, 1)
        self.connect_nodes(0, 2)
        # Only blocks need to be in sync during setup; the ghost node will never
        # have a matching mempool, so do not sync mempools here.
        self.sync_blocks()

    def wait_for_mempool(self, node, txid, *, timeout=60):
        self.wait_until(lambda: txid in node.getrawmempool(), timeout=timeout)

    def assert_not_in_mempool(self, node, txid):
        assert txid not in node.getrawmempool(), (
            f"tx {txid} unexpectedly present in mempool of {node.index}"
        )

    def run_test(self):
        node_a, node_b, node_c = self.nodes
        self.wallet = MiniWallet(node_a)

        self.log.info("Fund the MiniWallet on node A and sync the chain to B and C")
        # Five coinbase UTXOs to the wallet (four are spent below), then mature
        # them so create_self_transfer has confirmed inputs to draw from.
        self.generate(self.wallet, 5, sync_fun=self.sync_blocks)
        self.generate(node_a, COINBASE_MATURITY, sync_fun=self.sync_blocks)

        self.log.info("A advertises tx_relay=false to its peers (like blocksonly)")
        for info in node_b.getpeerinfo():
            # From B's point of view, A is the peer that told us not to relay.
            assert_equal(info["relaytxes"], False)
        for info in node_c.getpeerinfo():
            assert_equal(info["relaytxes"], False)

        # ------------------------------------------------------------------
        # (a) A's own transaction reaches both B and C.
        # ------------------------------------------------------------------
        self.log.info("Local egress: A's own tx propagates to B and C")
        tx_a = self.wallet.create_self_transfer()
        node_a.sendrawtransaction(tx_a["hex"])
        assert tx_a["txid"] in node_a.getrawmempool()
        self.wait_for_mempool(node_b, tx_a["txid"])
        self.wait_for_mempool(node_c, tx_a["txid"])
        self.log.info("A's own transaction reached both peers")

        # ------------------------------------------------------------------
        # (b) A transaction originated on B is black-holed at A.
        # ------------------------------------------------------------------
        self.log.info("A peer tx originated on B does not propagate through A")
        tx_b = self.wallet.create_self_transfer()
        node_b.sendrawtransaction(tx_b["hex"])
        assert tx_b["txid"] in node_b.getrawmempool()

        # Use a second egress tx from A as a "flush": once it has reached C we
        # know enough gossip rounds have elapsed that tx_b would have arrived too
        # if it were ever going to.
        tx_a2 = self.wallet.create_self_transfer()
        node_a.sendrawtransaction(tx_a2["hex"])
        self.wait_for_mempool(node_c, tx_a2["txid"])

        self.assert_not_in_mempool(node_a, tx_b["txid"])
        self.assert_not_in_mempool(node_c, tx_b["txid"])
        # The tx is perfectly valid — it simply has nowhere to go from B, whose
        # only peer (A) refused transaction relay.
        assert tx_b["txid"] in node_b.getrawmempool()
        self.log.info("B's transaction stayed on B; A refused to relay it")

        # ------------------------------------------------------------------
        # (c) A rejects a tx that a peer force-sends over the wire.
        # ------------------------------------------------------------------
        self.log.info("A rejects and disconnects a peer that force-sends a tx")
        mempool_before = set(node_a.getrawmempool())
        forced = self.wallet.create_self_transfer()
        peer = node_a.add_p2p_connection(P2PInterface())
        with node_a.assert_debug_log(["transaction sent in violation of protocol"]):
            peer.send_without_ping(msg_tx(forced["tx"]))
            peer.wait_for_disconnect()
        self.assert_not_in_mempool(node_a, forced["txid"])
        assert_equal(set(node_a.getrawmempool()), mempool_before)
        self.log.info("Force-sent peer tx was rejected; A's mempool unchanged")


if __name__ == "__main__":
    GhostModeLocalEgressTest(__file__).main()
