#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Ghost BUDS tier-policy mempool-acceptance gate.

ghostd classifies every transaction into a BUDS tier (T0-T3, the C++ port of
ghost-pool's classifier) and rejects, at mempool acceptance, any transaction
whose tier is not in the operator's allowed-tier set. Rejected transactions are
never entered into the mempool and therefore never relayed or mined.

To isolate the tier gate as the *sole* cause of any rejection, the node runs
with the competing filters switched off:
  * -acceptnonstdtxn=1     -> skip standardness/datacarrier/dust checks
  * -ghostreaper=disabled  -> skip the dead-code Reaper detectors

Assertions:
  (a) Strict tier set {T0,T1}: a T0 payment and a T1 (bare multisig) are
      accepted; a T2 (small OP_RETURN) and a T3 (large OP_RETURN) are rejected
      with reason "tier-policy" and are absent from the mempool (not relayed).
  (b) full_open (all tiers): after restart, all four transactions are accepted.
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import COIN, CTransaction, CTxIn, CTxOut, COutPoint
from test_framework.script import CScript, OP_1, OP_CHECKMULTISIG, OP_RETURN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


class GhostTierPolicyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        # Strict tier set {T0, T1}. Competing filters disabled (see module docs)
        # so the tier gate is the only thing that can reject a transaction.
        self.extra_args = [[
            "-ghostpolicy-allowtiers=0,1",
            "-acceptnonstdtxn=1",
            "-ghostreaper=disabled",
        ]]

    def build_tx(self, extra_outputs):
        """Spend one confirmed wallet UTXO into a P2TR change output plus the
        given extra outputs. The wallet's inputs are anyone-can-spend, so the
        outputs are not signature-committed and can be shaped freely."""
        utxo = self.wallet.get_utxo(confirmed_only=True)
        tx = CTransaction()
        tx.version = 2
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        fee = 10000
        extra_value = sum(o.nValue for o in extra_outputs)
        change = int(COIN * utxo["value"]) - fee - extra_value
        assert change > 0
        change_spk = bytearray(self.wallet.get_output_script())
        tx.vout = [CTxOut(change, change_spk)] + extra_outputs
        self.wallet.sign_tx(tx)
        return tx

    def tier_t0(self):
        # Plain payment: one change output, no data, small witness.
        return self.build_tx([])

    def tier_t1(self):
        # Bare 1-of-1 multisig output -> classifier detects multisig -> T1.
        pubkey = b"\x02" + bytes(32)
        multisig = CScript([OP_1, pubkey, OP_1, OP_CHECKMULTISIG])
        return self.build_tx([CTxOut(1000, multisig)])

    def tier_t2(self):
        # Small OP_RETURN (40-byte payload, <= 80) -> T2.
        return self.build_tx([CTxOut(0, CScript([OP_RETURN, bytes(40)]))])

    def tier_t3(self):
        # Large OP_RETURN (100-byte payload, > 80) -> T3.
        return self.build_tx([CTxOut(0, CScript([OP_RETURN, bytes(100)]))])

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        self.log.info("Fund the wallet and mature its coinbase outputs")
        self.generate(self.wallet, 10)
        self.generate(node, COINBASE_MATURITY)

        # ------------------------------------------------------------------
        # (a) Strict {T0, T1}: T0/T1 accepted, T2/T3 rejected + not relayed.
        # ------------------------------------------------------------------
        self.log.info("Strict {T0,T1}: T0 payment accepted")
        t0 = self.tier_t0()
        node.sendrawtransaction(t0.serialize().hex())
        assert t0.txid_hex in node.getrawmempool()

        self.log.info("Strict {T0,T1}: T1 bare multisig accepted")
        t1 = self.tier_t1()
        node.sendrawtransaction(t1.serialize().hex())
        assert t1.txid_hex in node.getrawmempool()

        self.log.info("Strict {T0,T1}: T2 small OP_RETURN rejected (tier-policy)")
        t2 = self.tier_t2()
        assert_raises_rpc_error(-26, "tier-policy", node.sendrawtransaction, t2.serialize().hex())
        assert t2.txid_hex not in node.getrawmempool()

        self.log.info("Strict {T0,T1}: T3 large OP_RETURN rejected (tier-policy)")
        t3 = self.tier_t3()
        assert_raises_rpc_error(-26, "tier-policy", node.sendrawtransaction, t3.serialize().hex())
        assert t3.txid_hex not in node.getrawmempool()

        # The rejected transactions were never entered into the mempool, so they
        # cannot be relayed. Only the two accepted txs are present.
        assert_equal(set(node.getrawmempool()), {t0.txid_hex, t1.txid_hex})
        self.log.info("Rejected T2/T3 are absent from the mempool (not relayed)")

        # Confirm the accepted txs and clear the mempool before switching profile.
        self.generate(node, 1)
        assert_equal(node.getrawmempool(), [])

        # ------------------------------------------------------------------
        # (b) full_open: restart with all tiers, everything accepted.
        # ------------------------------------------------------------------
        self.log.info("Restart with full_open (all tiers): every tier accepted")
        self.restart_node(0, extra_args=["-acceptnonstdtxn=1", "-ghostreaper=disabled"])
        self.wallet.rescan_utxos()

        for name, builder in [("T0", self.tier_t0), ("T1", self.tier_t1),
                              ("T2", self.tier_t2), ("T3", self.tier_t3)]:
            tx = builder()
            txid = node.sendrawtransaction(tx.serialize().hex())
            assert txid in node.getrawmempool(), f"{name} not accepted under full_open"
            self.log.info(f"full_open: {name} accepted into mempool")


if __name__ == "__main__":
    GhostTierPolicyTest(__file__).main()
