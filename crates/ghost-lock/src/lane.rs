//|======================================================================================================================|
//|                                                                                                                      |
//|  ▄▄▄▄    ██▓▄▄▄█████▓ ▄████▄   ▒█████   ██▓ ███▄    █      ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓   ▄████████▄    |
//| ▓█████▄ ▓██▒▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▓██▒ ██ ▀█   █     ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒   ███▀██▀███    |
//| ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██▒▓██  ▀█ ██▒   ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░   ██████████░   |
//| ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓▓▄ ▄██▒▒██   ██░░██░▓██▒  ▐▌██▒   ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░    ██████████░░▒ |
//| ░▓█  ▀█▓░██░  ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░██░▒██░   ▓██░   ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░    ██▀▀██▀▀██░▒  |
//| ░▒▓███▀▒░▓    ▒ ░░   ░ ░▒ ▒  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒     ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░      ▒ ░░▒░▒ ░░▒░  |
//| ▒░▒   ░  ▒ ░    ░      ░  ▒     ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░     ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░         ▒ ░░▒░▒░ ░  |
//|  ░    ░  ▒ ░  ░      ░        ░ ░ ░ ▒   ▒ ░   ░   ░ ░    ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░               ░  ░    |
//|  ░       ░           ░ ░          ░ ░   ░           ░          ░  ░  ░  ░    ░ ░        ░                            |
//|       ░              ░                                                                                               |
//|----------------------------------------------------------------------------------------------------------------------|
//|             < B I T C O I N  G H O S T > < D E F E N W Y C K E > < R E A D  T H E  W H I T E P A P E R >             |
//|----------------------------------------------------------------------------------------------------------------------|
//| PROJECT: Bitcoin Ghost                                                                                               |
//| REPO: https://github.com/bitcoin-ghost                                                                               |
//| WEB: https://bitcoinghost.org/                                                                                       |
//| LICENSE: MIT                                                                                                         |
//| FILE: lane.rs                                                                                                        |
//|======================================================================================================================|

//! The three lanes of a Ghost Lock, as Taproot policies.
//!
//! A Lock is a **policy, not a coin** — many UTXOs sit under one Lock, and the
//! identity is the policy rather than any address.
//!
//! Every lane spends through the **key path** in the normal case. That is
//! deliberate and load-bearing: a key-path spend is a single 64-byte Schnorr
//! signature over a bare 32-byte output key, indistinguishable from any
//! ordinary single-signature wallet. A script-path spend reveals its leaf, and
//! on the hot lane that would mark every round input as Wraith.
//!
//! ```text
//! VAULT      key path  musig(owner, backup)   quorum has NO part
//!            leaf 1    older(61_200)  owner   ~14 months
//!            leaf 2    older(65_535)  backup  ~15 months (CSV ceiling)
//!            leaf 3    after(HEIGHT)  heir    absolute — CSV cannot reach this
//!
//! HOT        key path  musig(owner, quorum)   quorum can ONLY complete
//!            leaf 1    older(EXIT)    owner   what the owner pre-signed
//!
//! LIQUIDITY  key path  quorum                 quorum CAN spend alone.
//!            leaf 1    older(RECALL)  owner   bonded. this lane is custody.
//! ```
//!
//! The aggregate keys are taken as opaque [`XOnlyPublicKey`] inputs. Producing
//! them is MuSig2 key aggregation, which belongs in a vetted implementation and
//! is deliberately not done here.

use bitcoin::opcodes::all::{OP_CHECKSIG, OP_CLTV, OP_CSV, OP_DROP};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Secp256k1, Verification, XOnlyPublicKey};
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};
use bitcoin::{Address, Network, ScriptBuf};

use crate::constants::*;
use crate::error::LockError;

/// A leaf spendable by one key after a **relative** timelock.
///
/// `<blocks> OP_CSV OP_DROP <pk> OP_CHECKSIG`
pub fn relative_timelock_leaf(blocks: u32, key: &XOnlyPublicKey) -> Result<ScriptBuf, LockError> {
    if blocks > CSV_MAX_BLOCKS {
        return Err(LockError::TimelockTooLong {
            blocks,
            max: CSV_MAX_BLOCKS,
        });
    }
    Ok(Builder::new()
        .push_int(i64::from(blocks))
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_x_only_key(key)
        .push_opcode(OP_CHECKSIG)
        .into_script())
}

/// A leaf spendable by one key after an **absolute** block height.
///
/// `<height> OP_CLTV OP_DROP <pk> OP_CHECKSIG`
///
/// Inheritance uses this rather than CSV because [`CSV_MAX_BLOCKS`] tops out at
/// roughly fifteen months and an 18–24 month delay does not fit. The height is
/// pushed forward at every rollover, so it matures only if the owner stopped
/// rolling over — a dead-man's switch built from a timelock rather than a
/// service.
pub fn absolute_timelock_leaf(height: u32, key: &XOnlyPublicKey) -> ScriptBuf {
    Builder::new()
        .push_int(i64::from(height))
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_x_only_key(key)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// A fully described lane: its Taproot tree and the address that funds it.
#[derive(Debug, Clone)]
pub struct Lane {
    /// Tree, control blocks and the tweaked output key.
    pub spend_info: TaprootSpendInfo,
    /// The funding address.
    pub address: Address,
}

impl Lane {
    fn assemble<C: Verification>(
        secp: &Secp256k1<C>,
        internal_key: XOnlyPublicKey,
        leaves: Vec<(u8, ScriptBuf)>,
        network: Network,
    ) -> Result<Self, LockError> {
        let mut builder = TaprootBuilder::new();
        for (depth, script) in leaves {
            builder = builder
                .add_leaf(depth, script)
                .map_err(|e| LockError::Taproot(e.to_string()))?;
        }
        let spend_info = builder
            .finalize(secp, internal_key)
            .map_err(|_| LockError::Taproot("tree is not finalizable".into()))?;
        let address = Address::p2tr_tweaked(spend_info.output_key(), network);
        Ok(Self {
            spend_info,
            address,
        })
    }
}

/// The savings lane. The quorum has no part in it at all.
#[derive(Debug, Clone, Copy)]
pub struct VaultPolicy {
    /// MuSig2 aggregate of the owner and backup keys — the normal spend.
    pub aggregate: XOnlyPublicKey,
    /// Owner key, for the ~14 month recovery leaf.
    pub owner: XOnlyPublicKey,
    /// Backup key, for the ~15 month recovery leaf.
    pub backup: XOnlyPublicKey,
    /// Heir key, for the absolute-height inheritance leaf.
    pub heir: XOnlyPublicKey,
    /// Absolute height at which the heir leaf matures.
    pub inherit_height: u32,
}

impl VaultPolicy {
    /// Build the vault lane, anchored at `anchor_height` (the current tip when
    /// the Lock is created or rolled over).
    pub fn build<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        anchor_height: u32,
        network: Network,
    ) -> Result<Lane, LockError> {
        if self.inherit_height <= anchor_height {
            return Err(LockError::InheritanceNotInFuture {
                height: self.inherit_height,
                anchor: anchor_height,
            });
        }
        Lane::assemble(
            secp,
            self.aggregate,
            vec![
                (
                    1,
                    relative_timelock_leaf(OWNER_RECOVERY_BLOCKS, &self.owner)?,
                ),
                (
                    2,
                    relative_timelock_leaf(BACKUP_RECOVERY_BLOCKS, &self.backup)?,
                ),
                (2, absolute_timelock_leaf(self.inherit_height, &self.heir)),
            ],
            network,
        )
    }
}

/// The spending lane. Wraith-resident.
///
/// The quorum holds half of the aggregate and can only complete what the owner
/// pre-signed — it cannot redirect, and it cannot spend alone. That is what
/// makes this delegation and not custody.
#[derive(Debug, Clone, Copy)]
pub struct HotPolicy {
    /// MuSig2 aggregate of the owner and the coin's quorum.
    pub aggregate: XOnlyPublicKey,
    /// Owner key, for the escape leaf if the quorum goes dark.
    pub owner: XOnlyPublicKey,
}

impl HotPolicy {
    /// Build the hot lane.
    pub fn build<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        network: Network,
    ) -> Result<Lane, LockError> {
        Lane::assemble(
            secp,
            self.aggregate,
            vec![(0, relative_timelock_leaf(HOT_EXIT_BLOCKS, &self.owner)?)],
            network,
        )
    }
}

/// The earning lane. **This lane is custody** — the quorum spends alone.
///
/// The recall leaf bounds how long a silent quorum can hold the funds. Total
/// deposits across all liquidity lanes must not exceed aggregate bond, or the
/// guarantee behind them is theatre.
#[derive(Debug, Clone, Copy)]
pub struct LiquidityPolicy {
    /// Quorum key — spends alone, via the key path.
    pub quorum: XOnlyPublicKey,
    /// Owner key, for the recall leaf.
    pub owner: XOnlyPublicKey,
}

impl LiquidityPolicy {
    /// Build the liquidity lane.
    pub fn build<C: Verification>(
        &self,
        secp: &Secp256k1<C>,
        network: Network,
    ) -> Result<Lane, LockError> {
        Lane::assemble(
            secp,
            self.quorum,
            vec![(
                0,
                relative_timelock_leaf(LIQUIDITY_RECALL_BLOCKS, &self.owner)?,
            )],
            network,
        )
    }
}
