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
//| FILE: set_report.rs                                                                                                 |
//|======================================================================================================================|

//! Building the round's honest anonymity figure from what the coordinator holds.
//!
//! `clustering` finds linkage, `anonymity_set` counts entities, and this joins
//! them to the coordinator's own state so the number can be served. It reads
//! only the registered inputs and the declared roles — both already stored —
//! so producing the honest figure costs no extra chain access.
//!
//! # It is served, not trusted
//!
//! A wallet should recompute this from the round transaction and the chain
//! rather than believe it. The coordinator publishing a number does not make the
//! number true, and this one is served precisely so a wallet has something to
//! compare against: a coordinator that lies here disagrees with the wallet's own
//! arithmetic, which is a louder failure than silence.
//!
//! Every input is public chain data, so the two computations should agree
//! exactly. A mismatch is a bug or a lie, and either is worth surfacing.

use wraith_protocol::admission::SeatCandidate;
use wraith_protocol::anonymity_set::{assess, Role, Seat, SetReport};
use wraith_protocol::clustering::{cluster_coins, CoinFacts};
use wraith_protocol::signing_ledger::OutPointKey;

use crate::inputs::AcceptedInputs;
use crate::state::CoordinatorState;

/// Decode a hex txid into the internal byte order `OutPointKey` uses.
///
/// The value is only ever hashed and compared against itself, so the ordering
/// convention does not matter here — but it must be **consistent**, or two
/// coins of one transaction would fail to cluster.
fn txid_bytes(txid_hex: &str) -> Option<[u8; 32]> {
    let raw = hex::decode(txid_hex.trim()).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Some(out)
}

/// The honest anonymity figure for `session_id`.
///
/// `None` when the session is unknown. A session with no registered inputs
/// yields a report of zero entities rather than an optimistic default — an
/// empty round is not a private one.
pub fn session_set_report(state: &CoordinatorState, session_id: &str) -> Option<SetReport> {
    let session = state.sessions.get(session_id)?;

    let registered: Vec<AcceptedInputs> = {
        let store = state.inputs_store.lock().expect("inputs_store poisoned");
        store.get(session_id).cloned().unwrap_or_default()
    };

    // Role by ghost_id, from the session's own participant list. A registration
    // with no matching participant is skipped rather than defaulted: counting a
    // seat we cannot attribute would inflate the figure, which is the one
    // direction that must never happen.
    let role_of = |ghost_id: &str| -> Option<Role> {
        session
            .participants
            .iter()
            .find(|p| p.ghost_id == ghost_id)
            .map(|p| p.role)
    };

    // Flatten to coins, remembering which seat each came from, so the cluster
    // ids can be attached back afterwards.
    let mut facts: Vec<CoinFacts> = Vec::new();
    let mut owner: Vec<(usize, Role)> = Vec::new();
    for (seat_idx, entry) in registered.iter().enumerate() {
        let Some(role) = role_of(&entry.ghost_id) else {
            continue;
        };
        for rung in &entry.inputs {
            let Some(txid) = txid_bytes(&rung.txid) else {
                continue;
            };
            facts.push(CoinFacts {
                outpoint: OutPointKey {
                    txid,
                    vout: rung.vout,
                },
                script_pubkey: hex::decode(rung.scriptpubkey_hex.trim()).unwrap_or_default(),
            });
            owner.push((seat_idx, role));
        }
    }

    let clusters = cluster_coins(&facts);

    // One `Seat` per coin, not per participant. `assess` merges by cluster, and
    // a participant's own rungs share a funding transaction, so they collapse
    // back into one entity on their own — which is both correct and the same
    // path an attacker's linked coins take.
    let seats: Vec<Seat> = facts
        .iter()
        .zip(clusters.iter())
        .zip(owner.iter())
        .map(|((f, cluster), (_, role))| Seat {
            candidate: SeatCandidate {
                coin: f.outpoint,
                // Not used by `assess`; the age rule lives in `admission`,
                // which sees the real height at registration.
                confirmed_height: 0,
                cluster: *cluster,
            },
            role: *role,
        })
        .collect();

    Some(assess(&seats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inputs::TxInputRef;

    fn hex32(b: u8) -> String {
        hex::encode([b; 32])
    }

    fn rung(txid: u8, vout: u32, script: &str) -> TxInputRef {
        TxInputRef {
            txid: hex32(txid),
            vout,
            value_sats: 100_000,
            scriptpubkey_hex: script.to_string(),
        }
    }

    #[test]
    fn a_txid_decodes_to_thirty_two_bytes_or_not_at_all() {
        assert!(txid_bytes(&hex32(9)).is_some());
        assert_eq!(txid_bytes("abcd"), None);
        assert_eq!(txid_bytes("not hex"), None);
    }

    #[test]
    fn a_ladder_participants_rungs_collapse_to_one_entity() {
        // Six rungs from one preparatory split share a txid, so they cluster and
        // `assess` merges them. A participant is one entity however many coins
        // they bring — counting rungs would inflate every honest round.
        let facts: Vec<CoinFacts> = (0..6u32)
            .map(|v| CoinFacts {
                outpoint: OutPointKey {
                    txid: [3u8; 32],
                    vout: v,
                },
                script_pubkey: vec![v as u8],
            })
            .collect();
        let clusters = cluster_coins(&facts);
        let seats: Vec<Seat> = facts
            .iter()
            .zip(clusters.iter())
            .map(|(f, c)| Seat {
                candidate: SeatCandidate {
                    coin: f.outpoint,
                    confirmed_height: 0,
                    cluster: *c,
                },
                role: Role::Payer,
            })
            .collect();
        let r = assess(&seats);
        assert_eq!(r.seats, 6);
        assert_eq!(r.entities, 1, "one participant is one entity");
    }

    #[test]
    fn sybils_split_from_one_coin_collapse_the_same_way() {
        // The attack shape, through the identical path as the honest case above
        // — which is why it needs no special handling.
        let facts: Vec<CoinFacts> = (0..20u32)
            .map(|v| CoinFacts {
                outpoint: OutPointKey {
                    txid: [7u8; 32],
                    vout: v,
                },
                script_pubkey: vec![v as u8, 0xfe],
            })
            .collect();
        let clusters = cluster_coins(&facts);
        let seats: Vec<Seat> = facts
            .iter()
            .zip(clusters.iter())
            .map(|(f, c)| Seat {
                candidate: SeatCandidate {
                    coin: f.outpoint,
                    confirmed_height: 0,
                    cluster: *c,
                },
                role: Role::Payer,
            })
            .collect();
        assert_eq!(assess(&seats).entities, 1, "twenty seats, one attacker");
    }

    #[test]
    fn a_rung_with_an_undecodable_txid_is_dropped_not_defaulted() {
        // Defaulting to a zero txid would cluster every malformed coin together
        // and change the answer. Dropping it under-counts, which is the safe
        // direction.
        let r = rung(0, 0, "00");
        let bad = TxInputRef {
            txid: "zzzz".into(),
            ..r.clone()
        };
        assert!(txid_bytes(&bad.txid).is_none());
        assert!(txid_bytes(&r.txid).is_some());
    }
}
