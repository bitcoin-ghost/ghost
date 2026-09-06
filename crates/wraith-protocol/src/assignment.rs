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
//| FILE: assignment.rs                                                                                                 |
//|======================================================================================================================|

//! Which round a participant lands in — and why neither side chooses.
//!
//! A coordinator that picks the participant set can seat its own Sybils beside
//! one victim for free. No fee stops that, because the fee is paid to miners out
//! of a transaction whose composition the attacker controls. Every economic
//! defence in `admission` and `composition` assumes the attacker is an outsider;
//! this is the one that does not.
//!
//! So the assignment is derived, not decided:
//!
//! ```text
//! round = H(domain ‖ epoch ‖ beacon ‖ participant coins) mod open_rounds
//! ```
//!
//! Nothing the coordinator holds appears in that expression. It cannot place a
//! participant, cannot move one, and cannot tell in advance where the next one
//! will land.
//!
//! # A ladder lands in one round, not scattered across several
//!
//! Assignment binds the participant's **whole coin set**, not one outpoint. Per
//! outpoint, a ladder participant's six rungs would scatter into six different
//! rounds and the payment could never be assembled. The set is canonicalised
//! first, so the order the wallet happens to list its coins in cannot change
//! where they go.
//!
//! # The back door, and closing it
//!
//! `open_rounds` is the modulus. A coordinator that controls it sets it to 1,
//! every participant lands in the same round, and the defence evaporates while
//! appearing to run. So it is **not** a coordinator input: it derives from a
//! volume figure committed at the start of the epoch, which the participant can
//! read and check for itself. [`verify_assignment`] is that check.
//!
//! # What a participant can still do, stated plainly
//!
//! A participant chooses which coins to spend, so it can grind its own
//! placement by trying different coin sets — roughly `open_rounds` attempts to
//! reach a chosen round, each costing real UTXO management, and each changing
//! the ladder it is paying with.
//!
//! That matters for the Sybil who wants several identities in *one* round. It is
//! a cost rather than a barrier, and it is not the only one in the way:
//! `composition` caps mixing slots at a number no amount of grinding raises, and
//! payment seats still cost a fee each. This layer makes concentration
//! expensive; it does not make it impossible, and it should never be described
//! as though it did.

use bitcoin::hashes::{sha256, Hash};

use crate::signing_ledger::OutPointKey;

/// Domain tag. Versioned.
pub const ASSIGNMENT_TAG: &str = "wraith/assignment/v1";

/// Recent payments per open round, above the floor.
pub const PAYMENTS_PER_ROUND: u64 = 20;

/// Below this many recent payments an epoch runs a single round.
///
/// Splitting divides participants, and smaller rounds are weaker rounds: at low
/// volume one round of twenty beats four rounds of five. So the concentration
/// defence is **off** below the floor, which is correct rather than a
/// compromise — it would cost more anonymity than it protects.
///
/// # Why this is three rounds' worth and not two
///
/// It was 40, which is exactly where `volume / PAYMENTS_PER_ROUND` reaches 2 —
/// so the guard never changed an answer and the constant was decoration. A
/// mutation deleting it survived the whole suite, which is what surfaced it.
///
/// The margin is the point: volume fluctuates, and splitting the instant the
/// average supports two rounds means an ordinary dip leaves two half-empty ones.
/// Requiring three rounds' worth before splitting at all means a dip still
/// leaves rounds worth being in.
pub const SPLIT_FLOOR_PAYMENTS: u64 = PAYMENTS_PER_ROUND * 3;

/// Hard ceiling on concurrent rounds per tier.
pub const MAX_OPEN_ROUNDS: u64 = 8;

/// Why an assignment was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AssignmentError {
    /// The coordinator placed this participant somewhere the derivation does
    /// not put them.
    #[error("assigned to round {claimed} but the derivation gives {derived}; the coordinator does not choose placement")]
    WrongRound {
        /// Where the coordinator says.
        claimed: u32,
        /// Where the derivation says.
        derived: u32,
    },
    /// The modulus does not match the epoch's committed volume.
    ///
    /// The back door: a coordinator narrowing this to 1 funnels everyone into
    /// one round while appearing to follow the rule.
    #[error("round count {claimed} does not match the {derived} the epoch's committed volume gives; a narrowed modulus funnels every participant into one round")]
    WrongModulus {
        /// What the coordinator used.
        claimed: u64,
        /// What the committed volume gives.
        derived: u64,
    },
    /// No coins were offered.
    #[error("cannot assign a participant with no coins")]
    NoCoins,
}

/// How many rounds an epoch runs, from its committed volume.
///
/// Deterministic and coordinator-free: same committed figure, same answer on
/// every node and in every wallet.
pub fn open_rounds_for(committed_volume: u64) -> u64 {
    if committed_volume < SPLIT_FLOOR_PAYMENTS {
        return 1;
    }
    (committed_volume / PAYMENTS_PER_ROUND).clamp(1, MAX_OPEN_ROUNDS)
}

/// Canonical digest of a participant's coin set.
///
/// Sorted and deduplicated, so the order a wallet lists its coins in cannot
/// change where it lands — otherwise a participant could grind placement by
/// reordering, which costs nothing.
fn coins_digest(coins: &[OutPointKey]) -> [u8; 32] {
    let mut sorted: Vec<&OutPointKey> = coins.iter().collect();
    sorted.sort_unstable_by(|a, b| a.txid.cmp(&b.txid).then(a.vout.cmp(&b.vout)));
    sorted.dedup_by(|a, b| a.txid == b.txid && a.vout == b.vout);

    let mut buf = Vec::with_capacity(sorted.len() * 36);
    for c in sorted {
        buf.extend_from_slice(&c.txid);
        buf.extend_from_slice(&c.vout.to_be_bytes());
    }
    sha256::Hash::hash(&buf).to_byte_array()
}

/// The round this participant belongs in.
///
/// Binds the whole coin set, so a ladder stays together.
pub fn assign(
    epoch: u64,
    beacon: &[u8; 32],
    coins: &[OutPointKey],
    open_rounds: u64,
) -> Result<u32, AssignmentError> {
    if coins.is_empty() {
        return Err(AssignmentError::NoCoins);
    }
    let rounds = open_rounds.max(1);

    let mut buf = Vec::with_capacity(ASSIGNMENT_TAG.len() + 72);
    buf.extend_from_slice(ASSIGNMENT_TAG.as_bytes());
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(beacon);
    buf.extend_from_slice(&coins_digest(coins));
    let h = sha256::Hash::hash(&buf).to_byte_array();

    let mut n = [0u8; 8];
    n.copy_from_slice(&h[..8]);
    Ok((u64::from_be_bytes(n) % rounds) as u32)
}

/// Check the coordinator placed this participant where the rule says.
///
/// Verifies the modulus as well as the placement — checking only the placement
/// would accept a narrowed modulus, which is the whole back door.
pub fn verify_assignment(
    epoch: u64,
    beacon: &[u8; 32],
    coins: &[OutPointKey],
    committed_volume: u64,
    claimed_round: u32,
    claimed_open_rounds: u64,
) -> Result<(), AssignmentError> {
    let derived_rounds = open_rounds_for(committed_volume);
    if claimed_open_rounds != derived_rounds {
        return Err(AssignmentError::WrongModulus {
            claimed: claimed_open_rounds,
            derived: derived_rounds,
        });
    }
    let derived = assign(epoch, beacon, coins, derived_rounds)?;
    if derived != claimed_round {
        return Err(AssignmentError::WrongRound {
            claimed: claimed_round,
            derived,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coin(id: u8, vout: u32) -> OutPointKey {
        OutPointKey {
            txid: [id; 32],
            vout,
        }
    }
    fn beacon() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn a_whole_ladder_lands_in_one_round() {
        // Per-outpoint assignment would scatter six rungs across six rounds and
        // the payment could never be assembled.
        let rungs = vec![coin(1, 0), coin(2, 0), coin(3, 0), coin(4, 1), coin(4, 2)];
        let r = assign(9, &beacon(), &rungs, 4).unwrap();
        assert!(r < 4);
        // Same set, same answer — there is one placement for the participant.
        assert_eq!(assign(9, &beacon(), &rungs, 4).unwrap(), r);
    }

    #[test]
    fn reordering_the_coins_cannot_move_a_participant() {
        // Otherwise placement is grindable by reordering, which costs nothing.
        let a = vec![coin(1, 0), coin(2, 0), coin(3, 0)];
        let b = vec![coin(3, 0), coin(1, 0), coin(2, 0)];
        assert_eq!(
            assign(9, &beacon(), &a, 5).unwrap(),
            assign(9, &beacon(), &b, 5).unwrap()
        );
    }

    #[test]
    fn nothing_the_coordinator_holds_appears_in_the_derivation() {
        // Placement is a function of (epoch, beacon, coins) only — there is no
        // coordinator input to change.
        //
        // Compared over 200 participants rather than one: a single `assert_ne!`
        // on a value mod 8 collides one time in eight, which is a test that
        // passes today and fails in CI next week.
        let placements = |epoch: u64, b: [u8; 32]| -> Vec<u32> {
            (0..200u8)
                .map(|i| assign(epoch, &b, &[coin(i, 0)], 8).unwrap())
                .collect()
        };
        let base = placements(9, beacon());
        assert_ne!(base, placements(10, beacon()), "epoch must move placement");
        assert_ne!(base, placements(9, [8u8; 32]), "beacon must move placement");
    }

    #[test]
    fn placement_spreads_across_the_open_rounds() {
        // A derivation that piled everyone into round 0 would look correct and
        // do nothing.
        let mut hit = std::collections::HashSet::new();
        for i in 0..200u8 {
            hit.insert(assign(3, &beacon(), &[coin(i, 0)], 4).unwrap());
        }
        assert_eq!(hit.len(), 4, "every open round should receive traffic");
    }

    #[test]
    fn low_volume_runs_a_single_round() {
        // Splitting divides participants, and at low volume one round of twenty
        // beats four of five. Off below the floor is correct, not a compromise.
        assert_eq!(open_rounds_for(0), 1);
        assert_eq!(open_rounds_for(SPLIT_FLOOR_PAYMENTS - 1), 1);
        assert_eq!(
            open_rounds_for(SPLIT_FLOOR_PAYMENTS),
            SPLIT_FLOOR_PAYMENTS / PAYMENTS_PER_ROUND
        );
    }

    #[test]
    fn the_floor_actually_changes_an_answer() {
        // The floor was 40 while `volume / 20` already gave 1 below it, so the
        // guard never changed anything and the constant was decoration. A
        // mutation deleting it survived the entire suite.
        //
        // This asserts on a volume where the two rules disagree, so removing
        // the floor fails here.
        let v = SPLIT_FLOOR_PAYMENTS - 1;
        assert!(
            v / PAYMENTS_PER_ROUND > 1,
            "fixture is pointless unless the unguarded rule would split here"
        );
        assert_eq!(open_rounds_for(v), 1, "the floor must hold it at one round");
    }

    #[test]
    fn the_floor_leaves_room_for_a_dip() {
        // Splitting the instant the average supports two rounds means an
        // ordinary fluctuation leaves two half-empty ones.
        assert!(SPLIT_FLOOR_PAYMENTS >= PAYMENTS_PER_ROUND * 3);
    }

    #[test]
    fn the_round_count_is_capped() {
        assert_eq!(open_rounds_for(10_000), MAX_OPEN_ROUNDS);
    }

    #[test]
    fn a_narrowed_modulus_is_caught_even_when_the_placement_is_consistent() {
        // The back door: a coordinator setting open_rounds to 1 funnels everyone
        // into one round. Its placements are then self-consistent, so checking
        // only the placement accepts it.
        let coins = vec![coin(1, 0)];
        let volume = 200; // committed volume gives several rounds
        let honest = open_rounds_for(volume);
        assert!(honest > 1);

        let funnelled = assign(4, &beacon(), &coins, 1).unwrap();
        assert_eq!(funnelled, 0);

        assert_eq!(
            verify_assignment(4, &beacon(), &coins, volume, funnelled, 1),
            Err(AssignmentError::WrongModulus {
                claimed: 1,
                derived: honest
            })
        );
    }

    #[test]
    fn a_misplaced_participant_is_caught() {
        let coins = vec![coin(5, 0)];
        let volume = 200;
        let rounds = open_rounds_for(volume);
        let correct = assign(4, &beacon(), &coins, rounds).unwrap();
        let wrong = (correct + 1) % rounds as u32;
        assert!(matches!(
            verify_assignment(4, &beacon(), &coins, volume, wrong, rounds),
            Err(AssignmentError::WrongRound { .. })
        ));
        assert!(verify_assignment(4, &beacon(), &coins, volume, correct, rounds).is_ok());
    }

    #[test]
    fn a_participant_with_no_coins_cannot_be_placed() {
        assert_eq!(assign(1, &beacon(), &[], 4), Err(AssignmentError::NoCoins));
    }

    #[test]
    fn the_modulus_error_says_what_a_narrowed_one_does() {
        let msg = AssignmentError::WrongModulus {
            claimed: 1,
            derived: 4,
        }
        .to_string();
        assert!(msg.contains("funnels every participant"), "{msg}");
    }
}
