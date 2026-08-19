//! The challenge a participant signs to prove it controls its round input.
//!
//! Lives in the protocol crate because the wallet and the coordinator must
//! construct byte-identical strings — a mismatch would show up as every
//! proof failing verification, with nothing to say which side was wrong.
//!
//! ## What the challenge binds, and why
//!
//! - **A domain tag.** The key that signs this also signs round
//!   transactions. Without a tag that no transaction sighash can collide
//!   with, "prove you own this coin" could be turned into "sign this
//!   spend".
//! - **The session id.** Otherwise one proof is good for every round the
//!   participant ever joins, so a proof captured once could be replayed
//!   into a round the owner never agreed to enter.
//! - **The outpoint.** Otherwise a proof for a coin the submitter really
//!   does own would authorise registering any *other* coin, which is
//!   precisely the substitution the proof exists to stop.
//!
//! Nothing else goes in. The `ghost_id` in particular is left out: it is
//! a per-round handle the participant chooses, so binding it would let a
//! participant invalidate its own proof by changing a value only it
//! controls, and it adds no protection the outpoint does not already give.
//!
//! See #699.

/// Domain tag. Versioned so a future change to the binding is a distinct
/// message rather than a silently different interpretation of the same one.
pub const OWNERSHIP_CHALLENGE_TAG: &str = "wraith/ownership/v1";

/// The exact string a participant signs, per BIP-322, to prove control of
/// the input it is registering.
///
/// The txid is lowercased so two spellings of one coin cannot produce two
/// different challenges. The layout is fixed-shape — tag, session, outpoint,
/// one per line — and every field is either caller-controlled but
/// newline-free by construction (`session_id` is coordinator-generated) or
/// strictly formatted (hex txid, decimal vout).
pub fn ownership_challenge(session_id: &str, txid: &str, vout: u32) -> String {
    format!(
        "{OWNERSHIP_CHALLENGE_TAG}\n{session_id}\n{}:{vout}",
        txid.trim().to_ascii_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_has_the_documented_shape() {
        assert_eq!(
            ownership_challenge("round-7", &"AB".repeat(32), 3),
            format!("wraith/ownership/v1\nround-7\n{}:3", "ab".repeat(32))
        );
    }

    #[test]
    fn txid_spelling_does_not_change_the_challenge() {
        let lower = ownership_challenge("s", &"ab".repeat(32), 0);
        let upper = ownership_challenge("s", &"AB".repeat(32), 0);
        let padded = ownership_challenge("s", &format!("  {}  ", "ab".repeat(32)), 0);
        assert_eq!(lower, upper);
        assert_eq!(lower, padded);
    }

    #[test]
    fn a_different_session_is_a_different_challenge() {
        // Or one proof would be good for every round the participant
        // ever joins.
        assert_ne!(
            ownership_challenge("round-1", &"ab".repeat(32), 0),
            ownership_challenge("round-2", &"ab".repeat(32), 0),
        );
    }

    #[test]
    fn a_different_coin_is_a_different_challenge() {
        // Or a proof for a coin you own would authorise registering one
        // you don't.
        assert_ne!(
            ownership_challenge("s", &"ab".repeat(32), 0),
            ownership_challenge("s", &"cd".repeat(32), 0),
        );
        assert_ne!(
            ownership_challenge("s", &"ab".repeat(32), 0),
            ownership_challenge("s", &"ab".repeat(32), 1),
        );
    }

    #[test]
    fn the_vout_boundary_cannot_be_moved_by_the_session_id() {
        // `session_id` sits on its own line, so no value of it can make
        // one outpoint's challenge equal another's.
        let a = ownership_challenge(&format!("s\n{}:9", "ab".repeat(32)), &"cd".repeat(32), 0);
        let b = ownership_challenge("s", &"ab".repeat(32), 9);
        assert_ne!(a, b);
    }
}
