//! Optional user-supplied entropy, mixed into a new wallet seed.
//!
//! ## Why this exists
//!
//! Master spec §6A rule E-1 requires every secret to come from the OS CSPRNG,
//! and originally forbade user-supplied entropy outright. That rule is right
//! about *substitution* and was wrong about *mixing*, and the Coldcard
//! incident is why it was amended.
//!
//! From 1 March 2021 Coldcard firmware generated seeds through MicroPython's
//! Yasmarang PRNG instead of the STM32 hardware TRNG. Effective entropy fell
//! to roughly 40 bits on Mk3 and 72 on later models. Nothing downstream could
//! see it: the output distribution was fine, only the seed space was small.
//! From 30 July 2026 an attacker enumerated that space and swept about 1,816
//! BTC from more than 5,200 addresses.
//!
//! With a single source there is no floor. If it silently degrades, every
//! seed it produces is weak and nothing inside the device can tell. Dice give
//! a floor that does not depend on any implementation being correct.
//!
//! ## The rule this module implements
//!
//! **Mixed, never substituted.** The seed is
//!
//! ```text
//! seed = SHA256( tag ‖ os_bytes ‖ user_digest )
//! ```
//!
//! so it can never be weaker than `os_bytes` alone — an attacker has to break
//! the OS source *and* guess the user's rolls. Supplying no user entropy, or
//! supplying entirely predictable rolls, leaves the seed exactly as strong as
//! it would have been. That one-directional property is the whole point, and
//! it is why a "dice only" mode is not offered here: it would make the seed
//! depend on the user rolling honestly and well, with no safety net.
//!
//! ## What a roll is worth
//!
//! A d6 carries log2(6) ≈ 2.585 bits; a coin flip carries exactly 1. So 99
//! rolls or 256 flips reach a full 256-bit contribution, and 50 rolls or 128
//! flips reach 128. [`MIN_USER_BITS`] is the floor for supplying any at all:
//! below it a user is doing work that feels meaningful and is not, and being
//! told so is better than being humoured.

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Domain tag. Versioned so a future change to the mixing construction is a
/// distinct derivation rather than a silently different reading of one.
const SEED_MIX_TAG: &[u8] = b"GhostWallet/seed-mix/v1";

/// Tag for reducing a roll sequence to a digest, kept distinct from the mix
/// tag so the two hashes can never be confused for one another.
const USER_ENTROPY_TAG: &[u8] = b"GhostWallet/user-entropy/v1";

/// Bits carried by one six-sided die roll: log2(6).
pub const BITS_PER_DIE_ROLL: f64 = 2.584_962_500_721_156;

/// Bits carried by one coin flip.
pub const BITS_PER_COIN_FLIP: f64 = 1.0;

/// Least user entropy accepted when a user chooses to supply any: 128 bits,
/// i.e. 50 die rolls or 128 coin flips.
///
/// Mixing means any amount is *safe*, so this floor is not about safety. It
/// is about not letting someone believe six rolls bought them something. If
/// they want the protection, they should have enough of it to matter.
pub const MIN_USER_BITS: f64 = 128.0;

/// A full-strength contribution, matching the 256-bit seed it mixes into:
/// 99 die rolls or 256 coin flips.
pub const RECOMMENDED_USER_BITS: f64 = 256.0;

#[derive(Debug, thiserror::Error)]
pub enum UserEntropyError {
    #[error("a die roll must be 1-6, got {0}")]
    DieOutOfRange(u8),
    #[error(
        "only {supplied:.0} bits of user entropy supplied; at least {required:.0} is required \
         ({rolls} more die rolls, or {flips} more coin flips)"
    )]
    TooLittle {
        supplied: f64,
        required: f64,
        rolls: usize,
        flips: usize,
    },
}

/// How the user is producing their entropy. Both are counted in the same
/// accumulator so a user may mix methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A six-sided die, recorded as 1-6.
    Die,
    /// A coin, recorded as 0 or 1.
    Coin,
}

/// Accumulates a user's rolls and reduces them to a digest.
///
/// The raw sequence is zeroized on drop — it reconstructs the contribution,
/// so it is key material until it is mixed.
#[derive(Debug, Default)]
pub struct UserEntropy {
    /// Canonical encoding of the sequence: one byte per event, `Die` as its
    /// face value 1-6 and `Coin` as `b'H'` / `b'T'`. Encoding the *kind*
    /// distinctly means a die 1 and a tails cannot collide into the same
    /// digest.
    events: Vec<u8>,
    die_rolls: usize,
    coin_flips: usize,
}

impl UserEntropy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one die roll, 1-6.
    pub fn push_die(&mut self, face: u8) -> Result<(), UserEntropyError> {
        if !(1..=6).contains(&face) {
            return Err(UserEntropyError::DieOutOfRange(face));
        }
        self.events.push(face);
        self.die_rolls += 1;
        Ok(())
    }

    /// Record one coin flip. `true` is heads.
    pub fn push_coin(&mut self, heads: bool) {
        self.events.push(if heads { b'H' } else { b'T' });
        self.coin_flips += 1;
    }

    pub fn die_rolls(&self) -> usize {
        self.die_rolls
    }

    pub fn coin_flips(&self) -> usize {
        self.coin_flips
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Bits contributed so far.
    ///
    /// This is the entropy of the *process*, which is what a user can be
    /// advised about. It assumes fair dice and honest rolling; nothing here
    /// can check that, which is exactly why the result is mixed rather than
    /// substituted.
    pub fn bits(&self) -> f64 {
        self.die_rolls as f64 * BITS_PER_DIE_ROLL + self.coin_flips as f64 * BITS_PER_COIN_FLIP
    }

    /// How many more events would reach `target` bits, by each method.
    /// Returns `(die_rolls, coin_flips)`, either of which alone suffices.
    pub fn remaining_for(&self, target: f64) -> (usize, usize) {
        let short = (target - self.bits()).max(0.0);
        (
            (short / BITS_PER_DIE_ROLL).ceil() as usize,
            (short / BITS_PER_COIN_FLIP).ceil() as usize,
        )
    }

    /// Reduce the sequence to a 32-byte digest, refusing a contribution too
    /// small to be worth the user's belief in it.
    pub fn digest(&self) -> Result<[u8; 32], UserEntropyError> {
        let bits = self.bits();
        if bits < MIN_USER_BITS {
            let (rolls, flips) = self.remaining_for(MIN_USER_BITS);
            return Err(UserEntropyError::TooLittle {
                supplied: bits,
                required: MIN_USER_BITS,
                rolls,
                flips,
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(USER_ENTROPY_TAG);
        hasher.update((self.events.len() as u64).to_be_bytes());
        hasher.update(&self.events);
        Ok(hasher.finalize().into())
    }
}

impl Drop for UserEntropy {
    fn drop(&mut self) {
        self.events.zeroize();
    }
}

/// Combine OS entropy with a user contribution.
///
/// One-directional by construction: `os_bytes` is hashed in whatever the user
/// supplied, so the result is at least as strong as `os_bytes` alone. Passing
/// `None` returns a hash of the OS bytes, which is the same strength again —
/// the user's choice not to roll costs them nothing.
pub fn mix_seed_entropy(os_bytes: &[u8; 32], user_digest: Option<&[u8; 32]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SEED_MIX_TAG);
    hasher.update(os_bytes);
    if let Some(user) = user_digest {
        hasher.update(user);
    }
    hasher.finalize().into()
}

/// Plain-words guidance shown before a user starts rolling.
///
/// Kept here rather than in each front-end so the CLI and the GUI cannot
/// drift into telling people different things about their own key material.
pub fn guidance() -> &'static str {
    "Your dice are mixed with the randomness this computer produces — they are never used\n\
     instead of it. That means your rolls can only help: if the operating system's random\n\
     source were ever weak or broken, your rolls still stand between an attacker and your\n\
     coins, and if your rolls are poor, the seed is exactly as strong as it would have been.\n\
     \n\
     How to do it well:\n\
       • Use real dice you can see. Casino-style dice are fairest; cheap rounded ones drift.\n\
       • Roll on a hard, flat surface, and read the face that lands up. Re-roll cocked dice.\n\
       • Enter every roll, including repeats. A run of the same number is normal and is not\n\
         a reason to start again — discarding results you dislike is what makes a sequence\n\
         predictable.\n\
       • Never reuse a sequence you have used before, and never use one you can remember or\n\
         that means something (a birthday, a phone number). Anything memorable is guessable.\n\
       • Count matters more than anything else: 99 rolls give a full-strength contribution,\n\
         50 is the minimum accepted. Coin flips work too, at 256 and 128 respectively.\n\
       • Nobody should be watching, and this screen should not be recorded or screenshotted."
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rolled(n: usize) -> UserEntropy {
        let mut e = UserEntropy::new();
        for i in 0..n {
            e.push_die((i % 6 + 1) as u8).unwrap();
        }
        e
    }

    #[test]
    fn a_die_face_outside_one_to_six_is_refused() {
        let mut e = UserEntropy::new();
        assert!(e.push_die(0).is_err());
        assert!(e.push_die(7).is_err());
        assert!(e.push_die(1).is_ok());
    }

    #[test]
    fn bits_accumulate_at_the_documented_rate() {
        let e = rolled(99);
        assert!(e.bits() >= 255.0, "99 rolls should reach ~256 bits");
        let mut c = UserEntropy::new();
        for _ in 0..128 {
            c.push_coin(true);
        }
        assert_eq!(c.bits(), 128.0);
    }

    #[test]
    fn too_few_rolls_are_refused_with_a_count_of_what_is_missing() {
        let e = rolled(10);
        match e.digest() {
            Err(UserEntropyError::TooLittle { rolls, flips, .. }) => {
                assert_eq!(rolls, 40, "10 of the 50 rolls done");
                assert!(flips > 100);
            }
            other => panic!("expected TooLittle, got {other:?}"),
        }
        assert!(rolled(50).digest().is_ok());
    }

    #[test]
    fn dice_and_coins_count_towards_the_same_floor() {
        let mut e = UserEntropy::new();
        for _ in 0..25 {
            e.push_die(3).unwrap();
        }
        for _ in 0..64 {
            e.push_coin(false);
        }
        assert!(e.bits() >= MIN_USER_BITS);
        assert!(e.digest().is_ok());
    }

    #[test]
    fn a_die_one_and_a_tails_are_not_the_same_event() {
        // Both are "the low outcome"; encoding them distinctly stops two
        // different sequences reducing to one digest.
        let mut dice = UserEntropy::new();
        let mut coins = UserEntropy::new();
        for _ in 0..50 {
            dice.push_die(1).unwrap();
        }
        for _ in 0..50 {
            coins.push_coin(false);
        }
        for _ in 0..78 {
            coins.push_coin(false);
        }
        assert_ne!(dice.digest().unwrap(), coins.digest().unwrap());
    }

    #[test]
    fn the_order_of_rolls_changes_the_digest() {
        let mut a = UserEntropy::new();
        let mut b = UserEntropy::new();
        for i in 0..50 {
            a.push_die((i % 6 + 1) as u8).unwrap();
            b.push_die((5 - i % 6 + 1) as u8).unwrap();
        }
        assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    }

    #[test]
    fn mixing_changes_the_result_but_omitting_user_entropy_is_still_valid() {
        let os = [7u8; 32];
        let user = rolled(99).digest().unwrap();
        let with = mix_seed_entropy(&os, Some(&user));
        let without = mix_seed_entropy(&os, None);
        assert_ne!(with, without);
        assert_ne!(with, os, "the seed is the mix, not the raw OS bytes");
        assert_ne!(without, os);
    }

    #[test]
    fn different_os_bytes_give_different_seeds_for_identical_rolls() {
        // The one-directional property: the OS contribution is always in
        // there, so identical dice cannot pin the seed.
        let user = rolled(99).digest().unwrap();
        let a = mix_seed_entropy(&[1u8; 32], Some(&user));
        let b = mix_seed_entropy(&[2u8; 32], Some(&user));
        assert_ne!(a, b);
    }

    #[test]
    fn mixing_is_deterministic_for_the_same_inputs() {
        let os = [9u8; 32];
        let user = rolled(60).digest().unwrap();
        assert_eq!(
            mix_seed_entropy(&os, Some(&user)),
            mix_seed_entropy(&os, Some(&user))
        );
    }
}
