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
//| FILE: signature_scope.rs                                                                                           |
//|======================================================================================================================|

//! What a signature actually commits to — and why `pre_sign` depends on it.
//!
//! [`crate::pre_sign`] lets a participant verify a round before signing: their
//! output is present, the fee is sane, the set is large enough, no marker.
//!
//! **Every one of those checks is worthless unless the signature commits to the
//! thing that was checked.** Verifying the output set and then signing with
//! `SIGHASH_NONE` is theatre: the coordinator is free to replace every output
//! afterwards and the signature stays valid. The participant did the work,
//! reached the right conclusion, and signed it away.
//!
//! This module names what each sighash type binds, and reports which `pre_sign`
//! guarantees survive it. It exists because the failure is silent — a wrong
//! sighash produces a perfectly valid transaction that simply is not the one
//! anybody agreed to.
//!
//! # The short version
//!
//! Round participants sign `SIGHASH_ALL` (or Taproot `Default`, which means the
//! same). Anything else weakens or voids the verification that preceded it.

use bitcoin::sighash::TapSighashType;

/// What a signature binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope {
    /// The signature covers every input, so none can be added or removed.
    pub commits_all_inputs: bool,
    /// The signature covers every output, so none can be altered.
    pub commits_all_outputs: bool,
    /// The signature covers only the output at the signer's own index.
    pub commits_own_output_only: bool,
}

/// What a Taproot sighash type binds.
pub fn scope_of(ty: TapSighashType) -> Scope {
    use TapSighashType as T;
    match ty {
        T::Default | T::All => Scope {
            commits_all_inputs: true,
            commits_all_outputs: true,
            commits_own_output_only: false,
        },
        T::None => Scope {
            commits_all_inputs: true,
            commits_all_outputs: false,
            commits_own_output_only: false,
        },
        T::Single => Scope {
            commits_all_inputs: true,
            commits_all_outputs: false,
            commits_own_output_only: true,
        },
        T::AllPlusAnyoneCanPay => Scope {
            commits_all_inputs: false,
            commits_all_outputs: true,
            commits_own_output_only: false,
        },
        T::NonePlusAnyoneCanPay => Scope {
            commits_all_inputs: false,
            commits_all_outputs: false,
            commits_own_output_only: false,
        },
        T::SinglePlusAnyoneCanPay => Scope {
            commits_all_inputs: false,
            commits_all_outputs: false,
            commits_own_output_only: true,
        },
    }
}

/// A verification that does not survive the chosen sighash type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VoidedCheck {
    /// The coordinator may replace outputs after signing.
    #[error("outputs are not committed: every `pre_sign` output check — my payment, the fee, markers, uniform values — can be undone after signing")]
    OutputsUncommitted,

    /// The coordinator may add or remove inputs after signing.
    #[error("inputs are not committed: the anonymity set verified before signing can be changed afterwards")]
    InputsUncommitted,

    /// The signer's index binds them to the output at the same index.
    #[error("SIGHASH_SINGLE pairs input i with output i, publishing the mapping the round exists to destroy")]
    IndexPairingIsPublished,
}

/// Which `pre_sign` guarantees evaporate under this sighash type.
///
/// Empty means the verification holds. Anything else means the participant
/// checked something the signature does not bind.
pub fn voided_checks(ty: TapSighashType) -> Vec<VoidedCheck> {
    let s = scope_of(ty);
    let mut out = Vec::new();
    if s.commits_own_output_only {
        out.push(VoidedCheck::IndexPairingIsPublished);
    }
    if !s.commits_all_outputs {
        out.push(VoidedCheck::OutputsUncommitted);
    }
    if !s.commits_all_inputs {
        out.push(VoidedCheck::InputsUncommitted);
    }
    out
}

/// Whether a participant may sign a round with this sighash type.
///
/// Only `Default` and `All` qualify. Everything else leaves the coordinator room
/// to change what was agreed.
pub fn is_safe_for_round(ty: TapSighashType) -> bool {
    voided_checks(ty).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::sighash::TapSighashType as T;

    #[test]
    fn all_commits_to_everything_that_was_verified() {
        for ty in [T::Default, T::All] {
            assert!(is_safe_for_round(ty), "{ty:?} should be the safe choice");
            assert_eq!(voided_checks(ty), vec![]);
        }
    }

    #[test]
    fn none_makes_the_whole_verification_theatre() {
        // A participant checks their output is present, then signs something
        // that lets the coordinator replace it. The transaction stays valid.
        let v = voided_checks(T::None);
        assert!(v.contains(&VoidedCheck::OutputsUncommitted));
        assert!(!is_safe_for_round(T::None));
    }

    #[test]
    fn single_publishes_the_mapping_the_round_exists_to_destroy() {
        // Tempting because it looks self-contained: sign my own input and my own
        // output. But binding input i to output i is the input-to-output
        // mapping, written into the transaction by construction.
        let v = voided_checks(T::Single);
        assert!(v.contains(&VoidedCheck::IndexPairingIsPublished));
        assert!(!is_safe_for_round(T::Single));
    }

    #[test]
    fn anyonecanpay_leaves_the_anonymity_set_editable() {
        // Attractive for collecting signatures asynchronously, and it means the
        // set a participant verified is not the set that broadcasts.
        let v = voided_checks(T::AllPlusAnyoneCanPay);
        assert!(v.contains(&VoidedCheck::InputsUncommitted));
        assert!(
            !v.contains(&VoidedCheck::OutputsUncommitted),
            "outputs are still bound"
        );
        assert!(!is_safe_for_round(T::AllPlusAnyoneCanPay));
    }

    #[test]
    fn the_worst_combination_voids_everything() {
        let v = voided_checks(T::NonePlusAnyoneCanPay);
        assert!(v.contains(&VoidedCheck::OutputsUncommitted));
        assert!(v.contains(&VoidedCheck::InputsUncommitted));
    }

    #[test]
    fn every_sighash_type_is_classified() {
        // A new variant must not silently default to "safe".
        for ty in [
            T::Default,
            T::All,
            T::None,
            T::Single,
            T::AllPlusAnyoneCanPay,
            T::NonePlusAnyoneCanPay,
            T::SinglePlusAnyoneCanPay,
        ] {
            let s = scope_of(ty);
            let safe = is_safe_for_round(ty);
            assert_eq!(
                safe,
                s.commits_all_inputs && s.commits_all_outputs && !s.commits_own_output_only,
                "{ty:?} classification disagrees with its own scope"
            );
        }
    }

    #[test]
    fn only_two_types_are_ever_safe() {
        let safe: Vec<T> = [
            T::Default,
            T::All,
            T::None,
            T::Single,
            T::AllPlusAnyoneCanPay,
            T::NonePlusAnyoneCanPay,
            T::SinglePlusAnyoneCanPay,
        ]
        .into_iter()
        .filter(|t| is_safe_for_round(*t))
        .collect();
        assert_eq!(safe, vec![T::Default, T::All]);
    }
}
