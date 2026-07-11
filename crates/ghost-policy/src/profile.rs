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
//| FILE: profile.rs                                                                                                     |
//|======================================================================================================================|

//! Policy profile definitions
//!
//! Built-in and custom policy profiles for transaction filtering.

use serde::{Deserialize, Serialize};

use ghost_buds::BudsTier;
use ghost_common::constants::*;

/// Policy profile configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyProfile {
    /// Profile name
    pub name: String,
    /// Profile description
    pub description: String,
    /// Allowed BUDS tiers
    pub allowed_tiers: Vec<BudsTier>,
    /// Maximum OP_RETURN size (0 = none allowed)
    pub max_op_return_size: usize,
    /// Maximum witness size per input (bytes)
    pub max_witness_per_input: usize,
    /// Maximum outputs per transaction
    pub max_tx_outputs: usize,
    /// Maximum transaction size (bytes)
    pub max_tx_size: usize,
    /// Allow inscription transactions
    pub allow_inscriptions: bool,
    /// Allow Runes transactions
    pub allow_runes: bool,
    /// Allow BRC-20 transactions
    pub allow_brc20: bool,
    /// Minimum fee rate (sat/vB, 0 = no minimum)
    pub min_fee_rate: f64,
    /// Priority boost for T0 transactions
    pub t0_priority_boost: f64,
}

impl PolicyProfile {
    /// Bitcoin Pure profile - financial transactions only
    ///
    /// Accepts only T0 (standard payments) and T1 (multisig, timelocks)
    /// No OP_RETURN, inscriptions, or exotic data
    pub fn bitcoin_pure() -> Self {
        Self {
            name: "strict".to_string(),
            description: "Financial transactions only (T0+T1), no data embedding".to_string(),
            allowed_tiers: vec![BudsTier::T0, BudsTier::T1],
            max_op_return_size: 0,
            max_witness_per_input: MAX_WITNESS_BYTES_PER_INPUT,
            max_tx_outputs: MAX_TX_OUTPUTS_BITCOIN_PURE,
            max_tx_size: MAX_TX_SIZE_BITCOIN_PURE,
            allow_inscriptions: false,
            allow_runes: false,
            allow_brc20: false,
            min_fee_rate: 1.0,
            t0_priority_boost: 1.2,
        }
    }

    /// Permissive profile - most common choice
    ///
    /// Accepts T0, T1, and T2 (small OP_RETURN for Lightning commitments)
    /// No inscriptions or heavy data
    pub fn permissive() -> Self {
        Self {
            name: "permissive".to_string(),
            description: "Financial + small data (T0+T1+T2), Lightning-compatible".to_string(),
            allowed_tiers: vec![BudsTier::T0, BudsTier::T1, BudsTier::T2],
            max_op_return_size: MAX_OP_RETURN_SMALL_BYTES,
            max_witness_per_input: MAX_WITNESS_BYTES_PER_INPUT,
            max_tx_outputs: 100,
            max_tx_size: 200_000,
            allow_inscriptions: false,
            allow_runes: false,
            allow_brc20: false,
            min_fee_rate: 1.0,
            t0_priority_boost: 1.1,
        }
    }

    /// Full Open profile - accept everything
    ///
    /// Accepts all transaction types including inscriptions
    /// Maximum fee revenue, no filtering
    pub fn full_open() -> Self {
        Self {
            name: "full_open".to_string(),
            description: "Accept all valid transactions (T0-T3)".to_string(),
            allowed_tiers: vec![BudsTier::T0, BudsTier::T1, BudsTier::T2, BudsTier::T3],
            max_op_return_size: 520,          // Bitcoin consensus limit
            max_witness_per_input: 4_000_000, // Essentially unlimited
            max_tx_outputs: 2500,             // Near consensus limit
            max_tx_size: 400_000,             // Standard relay limit
            allow_inscriptions: true,
            allow_runes: true,
            allow_brc20: true,
            min_fee_rate: 0.0,
            t0_priority_boost: 1.0,
        }
    }

    /// Create a custom profile
    pub fn custom(name: impl Into<String>, allowed_tiers: Vec<BudsTier>) -> Self {
        Self {
            name: name.into(),
            description: "Custom policy profile".to_string(),
            allowed_tiers,
            max_op_return_size: MAX_OP_RETURN_SMALL_BYTES,
            max_witness_per_input: MAX_WITNESS_BYTES_PER_INPUT,
            max_tx_outputs: MAX_TX_OUTPUTS_BITCOIN_PURE,
            max_tx_size: MAX_TX_SIZE_BITCOIN_PURE,
            allow_inscriptions: false,
            allow_runes: false,
            allow_brc20: false,
            min_fee_rate: 1.0,
            t0_priority_boost: 1.0,
        }
    }

    /// Check if a tier is allowed by this profile
    pub fn allows_tier(&self, tier: BudsTier) -> bool {
        self.allowed_tiers.contains(&tier)
    }

    /// Get the highest allowed tier
    pub fn highest_allowed_tier(&self) -> Option<BudsTier> {
        self.allowed_tiers.iter().max().copied()
    }

    /// Check if profile allows any data-anchoring (T2+)
    pub fn allows_data(&self) -> bool {
        self.allowed_tiers.iter().any(|t| *t >= BudsTier::T2)
    }

    /// Check if profile allows heavy data (T3)
    pub fn allows_heavy_data(&self) -> bool {
        self.allowed_tiers.contains(&BudsTier::T3)
    }

    /// Get the profile's strictness level (0-3)
    pub fn strictness(&self) -> u8 {
        match self.highest_allowed_tier() {
            Some(BudsTier::T0) => 3,
            Some(BudsTier::T1) => 2,
            Some(BudsTier::T2) => 1,
            Some(BudsTier::T3) | None => 0,
        }
    }
}

impl Default for PolicyProfile {
    fn default() -> Self {
        // Matches PolicyConfig's default (full_open / inert): a node with no
        // explicit policy behaves as stock Core until the operator opts in.
        Self::full_open()
    }
}

/// Profile preset names
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfilePreset {
    #[serde(rename = "strict", alias = "bitcoin_pure")]
    BitcoinPure,
    Permissive,
    FullOpen,
    Custom,
}

impl ProfilePreset {
    pub fn to_profile(&self) -> PolicyProfile {
        match self {
            Self::BitcoinPure => PolicyProfile::bitcoin_pure(),
            Self::Permissive => PolicyProfile::permissive(),
            Self::FullOpen => PolicyProfile::full_open(),
            Self::Custom => PolicyProfile::permissive(), // Start from permissive
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::BitcoinPure => "strict",
            Self::Permissive => "permissive",
            Self::FullOpen => "full_open",
            Self::Custom => "custom",
        }
    }
}

impl std::fmt::Display for ProfilePreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Profile builder for customization
#[derive(Debug, Clone)]
pub struct ProfileBuilder {
    profile: PolicyProfile,
}

impl ProfileBuilder {
    /// Start from a preset
    pub fn from_preset(preset: ProfilePreset) -> Self {
        Self {
            profile: preset.to_profile(),
        }
    }

    /// Start from scratch (permissive base)
    pub fn new(name: impl Into<String>) -> Self {
        let mut profile = PolicyProfile::permissive();
        profile.name = name.into();
        Self { profile }
    }

    /// Set allowed tiers
    pub fn allowed_tiers(mut self, tiers: Vec<BudsTier>) -> Self {
        self.profile.allowed_tiers = tiers;
        self
    }

    /// Set max OP_RETURN size
    pub fn max_op_return(mut self, size: usize) -> Self {
        self.profile.max_op_return_size = size;
        self
    }

    /// Set max witness size per input
    pub fn max_witness(mut self, size: usize) -> Self {
        self.profile.max_witness_per_input = size;
        self
    }

    /// Set max outputs per transaction
    pub fn max_outputs(mut self, count: usize) -> Self {
        self.profile.max_tx_outputs = count;
        self
    }

    /// Set max transaction size
    pub fn max_tx_size(mut self, size: usize) -> Self {
        self.profile.max_tx_size = size;
        self
    }

    /// Allow inscriptions
    pub fn allow_inscriptions(mut self, allow: bool) -> Self {
        self.profile.allow_inscriptions = allow;
        self
    }

    /// Allow Runes
    pub fn allow_runes(mut self, allow: bool) -> Self {
        self.profile.allow_runes = allow;
        self
    }

    /// Allow BRC-20
    pub fn allow_brc20(mut self, allow: bool) -> Self {
        self.profile.allow_brc20 = allow;
        self
    }

    /// Set minimum fee rate
    pub fn min_fee_rate(mut self, rate: f64) -> Self {
        self.profile.min_fee_rate = rate;
        self
    }

    /// Set T0 priority boost
    pub fn t0_priority_boost(mut self, boost: f64) -> Self {
        self.profile.t0_priority_boost = boost;
        self
    }

    /// Set description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.profile.description = desc.into();
        self
    }

    /// Build the profile
    pub fn build(self) -> PolicyProfile {
        self.profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitcoin_pure_profile() {
        let profile = PolicyProfile::bitcoin_pure();

        assert!(profile.allows_tier(BudsTier::T0));
        assert!(profile.allows_tier(BudsTier::T1));
        assert!(!profile.allows_tier(BudsTier::T2));
        assert!(!profile.allows_tier(BudsTier::T3));
        assert_eq!(profile.max_op_return_size, 0);
        assert!(!profile.allow_inscriptions);
    }

    #[test]
    fn test_permissive_profile() {
        let profile = PolicyProfile::permissive();

        assert!(profile.allows_tier(BudsTier::T0));
        assert!(profile.allows_tier(BudsTier::T1));
        assert!(profile.allows_tier(BudsTier::T2));
        assert!(!profile.allows_tier(BudsTier::T3));
        assert_eq!(profile.max_op_return_size, 80);
    }

    #[test]
    fn test_full_open_profile() {
        let profile = PolicyProfile::full_open();

        assert!(profile.allows_tier(BudsTier::T0));
        assert!(profile.allows_tier(BudsTier::T3));
        assert!(profile.allow_inscriptions);
        assert!(profile.allow_runes);
    }

    #[test]
    fn test_profile_builder() {
        let profile = ProfileBuilder::new("my_custom")
            .allowed_tiers(vec![BudsTier::T0])
            .max_op_return(0)
            .min_fee_rate(2.0)
            .description("My strict profile")
            .build();

        assert_eq!(profile.name, "my_custom");
        assert_eq!(profile.allowed_tiers, vec![BudsTier::T0]);
        assert_eq!(profile.min_fee_rate, 2.0);
    }

    #[test]
    fn test_strictness() {
        assert_eq!(PolicyProfile::bitcoin_pure().strictness(), 2); // T0+T1
        assert_eq!(PolicyProfile::permissive().strictness(), 1); // T0+T1+T2
        assert_eq!(PolicyProfile::full_open().strictness(), 0); // T0-T3
    }
}
