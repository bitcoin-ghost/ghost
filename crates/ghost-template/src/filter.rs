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
//| FILE: filter.rs                                                                                                      |
//|======================================================================================================================|

//! Template filtering with BUDS and policy

use tracing::{debug, info, warn};

use ghost_buds::BudsClassifier;
use ghost_policy::{PolicyEngine, PolicyProfile};

use crate::merkle::compute_merkle_root;
use crate::template::{BlockTemplate, FilteredTemplate, TemplateStats, TierRejections};

/// Template filter
#[derive(Debug)]
pub struct TemplateFilter {
    /// BUDS classifier (used for transaction classification)
    #[allow(dead_code)]
    classifier: BudsClassifier,
    /// Policy engine
    policy: PolicyEngine,
}

impl TemplateFilter {
    /// Create a new filter with the given policy
    pub fn new(profile: PolicyProfile) -> Self {
        Self {
            classifier: BudsClassifier::new(),
            policy: PolicyEngine::new(profile),
        }
    }

    /// Create with bitcoin_pure policy
    pub fn bitcoin_pure() -> Self {
        Self::new(PolicyProfile::bitcoin_pure())
    }

    /// Create with permissive policy
    pub fn permissive() -> Self {
        Self::new(PolicyProfile::permissive())
    }

    /// Create with full_open policy
    pub fn full_open() -> Self {
        Self::new(PolicyProfile::full_open())
    }

    /// Update the policy profile
    pub fn set_profile(&mut self, profile: PolicyProfile) {
        self.policy.set_profile(profile);
    }

    /// Get current profile
    pub fn profile(&self) -> &PolicyProfile {
        self.policy.profile()
    }

    /// Filter a block template
    pub fn filter(&mut self, template: BlockTemplate) -> FilteredTemplate {
        info!(
            height = template.height,
            tx_count = template.transactions.len(),
            profile = %self.policy.profile().name,
            "Filtering block template"
        );

        let mut included_indices = Vec::new();
        let mut rejected_indices = Vec::new();
        let mut _tier_rejections = TierRejections::default();
        let mut total_fee = 0u64;
        let mut total_weight = 0u64;

        // Track dependencies - if a tx is rejected, dependent txs must also be rejected
        let mut rejected_set = std::collections::HashSet::new();

        for (i, template_tx) in template.transactions.iter().enumerate() {
            // Check if any dependency was rejected
            let dependency_rejected = template_tx
                .depends
                .iter()
                .any(|&dep| rejected_set.contains(&dep));

            if dependency_rejected {
                debug!(
                    txid = %template_tx.txid,
                    "Rejecting transaction due to rejected dependency"
                );
                rejected_indices.push(i);
                rejected_set.insert(i);
                continue;
            }

            // Decode and classify transaction
            let tx = match template_tx.decode() {
                Ok(tx) => tx,
                Err(e) => {
                    warn!(
                        txid = %template_tx.txid,
                        error = %e,
                        "Failed to decode transaction"
                    );
                    rejected_indices.push(i);
                    rejected_set.insert(i);
                    continue;
                }
            };

            // Evaluate against policy
            let decision = self.policy.evaluate(&tx);

            if decision.is_accepted() {
                included_indices.push(i);
                total_fee += template_tx.fee;
                total_weight += template_tx.weight;
            } else {
                rejected_indices.push(i);
                rejected_set.insert(i);

                // Track rejection by tier
                match decision.tier() {
                    ghost_buds::BudsTier::T0 => _tier_rejections.t0 += 1,
                    ghost_buds::BudsTier::T1 => _tier_rejections.t1 += 1,
                    ghost_buds::BudsTier::T2 => _tier_rejections.t2 += 1,
                    ghost_buds::BudsTier::T3 => _tier_rejections.t3 += 1,
                }

                debug!(
                    txid = %template_tx.txid,
                    tier = %decision.tier(),
                    "Transaction rejected by policy"
                );
            }
        }

        // Compute new merkle root with filtered transactions
        let included_txids: Vec<[u8; 32]> = included_indices
            .iter()
            .map(|&i| {
                let mut txid = [0u8; 32];
                if let Ok(bytes) = hex::decode(&template.transactions[i].txid) {
                    if bytes.len() == 32 {
                        txid.copy_from_slice(&bytes);
                    }
                }
                txid
            })
            .collect();

        let merkle_root = compute_merkle_root(&included_txids);

        info!(
            included = included_indices.len(),
            rejected = rejected_indices.len(),
            total_fee = total_fee,
            rejection_rate = format!(
                "{:.1}%",
                rejected_indices.len() as f64 / template.transactions.len() as f64 * 100.0
            ),
            "Template filtering complete"
        );

        FilteredTemplate {
            original: template,
            included_indices,
            rejected_indices,
            merkle_root,
            total_fee,
            total_weight,
        }
    }

    /// Filter and return statistics
    pub fn filter_with_stats(
        &mut self,
        template: BlockTemplate,
    ) -> (FilteredTemplate, TemplateStats) {
        let filtered = self.filter(template);
        let stats = TemplateStats::from_filtered(&filtered);
        (filtered, stats)
    }

    /// Get policy statistics
    pub fn policy_stats(&self) -> &ghost_policy::PolicyStats {
        self.policy.stats()
    }

    /// Reset policy statistics
    pub fn reset_stats(&mut self) {
        self.policy.reset_stats();
    }
}

/// Filter result summary
#[derive(Debug, Clone)]
pub struct FilterSummary {
    /// Number of transactions accepted
    pub accepted: usize,
    /// Number of transactions rejected
    pub rejected: usize,
    /// Total fees from accepted transactions
    pub total_fees: u64,
    /// Fees lost to rejection
    pub lost_fees: u64,
    /// Breakdown by rejection reason
    pub rejection_breakdown: RejectionBreakdown,
}

/// Breakdown of rejections
#[derive(Debug, Clone, Default)]
pub struct RejectionBreakdown {
    pub tier_not_allowed: usize,
    pub size_exceeded: usize,
    pub policy_violation: usize,
    pub dependency_rejected: usize,
    pub decode_error: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_template() -> BlockTemplate {
        BlockTemplate {
            version: 0x20000000,
            previousblockhash: "0".repeat(64),
            transactions: vec![],
            coinbaseaux: Default::default(),
            coinbasevalue: 312500000,
            bits: "1d00ffff".to_string(),
            height: 100,
            curtime: 1234567890,
            mintime: 1234567800,
            mutable: vec!["time".to_string()],
            noncerange: "00000000ffffffff".to_string(),
            sigoplimit: 80000,
            sizelimit: 4000000,
            weightlimit: 4000000,
            longpollid: None,
            target: "0".repeat(64),
        }
    }

    #[test]
    fn test_filter_empty_template() {
        let mut filter = TemplateFilter::permissive();
        let template = create_test_template();
        let filtered = filter.filter(template);

        assert_eq!(filtered.included_indices.len(), 0);
        assert_eq!(filtered.rejected_indices.len(), 0);
    }

    #[test]
    fn test_policy_profiles() {
        let bitcoin_pure = TemplateFilter::bitcoin_pure();
        assert_eq!(bitcoin_pure.profile().name, "strict");

        let permissive = TemplateFilter::permissive();
        assert_eq!(permissive.profile().name, "permissive");

        let full_open = TemplateFilter::full_open();
        assert_eq!(full_open.profile().name, "full_open");
    }
}
