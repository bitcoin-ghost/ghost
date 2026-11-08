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
//| FILE: lib.rs                                                                                                         |
//|======================================================================================================================|

//! Ghost Pool Library
//!
//! The ghost-mining node: block templates for the co-located pool_sv2, the mesh health and
//! discovery plumbing, round statistics and the operator API. What a block pays is the solo
//! rule (`ghost_common::solo`, built per job by pool_sv2: the treasury `subsidy / 200`, the
//! finding miner the rest); nothing here decides it.
//!
//! # Modules
//!
//! - [`reorg`] - Chain reorganization detection and handling
//! - [`round`] - Mining round statistics
//! - [`template`] - Block template processing with BUDS filtering
//! - [`template_provider`] - Template Distribution Protocol (TDP) server

/// Periodic operator-alert monitors (behind-tip, update-available, mempool, fees, low disk).
pub mod alert_monitors;

/// `tracing` layer that feeds ghost-mining's log tail into the dashboard `/logs`
/// ring buffer.
pub mod log_ring;

/// Chain reorganization detection.
pub mod reorg;

/// Mining round statistics.
pub mod round;

/// Weight, sigop and coinbase-size limits for the blocks this node builds.
pub mod block_limits;

/// Node pool payee-script classes for miner payout addresses.
pub mod payee_class;

/// Block template processing with policy filtering.
pub mod template;

/// Template Distribution Protocol (TDP) for SRI integration.
pub mod template_provider;

/// Hardware-derived miner capacity.
pub mod capacity;

/// Reaper observability counters.
pub mod reaper_stats;

/// Is one of our own addresses in the mining DNS answer? (B4)
///
/// `--status` used to report `in_dns` from the central registry's claim about us. That service is being
/// deleted, and the fact does not need a central service: a node can resolve the mining name and look
/// for itself in the answer. A direct observation rather than someone's assertion about it.
///
/// This is the check that would have surfaced #596 — vm5-8 were absent from `pool.bitcoinghost.org` for
/// weeks while every node reported itself healthy, because nothing compared the two.
///
/// `resolved` is the A-record set for the mining name; `local` is this node's own addresses. Both are
/// passed in so the decision is testable without DNS or network.
pub fn is_in_mining_dns(resolved: &[std::net::IpAddr], local: &[std::net::IpAddr]) -> InDns {
    if resolved.is_empty() {
        // Nothing resolved: the name is down, or we cannot see it. That is NOT "we are absent" — saying
        // so would turn a resolver problem into a false alarm about this node.
        return InDns::Unknown;
    }
    if local.is_empty() {
        return InDns::Unknown;
    }
    if local.iter().any(|l| resolved.contains(l)) {
        InDns::Yes
    } else {
        InDns::No
    }
}

/// Three-valued because "we could not tell" must not be reported as "we are not in DNS".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InDns {
    Yes,
    No,
    /// The name did not resolve, or we could not enumerate our own addresses.
    Unknown,
}

#[cfg(test)]
mod in_dns_tests {
    use super::{is_in_mining_dns, InDns};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The #596 case: this node is NOT in the mining DNS answer, and must say so.
    ///
    /// vm5-8 sat absent from `pool.bitcoinghost.org` for weeks while reporting themselves healthy,
    /// because nothing compared the node's own address against the name it is supposed to be behind.
    #[test]
    fn a_node_absent_from_the_dns_answer_is_reported_absent() {
        let resolved = vec![ip("83.136.251.162"), ip("85.9.198.212")];
        let local = vec![ip("94.237.102.192")]; // vm5, not in the answer
        assert_eq!(is_in_mining_dns(&resolved, &local), InDns::No);
    }

    #[test]
    fn a_node_present_in_the_dns_answer_is_reported_present() {
        let resolved = vec![ip("83.136.251.162"), ip("94.237.102.192")];
        let local = vec![ip("94.237.102.192")];
        assert_eq!(is_in_mining_dns(&resolved, &local), InDns::Yes);
    }

    /// THE failure mode worth guarding: an empty resolve is "we could not tell", NOT "we are absent".
    ///
    /// If the name is down, or the resolver is unreachable, reporting `No` turns an infrastructure
    /// problem into a false alarm pointed at this node — and an operator chasing the wrong thing is
    /// worse than one told plainly that the check did not run.
    #[test]
    fn an_unresolvable_name_is_unknown_not_absent() {
        let local = vec![ip("94.237.102.192")];
        assert_eq!(is_in_mining_dns(&[], &local), InDns::Unknown);
    }

    /// Same in the other direction: if we cannot enumerate our own addresses we know nothing.
    #[test]
    fn no_local_addresses_is_unknown_not_absent() {
        let resolved = vec![ip("83.136.251.162")];
        assert_eq!(is_in_mining_dns(&resolved, &[]), InDns::Unknown);
    }

    /// A node with several addresses counts as present if ANY of them is in the answer — the fleet is
    /// dual-stacked and a node behind one of its addresses is still receiving miners.
    #[test]
    fn any_matching_local_address_counts_as_present() {
        let resolved = vec![ip("83.136.251.162"), ip("2001:db8::1")];
        let local = vec![ip("10.0.0.5"), ip("2001:db8::1")];
        assert_eq!(is_in_mining_dns(&resolved, &local), InDns::Yes);
    }
}
