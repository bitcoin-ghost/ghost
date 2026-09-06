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
//| FILE: mailbox.rs                                                                                                    |
//|======================================================================================================================|

//! The mailbox — delivering to a recipient whose phone is asleep.
//!
//! An instant payment hands the recipient a signed transaction. If they are
//! offline it has to wait somewhere, and the coordinator is the obvious place.
//!
//! # The obvious design is a social graph
//!
//! Store each entry under `recipient_ghost_id` and retrieval becomes trivial —
//! and the coordinator now holds a list of who receives from whom. Combined with
//! what it already knows (who deposited), that is the payment graph the blind
//! signature exists to prevent. The mailbox would hand back at rest what the
//! round protects in flight.
//!
//! So entries are addressed by a **short tag** derived from the recipient's key.
//! A fetch returns everyone sharing that tag; the recipient decrypts what is
//! theirs and cannot read the rest. This is the same shape as BIP-352 scanning:
//! spend bandwidth to avoid telling anyone which entry you wanted.
//!
//! # The tag length *is* the recipient's anonymity set
//!
//! It is the whole security parameter, and it is a straight trade:
//!
//! ```text
//!   tag bits    bucket occupancy at 1M users    bandwidth per fetch
//!        8              ~3900                        high
//!       12               ~244
//!       16                ~15
//!       24                  ~0.06   ← a social graph with extra steps
//! ```
//!
//! [`recipient_anonymity_set`] computes it, and [`MailboxPolicy::validate`]
//! refuses a configuration that would deanonymise recipients rather than
//! documenting the risk and shipping it.

use std::collections::HashMap;

use bitcoin::hashes::{sha256, Hash};

/// Domain tag, versioned so a future change is a distinct derivation.
pub const MAILBOX_TAG: &str = "wraith/mailbox/v1";

/// Why a mailbox operation was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MailboxError {
    /// The tag is precise enough to identify recipients.
    #[error("{bits}-bit tags give a bucket of ~{occupancy} at {population} users; recipients need at least {floor}")]
    TagTooPrecise {
        /// Configured tag width.
        bits: u8,
        /// Expected recipients sharing a tag.
        occupancy: u64,
        /// Population assumed.
        population: u64,
        /// Minimum acceptable set.
        floor: u64,
    },
}

/// Address an entry by the recipient's scan key.
///
/// Truncated deliberately. `bits` above ~20 starts identifying people.
pub fn bucket_tag(recipient_scan_key: &[u8; 32], bits: u8) -> u32 {
    let mut buf = Vec::with_capacity(MAILBOX_TAG.len() + 32);
    buf.extend_from_slice(MAILBOX_TAG.as_bytes());
    buf.extend_from_slice(recipient_scan_key);
    let h = sha256::Hash::hash(&buf);
    let raw = u32::from_be_bytes([h[0], h[1], h[2], h[3]]);
    if bits >= 32 {
        raw
    } else {
        raw >> (32 - bits)
    }
}

/// How many recipients are expected to share a tag.
///
/// This is the recipient's anonymity set against the coordinator, and the only
/// thing the tag width buys.
pub fn recipient_anonymity_set(population: u64, bits: u8) -> f64 {
    let buckets = 2f64.powi(i32::from(bits.min(32)));
    population as f64 / buckets
}

/// Mailbox configuration.
#[derive(Debug, Clone, Copy)]
pub struct MailboxPolicy {
    /// Tag width in bits.
    pub tag_bits: u8,
    /// Population the deployment expects.
    pub expected_population: u64,
    /// Smallest acceptable recipient anonymity set.
    pub min_anonymity_set: u64,
    /// How long an undelivered entry is kept, in seconds.
    pub retention_secs: u64,
}

impl MailboxPolicy {
    /// Refuse a configuration that would deanonymise recipients.
    ///
    /// Called at startup, not per request: a mailbox that identifies its users
    /// should never accept a single entry.
    pub fn validate(&self) -> Result<(), MailboxError> {
        let set = recipient_anonymity_set(self.expected_population, self.tag_bits);
        if (set as u64) < self.min_anonymity_set {
            return Err(MailboxError::TagTooPrecise {
                bits: self.tag_bits,
                occupancy: set as u64,
                population: self.expected_population,
                floor: self.min_anonymity_set,
            });
        }
        Ok(())
    }
}

/// One waiting delivery. The coordinator cannot read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Truncated recipient tag.
    pub tag: u32,
    /// Sealed payload — a signed transaction and its attestation.
    pub ciphertext: Vec<u8>,
    /// Unix seconds after which it is dropped.
    pub expires_at: u64,
}

/// Holds undelivered entries.
#[derive(Debug, Default)]
pub struct Mailbox {
    by_tag: HashMap<u32, Vec<Entry>>,
}

impl Mailbox {
    /// Empty mailbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a delivery.
    pub fn put(&mut self, entry: Entry) {
        self.by_tag.entry(entry.tag).or_default().push(entry);
    }

    /// Everything sharing a tag.
    ///
    /// Returns other recipients' entries too, by design — the caller decrypts
    /// what is theirs and learns nothing from the rest. A fetch that returned
    /// only your own entries would tell the coordinator which were yours.
    pub fn fetch(&self, tag: u32) -> &[Entry] {
        self.by_tag.get(&tag).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Drop everything past its retention.
    pub fn evict_expired(&mut self, now_secs: u64) -> usize {
        let mut dropped = 0;
        self.by_tag.retain(|_, entries| {
            let before = entries.len();
            entries.retain(|e| e.expires_at > now_secs);
            dropped += before - entries.len();
            !entries.is_empty()
        });
        dropped
    }

    /// Total entries held.
    pub fn len(&self) -> usize {
        self.by_tag.values().map(|v| v.len()).sum()
    }

    /// Whether anything is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn entry(tag: u32, expires_at: u64) -> Entry {
        Entry {
            tag,
            ciphertext: vec![1, 2, 3],
            expires_at,
        }
    }

    #[test]
    fn a_tag_is_deterministic_and_domain_separated() {
        assert_eq!(bucket_tag(&key(1), 12), bucket_tag(&key(1), 12));
        assert_ne!(bucket_tag(&key(1), 12), bucket_tag(&key(2), 12));
    }

    #[test]
    fn fewer_bits_means_a_larger_crowd() {
        let pop = 1_000_000;
        let wide = recipient_anonymity_set(pop, 8);
        let narrow = recipient_anonymity_set(pop, 16);
        assert!(wide > narrow);
        assert!(
            wide > 3_000.0,
            "8-bit tags should hide a recipient well: {wide}"
        );
        assert!(narrow < 20.0, "16-bit tags barely hide anyone: {narrow}");
    }

    #[test]
    fn a_precise_tag_is_refused_rather_than_documented() {
        // 24 bits over a million users is under one recipient per bucket — a
        // social graph with extra steps.
        let p = MailboxPolicy {
            tag_bits: 24,
            expected_population: 1_000_000,
            min_anonymity_set: 100,
            retention_secs: 86_400,
        };
        assert!(matches!(
            p.validate(),
            Err(MailboxError::TagTooPrecise { .. })
        ));
    }

    #[test]
    fn a_sane_configuration_validates() {
        let p = MailboxPolicy {
            tag_bits: 12,
            expected_population: 1_000_000,
            min_anonymity_set: 100,
            retention_secs: 86_400,
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn a_small_deployment_needs_a_shorter_tag() {
        // The parameter is population-relative. A configuration that is safe at
        // a million users deanonymises everyone at a thousand, which is exactly
        // the state a new deployment launches in.
        let launch = MailboxPolicy {
            tag_bits: 12,
            expected_population: 1_000,
            min_anonymity_set: 100,
            retention_secs: 86_400,
        };
        assert!(
            launch.validate().is_err(),
            "12-bit tags at 1k users give a quarter of a recipient per bucket"
        );
    }

    #[test]
    fn a_fetch_returns_the_whole_bucket() {
        // Returning only the caller's entries would tell the coordinator which
        // were theirs — the leak this design exists to avoid.
        let mut m = Mailbox::new();
        m.put(entry(7, 100));
        m.put(entry(7, 100));
        m.put(entry(9, 100));
        assert_eq!(m.fetch(7).len(), 2, "both entries in the bucket, not one");
        assert_eq!(m.fetch(9).len(), 1);
        assert!(m.fetch(11).is_empty());
    }

    #[test]
    fn expired_entries_are_dropped() {
        let mut m = Mailbox::new();
        m.put(entry(7, 50));
        m.put(entry(7, 500));
        assert_eq!(m.evict_expired(100), 1);
        assert_eq!(m.len(), 1);
        assert_eq!(m.evict_expired(1_000), 1);
        assert!(m.is_empty());
    }

    #[test]
    fn an_emptied_bucket_leaves_no_trace() {
        // A lingering empty bucket would record that someone with that tag once
        // had mail.
        let mut m = Mailbox::new();
        m.put(entry(7, 50));
        m.evict_expired(100);
        assert!(m.fetch(7).is_empty());
        assert!(m.is_empty());
    }
}
