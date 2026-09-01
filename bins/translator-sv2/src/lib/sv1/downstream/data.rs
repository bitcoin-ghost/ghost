use std::time::Instant;
use stratum_apps::{
    stratum_core::{
        bitcoin::Target,
        sv1_api::{
            json_rpc,
            utils::{Extranonce, HexU32Be},
        },
    },
    utils::types::{ChannelId, DownstreamId, Hashrate},
};
use tracing::debug;

use super::SubmitShareWithChannelId;

#[derive(Debug)]
pub struct DownstreamData {
    pub channel_id: Option<ChannelId>,
    pub extranonce1: Extranonce<'static>,
    pub extranonce2_len: usize,
    pub target: Target,
    pub hashrate: Option<Hashrate>,
    /// Hashrate declared by the miner itself, via `mining.suggest_difficulty` or a `d=` in the
    /// `mining.authorize` password, converted from the difficulty it asked for. `None` when the
    /// miner said nothing, in which case the configured `min_individual_miner_hashrate` stands.
    ///
    /// This exists because vardiff alone cannot size a large miner quickly: it starts every
    /// connection at the configured floor (bitaxe-sized here) and caps any correction above
    /// 1000% to ×3–×5 per 60s tick, so a farm or a rented-hashrate order spends minutes
    /// flooding shares before converging. A declared size skips the ramp entirely.
    pub suggested_hashrate: Option<Hashrate>,
    /// True when this connection arrived on the farm/rental listener rather than the hobby
    /// one. Only used to decide whether an oversized miner should be nudged to move: a large
    /// miner on the hobby port is not stealing anything (payout is proportional to work, and
    /// a share's work IS its difficulty), it just costs this node far more share validation,
    /// bandwidth and database writes than it needs to.
    pub on_farm_tier: bool,
    pub version_rolling_mask: Option<HexU32Be>,
    pub version_rolling_min_bit: Option<HexU32Be>,
    pub last_job_version_field: Option<u32>,
    pub authorized_worker_name: String,
    pub user_identity: String,
    pub cached_set_difficulty: Option<json_rpc::Message>,
    pub cached_notify: Option<json_rpc::Message>,
    pub pending_target: Option<Target>,
    /// The target this downstream was working against BEFORE the most recent change, and when
    /// the change happened.
    ///
    /// `target` is swapped the instant `mining.set_difficulty` is SENT. The miner's already
    /// computed shares were made against the old, easier target and keep arriving for as long
    /// as the network round trip and its own pipeline take — and every one of them then fails
    /// `hash_as_target < target` and is thrown away. That is real work the miner performed and
    /// the pool declined because the goalposts moved mid-flight.
    ///
    /// Measured under a 1 PH/s farm-tier test: on the two busiest nodes ~20% of all submitted
    /// shares, tracking target-change frequency almost exactly (#811).
    ///
    /// Accepting against EITHER target for a short window is standard stratum practice.
    pub previous_target: Option<Target>,
    pub previous_target_since: Option<std::time::Instant>,
    pub pending_hashrate: Option<Hashrate>,
    // Queue of Sv1 handshake messages received while waiting for SV2 channel to open
    pub queued_sv1_handshake_messages: Vec<json_rpc::Message>,
    // Whether an OpenExtendedMiningChannel has already been SENT for this downstream.
    //
    // `channel_id` is only populated when OpenExtendedMiningChannelSuccess comes back, so it
    // cannot guard the request itself: with the channel opening on `mining.subscribe`, a
    // pipelining miner's `mining.authorize` arrives while the open is still in flight and
    // `channel_id` is still None, which would burn a second upstream channel for one miner.
    // This is set the moment the request goes out and is the real guard.
    pub channel_open_requested: bool,
    // Whether THIS channel was opened before `mining.authorize`, under the provisional
    // identity — which decides what the per-share TLV must carry.
    //
    // It is a property of the connection, NOT of the config. With the subscribe-open
    // debounced, a pipelining miner still opens on authorize with its own
    // `<address>.<worker>` as the channel identity, while a serialising one opens early under
    // the sentinel. Keying the TLV on the config flag instead credited a pipelining miner as
    // `<addr>.<addr>.<worker>`, because the pool spliced a full identity onto a channel that
    // already carried the address.
    pub channel_opened_provisionally: bool,
    // Whether the client opted in to `subscribe-extranonce` via `mining.configure`.
    //
    // `mining.set_extranonce` is opt-in. Sending it to a client that never asked is a
    // protocol violation; Braiins' hashrate proxy closes the connection on receipt
    // (observed 2026-08-28: valid job delivered, then a clean FIN ~13 ms later, 12,929
    // reconnects in 24 h on one node). Miners that send no `mining.configure` at all
    // leave this false.
    pub extranonce_subscribe_negotiated: bool,
    // Set when a miner-declared difficulty (`d=` in the authorize password, or
    // `mining.suggest_difficulty`) arrives AFTER the channel is already open, so the
    // channel-open path can no longer size itself from it.
    //
    // Without an explicit push it would sit until the next vardiff tick — the loop runs on a
    // 60s interval and `try_vardiff` returns None for a miner that has not submitted yet, so
    // "next tick" can be far longer than 60s. Measured on vm4 (320ms RTT): the miner was told
    // the 2,048 floor and never the 1,000,000 it asked for. On a fast link authorize wins the
    // race against channel open and the first `set_difficulty` already carries the declared
    // value, which is why this is invisible except to distant miners.
    pub declared_difficulty_needs_push: bool,
    // Stores pending shares to be sent to the sv1_server
    pub pending_share: Option<SubmitShareWithChannelId>,
    // Tracks the upstream target for this downstream, used for vardiff target comparison
    pub upstream_target: Option<Target>,
    // Timestamp of when the last job was received by this downstream, used for keepalive check
    pub last_job_received_time: Option<Instant>,
}

impl DownstreamData {
    /// `extranonce2_len` is the configured `downstream_extranonce2_size`. It is only the
    /// PLACEHOLDER value, used for the `mining.subscribe` response when a serializing miner
    /// (or a pool-capability probe) forces the 1.5s subscribe-defer fallback before the SV2
    /// channel has opened. It must match the configured size because that placeholder is what
    /// such clients read to decide whether the pool is compatible — Braiins' hashrate
    /// marketplace, for one, rejects any pool advertising `extranonce2_size < 7` and never
    /// sends `mining.authorize`, so it only ever sees this value. Once the channel opens, the
    /// real channel-allocated size from `OpenExtendedMiningChannelSuccess` overwrites it.
    ///
    /// NB: the `extranonce1` placeholder stays 8 zero bytes — `sv1_server` identifies the
    /// placeholder by exactly that (`len() == 8` and all-zero) to decide whether to send the
    /// corrective `mining.set_extranonce`. Changing it would strand serializing miners on the
    /// placeholder extranonce and reject every share they submit.
    pub fn new(hashrate: Option<Hashrate>, target: Target, extranonce2_len: usize) -> Self {
        DownstreamData {
            channel_id: None,
            extranonce1: vec![0; 8]
                .try_into()
                .expect("8-byte extranonce is always valid"),
            extranonce2_len,
            target,
            hashrate,
            suggested_hashrate: None,
            on_farm_tier: false,
            version_rolling_mask: None,
            version_rolling_min_bit: None,
            last_job_version_field: None,
            authorized_worker_name: String::new(),
            user_identity: String::new(),
            cached_set_difficulty: None,
            cached_notify: None,
            pending_target: None,
            previous_target: None,
            previous_target_since: None,
            pending_hashrate: None,
            queued_sv1_handshake_messages: Vec::new(),
            extranonce_subscribe_negotiated: false,
            declared_difficulty_needs_push: false,
            channel_open_requested: false,
            channel_opened_provisionally: false,
            pending_share: None,
            upstream_target: None,
            last_job_received_time: None,
        }
    }

    pub fn set_pending_target(&mut self, new_target: Target, downstream_id: DownstreamId) {
        self.pending_target = Some(new_target);
        debug!("Downstream {downstream_id}: Set pending target");
    }

    /// Adopt a staged target, remembering the one it replaces.
    ///
    /// One place, so the two call sites that swap the target cannot disagree about whether the
    /// previous one is retained — they already drifted once on whether to adopt at all.
    pub fn adopt_pending_target(&mut self) {
        if let Some(new_target) = self.pending_target.take() {
            // Only remember a target the miner actually worked against. Repeated adoptions
            // inside one grace window must not overwrite it with an equally new value, or the
            // window silently shrinks to nothing under exactly the churn it exists for.
            if self.target != new_target {
                self.previous_target = Some(self.target);
                self.previous_target_since = Some(std::time::Instant::now());
            }
            self.target = new_target;
        }
    }

    /// The superseded target, if it is still within the grace window.
    ///
    /// `None` once the window has passed, so a stale target cannot be used to accept a share
    /// indefinitely — that would quietly hand every miner a permanent difficulty discount.
    pub fn target_within_grace(&self, grace: std::time::Duration) -> Option<Target> {
        match (self.previous_target, self.previous_target_since) {
            (Some(t), Some(since)) if since.elapsed() <= grace => Some(t),
            _ => None,
        }
    }

    pub fn set_pending_hashrate(
        &mut self,
        new_hashrate: Option<Hashrate>,
        downstream_id: DownstreamId,
    ) {
        self.pending_hashrate = new_hashrate;
        debug!("Downstream {downstream_id}: Set pending hashrate");
    }

    pub fn set_upstream_target(&mut self, upstream_target: Target, downstream_id: DownstreamId) {
        self.upstream_target = Some(upstream_target);
        debug!(
            "Downstream {downstream_id}: Set upstream target to {}",
            upstream_target
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stratum ordering rule this fix depends on: a miner must never see
    /// `set_difficulty` before its first `mining.notify`.
    ///
    /// #455 sends `set_difficulty` straight to the wire once the miner has a job, and keeps
    /// the old caching behaviour before that. The whole guard is
    /// `last_job_received_time.is_some()`, so a fresh downstream MUST start as `None` — if it
    /// ever defaulted to `Some`, the very first difficulty for a brand-new miner would be sent
    /// ahead of its first job, which is the ordering violation the cache exists to prevent.
    #[test]
    fn a_fresh_downstream_has_no_job_so_difficulty_is_still_cached() {
        let d = DownstreamData::new(None, Target::from_le_bytes([0xff; 32]), 8);
        assert!(
            d.last_job_received_time.is_none(),
            "a downstream with no job must cache set_difficulty, not send it"
        );
        assert!(
            d.cached_set_difficulty.is_none(),
            "nothing should be cached before anything is received"
        );
    }
}

#[cfg(test)]
mod superseded_target_tests {
    use super::*;
    use std::time::Duration;

    // #811: `target` is swapped the instant mining.set_difficulty is SENT, so shares already
    // computed against the previous, easier target keep arriving and were all discarded — ~20%
    // of submitted work on the busiest nodes under a 1 PH/s farm-tier test.

    fn data_with(target: Target) -> DownstreamData {
        DownstreamData::new(None, target, 8)
    }

    fn target_from(byte: u8) -> Target {
        // Larger array value = easier target. Two clearly different values are all these tests
        // need; the ordering semantics are validate_sv1_share's business, not this type's.
        let mut b = [0u8; 32];
        b[0] = byte;
        Target::from_le_bytes(b)
    }

    #[test]
    fn adopting_a_target_remembers_the_one_it_replaces() {
        let old = target_from(1);
        let new = target_from(2);
        let mut d = data_with(old);
        d.pending_target = Some(new);
        d.adopt_pending_target();

        assert_eq!(d.target, new, "the new target must be live");
        assert_eq!(
            d.target_within_grace(Duration::from_secs(10)),
            Some(old),
            "the superseded target must still be reachable"
        );
    }

    #[test]
    fn the_superseded_target_expires() {
        // Without expiry this is a permanent difficulty discount for every miner, which is
        // strictly worse than the bug it fixes.
        let mut d = data_with(target_from(1));
        d.pending_target = Some(target_from(2));
        d.adopt_pending_target();

        assert!(d.target_within_grace(Duration::from_secs(10)).is_some());
        // Anything genuinely older than the window is gone.
        d.previous_target_since = Some(std::time::Instant::now() - Duration::from_secs(60));
        assert!(
            d.target_within_grace(Duration::from_secs(10)).is_none(),
            "a target superseded a minute ago must NOT still accept shares"
        );
    }

    #[test]
    fn repeated_adoptions_do_not_shrink_the_window_to_nothing() {
        // The failure this guards: under churn, adopting again immediately would overwrite
        // `previous_target` with an equally-new value and the grace window would cover a target
        // no miner ever worked against — silently reintroducing the bug under exactly the
        // conditions that caused it.
        let first = target_from(1);
        let second = target_from(2);
        let mut d = data_with(first);

        d.pending_target = Some(second);
        d.adopt_pending_target();
        assert_eq!(d.target_within_grace(Duration::from_secs(10)), Some(first));

        // Adopt the SAME target again — nothing actually changed for the miner.
        d.pending_target = Some(second);
        d.adopt_pending_target();
        assert_eq!(
            d.target_within_grace(Duration::from_secs(10)),
            Some(first),
            "re-adopting the same target must not discard the real previous one"
        );
    }

    #[test]
    fn with_no_change_there_is_no_superseded_target() {
        // The accept-side control: a downstream that has never had a difficulty change must not
        // get a second target to validate against.
        let d = data_with(target_from(1));
        assert!(d.target_within_grace(Duration::from_secs(10)).is_none());
    }

    #[test]
    fn a_harder_target_is_the_numerically_smaller_one() {
        // The late-accept guard picks the harder of (previous downstream, upstream) with `min`,
        // and the difficulty manager gates set_difficulty on `new_target >= upstream_target`.
        // Both rest on Target ordering being numeric, smaller = harder. If that ever inverts,
        // the guard silently starts accepting shares the pool will refuse.
        let easier = target_from(2);
        let harder = target_from(1);
        assert!(
            harder < easier,
            "smaller target value must compare as harder"
        );
        assert_eq!(
            easier.min(harder),
            harder,
            "min must select the harder target"
        );
    }

    #[test]
    fn adopting_with_nothing_pending_changes_nothing() {
        let t = target_from(1);
        let mut d = data_with(t);
        d.adopt_pending_target();
        assert_eq!(d.target, t);
        assert!(d.target_within_grace(Duration::from_secs(10)).is_none());
    }
}
