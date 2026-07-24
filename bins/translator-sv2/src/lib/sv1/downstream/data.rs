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
    pub version_rolling_mask: Option<HexU32Be>,
    pub version_rolling_min_bit: Option<HexU32Be>,
    pub last_job_version_field: Option<u32>,
    pub authorized_worker_name: String,
    pub user_identity: String,
    pub cached_set_difficulty: Option<json_rpc::Message>,
    pub cached_notify: Option<json_rpc::Message>,
    pub pending_target: Option<Target>,
    pub pending_hashrate: Option<Hashrate>,
    // Queue of Sv1 handshake messages received while waiting for SV2 channel to open
    pub queued_sv1_handshake_messages: Vec<json_rpc::Message>,
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
            version_rolling_mask: None,
            version_rolling_min_bit: None,
            last_job_version_field: None,
            authorized_worker_name: String::new(),
            user_identity: String::new(),
            cached_set_difficulty: None,
            cached_notify: None,
            pending_target: None,
            pending_hashrate: None,
            queued_sv1_handshake_messages: Vec::new(),
            pending_share: None,
            upstream_target: None,
            last_job_received_time: None,
        }
    }

    pub fn set_pending_target(&mut self, new_target: Target, downstream_id: DownstreamId) {
        self.pending_target = Some(new_target);
        debug!("Downstream {downstream_id}: Set pending target");
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
