//! pool_sv2's half of the node pool job layer (W2.3): share tags, slot classes and sensing.
//!
//! Dark by default: nothing here runs unless the `[node_pool]` config section is present, and
//! even then only for templates whose BIP34 height reaches the activation height, which defaults
//! to `NODE_POOL_ACTIVATION_HEIGHT` (`u64::MAX`). Below it every path is the existing one.
//!
//! ## What it does when active
//!
//! Every channel mines its own job, built by the channel's own factory exactly as
//! SHARE_TIER_BIND does (`tier_binding.rs`), but the template's `GHPP` and `GHNT` pushes are
//! both replaced: `GHPP` carries `parent_anchor[..16]` and `GHNT` the `GhostShare/v2` tag
//!
//! ```text
//! sha256("GhostShare/v2" || node_id || tier || slot_class || sha256(payee) || parent_anchor
//!        || batch_root)[..20]
//! ```
//!
//! from `ghost_common::share_commit`. Same 46 encoded bytes out of the template prefix and back
//! in through the factory's budget-guarded extra push, so the scriptSig length does not move.
//!
//! - **Anchors.** `parent_anchor` and `batch_root` come from an [`AnchorDriver`], a watch
//!   channel the relay layer (W2.5) will publish to. Every publish re-stamps every channel and
//!   pushes a fresh job against the active template. Until the first publish both are zero.
//! - **Standard channels** always carry the full class (500 outputs): the miner receives only a
//!   header, so the coinbase size never reaches its firmware (spec 2.1).
//! - **Extended channels** carry the class their miner's [`ClassSensor`] serves.
//!
//! ## Where the sensing loop lives, and why here
//!
//! In pool_sv2, not the translator. The pool builds the coinbase, so it is the only place that
//! can enforce the ceiling on the bytes it emits; it validates every share against the exact
//! coinbase it built, which is the "does it recompute" signal; it knows which class every job id
//! was built at, which the stale-work signal needs; and a class change is a job rebuild, which
//! only the pool can do without a round trip. Native SV2 extended miners never pass through the
//! translator at all. The one thing the pool cannot see is the SV1 user agent, so the translator
//! sends it once, at channel open, in a Ghost TLV (`AGENT_TLV_EXTENSION_TYPE`).
//!
//! Sessions are keyed by the channel's user identity and live in memory for the process
//! lifetime: a reconnecting miner keeps its failed classes, and a settled miner its class; a
//! drop fails a class only while it is being tested. A native SV2 miner with no agent TLV is
//! looked up by its `SetupConnection` vendor, hardware_version and firmware. Nothing persists; W2.4 owns storage
//! through `ghost_common::slot_class_sensing::SensingStore`.
//!
//! ## Not here yet
//!
//! - The coinbase OUTPUTS are still the template's; building the canonical outputs for a class
//!   is W2.6. Until then the class is committed in the tag only.
//! - The zero-value 31-byte output added to each channel's FIRST job on the open paths
//!   (`payout_mode.coinbase_outputs` with `coinbase_tx_value_remaining == 0`,
//!   `mining_message_handler.rs` standard and extended open) is left alone; W2.6 removes it.
//! - Relaying shares and anchors is W2.5; [`NodePool::job_preimage`] is its lookup.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::Instant,
};

use ghost_common::{
    coinbase_tags::{encode_node_tag, encode_payout_tag, PAYOUT_ID_LEN, PAYOUT_TAG_MAGIC},
    node_pool_constants::{NODE_POOL_ACTIVATION_HEIGHT, SLOT_CLASSES},
    sanitize_for_log,
    share_commit::{payee_script_class, ShareTagPreimage},
    slot_class_sensing::{
        clamp_agent, ClassChange, ClassSensor, MinerIdentity, SensingParams, SensingStatus,
        ShareVerdict, Sv2Device, AGENT_TLV_EXTENSION_TYPE, AGENT_TLV_FIELD_TYPE, FULL_CLASS_INDEX,
    },
};
use stratum_apps::{
    stratum_core::{bitcoin::Target, parsers_sv2::Tlv, template_distribution_sv2::NewTemplate},
    utils::types::{ChannelId, DownstreamId},
};
use tokio::sync::watch;
use tracing::{error, info, warn};

use crate::{
    tier_binding::{bip34_height, strip_plain_node_tag, tag_len_at, TierBinding},
    utils::PayoutMode,
};

/// One channel on one downstream connection.
pub type ChannelKey = (DownstreamId, ChannelId);

/// What the relay layer publishes: the anchor new jobs build on and the batch they would lock in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorUpdate {
    /// The anchor jobs are built on.
    pub parent_anchor: [u8; 32],
    /// Root of the batch a job would lock in if it became an anchor.
    pub batch_root: [u8; 32],
}

/// The handle the relay layer (W2.5) publishes anchor updates through; also the test driver.
/// Publishing re-stamps every channel and pushes fresh jobs.
#[derive(Clone)]
pub struct AnchorDriver {
    tx: Arc<watch::Sender<Option<AnchorUpdate>>>,
}

impl AnchorDriver {
    /// Publish a new anchor (or batch root). Never blocks, never fails.
    pub fn publish(&self, update: AnchorUpdate) {
        self.tx.send_replace(Some(update));
    }

    /// The last published update.
    pub fn current(&self) -> Option<AnchorUpdate> {
        *self.tx.borrow()
    }
}

/// Which kind of SV2 channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    /// Header-only work: always the full class.
    Standard,
    /// The miner builds the coinbase from prefix and suffix: sensed.
    Extended,
}

/// Status of one channel, for logs and the status API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStatus {
    /// The channel.
    pub key: ChannelKey,
    /// Its kind.
    pub kind: ChannelKind,
    /// Miner outputs its jobs carry.
    pub slot_class: u16,
    /// Sensing state, for extended channels.
    pub sensing: Option<SensingStatus>,
}

/// Jobs remembered per channel for class lookup and the relay.
const JOBS_KEPT: usize = 64;
/// Future templates remembered until their `SetNewPrevHash`.
const FUTURE_TEMPLATES_KEPT: usize = 4;
/// Sensing sessions kept; disconnected ones are evicted beyond this.
const SESSIONS_KEPT: usize = 4_096;

struct ChannelSlot {
    kind: ChannelKind,
    payee_script: Vec<u8>,
    session: Option<String>,
    last_stamp: Option<ShareTagPreimage>,
    jobs: VecDeque<(u32, ShareTagPreimage)>,
}

#[derive(Default)]
struct State {
    channels: HashMap<ChannelKey, ChannelSlot>,
    agents: HashMap<ChannelKey, MinerIdentity>,
    sessions: HashMap<String, ClassSensor>,
    future_templates: VecDeque<NewTemplate<'static>>,
    active_template: Option<NewTemplate<'static>>,
}

/// The node pool job layer's state.
pub struct NodePool {
    tiers: TierBinding,
    params: SensingParams,
    anchor: Arc<watch::Sender<Option<AnchorUpdate>>>,
    epoch: Instant,
    state: Mutex<State>,
    relay_sink: Mutex<Option<RelaySink>>,
}

/// Where accepted shares go when `[node_pool.relay]` runs: the relay's local queue, and the tier
/// base that decides which hashes could be network shares at all.
struct RelaySink {
    tx: tokio::sync::mpsc::Sender<ghost_np_relay::wire::NetShare>,
    tier_base: ghost_common::node_pool_u256::U256,
}

impl NodePool {
    /// Build from an already-resolved identity.
    pub fn from_parts(
        node_id: [u8; 32],
        activation_height: u64,
        shares_per_minute: f32,
        min_shares: u32,
    ) -> Self {
        Self {
            tiers: TierBinding::from_parts(node_id, activation_height),
            params: SensingParams::for_shares_per_minute(shares_per_minute, min_shares),
            anchor: Arc::new(watch::channel(None).0),
            epoch: Instant::now(),
            state: Mutex::new(State::default()),
            relay_sink: Mutex::new(None),
        }
    }

    /// Resolve from config. The identity is read exactly as `[share_tier_binding]` reads it.
    pub async fn resolve(
        cfg: &crate::config::NodePoolConfig,
        shares_per_minute: f32,
    ) -> Result<Self, String> {
        let activation_height = cfg.activation_height.unwrap_or(NODE_POOL_ACTIVATION_HEIGHT);
        let identity = crate::config::ShareTierBindingConfig {
            node_id: cfg.node_id.clone(),
            ghost_pool_health_url: cfg.ghost_pool_health_url.clone(),
            activation_height,
        };
        let tb = TierBinding::resolve(&identity).await?;
        let min_shares = cfg
            .sensing_min_shares
            .unwrap_or(SensingParams::default().min_shares);
        Ok(Self::from_parts(
            *tb.node_id(),
            activation_height,
            shares_per_minute,
            min_shares,
        ))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A poisoned lock still holds consistent maps: every mutation here is a single insert,
        // remove or field write.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// The template height at/above which the job layer runs.
    pub fn activation_height(&self) -> u64 {
        self.tiers.activation_height()
    }

    /// Whether `template` is at/above the activation height. An unparseable height is below.
    pub fn template_is_active(&self, template: &NewTemplate<'_>) -> bool {
        bip34_height(template.coinbase_prefix.inner_as_ref())
            .is_some_and(|h| h >= self.tiers.activation_height())
    }

    /// The anchor feed's publishing handle.
    pub fn anchor_driver(&self) -> AnchorDriver {
        AnchorDriver {
            tx: self.anchor.clone(),
        }
    }

    /// A receiver that wakes on every anchor publish.
    pub fn subscribe(&self) -> watch::Receiver<Option<AnchorUpdate>> {
        self.anchor.subscribe()
    }

    /// Quantise a channel target to its tier, as SHARE_TIER_BIND does: the tag commits the tier.
    pub fn quantise_target(&self, target: &Target, requested_max: &Target) -> Target {
        self.tiers.quantise_target(target, requested_max)
    }

    /// The template with both Ghost tags (`GHPP`, `GHNT`) taken out of its prefix: the 46 bytes
    /// the per-channel stamp puts back.
    pub fn prepare_template(&self, template: &NewTemplate<'static>) -> NewTemplate<'static> {
        let out = strip_plain_node_tag(template);
        let prefix = out.coinbase_prefix.inner_as_ref();
        let Some(height_len) = prefix.first().map(|l| 1 + *l as usize) else {
            return out;
        };
        let tag = prefix
            .get(height_len..)
            .map_or(0, |rest| tag_len_at(rest, PAYOUT_TAG_MAGIC, PAYOUT_ID_LEN));
        if tag == 0 {
            warn!(
                template_id = template.template_id,
                "NODE_POOL: template has no GHPP slot; the 21 bytes the parent anchor needs come \
                 out of the pool tag budget instead"
            );
            return out;
        }
        let mut stripped = prefix[..height_len].to_vec();
        stripped.extend_from_slice(&prefix[height_len + tag..]);
        let mut out = out;
        out.coinbase_prefix = stripped.try_into().expect("a shorter prefix still fits");
        out
    }

    /// The payout script a channel identity credits, if the node pool accepts it (P2SH, P2WPKH,
    /// P2WSH, P2TR). On refusal, the `OpenMiningChannelError` code.
    pub fn payee_for_identity(user_identity: &str) -> Result<Vec<u8>, &'static str> {
        let script = match PayoutMode::try_from(user_identity) {
            Ok(PayoutMode::Solo { script }) | Ok(PayoutMode::Donate { script, .. }) => {
                script.script_pubkey().to_bytes()
            }
            _ => return Err("node-pool-no-payee"),
        };
        if payee_script_class(&script).is_none() {
            return Err("node-pool-payee-script-refused");
        }
        Ok(script)
    }

    /// Remember who a channel's miner says it is (the SV1 agent from the translator, else a
    /// native SV2 miner's `SetupConnection`), until the channel is first stamped.
    pub fn note_identity(&self, key: ChannelKey, identity: Option<MinerIdentity>) {
        if let Some(identity) = identity {
            self.lock().agents.insert(key, identity);
        }
    }

    /// The identity a channel open carries: the agent TLV when present, else the connection's
    /// SV2 `SetupConnection` fields.
    pub fn identity_for_open(
        tlvs: Option<&[Tlv]>,
        setup: Option<&Sv2Device>,
    ) -> Option<MinerIdentity> {
        agent_from_tlvs(tlvs)
            .map(MinerIdentity::Agent)
            .or_else(|| setup.cloned().map(MinerIdentity::Sv2))
    }

    /// The stamp for a channel's next job: `(tier, GHPP push || GHNT push)`. Registers the
    /// channel on first use.
    pub fn stamp(
        &self,
        key: ChannelKey,
        kind: ChannelKind,
        user_identity: &str,
        target: &Target,
    ) -> (u32, Vec<u8>) {
        let tier = self.tiers.tier_for_target(target);
        let anchor = self.anchor.borrow().unwrap_or(AnchorUpdate {
            parent_anchor: [0; 32],
            batch_root: [0; 32],
        });
        let now = self.now_ms();
        let mut st = self.lock();
        if !st.channels.contains_key(&key) {
            register(&mut st, key, kind, user_identity, self.params, now);
        }
        let slot_class = class_of(&st, key);
        let node_id = *self.tiers.node_id();
        let slot = st.channels.get_mut(&key).expect("registered above");
        let preimage = ShareTagPreimage {
            node_id,
            tier: tier.min(u8::MAX as u32) as u8,
            slot_class,
            payee_script: slot.payee_script.clone(),
            parent_anchor: anchor.parent_anchor,
            batch_root: anchor.batch_root,
        };
        let mut push = encode_payout_tag(&preimage.parent_anchor_tag());
        push.extend(encode_node_tag(&preimage.tag()));
        slot.last_stamp = Some(preimage);
        (tier, push)
    }

    /// Record that `job_id` was built with the channel's last stamp.
    pub fn bind_job(&self, key: ChannelKey, job_id: u32) {
        let mut st = self.lock();
        if let Some(slot) = st.channels.get_mut(&key) {
            if let Some(p) = slot.last_stamp.clone() {
                slot.jobs.retain(|(id, _)| *id != job_id);
                slot.jobs.push_back((job_id, p));
                while slot.jobs.len() > JOBS_KEPT {
                    slot.jobs.pop_front();
                }
            }
        }
    }

    /// The tag preimage a job was built with, for the relay (W2.5) to send with its shares.
    pub fn job_preimage(&self, key: ChannelKey, job_id: u32) -> Option<ShareTagPreimage> {
        let st = self.lock();
        st.channels
            .get(&key)?
            .jobs
            .iter()
            .find(|(id, _)| *id == job_id)
            .map(|(_, p)| p.clone())
    }

    /// Send accepted shares to the share-chain relay (`[node_pool.relay]`).
    pub fn set_relay_sink(
        &self,
        tx: tokio::sync::mpsc::Sender<ghost_np_relay::wire::NetShare>,
        tier_base: ghost_common::node_pool_u256::U256,
    ) {
        *self.relay_sink.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(RelaySink { tx, tier_base });
    }

    /// An accepted share on `job_id`: hand it to the relay if its hash meets the lowest network
    /// tier. `coinbase` is the full serialized coinbase the miner hashed and `merkle_path` the
    /// branch to the header's merkle root. Never blocks: a full relay queue drops the share.
    pub fn offer_share(
        &self,
        key: ChannelKey,
        job_id: u32,
        header80: &[u8],
        coinbase: Vec<u8>,
        merkle_path: Vec<[u8; 32]>,
    ) {
        let sink = self.relay_sink.lock().unwrap_or_else(|p| p.into_inner());
        let Some(sink) = sink.as_ref() else {
            return;
        };
        let Some(tag) = self.job_preimage(key, job_id) else {
            return;
        };
        let Ok(share) =
            ghost_np_relay::wire::NetShare::from_parts(header80, coinbase, merkle_path, tag)
        else {
            return;
        };
        if !ghost_common::share_commit::hash_meets_tier(
            &share.id(),
            sink.tier_base,
            ghost_common::node_pool_constants::T_NET_FLOOR,
        ) {
            return;
        }
        if sink.tx.try_send(share).is_err() {
            warn!("NODE_POOL_RELAY: relay queue full; a network share was dropped");
        }
    }

    /// The class a channel's jobs carry now.
    pub fn slot_class(&self, key: ChannelKey) -> Option<u16> {
        let st = self.lock();
        st.channels.contains_key(&key).then(|| class_of(&st, key))
    }

    /// A share on `job_id` was judged `verdict`. Returns the class change, if any; the caller
    /// rebuilds the channel's job when `from != to`.
    pub fn on_share(
        &self,
        key: ChannelKey,
        job_id: u32,
        verdict: ShareVerdict,
    ) -> Option<ClassChange> {
        let now = self.now_ms();
        let mut st = self.lock();
        let slot = st.channels.get(&key)?;
        let session = slot.session.clone()?;
        let job_class = slot
            .jobs
            .iter()
            .find(|(id, _)| *id == job_id)
            .map(|(_, p)| p.slot_class)?;
        let change = st
            .sessions
            .get_mut(&session)?
            .on_share(job_class, verdict, now);
        log_change(key, &session, change);
        change
    }

    /// A channel closed: its sensor sees a disconnect.
    pub fn on_channel_closed(&self, key: ChannelKey) {
        let now = self.now_ms();
        let mut st = self.lock();
        close(&mut st, key, now);
    }

    /// A downstream connection went away with all its channels.
    pub fn on_downstream_removed(&self, downstream_id: DownstreamId) {
        let now = self.now_ms();
        let mut st = self.lock();
        let keys: Vec<ChannelKey> = st
            .channels
            .keys()
            .chain(st.agents.keys())
            .filter(|k| k.0 == downstream_id)
            .copied()
            .collect();
        for key in keys {
            close(&mut st, key, now);
        }
    }

    /// Run every sensor's clocks. Returns the channels whose class changed.
    pub fn tick(&self) -> Vec<(ChannelKey, ClassChange)> {
        let now = self.now_ms();
        let mut st = self.lock();
        let live: Vec<(ChannelKey, String)> = st
            .channels
            .iter()
            .filter_map(|(k, s)| s.session.clone().map(|sess| (*k, sess)))
            .collect();
        let mut out = vec![];
        for (key, session) in live {
            if let Some(change) = st.sessions.get_mut(&session).and_then(|s| s.tick(now)) {
                log_change(key, &session, Some(change));
                out.push((key, change));
            }
        }
        out
    }

    /// Track templates so a re-stamp can rebuild against the one miners are working on.
    pub fn on_new_template(&self, template: &NewTemplate<'_>) {
        let t = template.clone().into_static();
        let mut st = self.lock();
        if t.future_template {
            st.future_templates.push_back(t);
            while st.future_templates.len() > FUTURE_TEMPLATES_KEPT {
                st.future_templates.pop_front();
            }
        } else {
            st.active_template = Some(t);
        }
    }

    /// The future template `template_id` is now active.
    pub fn on_set_new_prev_hash(&self, template_id: u64) {
        let mut st = self.lock();
        if let Some(i) = st
            .future_templates
            .iter()
            .position(|t| t.template_id == template_id)
        {
            let mut t = st.future_templates.remove(i).expect("index just found");
            t.future_template = false;
            st.active_template = Some(t);
        }
    }

    /// The template miners are working on now, as a non-future template.
    pub fn active_template(&self) -> Option<NewTemplate<'static>> {
        self.lock().active_template.clone()
    }

    /// Every registered channel's class and sensing state.
    pub fn channel_status(&self) -> Vec<ChannelStatus> {
        let st = self.lock();
        let mut out: Vec<ChannelStatus> = st
            .channels
            .iter()
            .map(|(key, slot)| ChannelStatus {
                key: *key,
                kind: slot.kind,
                slot_class: class_of(&st, *key),
                sensing: slot
                    .session
                    .as_ref()
                    .and_then(|s| st.sessions.get(s))
                    .map(ClassSensor::status),
            })
            .collect();
        out.sort_by_key(|s| s.key);
        out
    }
}

fn class_of(st: &State, key: ChannelKey) -> u16 {
    let Some(slot) = st.channels.get(&key) else {
        return SLOT_CLASSES[0];
    };
    match (slot.kind, &slot.session) {
        (ChannelKind::Standard, _) => SLOT_CLASSES[FULL_CLASS_INDEX],
        (ChannelKind::Extended, Some(s)) => st
            .sessions
            .get(s)
            .map_or(SLOT_CLASSES[0], ClassSensor::serving_class),
        (ChannelKind::Extended, None) => SLOT_CLASSES[0],
    }
}

fn register(
    st: &mut State,
    key: ChannelKey,
    kind: ChannelKind,
    user_identity: &str,
    params: SensingParams,
    now: u64,
) {
    let payee_script = NodePool::payee_for_identity(user_identity).unwrap_or_else(|code| {
        error!(
            downstream_id = key.0,
            channel_id = key.1,
            code,
            "NODE_POOL: channel identity has no acceptable payee; its shares cannot be credited"
        );
        Vec::new()
    });
    let agent = st.agents.remove(&key);
    let session = (kind == ChannelKind::Extended).then(|| {
        // One live channel per session; a second channel under the same identity senses alone.
        let taken = st
            .channels
            .values()
            .any(|c| c.session.as_deref() == Some(user_identity));
        let name = if taken {
            format!("{user_identity}#{}:{}", key.0, key.1)
        } else {
            user_identity.to_string()
        };
        match st.sessions.get_mut(&name) {
            Some(sensor) if !sensor.is_connected() => sensor.on_reconnect(now),
            _ => {
                let sensor = ClassSensor::for_identity(agent.as_ref(), params, now);
                let status = sensor.status();
                match &status.warning {
                    Some(w) => warn!(
                        downstream_id = key.0,
                        channel_id = key.1,
                        model = w.model,
                        limited_to_class = w.limited_to_class,
                        "NODE_POOL: {w}"
                    ),
                    None => info!(
                        downstream_id = key.0,
                        channel_id = key.1,
                        model = status.model,
                        ceiling_class = status.ceiling_class,
                        agent = agent
                            .as_ref()
                            .map(|a| sanitize_for_log(a.display()))
                            .unwrap_or_default(),
                        "NODE_POOL: sensing slot class"
                    ),
                }
                if st.sessions.len() >= SESSIONS_KEPT {
                    st.sessions.retain(|_, s| s.is_connected());
                }
                st.sessions.insert(name.clone(), sensor);
            }
        }
        name
    });
    st.channels.insert(
        key,
        ChannelSlot {
            kind,
            payee_script,
            session,
            last_stamp: None,
            jobs: VecDeque::new(),
        },
    );
}

fn close(st: &mut State, key: ChannelKey, now: u64) {
    st.agents.remove(&key);
    let Some(slot) = st.channels.remove(&key) else {
        return;
    };
    if let Some(session) = slot.session {
        if let Some(sensor) = st.sessions.get_mut(&session) {
            // Fails the class only if it was still being tested; a settled miner keeps it.
            let change = sensor.on_disconnect(now);
            log_change(key, &session, change);
        }
    }
}

fn log_change(key: ChannelKey, session: &str, change: Option<ClassChange>) {
    if let Some(c) = change.filter(|c| c.from != c.to) {
        info!(
            downstream_id = key.0,
            channel_id = key.1,
            miner = sanitize_for_log(session),
            from = c.from,
            to = c.to,
            cause = ?c.cause,
            "NODE_POOL: slot class changed"
        );
    }
}

/// The user agent a channel open carries in the Ghost agent TLV, if any.
pub fn agent_from_tlvs(tlvs: Option<&[Tlv]>) -> Option<String> {
    let tlv = tlvs?.iter().find(|t| {
        t.r#type.extension_type == AGENT_TLV_EXTENSION_TYPE
            && t.r#type.field_type == AGENT_TLV_FIELD_TYPE
    })?;
    let agent = String::from_utf8_lossy(&tlv.value);
    Some(clamp_agent(&agent).to_string())
}

/// How a channel's jobs are built when they are built per channel: SHARE_TIER_BIND's tier stamp,
/// or the node pool's share tag. The tier variant delegates to `TierBinding` unchanged.
#[derive(Clone)]
pub(crate) enum PerChannelMode {
    Tier(Arc<TierBinding>),
    NodePool(Arc<NodePool>),
}

impl PerChannelMode {
    /// Quantise a channel target to its tier's exact target.
    pub(crate) fn quantise_target(&self, target: &Target, requested_max: &Target) -> Target {
        match self {
            PerChannelMode::Tier(tb) => tb.quantise_target(target, requested_max),
            PerChannelMode::NodePool(np) => np.quantise_target(target, requested_max),
        }
    }

    /// The template with the bytes the stamp replaces taken out.
    pub(crate) fn prepare_template(&self, template: &NewTemplate<'static>) -> NewTemplate<'static> {
        match self {
            PerChannelMode::Tier(_) => strip_plain_node_tag(template),
            PerChannelMode::NodePool(np) => np.prepare_template(template),
        }
    }

    /// The `(tier, push)` to stamp into a channel's next job.
    pub(crate) fn stamp(
        &self,
        key: ChannelKey,
        kind: ChannelKind,
        user_identity: &str,
        target: &Target,
    ) -> (u32, Vec<u8>) {
        match self {
            PerChannelMode::Tier(tb) => tb.stamp_for_target(target),
            PerChannelMode::NodePool(np) => np.stamp(key, kind, user_identity, target),
        }
    }

    /// Record the job a stamp went into.
    pub(crate) fn bind_job(&self, key: ChannelKey, job_id: u32) {
        if let PerChannelMode::NodePool(np) = self {
            np.bind_job(key, job_id);
        }
    }
}

/// Channels whose class change needs a rebuild.
pub(crate) fn changed_keys(changes: &[(ChannelKey, ClassChange)]) -> HashSet<ChannelKey> {
    changes
        .iter()
        .filter(|(_, c)| c.from != c.to)
        .map(|(k, _)| *k)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::{
        coinbase_tags::{extract_node_tag, extract_payout_tag, node_commitment_plain},
        slot_class_sensing::{ChangeCause, FailureKind},
    };
    use stratum_apps::stratum_core::channels_sv2::target::hash_rate_to_target;

    const NODE: [u8; 32] = [0x7A; 32];
    /// A bech32 P2WPKH address (BIP173 test vector) as the miner's username.
    const ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    fn pool(height: u64, min_shares: u32) -> NodePool {
        NodePool::from_parts(NODE, height, 60.0, min_shares)
    }

    fn ghost_prefix(height: [u8; 3]) -> Vec<u8> {
        let mut p = vec![0x03];
        p.extend_from_slice(&height);
        p.extend_from_slice(&encode_payout_tag(&[0xC3; 16]));
        p.extend_from_slice(&encode_node_tag(&node_commitment_plain(&NODE)));
        p
    }

    fn template(id: u64, future: bool, prefix: Vec<u8>) -> NewTemplate<'static> {
        NewTemplate {
            template_id: id,
            future_template: future,
            version: 0x2000_0000,
            coinbase_tx_version: 2,
            coinbase_prefix: prefix.try_into().unwrap(),
            coinbase_tx_input_sequence: 0xffff_ffff,
            coinbase_tx_value_remaining: 0,
            coinbase_tx_outputs_count: 0,
            coinbase_tx_outputs: vec![].try_into().unwrap(),
            coinbase_tx_locktime: 0,
            merkle_path: vec![].try_into().unwrap(),
        }
    }

    fn target() -> Target {
        hash_rate_to_target(4.5e12, 6.0).unwrap()
    }

    #[test]
    fn dark_by_default_and_gated_by_template_height() {
        let np = pool(NODE_POOL_ACTIVATION_HEIGHT, 20);
        let t = template(1, true, ghost_prefix([0x00, 0xa6, 0x0e]));
        assert!(!np.template_is_active(&t), "u64::MAX is never reached");
        let np = pool(960_000, 20);
        assert!(np.template_is_active(&t));
        let below = template(1, true, ghost_prefix([0xff, 0xa5, 0x0e]));
        assert!(!np.template_is_active(&below));
        assert!(!np.template_is_active(&template(1, true, vec![0x09])));
    }

    #[test]
    fn strip_and_stamp_are_byte_neutral_and_carry_the_v2_tag() {
        let np = pool(0, 20);
        let t = template(1, true, ghost_prefix([0x00, 0xa6, 0x0e]));
        let prepared = np.prepare_template(&t);
        let p = prepared.coinbase_prefix.inner_as_ref();
        assert_eq!(p, &[0x03, 0x00, 0xa6, 0x0e], "only the height is left");
        assert_eq!(extract_payout_tag(p), None);
        assert_eq!(extract_node_tag(p), None);

        np.anchor_driver().publish(AnchorUpdate {
            parent_anchor: [0xAA; 32],
            batch_root: [0xBB; 32],
        });
        let key = (1, 1);
        let (tier, push) = np.stamp(key, ChannelKind::Standard, ADDR, &target());
        assert_eq!(
            t.coinbase_prefix.inner_as_ref().len(),
            p.len() + push.len(),
            "strip + stamp must not move the scriptSig length"
        );
        let want = ShareTagPreimage {
            node_id: NODE,
            tier: tier as u8,
            slot_class: 500,
            payee_script: NodePool::payee_for_identity(ADDR).unwrap(),
            parent_anchor: [0xAA; 32],
            batch_root: [0xBB; 32],
        };
        assert_eq!(extract_node_tag(&push), Some(want.tag()));
        assert_eq!(extract_payout_tag(&push), Some([0xAA; 16]));
        assert_eq!(push.len(), 46);
        np.bind_job(key, 7);
        assert_eq!(np.job_preimage(key, 7), Some(want));
    }

    #[test]
    fn accepted_shares_reach_the_relay_only_from_a_bound_job_at_the_network_floor() {
        use ghost_common::node_pool_u256::U256;
        use stratum_apps::stratum_core::bitcoin::{
            self as btc, block::Header, consensus::serialize, hashes::Hash,
        };
        let np = pool(0, 20);
        let key = (1, 1);
        np.stamp(key, ChannelKind::Standard, ADDR, &target());
        np.bind_job(key, 7);
        let coinbase = serialize(&btc::Transaction {
            version: btc::transaction::Version::TWO,
            lock_time: btc::absolute::LockTime::ZERO,
            input: vec![btc::TxIn {
                previous_output: btc::OutPoint::null(),
                script_sig: btc::ScriptBuf::from_bytes(vec![1, 2]),
                sequence: btc::Sequence::MAX,
                witness: btc::Witness::new(),
            }],
            output: vec![],
        });
        let base = U256::from_be_bytes([0xFF; 32]);
        let mut h = Header {
            version: btc::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: btc::BlockHash::all_zeros(),
            merkle_root: btc::hash_types::TxMerkleNode::all_zeros(),
            time: 1,
            bits: btc::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let meets = |h: &Header| {
            ghost_common::share_commit::hash_meets_tier(&h.block_hash().to_byte_array(), base, 10)
        };
        while !meets(&h) {
            h.nonce += 1;
        }
        let good = serialize(&h);
        h.nonce += 1;
        while meets(&h) {
            h.nonce += 1;
        }
        let weak = serialize(&h);

        // No sink: nothing happens.
        np.offer_share(key, 7, &good, coinbase.clone(), vec![]);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        np.set_relay_sink(tx, base);
        np.offer_share(key, 7, &weak, coinbase.clone(), vec![]);
        np.offer_share(key, 99, &good, coinbase.clone(), vec![]);
        assert!(
            rx.try_recv().is_err(),
            "below the floor, or from an unknown job"
        );
        np.offer_share(key, 7, &good, coinbase.clone(), vec![[3; 32]]);
        let s = rx.try_recv().expect("offered");
        assert_eq!(Some(s.tag), np.job_preimage(key, 7));
        assert_eq!(s.merkle_branch, vec![[3; 32]]);
        assert_eq!(serialize(&s.header), good);
    }

    #[test]
    fn a_template_without_a_payout_slot_only_loses_its_node_tag() {
        let np = pool(0, 20);
        let mut prefix = vec![0x03, 0x00, 0xa6, 0x0e];
        prefix.extend(encode_node_tag(&[1; 20]));
        let t = template(1, true, prefix);
        assert_eq!(
            np.prepare_template(&t).coinbase_prefix.inner_as_ref(),
            &[0x03, 0x00, 0xa6, 0x0e]
        );
    }

    #[test]
    fn payees_are_limited_to_the_four_script_classes() {
        assert!(NodePool::payee_for_identity(&format!("{ADDR}.rig1")).is_ok());
        assert_eq!(
            NodePool::payee_for_identity("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2.rig"),
            Err("node-pool-payee-script-refused"),
            "P2PKH costs 4 sigops an output"
        );
        assert_eq!(
            NodePool::payee_for_identity("sri/donate"),
            Err("node-pool-no-payee")
        );
    }

    #[test]
    fn standard_channels_always_carry_the_full_class() {
        let np = pool(0, 1);
        np.stamp((1, 1), ChannelKind::Standard, ADDR, &target());
        assert_eq!(np.slot_class((1, 1)), Some(500));
        assert_eq!(np.tick(), vec![]);
        assert_eq!(np.channel_status()[0].sensing, None);
    }

    #[test]
    fn anchor_updates_change_the_next_stamp() {
        let np = pool(0, 20);
        let key = (1, 2);
        let (_, a) = np.stamp(key, ChannelKind::Extended, ADDR, &target());
        let rx = np.subscribe();
        let driver = np.anchor_driver();
        driver.publish(AnchorUpdate {
            parent_anchor: [1; 32],
            batch_root: [2; 32],
        });
        assert!(
            rx.has_changed().unwrap(),
            "the channel manager wakes on publish"
        );
        let (_, b) = np.stamp(key, ChannelKind::Extended, ADDR, &target());
        assert_ne!(a, b);
        assert_eq!(extract_payout_tag(&b), Some([1; 16]));
        assert_eq!(driver.current().unwrap().batch_root, [2; 32]);
    }

    #[test]
    fn extended_channels_are_sensed_from_their_agent() {
        let np = pool(0, 2);
        let key = (3, 1);
        np.note_identity(
            key,
            NodePool::identity_for_open(
                Some(&[Tlv::new(
                    AGENT_TLV_EXTENSION_TYPE,
                    AGENT_TLV_FIELD_TYPE,
                    b"Avalon Nano 3s".to_vec(),
                )]),
                None,
            ),
        );
        np.stamp(key, ChannelKind::Extended, ADDR, &target());
        np.bind_job(key, 1);
        assert_eq!(np.slot_class(key), Some(3));
        let status = np.channel_status().remove(0).sensing.unwrap();
        assert_eq!(status.model, "Avalon");
        assert_eq!(status.warning.unwrap().limited_to_class, 44);

        assert_eq!(np.on_share(key, 1, ShareVerdict::Valid), None);
        let up = np.on_share(key, 1, ShareVerdict::Valid).unwrap();
        assert_eq!((up.from, up.to, up.cause), (3, 9, ChangeCause::Passed));
        np.stamp(key, ChannelKind::Extended, ADDR, &target());
        np.bind_job(key, 2);
        assert_eq!(np.job_preimage(key, 2).unwrap().slot_class, 9);

        let down = np.on_share(key, 2, ShareVerdict::Corrupt).unwrap();
        assert_eq!((down.from, down.to), (9, 3));
        assert_eq!(
            np.on_share(key, 99, ShareVerdict::Valid),
            None,
            "unknown job"
        );
    }

    #[test]
    fn a_reconnecting_miner_keeps_its_session() {
        let np = pool(0, 1);
        np.stamp((1, 1), ChannelKind::Extended, ADDR, &target());
        np.bind_job((1, 1), 1);
        np.on_share((1, 1), 1, ShareVerdict::Valid); // unknown agent: holds at 3
        np.on_downstream_removed(1);
        assert_eq!(np.slot_class((1, 1)), None);
        np.stamp((2, 1), ChannelKind::Extended, ADDR, &target());
        let st = np.channel_status().remove(0).sensing.unwrap();
        assert_eq!(st.failed, vec![], "a settled class survives the drop");
        assert_eq!(st.serving_class, 3);
        assert!(st.settled);
        assert_eq!(st.valid_shares, 1);
        // A second live channel under the same identity senses on its own.
        np.stamp((2, 2), ChannelKind::Extended, ADDR, &target());
        assert_eq!(
            np.channel_status()[1]
                .sensing
                .as_ref()
                .unwrap()
                .valid_shares,
            0
        );
    }

    #[test]
    fn a_native_sv2_miner_is_sensed_from_its_setup_connection() {
        let np = pool(0, 2);
        let device = Sv2Device::new("Bitmain", "S21", "1.0");
        // No agent TLV: the SetupConnection fields decide.
        np.note_identity((4, 1), NodePool::identity_for_open(None, device.as_ref()));
        np.stamp((4, 1), ChannelKind::Extended, ADDR, &target());
        let st = np.channel_status().remove(0).sensing.unwrap();
        assert_eq!(st.model, "Antminer S21");
        assert_eq!(st.warning.unwrap().limited_to_class, 44);
        // An agent TLV, when present, wins over the connection's fields.
        let tlv = [Tlv::new(
            AGENT_TLV_EXTENSION_TYPE,
            AGENT_TLV_FIELD_TYPE,
            b"Avalon".to_vec(),
        )];
        assert_eq!(
            NodePool::identity_for_open(Some(&tlv), device.as_ref()),
            Some(MinerIdentity::Agent("Avalon".into()))
        );
        assert_eq!(NodePool::identity_for_open(None, None), None);
    }

    #[test]
    fn a_settled_miner_keeps_its_class_across_reconnects_but_a_probe_fails() {
        let np = pool(0, 1);
        // Avalon: ceiling 44. One valid share passes a class at min_shares 1.
        let agent = || Some(MinerIdentity::Agent("Avalon".into()));
        let mut job = 0;
        let mut open = |ds: usize, np: &NodePool| {
            np.note_identity((ds, 1), agent());
            np.stamp((ds, 1), ChannelKind::Extended, ADDR, &target());
            job += 1;
            np.bind_job((ds, 1), job);
            job
        };
        let j = open(1, &np);
        np.on_share((1, 1), j, ShareVerdict::Valid); // 3 -> 9
        let j = open(1, &np);
        np.on_share((1, 1), j, ShareVerdict::Valid); // 9 -> 44
        let j = open(1, &np);
        np.on_share((1, 1), j, ShareVerdict::Valid); // 44 passes: settled at the ceiling
        assert_eq!(np.slot_class((1, 1)), Some(44));
        for ds in 2..6 {
            np.on_downstream_removed(ds - 1);
            open(ds, &np);
            assert_eq!(np.slot_class((ds, 1)), Some(44), "settled class resumes");
        }
        // A fresh miner mid-probe at 9 loses 9 on a drop.
        let other = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        np.note_identity((9, 1), agent());
        np.stamp((9, 1), ChannelKind::Extended, other, &target());
        np.bind_job((9, 1), 100);
        np.on_share((9, 1), 100, ShareVerdict::Valid); // probing 9
        assert_eq!(np.slot_class((9, 1)), Some(9));
        np.on_downstream_removed(9);
        np.stamp((10, 1), ChannelKind::Extended, other, &target());
        let st = np
            .channel_status()
            .into_iter()
            .find(|s| s.key == (10, 1))
            .unwrap()
            .sensing
            .unwrap();
        assert_eq!(st.serving_class, 3);
        assert_eq!(st.failed, vec![(9, FailureKind::Disconnect)]);
    }

    #[test]
    fn templates_become_active_on_their_prev_hash() {
        let np = pool(0, 20);
        np.on_new_template(&template(5, true, vec![0x01, 0x01]));
        assert!(np.active_template().is_none());
        np.on_set_new_prev_hash(5);
        let t = np.active_template().unwrap();
        assert_eq!(t.template_id, 5);
        assert!(!t.future_template, "rebuilt jobs are active jobs");
        np.on_new_template(&template(6, false, vec![0x01, 0x01]));
        assert_eq!(np.active_template().unwrap().template_id, 6);
    }

    #[test]
    fn changed_keys_skip_no_op_changes() {
        let c = |from, to| ClassChange {
            from,
            to,
            cause: ChangeCause::Passed,
        };
        let keys = changed_keys(&[((1, 1), c(3, 3)), ((1, 2), c(3, 9))]);
        assert_eq!(keys, HashSet::from([(1, 2)]));
    }
}
