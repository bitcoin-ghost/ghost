//! pool_sv2's half of the node pool: share tags, slot classes, sensing, and the canonical
//! coinbase every job carries (W2.3, W2.6).
//!
//! The node pool is the only mode. Every channel mines its own job, built by the channel's own
//! factory: the template's `GHPP` and `GHNT` pushes are both replaced, `GHPP` with
//! `parent_anchor[..16]` and `GHNT` with the `GhostShare/v2` tag
//!
//! ```text
//! sha256("GhostShare/v2" || node_id || tier || slot_class || sha256(payee) || parent_anchor
//!        || batch_root)[..20]
//! ```
//!
//! from `ghost_common::share_commit`. Same 46 encoded bytes out of the template prefix and back
//! in through the factory's budget-guarded extra push, so the scriptSig length does not move.
//!
//! ## The coinbase (W2.6, spec 2.1)
//!
//! Every job pays exactly `canonical_payout::coinbase_outputs` for its height, its slot class
//! and the snapshot table its parent anchor defines: the treasury (`S/200` plus change), the
//! miner outputs in rule order with the top balance last, the finder (this node's
//! `fee_address`, every transaction fee, omitted when there are none), the `GHNP` table-root
//! commitment and the witness commitment. The template provider hands over the whole coinbase
//! value (`coinbase_tx_value_remaining` = subsidy + fees) and the witness commitment as its only
//! output; the channel factory appends that output after the ones built here.
//!
//! The table is the relay's rule-4 table at `cut(H) = H - 20` for the job's parent anchor and
//! height ([`NodePool::fetch_table`], answered by the relay task after settlement has caught up
//! with the Bitcoin tip). Each job remembers the digest of the outputs it was built with. A solved
//! block is always submitted at once; its coinbase is checked against those outputs only after the
//! solution is queued, as an alarm ([`NodePool::submit_then_check`]). The real enforcement is
//! settlement on every other node, which retires nothing for a block that does not match.
//!
//! - **Anchors.** `parent_anchor` and `batch_root` come from an [`AnchorDriver`], a watch
//!   channel the relay (W2.5, `node_pool_relay.rs`) publishes to. Every publish re-stamps every
//!   channel and pushes a fresh job against the active template. Until the first publish both are
//!   zero.
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
//! looked up by its `SetupConnection` vendor, hardware_version and firmware.
//!
//! Relaying shares and anchors is `ghost-np-relay`, started by `[node_pool.relay]`
//! (`node_pool_relay.rs`); accepted shares reach it through [`NodePool::offer_share`].

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::Instant,
};

use ghost_common::{
    canonical_payout::{coinbase_outputs, outputs_digest, subsidy, CoinbaseOutput, Table},
    coinbase_tags::{encode_node_tag, encode_payout_tag, PAYOUT_ID_LEN, PAYOUT_TAG_MAGIC},
    node_pool_constants::SLOT_CLASSES,
    sanitize_for_log,
    share_commit::{payee_script_class, ShareTagPreimage},
    slot_class_sensing::{
        clamp_agent, ClassChange, ClassSensor, MinerIdentity, SensingParams, SensingStatus,
        ShareVerdict, Sv2Device, AGENT_TLV_EXTENSION_TYPE, AGENT_TLV_FIELD_TYPE, FULL_CLASS_INDEX,
    },
};
use ghost_np_relay::net::TableRequest;
use stratum_apps::{
    stratum_core::{
        bitcoin::{Amount, ScriptBuf, Target, Transaction, TxOut},
        channels_sv2::outputs::deserialize_template_outputs,
        parsers_sv2::Tlv,
        template_distribution_sv2::NewTemplate,
    },
    utils::types::{ChannelId, DownstreamId},
};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{error, info, warn};

use crate::{
    miner_stats::{now_secs, worker_name, MinerStats, Outcome},
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
    /// The payee script its shares credit.
    pub payee_script: Vec<u8>,
    /// The user identity it opened with (`address.worker`).
    pub user_identity: String,
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
/// Snapshot tables kept, by `(parent anchor, height)`.
const TABLES_KEPT: usize = 8;
/// How long a job build waits for the relay to answer a table request.
const TABLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One job: the tag preimage it was stamped with, and the digest of the canonical outputs it was
/// built with (`canonical_payout::outputs_digest`, witness commitment included).
#[derive(Clone)]
struct JobRecord {
    job_id: u32,
    preimage: ShareTagPreimage,
    outputs: Option<[u8; 32]>,
}

struct ChannelSlot {
    kind: ChannelKind,
    payee_script: Vec<u8>,
    user_identity: String,
    session: Option<String>,
    last_stamp: Option<ShareTagPreimage>,
    last_outputs: Option<[u8; 32]>,
    jobs: VecDeque<JobRecord>,
}

#[derive(Default)]
struct State {
    channels: HashMap<ChannelKey, ChannelSlot>,
    agents: HashMap<ChannelKey, MinerIdentity>,
    sessions: HashMap<String, ClassSensor>,
    future_templates: VecDeque<NewTemplate<'static>>,
    active_template: Option<NewTemplate<'static>>,
    tables: VecDeque<(TableKey, Arc<Table>)>,
}

/// A cached table's key: the job's parent anchor and height.
type TableKey = ([u8; 32], u32);

/// The node pool job layer's state.
pub struct NodePool {
    tiers: TierBinding,
    params: SensingParams,
    anchor: Arc<watch::Sender<Option<AnchorUpdate>>>,
    epoch: Instant,
    state: Mutex<State>,
    relay_sink: Mutex<Option<RelaySink>>,
    finder_script: Vec<u8>,
    table_source: Mutex<Option<mpsc::Sender<TableRequest>>>,
    stats: Arc<MinerStats>,
}

/// Where accepted shares go when `[node_pool.relay]` runs: the relay's local queue, and the tier
/// base that decides which hashes could be network shares at all.
struct RelaySink {
    tx: tokio::sync::mpsc::Sender<ghost_np_relay::wire::NetShare>,
    tier_base: ghost_common::node_pool_u256::U256,
}

impl NodePool {
    /// Build from an already-resolved identity and the finder script (the operator's fee
    /// address).
    pub fn from_parts(
        node_id: [u8; 32],
        finder_script: Vec<u8>,
        shares_per_minute: f32,
        min_shares: u32,
    ) -> Self {
        Self {
            tiers: TierBinding::from_parts(node_id),
            params: SensingParams::for_shares_per_minute(shares_per_minute, min_shares),
            anchor: Arc::new(watch::channel(None).0),
            epoch: Instant::now(),
            state: Mutex::new(State::default()),
            relay_sink: Mutex::new(None),
            finder_script,
            table_source: Mutex::new(None),
            stats: Arc::new(MinerStats::in_memory(now_secs())),
        }
    }

    /// The same job layer recording shares into `stats` (W2.17).
    pub fn with_miner_stats(mut self, stats: Arc<MinerStats>) -> Self {
        self.stats = stats;
        self
    }

    /// The per-worker share statistics.
    pub fn miner_stats(&self) -> &Arc<MinerStats> {
        &self.stats
    }

    /// Record a judged share for the miner pages: credited to the channel's payee, counted under
    /// the worker named in `identity` (the channel's own, or a proxy's per-miner identity).
    pub fn record_share(&self, key: ChannelKey, identity: &str, outcome: Outcome) {
        let script = self
            .lock()
            .channels
            .get(&key)
            .map(|s| s.payee_script.clone());
        let script = match script {
            Some(s) => s,
            None => match Self::payee_for_identity(identity) {
                Ok(s) => s,
                Err(_) => return,
            },
        };
        self.stats
            .record(&script, &worker_name(identity), outcome, now_secs());
    }

    /// Resolve from config: the identity from the co-located ghost-mining, the finder script
    /// from `fee_address`.
    pub async fn resolve(
        cfg: &crate::config::NodePoolConfig,
        shares_per_minute: f32,
    ) -> Result<Self, String> {
        let finder_script = Self::fee_script(&cfg.fee_address)?;
        let tb = TierBinding::resolve(cfg.node_id.as_deref(), cfg.ghost_pool_health_url.as_deref())
            .await?;
        let min_shares = cfg
            .sensing_min_shares
            .unwrap_or(SensingParams::default().min_shares);
        Ok(Self::from_parts(
            *tb.node_id(),
            finder_script,
            shares_per_minute,
            min_shares,
        ))
    }

    /// The finder script for a fee address: one of the four payee classes, like any payee.
    pub fn fee_script(fee_address: &str) -> Result<Vec<u8>, String> {
        let script = match PayoutMode::try_from(fee_address.trim()) {
            Ok(PayoutMode::Solo { script }) => script.script_pubkey().to_bytes(),
            _ => {
                return Err(format!(
                    "node_pool.fee_address {fee_address:?} is not an address"
                ))
            }
        };
        if payee_script_class(&script).is_none() {
            return Err(format!(
                "node_pool.fee_address {fee_address:?} must be P2SH, P2WPKH, P2WSH or P2TR"
            ));
        }
        Ok(script)
    }

    /// The node id this node's share tags commit.
    pub fn node_id(&self) -> [u8; 32] {
        *self.tiers.node_id()
    }

    /// The finder script this node's blocks pay their fees to.
    pub fn finder_script(&self) -> &[u8] {
        &self.finder_script
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A poisoned lock still holds consistent maps: every mutation here is a single insert,
        // remove or field write.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// A template's job height, from its BIP34 push.
    pub fn template_height(template: &NewTemplate<'_>) -> Option<u32> {
        bip34_height(template.coinbase_prefix.inner_as_ref()).and_then(|h| u32::try_from(h).ok())
    }

    /// Where table requests go: the relay task (`[node_pool.relay]`).
    pub fn set_table_source(&self, tx: mpsc::Sender<TableRequest>) {
        *self.table_source.lock().unwrap_or_else(|p| p.into_inner()) = Some(tx);
    }

    fn cached_table(&self, parent: &[u8; 32], h: u32) -> Option<Arc<Table>> {
        self.lock()
            .tables
            .iter()
            .find(|(k, _)| *k == (*parent, h))
            .map(|(_, t)| t.clone())
    }

    /// Put a table in the cache. The relay task's answers land here; tests use it directly.
    pub fn insert_table(&self, parent: [u8; 32], h: u32, table: Arc<Table>) {
        let mut st = self.lock();
        st.tables.retain(|(k, _)| *k != (parent, h));
        st.tables.push_back(((parent, h), table));
        while st.tables.len() > TABLES_KEPT {
            st.tables.pop_front();
        }
    }

    /// The table a job on `parent` at height `h` must pay, fetched from the relay task unless
    /// cached. `None` when there is no relay, it does not answer in time, or it does not hold
    /// `parent`.
    pub async fn fetch_table(&self, parent: [u8; 32], h: u32) -> Option<Arc<Table>> {
        if let Some(t) = self.cached_table(&parent, h) {
            return Some(t);
        }
        let tx = self
            .table_source
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()?;
        let (reply, rx) = oneshot::channel();
        tx.send(TableRequest {
            parent,
            height: h,
            prev: None,
            reply,
        })
        .await
        .ok()?;
        let t = tokio::time::timeout(TABLE_TIMEOUT, rx).await.ok()?.ok()??;
        self.insert_table(parent, h, t.clone());
        Some(t)
    }

    /// Fetch the table the next jobs on the active template need: the current anchor's at the
    /// template's height. Called before a rebuild takes the channel locks.
    pub async fn prepare_tables(&self, template: &NewTemplate<'_>) {
        let (Some(h), Some(a)) = (
            Self::template_height(template),
            self.anchor_driver().current(),
        ) else {
            return;
        };
        if self.fetch_table(a.parent_anchor, h).await.is_none() {
            warn!(
                height = h,
                parent = %hex::encode(a.parent_anchor),
                "NODE_POOL: no snapshot table for the job; its coinbase pays the whole subsidy \
                 to the treasury until the relay answers"
            );
        }
    }

    /// What a template gives the coinbase: its height, its witness commitment (its only output)
    /// and its fees (the value above the subsidy). A template that does not have that shape
    /// comes from a template provider that is not running the node pool.
    pub fn template_parts(template: &NewTemplate<'_>) -> Result<(u32, [u8; 32], u64), String> {
        let h = Self::template_height(template).ok_or("template has no BIP34 height")?;
        let template_outputs = deserialize_template_outputs(
            template.coinbase_tx_outputs.to_vec(),
            template.coinbase_tx_outputs_count,
        )
        .map_err(|e| format!("template outputs: {e:?}"))?;
        let [witness] = template_outputs.as_slice() else {
            return Err(format!(
                "the template carries {} outputs; the node pool needs exactly the witness \
                 commitment",
                template_outputs.len()
            ));
        };
        let commitment: [u8; 32] = witness
            .script_pubkey
            .as_bytes()
            .strip_prefix(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed][..])
            .and_then(|c| c.try_into().ok())
            .ok_or("the template's output is not a witness commitment")?;
        if witness.value.to_sat() != 0 {
            return Err("the template's witness commitment carries value".into());
        }
        let fees = template
            .coinbase_tx_value_remaining
            .checked_sub(subsidy(h))
            .ok_or_else(|| {
                format!(
                    "template value {} is below the subsidy {} at height {h}",
                    template.coinbase_tx_value_remaining,
                    subsidy(h)
                )
            })?;
        Ok((h, commitment, fees))
    }

    /// The canonical coinbase outputs of a job on `parent` with `slot_class` miner outputs for
    /// `template`, without the witness commitment (the template's own output, which the channel
    /// factory appends), and the digest of the full list.
    ///
    /// The table is the cached one for `(parent, height)`. Missing (no relay answer yet, or an
    /// anchor the relay does not hold), the job is built on the empty table: the treasury takes
    /// the whole subsidy and nobody is paid more than owed; the shares of such a job earn nothing
    /// on peers, so this only ever delays payouts.
    pub fn canonical_outputs(
        &self,
        parent: &[u8; 32],
        slot_class: u16,
        template: &NewTemplate<'_>,
    ) -> Result<(Vec<TxOut>, [u8; 32]), String> {
        let (h, commitment, fees) = Self::template_parts(template)?;
        let table = self.cached_table(parent, h).unwrap_or_else(|| {
            error!(
                height = h,
                parent = %hex::encode(parent),
                "NODE_POOL: building a job without its snapshot table: the treasury takes the \
                 subsidy"
            );
            Arc::new(Table::new())
        });
        let (outs, _) = coinbase_outputs(
            h,
            &table,
            slot_class as usize,
            &self.finder_script,
            fees,
            &commitment,
        )
        .map_err(|e| format!("canonical outputs: {e}"))?;
        #[cfg(feature = "np-fault-injection")]
        let outs = crate::node_pool_fault::apply(outs, &self.finder_script);
        let digest = outputs_digest(&outs);
        let reward = outs[..outs.len() - 1]
            .iter()
            .map(|(v, s)| TxOut {
                value: Amount::from_sat(*v),
                script_pubkey: ScriptBuf::from_bytes(s.clone()),
            })
            .collect();
        Ok((reward, digest))
    }

    /// The outputs for a channel's next job, built from the channel's last stamp (call
    /// [`NodePool::stamp`] first). Remembered for [`NodePool::bind_job`].
    pub fn job_outputs(
        &self,
        key: ChannelKey,
        template: &NewTemplate<'_>,
    ) -> Result<Vec<TxOut>, String> {
        let (parent, class) = {
            let st = self.lock();
            let p = st
                .channels
                .get(&key)
                .and_then(|s| s.last_stamp.as_ref())
                .ok_or("channel not stamped")?;
            (p.parent_anchor, p.slot_class)
        };
        let (outs, digest) = self.canonical_outputs(&parent, class, template)?;
        if let Some(slot) = self.lock().channels.get_mut(&key) {
            slot.last_outputs = Some(digest);
        }
        Ok(outs)
    }

    /// [`NodePool::check_block`] on a serialized coinbase, as a solved share carries it.
    pub fn check_block_bytes(
        &self,
        key: ChannelKey,
        job_id: u32,
        coinbase: &[u8],
    ) -> Result<(), String> {
        let tx: Transaction = stratum_apps::stratum_core::bitcoin::consensus::deserialize(coinbase)
            .map_err(|e| format!("the solved coinbase does not parse: {e}"))?;
        self.check_block(key, job_id, &tx)
    }

    /// A solved block on `job_id`: `submit` queues it for the template provider first, always,
    /// whenever there is a template; only then is its coinbase checked against the job's canonical
    /// outputs ([`NodePool::check_block_bytes`]) on a thread of its own, so it never holds up the
    /// handler that sends the solution, and a mismatch is logged and nothing else. A
    /// valid Bitcoin block is worth more than any payout mismatch; settlement on every other node
    /// retires nothing for a block that does not match. Returns whether it was submitted.
    pub fn submit_then_check<E>(
        self: &Arc<Self>,
        key: ChannelKey,
        job_id: u32,
        template_id: Option<u64>,
        coinbase: &[u8],
        submit: impl FnOnce(u64) -> Result<(), E>,
    ) -> Result<bool, E> {
        let Some(template_id) = template_id else {
            return Ok(false);
        };
        submit(template_id)?;
        let me = Arc::clone(self);
        let coinbase = coinbase.to_vec();
        let spawned = std::thread::Builder::new()
            .name("np-block-check".into())
            .spawn(move || {
                if let Err(e) = me.check_block_bytes(key, job_id, &coinbase) {
                    error!(
                        downstream_id = key.0,
                        channel_id = key.1,
                        job_id,
                        "NODE_POOL: submitted block's coinbase does not match its job's canonical \
                         outputs: {e}"
                    );
                }
            });
        if let Err(e) = spawned {
            error!("NODE_POOL: could not start the post-submit coinbase check: {e}");
        }
        Ok(true)
    }

    /// The post-submit alarm's check: whether a solved block on `job_id` pays
    /// exactly the canonical outputs that job was built with.
    pub fn check_block(
        &self,
        key: ChannelKey,
        job_id: u32,
        coinbase: &Transaction,
    ) -> Result<(), String> {
        let want = {
            let st = self.lock();
            st.channels
                .get(&key)
                .and_then(|s| s.jobs.iter().find(|j| j.job_id == job_id))
                .ok_or("unknown job")?
                .outputs
                .ok_or("the job was built without canonical outputs")?
        };
        let got: Vec<CoinbaseOutput> = coinbase
            .output
            .iter()
            .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
            .collect();
        if outputs_digest(&got) != want {
            return Err("the coinbase does not pay the job's canonical outputs".into());
        }
        Ok(())
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

    /// Record that `job_id` was built with the channel's last stamp and last outputs.
    pub fn bind_job(&self, key: ChannelKey, job_id: u32) {
        let mut st = self.lock();
        if let Some(slot) = st.channels.get_mut(&key) {
            if let Some(p) = slot.last_stamp.clone() {
                slot.jobs.retain(|j| j.job_id != job_id);
                slot.jobs.push_back(JobRecord {
                    job_id,
                    preimage: p,
                    outputs: slot.last_outputs.take(),
                });
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
            .find(|j| j.job_id == job_id)
            .map(|j| j.preimage.clone())
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
            .find(|j| j.job_id == job_id)
            .map(|j| j.preimage.slot_class)?;
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

    /// Track templates so a re-stamp can rebuild against the one miners are working on. Cached
    /// tables are dropped: a new template may follow a Bitcoin reorg that changed what settled.
    pub fn on_new_template(&self, template: &NewTemplate<'_>) {
        let t = template.clone().into_static();
        let mut st = self.lock();
        st.tables.clear();
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
                payee_script: slot.payee_script.clone(),
                user_identity: slot.user_identity.clone(),
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
            user_identity: crate::miner_stats::clamp_identity(user_identity),
            session,
            last_stamp: None,
            last_outputs: None,
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
    /// The operator's fee address (BIP173 P2WSH test vector).
    const FEE: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";

    fn pool(min_shares: u32) -> NodePool {
        NodePool::from_parts(NODE, NodePool::fee_script(FEE).unwrap(), 60.0, min_shares)
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
    fn a_template_height_is_its_bip34_push() {
        let t = template(1, true, ghost_prefix([0x00, 0xa6, 0x0e]));
        assert_eq!(NodePool::template_height(&t), Some(960_000));
        assert_eq!(
            NodePool::template_height(&template(1, true, vec![0x09])),
            None
        );
    }

    /// A template as the node pool's template provider sends it: the whole value, the witness
    /// commitment as its only output.
    fn np_template(value: u64) -> NewTemplate<'static> {
        let mut t = template(7, true, ghost_prefix([0x00, 0xa6, 0x0e]));
        let mut w = vec![0u8; 8];
        w.push(38);
        w.extend(ghost_common::canonical_payout::witness_script(&[0x11; 32]));
        t.coinbase_tx_value_remaining = value;
        t.coinbase_tx_outputs_count = 1;
        t.coinbase_tx_outputs = w.try_into().unwrap();
        t
    }

    const H: u32 = 960_000;

    fn owed_table(n: u32) -> Table {
        (0..n)
            .map(|i| {
                let mut script = vec![0x51, 0x20];
                script.extend_from_slice(&[(i % 251) as u8; 30]);
                script.extend_from_slice(&i.to_le_bytes()[..2]);
                (
                    script,
                    ghost_common::canonical_payout::Balance {
                        owed: (5_000 + i as i128) * ghost_common::node_pool_constants::FACE_PER_SAT,
                        queue_since: Some(900_000 + i / 7),
                    },
                )
            })
            .collect()
    }

    fn full(reward: &[TxOut]) -> Vec<CoinbaseOutput> {
        reward
            .iter()
            .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
            .chain([(
                0,
                ghost_common::canonical_payout::witness_script(&[0x11; 32]),
            )])
            .collect()
    }

    #[test]
    fn every_slot_class_builds_the_canonical_coinbase() {
        let np = pool(1);
        let parent = [0xAA; 32];
        let table = owed_table(600);
        np.insert_table(parent, H, Arc::new(table.clone()));
        let fees = 4_321;
        let t = np_template(subsidy(H) + fees);
        for class in SLOT_CLASSES {
            let (reward, digest) = np.canonical_outputs(&parent, class, &t).unwrap();
            let (want, _) = coinbase_outputs(
                H,
                &table,
                class as usize,
                np.finder_script(),
                fees,
                &[0x11; 32],
            )
            .unwrap();
            let got = full(&reward);
            assert_eq!(got, want, "class {class}");
            assert_eq!(digest, outputs_digest(&want));
            // treasury, the class's miners, finder, GHNP, witness
            assert_eq!(got.len(), class as usize + 4, "class {class}");
            assert_eq!(
                reward.iter().map(|o| o.value.to_sat()).sum::<u64>(),
                t.coinbase_tx_value_remaining,
                "the factory's sum check: every sat of the template's value"
            );
            assert_eq!(got[got.len() - 3], (fees, np.finder_script().to_vec()));
        }
    }

    #[test]
    fn the_finder_output_is_omitted_without_fees() {
        let np = pool(1);
        np.insert_table([1; 32], H, Arc::new(owed_table(5)));
        let (reward, _) = np
            .canonical_outputs(&[1; 32], 9, &np_template(subsidy(H)))
            .unwrap();
        let got = full(&reward);
        assert_eq!(got.len(), 1 + 5 + 2, "treasury, 5 miners, GHNP, witness");
        assert!(got.iter().all(|o| o.1 != np.finder_script()));
        let (reward, _) = np
            .canonical_outputs(&[1; 32], 9, &np_template(subsidy(H) + 1))
            .unwrap();
        assert_eq!(full(&reward)[6], (1, np.finder_script().to_vec()));
    }

    #[test]
    fn a_job_without_its_table_pays_the_subsidy_to_the_treasury() {
        let np = pool(1);
        let (reward, _) = np
            .canonical_outputs(&[9; 32], 500, &np_template(subsidy(H) + 7))
            .unwrap();
        let got = full(&reward);
        assert_eq!(got.len(), 4, "treasury, finder, GHNP, witness");
        assert_eq!(got[0].0, subsidy(H));
        assert_eq!(
            got[2].1,
            ghost_common::canonical_payout::commitment_script(
                &ghost_common::canonical_payout::table_root(&Table::new())
            )
        );
    }

    #[test]
    fn a_template_that_cannot_carry_a_canonical_coinbase_is_refused() {
        let ok = np_template(subsidy(H));
        assert!(NodePool::template_parts(&ok).is_ok());
        let low = np_template(subsidy(H) - 1);
        assert!(NodePool::template_parts(&low)
            .unwrap_err()
            .contains("below the subsidy"));
        let mut no_height = ok.clone();
        no_height.coinbase_prefix = vec![0x09].try_into().unwrap();
        assert!(NodePool::template_parts(&no_height).is_err());
        // The old template provider's shape: every output built, nothing left to the pool.
        let mut old = ok.clone();
        let mut outs = vec![];
        for _ in 0..2 {
            outs.extend(0u64.to_le_bytes());
            outs.push(38);
            outs.extend(ghost_common::canonical_payout::witness_script(&[0x11; 32]));
        }
        old.coinbase_tx_outputs_count = 2;
        old.coinbase_tx_outputs = outs.try_into().unwrap();
        old.coinbase_tx_value_remaining = 0;
        assert!(NodePool::template_parts(&old)
            .unwrap_err()
            .contains("2 outputs"));
        let mut not_witness = ok.clone();
        let mut o = vec![0u8; 8];
        o.push(34);
        o.extend(NodePool::fee_script(FEE).unwrap());
        not_witness.coinbase_tx_outputs = o.try_into().unwrap();
        assert!(NodePool::template_parts(&not_witness).is_err());
    }

    fn swapped_for_submit(outs: &[TxOut]) -> Vec<TxOut> {
        let mut o = outs.to_vec();
        o.swap(1, 2);
        o
    }

    #[test]
    fn a_solved_block_is_always_submitted_and_its_coinbase_checked_after() {
        use stratum_apps::stratum_core::bitcoin::{
            absolute::LockTime, transaction::Version, OutPoint, Sequence, TxIn, Witness,
        };
        let np = Arc::new(pool(1));
        let key = (1, 1);
        np.anchor_driver().publish(AnchorUpdate {
            parent_anchor: [0xAA; 32],
            batch_root: [0xBB; 32],
        });
        np.insert_table([0xAA; 32], H, Arc::new(owed_table(50)));
        let t = np_template(subsidy(H) + 99);
        np.stamp(key, ChannelKind::Standard, ADDR, &target());
        let reward = np.job_outputs(key, &t).unwrap();
        np.bind_job(key, 5);
        let tx = |outs: Vec<TxOut>| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![3, 0, 0xa6, 0x0e]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: outs,
        };
        let mut outs = reward.clone();
        outs.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(ghost_common::canonical_payout::witness_script(
                &[0x11; 32],
            )),
        });
        let good = tx(outs.clone());
        assert_eq!(np.check_block(key, 5, &good), Ok(()));
        let bytes = stratum_apps::stratum_core::bitcoin::consensus::serialize(&good);
        assert_eq!(np.check_block_bytes(key, 5, &bytes), Ok(()));
        // One sat moved between payees, a payee swapped, the finder skimming the treasury.
        let mut moved = outs.clone();
        moved[1].value -= Amount::from_sat(1);
        moved[2].value += Amount::from_sat(1);
        assert!(np.check_block(key, 5, &tx(moved)).is_err());
        let mut swapped = outs.clone();
        swapped.swap(1, 2);
        assert!(np.check_block(key, 5, &tx(swapped)).is_err());
        let mut skim = outs.clone();
        let n = skim.len();
        skim[0].value -= Amount::from_sat(10);
        skim[n - 3].value += Amount::from_sat(10);
        assert!(np.check_block(key, 5, &tx(skim)).is_err());
        assert!(np.check_block(key, 6, &good).is_err(), "unknown job");
        assert!(np.check_block_bytes(key, 5, &[1, 2, 3]).is_err());
        // Submission never waits on the check: a mismatched coinbase is still submitted (and
        // only logged), a matching one likewise, and a custom job (no template) is not.
        for (cb, label) in [
            (tx(swapped_for_submit(&outs)), "mismatched"),
            (good.clone(), "canonical"),
        ] {
            let raw = stratum_apps::stratum_core::bitcoin::consensus::serialize(&cb);
            let mut queued = Vec::new();
            let sent = np
                .submit_then_check(key, 5, Some(77), &raw, |t| {
                    queued.push(t);
                    Ok::<(), ()>(())
                })
                .unwrap();
            assert!(sent, "{label} block submitted");
            assert_eq!(
                queued,
                vec![77],
                "{label} block queued for the template provider"
            );
        }
        let raw = stratum_apps::stratum_core::bitcoin::consensus::serialize(&good);
        let none = np.submit_then_check(key, 5, None, &raw, |_| -> Result<(), ()> {
            panic!("no template: nothing to submit")
        });
        assert_eq!(none, Ok(false));
        // A job bound without outputs (stamped, never built) has nothing to submit against.
        np.stamp(key, ChannelKind::Standard, ADDR, &target());
        np.bind_job(key, 8);
        assert!(np.check_block(key, 8, &good).is_err());
    }

    #[test]
    fn the_fee_address_is_a_payee_class_script() {
        let s = NodePool::fee_script(FEE).unwrap();
        assert_eq!(s.len(), 34, "P2WSH");
        assert_eq!(pool(1).finder_script(), &s[..]);
        assert!(NodePool::fee_script("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_err());
        assert!(NodePool::fee_script("not an address").is_err());
    }

    #[test]
    fn strip_and_stamp_are_byte_neutral_and_carry_the_v2_tag() {
        let np = pool(20);
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
        let np = pool(20);
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
        let np = pool(20);
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
        let np = pool(1);
        np.stamp((1, 1), ChannelKind::Standard, ADDR, &target());
        assert_eq!(np.slot_class((1, 1)), Some(500));
        assert_eq!(np.tick(), vec![]);
        assert_eq!(np.channel_status()[0].sensing, None);
    }

    #[test]
    fn anchor_updates_change_the_next_stamp() {
        let np = pool(20);
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
        let np = pool(2);
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
        let np = pool(1);
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
        let np = pool(2);
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
        let np = pool(1);
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
        let np = pool(20);
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
