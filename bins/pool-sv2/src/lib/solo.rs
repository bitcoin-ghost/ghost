//! pool_sv2's solo layer: every channel mines its own job, paying its own miner.
//!
//! The pool is a solo pool (`docs/SOLO.md`). A channel is bound to the payout address of its
//! user identity (`address.worker`, or the payee TLV the translator sends for a channel it opened
//! on `mining.subscribe`); an identity with no address, or an address outside P2SH, P2WPKH, P2WSH
//! and P2TR, is refused at open. Every job the channel is given, extended or standard, pays
//! ([`ghost_common::solo::solo_outputs`]):
//!
//! 1. the treasury exactly `subsidy / 200`,
//! 2. the channel's miner `subsidy - subsidy / 200 + fees`,
//! 3. the template's own outputs (the witness commitment), appended by the channel's factory.
//!
//! The template's Ghost scriptSig tags (`GHPP`, `GHNT`), which ghost-mining still emits as
//! placeholders, are taken out of the prefix ([`Solo::prepare_template`]); the pool tag stays.
//!
//! A solved block is always submitted to the template provider first ([`Solo::submit_then_check`]).
//! Only then is its coinbase checked against the rule, on a thread of its own, as an alarm: a
//! valid block is never held back. The block is recorded ([`crate::blocks_found`]) and, when
//! `[solo] submit_rpc` lists other nodes, its transactions are asked of the template provider and
//! the whole block is sent to every one of them in parallel ([`crate::submit_rpc`]).

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
};

use ghost_common::{
    coinbase_tags::{
        bip34_height_from, NODE_ID_LEN, NODE_TAG_MAGIC, PAYOUT_ID_LEN, PAYOUT_TAG_MAGIC,
    },
    solo::{
        check_solo_outputs, payee_script_class, solo_outputs, subsidy, CoinbaseOutput, Halving,
        SoloNetwork, SoloPayout, AGENT_TLV_EXTENSION_TYPE, PAYEE_TLV_FIELD_TYPE,
    },
};
use stratum_apps::{
    stratum_core::{
        bitcoin::{
            address::Address, block::Header, consensus, Amount, CompactTarget, Script, ScriptBuf,
            Target, Transaction, TxOut,
        },
        channels_sv2::outputs::deserialize_template_outputs,
        parsers_sv2::Tlv,
        template_distribution_sv2::{NewTemplate, SetNewPrevHash},
    },
    utils::types::{ChannelId, DownstreamId},
};
use tracing::{error, info, warn};

use crate::{
    blocks_found::{BlocksFound, FoundBlock},
    miner_stats::{now_secs, worker_name, MinerStats, Outcome},
    submit_rpc::SubmitTargets,
    utils::PayoutMode,
};

/// One channel on one downstream connection.
pub type ChannelKey = (DownstreamId, ChannelId);

/// Which kind of SV2 channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelKind {
    /// Header-only work.
    Standard,
    /// The miner builds the coinbase from prefix and suffix.
    Extended,
}

impl ChannelKind {
    /// `standard` or `extended`.
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelKind::Standard => "standard",
            ChannelKind::Extended => "extended",
        }
    }
}

/// One open channel, for the API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStatus {
    /// The channel.
    pub key: ChannelKey,
    /// Its kind.
    pub kind: ChannelKind,
    /// The script its blocks pay.
    pub payee_script: Vec<u8>,
    /// The user identity it opened with (`address.worker`).
    pub user_identity: String,
}

/// Jobs remembered per channel for the post-submit check.
const JOBS_KEPT: usize = 64;
/// Future templates remembered until their `SetNewPrevHash`.
const FUTURE_TEMPLATES_KEPT: usize = 4;
/// Solved blocks waiting for their template's transactions (to send to the other nodes).
const PENDING_BLOCKS_KEPT: usize = 8;

/// What a job was built to pay.
#[derive(Clone)]
struct JobRecord {
    job_id: u32,
    height: u32,
    /// Every output the coinbase must carry, in order: treasury, miner, the template's own.
    outputs: Vec<CoinbaseOutput>,
    fees: u64,
}

struct ChannelSlot {
    kind: ChannelKind,
    payee_script: Vec<u8>,
    user_identity: String,
    /// The outputs of the job being built, until [`Solo::bind_job`] names its id.
    building: Option<JobRecord>,
    jobs: VecDeque<JobRecord>,
}

/// The Bitcoin tip as the template provider last announced it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TipView {
    /// The tip's hash, internal byte order.
    pub prev_hash: [u8; 32],
    /// The compact target of the next block.
    pub n_bits: u32,
    /// Its difficulty.
    pub difficulty: f64,
}

/// A solved block waiting for its transactions.
struct PendingBlock {
    template_id: u64,
    hash: String,
    height: u32,
    header80: Vec<u8>,
    coinbase: Vec<u8>,
}

#[derive(Default)]
struct State {
    channels: HashMap<ChannelKey, ChannelSlot>,
    awaiting_payee: HashSet<ChannelKey>,
    future_templates: VecDeque<NewTemplate<'static>>,
    active_template: Option<NewTemplate<'static>>,
    tip: Option<TipView>,
    pending_blocks: VecDeque<PendingBlock>,
}

/// The solo layer's state.
pub struct Solo {
    network: SoloNetwork,
    state: Mutex<State>,
    stats: Arc<MinerStats>,
    blocks: Arc<BlocksFound>,
    submit: Option<Arc<SubmitTargets>>,
}

impl Solo {
    /// A solo layer on `network`, with statistics and found blocks in memory only.
    pub fn new(network: SoloNetwork) -> Self {
        Self {
            network,
            state: Mutex::new(State::default()),
            stats: Arc::new(MinerStats::in_memory(now_secs())),
            blocks: Arc::new(BlocksFound::in_memory()),
            submit: None,
        }
    }

    /// The same layer recording shares into `stats`.
    pub fn with_miner_stats(mut self, stats: Arc<MinerStats>) -> Self {
        self.stats = stats;
        self
    }

    /// The same layer recording found blocks into `blocks`.
    pub fn with_blocks_found(mut self, blocks: Arc<BlocksFound>) -> Self {
        self.blocks = blocks;
        self
    }

    /// The same layer sending every found block to `targets` too.
    pub fn with_submit_targets(mut self, targets: Arc<SubmitTargets>) -> Self {
        self.submit = (!targets.is_empty()).then_some(targets);
        self
    }

    /// The network.
    pub fn network(&self) -> SoloNetwork {
        self.network
    }

    /// The subsidy schedule jobs are built on.
    pub fn halving(&self) -> Halving {
        self.network.halving()
    }

    /// The per-worker share statistics.
    pub fn miner_stats(&self) -> &Arc<MinerStats> {
        &self.stats
    }

    /// The blocks this pool found.
    pub fn blocks_found(&self) -> &Arc<BlocksFound> {
        &self.blocks
    }

    /// Whether found blocks go to other nodes too (their transactions must then be asked for).
    pub fn submits_elsewhere(&self) -> bool {
        self.submit.is_some()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // Every mutation is a single insert, remove or field write: a poisoned lock is still
        // consistent.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The address of `script` on this network, or the script as hex if it has none.
    pub fn address_of(&self, script: &[u8]) -> String {
        Address::from_script(Script::from_bytes(script), self.network.bitcoin_network())
            .map(|a| a.to_string())
            .unwrap_or_else(|_| hex::encode(script))
    }

    /// The payout script a channel identity pays, if the pool accepts it (P2SH, P2WPKH, P2WSH,
    /// P2TR). On refusal, the `OpenMiningChannelError` code.
    pub fn payee_for_identity(user_identity: &str) -> Result<Vec<u8>, &'static str> {
        let script = match PayoutMode::try_from(user_identity) {
            Ok(PayoutMode::Solo { script }) | Ok(PayoutMode::Donate { script, .. }) => {
                script.script_pubkey().to_bytes()
            }
            _ => return Err("no-payout-address"),
        };
        if payee_script_class(&script).is_none() {
            return Err("payout-address-type-refused");
        }
        Ok(script)
    }

    /// The payee a provisional channel is bound to: the Ghost payee TLV on an `UpdateChannel`.
    pub fn payee_from_tlvs(tlvs: Option<&[Tlv]>) -> Option<String> {
        tlvs?
            .iter()
            .find(|t| {
                t.r#type.extension_type == AGENT_TLV_EXTENSION_TYPE
                    && t.r#type.field_type == PAYEE_TLV_FIELD_TYPE
            })
            .and_then(|t| String::from_utf8(t.value.clone()).ok())
    }

    /// A channel opened under the provisional identity: it gets no job until its payee is bound.
    pub fn await_payee(&self, key: ChannelKey) {
        self.lock().awaiting_payee.insert(key);
    }

    /// Whether a channel still waits for its payee (and so must not be given a job).
    pub fn awaits_payee(&self, key: ChannelKey) -> bool {
        self.lock().awaiting_payee.contains(&key)
    }

    /// The channel's payee is bound (or the channel is gone).
    pub fn payee_bound(&self, key: ChannelKey) {
        self.lock().awaiting_payee.remove(&key);
    }

    /// A template's job height, from its BIP34 push.
    pub fn template_height(template: &NewTemplate<'_>) -> Option<u32> {
        bip34_height_from(template.coinbase_prefix.inner_as_ref())
            .and_then(|(h, _)| u32::try_from(h).ok())
    }

    /// What a template gives the coinbase: its height, its own outputs (which must carry no
    /// value: the witness commitment) and its fees (the value above the subsidy).
    pub fn template_parts(
        &self,
        template: &NewTemplate<'_>,
    ) -> Result<(u32, Vec<CoinbaseOutput>, u64), String> {
        let h = Self::template_height(template).ok_or("template has no BIP34 height")?;
        let template_outputs = deserialize_template_outputs(
            template.coinbase_tx_outputs.to_vec(),
            template.coinbase_tx_outputs_count,
        )
        .map_err(|e| format!("template outputs: {e:?}"))?;
        if let Some(o) = template_outputs.iter().find(|o| o.value.to_sat() != 0) {
            return Err(format!(
                "the template's own output {} carries {} sats; only zero-value outputs (the \
                 witness commitment) can follow the solo payouts",
                hex::encode(o.script_pubkey.as_bytes()),
                o.value.to_sat()
            ));
        }
        let fees = template
            .coinbase_tx_value_remaining
            .checked_sub(subsidy(h, self.halving()))
            .ok_or_else(|| {
                format!(
                    "template value {} is below the subsidy {} at height {h}",
                    template.coinbase_tx_value_remaining,
                    subsidy(h, self.halving())
                )
            })?;
        let own = template_outputs
            .iter()
            .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
            .collect();
        Ok((h, own, fees))
    }

    /// The outputs of the next job of channel `key` on `template` (treasury, then the miner),
    /// without the template's own outputs, which the channel factory appends. Registers the
    /// channel on first use; refused when its identity names no acceptable payee. Remembered
    /// for [`Solo::bind_job`].
    pub fn job_outputs(
        &self,
        key: ChannelKey,
        kind: ChannelKind,
        user_identity: &str,
        template: &NewTemplate<'_>,
    ) -> Result<Vec<TxOut>, String> {
        let (height, own, fees) = self.template_parts(template)?;
        let mut st = self.lock();
        if !st.channels.contains_key(&key) {
            let payee_script = Self::payee_for_identity(user_identity)
                .map_err(|code| format!("the channel's identity is refused: {code}"))?;
            st.channels.insert(
                key,
                ChannelSlot {
                    kind,
                    payee_script,
                    user_identity: crate::miner_stats::clamp_identity(user_identity),
                    building: None,
                    jobs: VecDeque::new(),
                },
            );
        }
        let slot = st.channels.get_mut(&key).expect("registered above");
        let pay = solo_outputs(height, self.network.halving(), fees, &slot.payee_script);
        let reward: Vec<TxOut> = pay
            .iter()
            .map(|(v, s)| TxOut {
                value: Amount::from_sat(*v),
                script_pubkey: ScriptBuf::from_bytes(s.clone()),
            })
            .collect();
        let mut outputs = pay.to_vec();
        outputs.extend(own);
        slot.building = Some(JobRecord {
            job_id: 0,
            height,
            outputs,
            fees,
        });
        Ok(reward)
    }

    /// Record that `job_id` was built with the channel's last outputs.
    pub fn bind_job(&self, key: ChannelKey, job_id: u32) {
        let mut st = self.lock();
        if let Some(slot) = st.channels.get_mut(&key) {
            if let Some(mut job) = slot.building.take() {
                job.job_id = job_id;
                slot.jobs.retain(|j| j.job_id != job_id);
                slot.jobs.push_back(job);
                while slot.jobs.len() > JOBS_KEPT {
                    slot.jobs.pop_front();
                }
            }
        }
    }

    /// The template with Ghost's `GHPP` and `GHNT` tags taken out of its prefix: a solo coinbase
    /// carries neither. The BIP34 height and anything after the tags stay.
    pub fn prepare_template(&self, template: &NewTemplate<'static>) -> NewTemplate<'static> {
        let prefix = template.coinbase_prefix.inner_as_ref();
        let stripped = strip_ghost_tags(prefix);
        if stripped.len() == prefix.len() {
            return template.clone();
        }
        let mut out = template.clone();
        out.coinbase_prefix = stripped
            .try_into()
            .expect("a shorter prefix still fits");
        out
    }

    /// Record a judged share for the miner pages: counted for the channel's payee, under the
    /// worker named in `identity` (the channel's own, or a proxy's per-miner identity).
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

    /// A solved block on `job_id`: `submit` queues it for the template provider first, always,
    /// whenever there is a template. Only then is it recorded and its coinbase checked against
    /// the solo rule on a thread of its own, so it never holds up the handler that sends the
    /// solution; a mismatch is logged loudly and nothing else. Returns whether it was submitted.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_then_check<E>(
        self: &Arc<Self>,
        key: ChannelKey,
        job_id: u32,
        template_id: Option<u64>,
        coinbase: &[u8],
        header80: &[u8],
        identity: &str,
        submit: impl FnOnce(u64) -> Result<(), E>,
    ) -> Result<bool, E> {
        let Some(template_id) = template_id else {
            return Ok(false);
        };
        submit(template_id)?;
        let hash = block_hash_of(header80).unwrap_or_default();
        let (height, payee, miner_sats, treasury_sats, fees) = {
            let st = self.lock();
            let slot = st.channels.get(&key);
            let job = slot.and_then(|s| s.jobs.iter().find(|j| j.job_id == job_id));
            (
                job.map_or(0, |j| j.height),
                slot.map(|s| s.payee_script.clone()).unwrap_or_default(),
                job.and_then(|j| j.outputs.get(1)).map_or(0, |o| o.0),
                job.and_then(|j| j.outputs.first()).map_or(0, |o| o.0),
                job.map_or(0, |j| j.fees),
            )
        };
        error!(
            height,
            hash = %hash,
            downstream_id = key.0,
            channel_id = key.1,
            "SOLO_BLOCK_FOUND: a block was found and submitted to the template provider"
        );
        self.blocks.record(FoundBlock {
            height,
            hash: hash.clone(),
            address: self.address_of(&payee),
            worker: worker_name(identity),
            reward_sats: miner_sats,
            treasury_sats,
            fees_sats: fees,
            found_at: now_secs(),
            check: None,
            submitted: vec![],
        });
        if self.submit.is_some() {
            let mut st = self.lock();
            st.pending_blocks.push_back(PendingBlock {
                template_id,
                hash: hash.clone(),
                height,
                header80: header80.to_vec(),
                coinbase: coinbase.to_vec(),
            });
            while st.pending_blocks.len() > PENDING_BLOCKS_KEPT {
                st.pending_blocks.pop_front();
            }
        }
        let me = Arc::clone(self);
        let coinbase = coinbase.to_vec();
        let spawned = std::thread::Builder::new()
            .name("solo-block-check".into())
            .spawn(move || {
                let verdict = me.check_block_bytes(key, job_id, &coinbase);
                match &verdict {
                    Ok(p) => info!(
                        hash = %hash,
                        treasury = p.treasury,
                        miner = p.miner,
                        fees = p.fees,
                        "SOLO: the submitted block pays the treasury and the miner by the rule"
                    ),
                    Err(e) => error!(
                        hash = %hash,
                        downstream_id = key.0,
                        channel_id = key.1,
                        job_id,
                        "SOLO_COINBASE_MISMATCH: the submitted block's coinbase does not follow \
                         the solo rule: {e}"
                    ),
                }
                me.blocks.note_check(&hash, verdict.map(|_| ()));
            });
        if let Err(e) = spawned {
            error!("SOLO: could not start the post-submit coinbase check: {e}");
        }
        Ok(true)
    }

    /// [`Solo::check_block`] on a serialized coinbase, as a solved share carries it.
    pub fn check_block_bytes(
        &self,
        key: ChannelKey,
        job_id: u32,
        coinbase: &[u8],
    ) -> Result<SoloPayout, String> {
        let tx: Transaction = consensus::deserialize(coinbase)
            .map_err(|e| format!("the solved coinbase does not parse: {e}"))?;
        self.check_block(key, job_id, &tx)
    }

    /// Whether a solved block on `job_id` pays exactly what that job was built with, and that
    /// this follows the solo rule (treasury `subsidy / 200`, the miner the rest).
    pub fn check_block(
        &self,
        key: ChannelKey,
        job_id: u32,
        coinbase: &Transaction,
    ) -> Result<SoloPayout, String> {
        let (job, payee) = {
            let st = self.lock();
            let slot = st.channels.get(&key).ok_or("unknown channel")?;
            let job = slot
                .jobs
                .iter()
                .find(|j| j.job_id == job_id)
                .ok_or("unknown job")?
                .clone();
            (job, slot.payee_script.clone())
        };
        let got: Vec<CoinbaseOutput> = coinbase
            .output
            .iter()
            .map(|o| (o.value.to_sat(), o.script_pubkey.to_bytes()))
            .collect();
        let paid = check_solo_outputs(
            &got,
            job.height,
            self.network.halving(),
            &payee,
            Some(job.fees),
        )?;
        if got != job.outputs {
            return Err("the coinbase does not carry the outputs its job was built with".into());
        }
        Ok(paid)
    }

    /// The template provider's transactions for `template_id`: every solved block on it is
    /// assembled and sent to the configured other nodes, in parallel.
    pub fn on_transaction_data(&self, template_id: u64, transactions: Vec<Vec<u8>>) {
        let Some(targets) = self.submit.clone() else {
            return;
        };
        let pending: Vec<PendingBlock> = {
            let mut st = self.lock();
            let (mine, rest): (VecDeque<_>, VecDeque<_>) = std::mem::take(&mut st.pending_blocks)
                .into_iter()
                .partition(|b| b.template_id == template_id);
            st.pending_blocks = rest;
            mine.into_iter().collect()
        };
        for b in pending {
            let raw = assemble_block(&b.header80, &b.coinbase, &transactions);
            let blocks = self.blocks.clone();
            let targets = targets.clone();
            tokio::spawn(async move {
                let results = targets.submit_block(&hex::encode(&raw)).await;
                for (node, result) in &results {
                    match result {
                        Ok(()) => info!(
                            height = b.height,
                            hash = %b.hash,
                            node = %node,
                            "SOLO: block accepted by another node"
                        ),
                        Err(e) => warn!(
                            height = b.height,
                            hash = %b.hash,
                            node = %node,
                            "SOLO: another node did not accept the block: {e}"
                        ),
                    }
                }
                blocks.note_submitted(&b.hash, results);
            });
        }
    }

    /// The template provider could not give the transactions of `template_id`: the blocks on it
    /// reach only the local node.
    pub fn on_transaction_data_error(&self, template_id: u64, why: &str) {
        let mut st = self.lock();
        let before = st.pending_blocks.len();
        st.pending_blocks.retain(|b| b.template_id != template_id);
        if st.pending_blocks.len() != before {
            error!(
                template_id,
                "SOLO: the template provider gave no transactions for a solved block ({why}); \
                 it was submitted to the local node only"
            );
        }
    }

    /// A channel closed.
    pub fn on_channel_closed(&self, key: ChannelKey) {
        let mut st = self.lock();
        st.channels.remove(&key);
        st.awaiting_payee.remove(&key);
    }

    /// A downstream connection went away with all its channels.
    pub fn on_downstream_removed(&self, downstream_id: DownstreamId) {
        let mut st = self.lock();
        st.channels.retain(|k, _| k.0 != downstream_id);
        st.awaiting_payee.retain(|k| k.0 != downstream_id);
    }

    /// Track templates, for the job height the API shows.
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

    /// A new tip: its template is now active.
    pub fn on_set_new_prev_hash(&self, msg: &SetNewPrevHash<'_>) {
        let mut st = self.lock();
        if let Some(i) = st
            .future_templates
            .iter()
            .position(|t| t.template_id == msg.template_id)
        {
            let mut t = st.future_templates.remove(i).expect("index just found");
            t.future_template = false;
            st.active_template = Some(t);
        }
        let mut prev_hash = [0u8; 32];
        let raw = msg.prev_hash.inner_as_ref();
        if raw.len() == 32 {
            prev_hash.copy_from_slice(raw);
        }
        st.tip = Some(TipView {
            prev_hash,
            n_bits: msg.n_bits,
            difficulty: Target::from_compact(CompactTarget::from_consensus(msg.n_bits))
                .difficulty_float(),
        });
    }

    /// The height jobs are being built at, if a template is active.
    pub fn job_height(&self) -> Option<u32> {
        self.lock()
            .active_template
            .as_ref()
            .and_then(|t| Self::template_height(t))
    }

    /// The Bitcoin tip, if announced.
    pub fn tip(&self) -> Option<TipView> {
        self.lock().tip
    }

    /// Every open channel with a payee.
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
            })
            .collect();
        out.sort_by_key(|s| s.key);
        out
    }
}

/// One Ghost coinbase tag is one push: `[len][magic][payload]`. Present or absent, never partial.
fn tag_len_at(bytes: &[u8], magic: &[u8; 4], payload_len: usize) -> usize {
    let total = 1 + 4 + payload_len;
    let present = bytes.len() >= total
        && bytes[0] as usize == 4 + payload_len
        && &bytes[1..5] == magic.as_slice();
    if present {
        total
    } else {
        0
    }
}

/// A template prefix with the `GHPP` and `GHNT` pushes that follow its BIP34 height taken out,
/// in the order ghost-mining emits them. A prefix with neither comes back unchanged.
pub fn strip_ghost_tags(prefix: &[u8]) -> Vec<u8> {
    let Some((_, height_len)) = bip34_height_from(prefix) else {
        return prefix.to_vec();
    };
    let payout = tag_len_at(&prefix[height_len..], PAYOUT_TAG_MAGIC, PAYOUT_ID_LEN);
    let node = tag_len_at(
        &prefix[height_len + payout..],
        NODE_TAG_MAGIC,
        NODE_ID_LEN,
    );
    let mut out = prefix[..height_len].to_vec();
    out.extend_from_slice(&prefix[height_len + payout + node..]);
    out
}

/// The hash of an 80-byte header, as explorers show it.
pub fn block_hash_of(header80: &[u8]) -> Option<String> {
    let header: Header = consensus::deserialize(header80).ok()?;
    Some(header.block_hash().to_string())
}

/// A whole block: the header, the transaction count, the coinbase and the template's
/// transactions, each already serialized.
pub fn assemble_block(header80: &[u8], coinbase: &[u8], transactions: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(
        header80.len() + 9 + coinbase.len() + transactions.iter().map(Vec::len).sum::<usize>(),
    );
    raw.extend_from_slice(header80);
    let n = transactions.len() as u64 + 1;
    match n {
        0..=0xfc => raw.push(n as u8),
        0xfd..=0xffff => {
            raw.push(0xfd);
            raw.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            raw.push(0xfe);
            raw.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            raw.push(0xff);
            raw.extend_from_slice(&n.to_le_bytes());
        }
    }
    raw.extend_from_slice(coinbase);
    for t in transactions {
        raw.extend_from_slice(t);
    }
    raw
}

#[cfg(test)]
#[path = "solo_tests.rs"]
mod tests;
