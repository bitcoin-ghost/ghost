//! Sv2 Standard Channel - Mining Server Abstraction.
//!
//! This module provides the [`StandardChannel`] struct, which models and manages the state of a
//! Stratum V2 (SV2) standard channel as maintained on a mining server.
//!
//! ## Responsibilities
//!
//! `StandardChannel` is responsible for managing all the state associated with an SV2 standard
//! channel, including:
//!
//! - **Channel Parameters**: Unique `channel_id`, `user_identity`, `extranonce_prefix`, maximum
//!   target, nominal hashrate, and other properties negotiated at channel opening.
//! - **Target Difficulty**: Maintains both the requested maximum target and the current working
//!   target for the channel, recalculated as hashrate or share rate changes.
//! - **Job Lifecycle Management**: Manages active, future, past, and stale jobs, including
//!   activation on new chain tips and template updates.
//! - **Share Validation and Accounting**: Validates submitted shares, updates share accounting
//!   state, detects duplicates, and manages batch acknowledgements for SV2 `SubmitShares.Success`
//!   responses.
//! - **Chain Tip Management**: Tracks the latest known chain tip (block height, previous hash,
//!   timestamp, and target) for constructing headers and validating shares.
//!
//! ## Usage
//!
//! Intended for use by pool servers or SV2-compliant job declaration clients (JDC), not by mining
//! devices or proxies. Encapsulates logic for handling SV2 messages such as `NewTemplate`,
//! `SetNewPrevHash`, and `SubmitSharesStandard`.
//!
//! ## Notes
//!
//! - Only one active job is allowed at a time. When a chain tip updates, jobs from the previous tip
//!   become stale and are tracked accordingly.
//! - Share batch acknowledgment logic is tied to the configured batch size.
//! - Extranonce prefix updates must be consistent with SV2 protocol constraints.
//! - Job lifecycle and share accounting are managed on a per-channel basis.
use crate::{
    chain_tip::ChainTip,
    server::{
        error::StandardChannelError,
        jobs::{
            error::JobFactoryError,
            extended::ExtendedJob,
            factory::{JobFactory, COINBASE_HEADER_BYTES},
            job_store::JobStore,
            standard::StandardJob,
        },
        share_accounting::{ShareAccounting, ShareValidationError, ShareValidationResult},
    },
    target::{bytes_to_hex, hash_rate_to_target, u256_to_block_hash},
    MAX_EXTRANONCE_PREFIX_LEN,
};
use bitcoin::{
    absolute::LockTime,
    blockdata::{
        block::{Header, Version},
        witness::Witness,
    },
    consensus::Encodable,
    hashes::sha256d::Hash,
    transaction::{OutPoint, Transaction, TxIn, TxOut, Version as TxVersion},
    CompactTarget, Sequence, Target,
};
use mining_sv2::SubmitSharesStandard;
use std::{collections::HashMap, convert::TryInto, marker::PhantomData};
use template_distribution_sv2::{NewTemplate, SetNewPrevHash};
use tracing::debug;

/// Abstraction of a Sv2 Standard Channel.
///
/// It keeps track of:
/// - the channel's unique `channel_id`
/// - the channel's `user_identity`
/// - the channel's unique `extranonce_prefix`
/// - the channel's requested max target (limit established by the client)
/// - the channel's current target
/// - the channel's mapping between `job_id` and target
/// - the channel's nominal hashrate
/// - the channel's [`JobStore`]
/// - the channel's share accounting state
/// - the channel's expected share per minute
/// - the channel's job factory
/// - the channel's chain tip
#[derive(Debug)]
pub struct StandardChannel<'a, J>
where
    J: JobStore<StandardJob<'a>>,
{
    pub channel_id: u32,
    user_identity: String,
    extranonce_prefix: Vec<u8>,
    requested_max_target: Target,
    target: Target,
    job_id_to_target: HashMap<u32, Target>,
    nominal_hashrate: f32,
    share_accounting: ShareAccounting,
    expected_share_per_minute: f32,
    job_store: J,
    job_factory: JobFactory,
    chain_tip: Option<ChainTip>,
    /// The difficulty-tier commitment to stamp into jobs built by this channel's own factory
    /// (SHARE_TIER_BIND): `(tier_log2, encoded scriptSig push)`. `None` — the default, and the
    /// only value below the gate — leaves every build byte-identical to before the field
    /// existed. The push bytes are opaque here (Ghost semantics stay out of the vendored fork);
    /// the tier label rides along so jobs can be credited by commitment, not by after-the-fact
    /// target lookup.
    tier_commitment: Option<(u32, Vec<u8>)>,
    phantom: PhantomData<&'a ()>,
}

impl<'a, J> StandardChannel<'a, J>
where
    J: JobStore<StandardJob<'a>>,
{
    /// Constructor of `StandardChannel` for a Sv2 Pool Server.
    /// Not meant for usage on a Sv2 Job Declaration Client.
    ///
    /// Initializes the standard channel state with the provided parameters, including channel
    /// identifiers, difficulty targets, share accounting, and job management.
    /// Returns an error if target/difficulty parameters are invalid or extranonce prefix
    /// requirements are not met.
    ///
    /// For non-JD jobs, `pool_tag_string` is added to the coinbase scriptSig in between `/`
    /// and `//` delimiters: `/pool_tag_string//`
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_pool(
        channel_id: u32,
        user_identity: String,
        extranonce_prefix: Vec<u8>,
        requested_max_target: Target,
        nominal_hashrate: f32,
        share_batch_size: usize,
        expected_share_per_minute: f32,
        job_store: J,
        pool_tag_string: String,
    ) -> Result<Self, StandardChannelError> {
        Self::new(
            channel_id,
            user_identity,
            extranonce_prefix,
            requested_max_target,
            nominal_hashrate,
            share_batch_size,
            expected_share_per_minute,
            job_store,
            Some(pool_tag_string),
            None,
        )
    }

    /// Constructor of `StandardChannel` for a Sv2 Job Declaration Client.
    /// Not meant for usage on a Sv2 Pool Server.
    ///
    /// Initializes the extended channel state with the provided parameters, including channel
    /// identifiers, difficulty targets, share accounting, and job management.
    /// Returns an error if target/difficulty parameters are invalid or extranonce prefix
    /// requirements are not met.
    ///
    /// The `pool_tag_string` and `miner_tag_string` are added to the coinbase scriptSig in between
    /// `/` delimiters: `/pool_tag_string/miner_tag_string/`
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_job_declaration_client(
        channel_id: u32,
        user_identity: String,
        extranonce_prefix: Vec<u8>,
        requested_max_target: Target,
        nominal_hashrate: f32,
        share_batch_size: usize,
        expected_share_per_minute: f32,
        job_store: J,
        pool_tag_string: Option<String>,
        miner_tag_string: String,
    ) -> Result<Self, StandardChannelError> {
        Self::new(
            channel_id,
            user_identity,
            extranonce_prefix,
            requested_max_target,
            nominal_hashrate,
            share_batch_size,
            expected_share_per_minute,
            job_store,
            pool_tag_string,
            Some(miner_tag_string),
        )
    }

    // private constructor
    #[allow(clippy::too_many_arguments)]
    fn new(
        channel_id: u32,
        user_identity: String,
        extranonce_prefix: Vec<u8>,
        requested_max_target: Target,
        nominal_hashrate: f32,
        share_batch_size: usize,
        expected_share_per_minute: f32,
        job_store: J,
        pool_tag_string: Option<String>,
        miner_tag_string: Option<String>,
    ) -> Result<Self, StandardChannelError> {
        let calculated_target =
            match hash_rate_to_target(nominal_hashrate.into(), expected_share_per_minute.into()) {
                Ok(target_u256) => target_u256,
                Err(_) => {
                    return Err(StandardChannelError::InvalidNominalHashrate);
                }
            };

        let target: Target = calculated_target;

        if target > requested_max_target {
            return Err(StandardChannelError::RequestedMaxTargetOutOfRange);
        }

        if extranonce_prefix.len() > MAX_EXTRANONCE_PREFIX_LEN {
            return Err(StandardChannelError::ExtranoncePrefixTooLarge);
        }

        let script_sig_size = 5 + // BIP34
            1 + // OP_PUSHBYTES
            3 + // `/` delimiters
            pool_tag_string.as_ref().map_or(0, |s| s.len()) +
            miner_tag_string.as_ref().map_or(0, |s| s.len()) +
            1 + // OP_PUSHBYTES
            extranonce_prefix.len();

        if script_sig_size > 100 {
            return Err(StandardChannelError::ScriptSigSizeTooLarge);
        }

        Ok(Self {
            channel_id,
            user_identity,
            extranonce_prefix,
            requested_max_target,
            target,
            job_id_to_target: HashMap::new(),
            nominal_hashrate,
            share_accounting: ShareAccounting::new(share_batch_size),
            expected_share_per_minute,
            job_factory: JobFactory::new(true, pool_tag_string, miner_tag_string),
            chain_tip: None,
            job_store,
            tier_commitment: None,
            phantom: PhantomData,
        })
    }

    /// Sets (or clears) the difficulty-tier commitment stamped into subsequently built jobs.
    ///
    /// `Some((tier_log2, push_bytes))` makes every later `on_new_template` build carry
    /// `push_bytes` as an extra scriptSig push (through the factory's budget guard, never
    /// spliced) and label the job with `tier_log2`. Call it before each build — the tier follows
    /// the channel's target, which vardiff moves. `None` restores the pre-tier build exactly.
    pub fn set_tier_commitment(&mut self, commitment: Option<(u32, Vec<u8>)>) {
        self.tier_commitment = commitment;
    }

    /// The tier (`log2`) committed by the coinbase of the job `job_id`, if that job is known
    /// (active, past or stale) and was built with a tier commitment.
    ///
    /// This is the value a share reporter must attach to shares for `job_id` — read from the
    /// job's build-time label, NOT re-derived from `job_id_to_target`, which binds at activation
    /// and can disagree with what the coinbase committed to.
    pub fn job_tier_log2(&self, job_id: u32) -> Option<u32> {
        let job = self
            .job_store
            .get_active_job()
            .filter(|j| j.get_job_id() == job_id)
            .or_else(|| self.job_store.get_past_job(job_id))
            .or_else(|| self.job_store.get_stale_job(job_id))?;
        job.get_tier_log2()
    }

    /// Returns the unique channel ID for this channel.
    pub fn get_channel_id(&self) -> u32 {
        self.channel_id
    }

    /// Returns the user identity string for this channel.
    pub fn get_user_identity(&self) -> &String {
        &self.user_identity
    }

    /// Returns the extranonce prefix bytes.
    /// Build the coinbase transaction for `job` with a given extranonce.
    ///
    /// The block-found path and the skeleton below must produce the *same* transaction, differing
    /// only in the extranonce bytes — that is the entire basis on which a share's proof of work can
    /// be said to commit to this pool's coinbase. Two constructions would be two chances to differ.
    fn build_coinbase(
        &self,
        job: &StandardJob<'_>,
        extranonce: &[u8],
    ) -> Result<Transaction, JobFactoryError> {
        // The JOB's captured extra pushes, never the factory's current ones: the factory's value
        // is whatever the last build set, and under per-tier jobs it moves between builds. Using
        // it here would reassemble a coinbase the miner never hashed — discovered on a won block.
        let mut script_sig = self.job_factory.script_sig_before_extranonce_with(
            &job.get_template().coinbase_prefix.to_vec(),
            self.extranonce_prefix.len(),
            job.get_extra_script_sig(),
        )?;
        script_sig.extend_from_slice(extranonce);

        let tx_in = TxIn {
            previous_output: OutPoint::null(),
            script_sig: script_sig.into(),
            sequence: Sequence(job.get_template().coinbase_tx_input_sequence),
            witness: Witness::from(vec![vec![0; 32]]),
        };

        Ok(Transaction {
            version: TxVersion::non_standard(job.get_template().coinbase_tx_version as i32),
            lock_time: LockTime::from_consensus(job.get_template().coinbase_tx_locktime),
            input: vec![tx_in],
            output: job.get_coinbase_outputs().to_vec(),
        })
    }

    /// The invariant parts of this channel's active-job coinbase, either side of the extranonce,
    /// plus the merkle path that reaches the header's merkle root.
    ///
    /// Returns `(coinbase_prefix, coinbase_suffix, merkle_path)`, where
    /// `prefix ‖ extranonce ‖ suffix` is the serialized coinbase byte-for-byte.
    ///
    /// This is what lets a share be verified *against the chain of hashes the miner actually
    /// worked on*, rather than against a claim about it: rebuild the coinbase, walk the path, and
    /// compare with the merkle root inside the submitted header. Nothing in it needs to be trusted
    /// — a wrong skeleton simply fails to reproduce the root.
    ///
    /// Derived by serializing the real coinbase and cutting it, not by re-deriving offsets. The
    /// cut is computed from the assembled scriptSig, so it cannot drift from what was built.
    pub fn coinbase_skeleton(&self) -> Option<(Vec<u8>, Vec<u8>, Vec<Vec<u8>>)> {
        let job = self.get_active_job()?;
        let extranonce_len = self.extranonce_prefix.len();

        let script_sig_head = self
            .job_factory
            .script_sig_before_extranonce_with(
                &job.get_template().coinbase_prefix.to_vec(),
                extranonce_len,
                job.get_extra_script_sig(),
            )
            .ok()?;
        let coinbase = self.build_coinbase(&job, &vec![0u8; extranonce_len]).ok()?;

        let mut serialized = Vec::new();
        coinbase.consensus_encode(&mut serialized).ok()?;

        let cut = COINBASE_HEADER_BYTES + script_sig_head.len();
        // A malformed cut would silently hand out a skeleton that reassembles into the wrong
        // transaction, so it is checked rather than assumed.
        if serialized.len() < cut + extranonce_len {
            return None;
        }

        let merkle_path = job
            .get_template()
            .merkle_path
            .inner_as_ref()
            .iter()
            .map(|n| n.to_vec())
            .collect();

        Some((
            serialized[..cut].to_vec(),
            serialized[cut + extranonce_len..].to_vec(),
            merkle_path,
        ))
    }

    pub fn get_extranonce_prefix(&self) -> &Vec<u8> {
        &self.extranonce_prefix
    }

    /// Sets a new extranonce prefix for this channel.
    ///
    /// Returns an error if the new prefix is too large.
    pub fn set_extranonce_prefix(
        &mut self,
        extranonce_prefix: Vec<u8>,
    ) -> Result<(), StandardChannelError> {
        if extranonce_prefix.len() > MAX_EXTRANONCE_PREFIX_LEN {
            return Err(StandardChannelError::ExtranoncePrefixTooLarge);
        }

        self.extranonce_prefix = extranonce_prefix;

        Ok(())
    }

    /// Updates the current target for this channel.
    ///
    /// Please note that this will NOT update the target associated with jobs that were already created.
    pub fn set_target(&mut self, target: Target) {
        self.target = target;
    }

    /// Updates the nominal hashrate for this channel.
    pub fn set_nominal_hashrate(&mut self, nominal_hashrate: f32) {
        self.nominal_hashrate = nominal_hashrate;
    }

    /// Returns the requested maximum target for this channel.
    pub fn get_requested_max_target(&self) -> &Target {
        &self.requested_max_target
    }

    /// Returns the current target for this channel.
    ///
    /// Please note that this is the current target for the channel. Jobs created before the current target are associated with previously set targets, for which shares will be validated against.
    pub fn get_target(&self) -> &Target {
        &self.target
    }

    /// Returns the target a specific job was issued against — the one `validate_share` judged a
    /// share for that job by.
    ///
    /// Use this, not [`Self::get_target`], to decide how much work a share is worth. Under vardiff
    /// the channel target moves while jobs are outstanding, and crediting an accepted share at the
    /// *current* target rather than its *job's* target over-states the work whenever the target has
    /// been raised since the job was issued. Downstream that share then claims more work than its
    /// hash can prove, and any party that re-derives the difficulty from the hash will reject it.
    pub fn job_target(&self, job_id: u32) -> Option<&Target> {
        self.job_id_to_target.get(&job_id)
    }

    /// Returns the nominal hashrate for this channel.
    pub fn get_nominal_hashrate(&self) -> f32 {
        self.nominal_hashrate
    }

    /// Updates channel configuration with a new nominal hashrate.
    ///
    /// Adjusts target difficulty and internal state. Returns an error if
    /// any input parameters are invalid or constraints are violated.
    ///
    /// This can be used in two scenarios:
    /// - Client sent `UpdateChannel` message, which contains a `requested_max_target` parameter
    ///   that's also used as input.
    /// - vardiff algorithm estimated a new nominal hashrate, in which case `requested_max_target`
    ///   is `None` and we use the value from the channel state (that was set either during channel
    ///   opening or some previous `UpdateChannel` message).
    pub fn update_channel(
        &mut self,
        nominal_hashrate: f32,
        requested_max_target: Option<Target>,
    ) -> Result<(), StandardChannelError> {
        let target = match hash_rate_to_target(
            nominal_hashrate.into(),
            self.expected_share_per_minute.into(),
        ) {
            Ok(target) => target,
            Err(_) => {
                return Err(StandardChannelError::InvalidNominalHashrate);
            }
        };

        let requested_max_target = match requested_max_target {
            Some(ref requested_max_target) => *requested_max_target,
            None => self.requested_max_target,
        };

        // debug hex of target_u256 and max_target
        // just like in share validation
        // to big-endian for display
        let target_bytes = target.to_be_bytes();
        let max_target_bytes = requested_max_target.to_be_bytes();

        // Get the old target for comparison on the debug log
        // Not really needed for the actual method functionality
        // But it's useful to have for debugging purposes
        let old_target = self.target;
        let old_target_bytes = old_target.to_be_bytes();

        debug!(
            "updating channel target \nold target:\t{}\nnew target:\t{}\nmax_target:\t{}",
            bytes_to_hex(&old_target_bytes),
            bytes_to_hex(&target_bytes),
            bytes_to_hex(&max_target_bytes)
        );

        let new_target: Target = target;

        if new_target > requested_max_target {
            return Err(StandardChannelError::RequestedMaxTargetOutOfRange);
        }

        self.target = new_target;
        self.nominal_hashrate = nominal_hashrate;
        self.requested_max_target = requested_max_target;
        Ok(())
    }

    /// Returns the currently active job, if any.
    pub fn get_active_job(&self) -> Option<StandardJob<'a>> {
        // cloning happens inside the job store
        self.job_store.get_active_job()
    }
    /// Returns the job ID for a future job from a template ID, if any.
    pub fn get_future_job_id_from_template_id(&self, template_id: u64) -> Option<u32> {
        self.job_store
            .get_future_job_id_from_template_id(template_id)
    }

    /// Returns an owned copy of a future job from its job ID, if any.
    pub fn get_future_job(&self, job_id: u32) -> Option<StandardJob<'a>> {
        // cloning happens inside the job store
        self.job_store.get_future_job(job_id)
    }

    /// Returns an owned copy of a past job from its job ID, if any.
    pub fn get_past_job(&self, job_id: u32) -> Option<StandardJob<'a>> {
        // cloning happens inside the job store
        self.job_store.get_past_job(job_id)
    }

    /// Returns an owned copy of a stale job from its job ID, if any.
    pub fn get_stale_job(&self, job_id: u32) -> Option<StandardJob<'a>> {
        // cloning happens inside the job store
        self.job_store.get_stale_job(job_id)
    }

    /// Returns the expected number of shares per minute for this channel.
    pub fn get_shares_per_minute(&self) -> f32 {
        self.expected_share_per_minute
    }

    /// Returns the current chain tip, if set.
    pub fn get_chain_tip(&self) -> Option<&ChainTip> {
        self.chain_tip.as_ref()
    }

    /// Only for testing purposes, not meant to be used in real apps.
    #[cfg(test)]
    fn set_chain_tip(&mut self, chain_tip: ChainTip) {
        self.chain_tip = Some(chain_tip);
    }

    /// Returns a reference to the share accounting state for this channel.
    pub fn get_share_accounting(&self) -> &ShareAccounting {
        &self.share_accounting
    }

    /// Updates the channel state with a new job.
    ///
    /// If the template is a future template, the chain tip is not used.
    /// If the template is not a future template, the chain tip must be set.
    ///
    /// Only meant for usage on a Sv2 Pool Server or a Sv2 Job Declaration Client,
    /// but not on mining clients such as Mining Devices or Proxies.
    ///
    /// Only meant to be used in case we want to broadcast standard jobs.
    /// In case we want to broadcast extended jobs via group channel, use `on_group_channel_job`
    /// instead.
    pub fn on_new_template(
        &mut self,
        template: NewTemplate<'a>,
        coinbase_reward_outputs: Vec<TxOut>,
    ) -> Result<(), StandardChannelError> {
        // Stamp the tier commitment (if any) into this build. `None` sets an empty extra, which
        // is byte-identical to the pre-tier factory — proven by the pinned job-byte tests.
        self.job_factory.set_extra_script_sig(
            self.tier_commitment
                .as_ref()
                .map(|(_, push)| push.clone())
                .unwrap_or_default(),
        );
        let tier_log2 = self.tier_commitment.as_ref().map(|(t, _)| *t);
        match template.future_template {
            true => {
                let mut new_job = self
                    .job_factory
                    .new_standard_job(
                        self.channel_id,
                        None,
                        self.extranonce_prefix.clone(),
                        template.clone(),
                        coinbase_reward_outputs,
                    )
                    .map_err(StandardChannelError::JobFactoryError)?;
                new_job.set_tier_log2(tier_log2);
                self.job_store.add_future_job(template.template_id, new_job);
            }
            false => {
                match self.chain_tip.clone() {
                    // we can only create non-future jobs if we have a chain tip
                    None => return Err(StandardChannelError::ChainTipNotSet),
                    Some(chain_tip) => {
                        let mut new_job = self
                            .job_factory
                            .new_standard_job(
                                self.channel_id,
                                Some(chain_tip),
                                self.extranonce_prefix.clone(),
                                template.clone(),
                                coinbase_reward_outputs,
                            )
                            .map_err(StandardChannelError::JobFactoryError)?;
                        new_job.set_tier_log2(tier_log2);

                        // associate the new active job with its validation target
                        self.job_id_to_target
                            .insert(new_job.get_job_id(), self.job_validation_target(&new_job));

                        // add the new active job to the job store
                        self.job_store.add_active_job(new_job);
                    }
                }
            }
        }

        Ok(())
    }

    /// The target shares for `job` are validated against.
    ///
    /// A tier-stamped job binds to its TIER's exact target rather than the channel's current
    /// one: the coinbase committed to `2^tier` at build time, the accounting layer credits
    /// exactly `2^tier`, and validating against anything else opens a gap where a share passes
    /// validation but misses its committed tier (or vice versa) whenever vardiff moved the
    /// channel target between build and activation. An unstamped job keeps today's behaviour:
    /// the channel target at bind time.
    fn job_validation_target(&self, job: &StandardJob<'a>) -> Target {
        match job.get_tier_log2() {
            Some(t) => crate::target::tier_target(t),
            None => self.target,
        }
    }

    /// Used as an alternative to `on_new_template` when an extended job is meant to be broadcast
    /// to the group channel, instead of multiple standard jobs to diffferent standard channels.
    ///
    /// We use this method to update the channel state, so it can validate share from the job that
    /// was broadcasted to the group channel.
    pub fn on_group_channel_job(
        &mut self,
        extended_job: ExtendedJob<'a>,
    ) -> Result<(), StandardChannelError> {
        let standard_job = extended_job
            .into_standard_job(self.channel_id, self.extranonce_prefix.clone())
            .map_err(|_| StandardChannelError::FailedToConvertToStandardJob)?;

        match standard_job.is_future() {
            true => {
                self.job_store
                    .add_future_job(standard_job.get_template().template_id, standard_job);
            }
            false => {
                // associate the new active job with its validation target (the tier's exact
                // target for a tier-stamped job, the channel target otherwise)
                self.job_id_to_target.insert(
                    standard_job.get_job_id(),
                    self.job_validation_target(&standard_job),
                );

                // add the new active job to the job store
                self.job_store.add_active_job(standard_job);
            }
        }

        Ok(())
    }

    /// Updates the channel state with a new `SetNewPrevHash` message.
    ///
    /// If there are no future jobs, returns an error.
    /// If there are future jobs, the active job is set to the job with the given `template_id`.
    ///
    /// All past jobs are cleared.
    pub fn on_set_new_prev_hash(
        &mut self,
        set_new_prev_hash: SetNewPrevHash<'a>,
    ) -> Result<(), StandardChannelError> {
        // clear the job id to target mapping
        self.job_id_to_target.clear();

        match self.job_store.has_future_jobs() {
            false => {
                return Err(StandardChannelError::TemplateIdNotFound);
            }
            // try to activate the future job, and also mark past jobs as stale
            true => {
                if !self.job_store.activate_future_job(
                    set_new_prev_hash.template_id,
                    set_new_prev_hash.header_timestamp,
                ) {
                    return Err(StandardChannelError::TemplateIdNotFound);
                }

                // associate the new active job with its validation target (the tier's exact
                // target for a tier-stamped job, the channel target otherwise)
                let job = self
                    .job_store
                    .get_active_job()
                    .expect("active job must exist");
                self.job_id_to_target
                    .insert(job.get_job_id(), self.job_validation_target(&job));
            }
        }

        // clear seen shares, as shares for past chain tip will be rejected as stale
        self.share_accounting.flush_seen_shares();

        // update the chain tip
        self.chain_tip = Some(set_new_prev_hash.into());

        Ok(())
    }

    /// Validates a submitted share and updates accounting state.
    ///
    /// Returns the result of share validation, including block found, valid share, duplicate, or
    /// error if the share is stale or does not meet target.
    pub fn validate_share(
        &mut self,
        share: SubmitSharesStandard,
    ) -> Result<ShareValidationResult, ShareValidationError> {
        let job_id = share.job_id;

        // check if job_id is active job
        let is_active_job = self
            .job_store
            .get_active_job()
            .is_some_and(|job| job.get_job_id() == job_id);

        // check if job_id is past job
        let is_past_job = self.job_store.get_past_job(job_id).is_some();

        // check if job_id is stale job
        let is_stale_job = self.job_store.get_stale_job(job_id).is_some();

        if is_stale_job {
            return Err(ShareValidationError::Stale);
        }

        // if job_id is not active, past or stale, return error
        if !is_active_job && !is_past_job && !is_stale_job {
            return Err(ShareValidationError::InvalidJobId);
        }

        let job = if is_active_job {
            self.job_store
                .get_active_job()
                .expect("active job must exist")
        } else if is_past_job {
            self.job_store
                .get_past_job(job_id)
                .expect("past job must exist")
        } else {
            self.job_store
                .get_stale_job(job_id)
                .expect("stale job must exist")
        };

        let job_target = self
            .job_id_to_target
            .get(&job_id)
            .expect("job target must exist");

        let merkle_root: [u8; 32] = job
            .get_merkle_root()
            .inner_as_ref()
            .try_into()
            .expect("merkle root must be 32 bytes");

        let chain_tip = self
            .chain_tip
            .as_ref()
            .ok_or(ShareValidationError::NoChainTip)?;

        let prev_hash = chain_tip.prev_hash();
        let nbits = CompactTarget::from_consensus(chain_tip.nbits());

        // create the header for validation
        let header = Header {
            version: Version::from_consensus(share.version as i32),
            prev_blockhash: u256_to_block_hash(prev_hash.clone()),
            merkle_root: (*Hash::from_bytes_ref(&merkle_root)).into(),
            time: share.ntime,
            bits: nbits,
            nonce: share.nonce,
        };

        // convert the header hash to a target type for easy comparison
        let share_hash = header.block_hash();
        let share_raw_hash: [u8; 32] = *share_hash.to_raw_hash().as_ref();
        let share_hash_target = Target::from_le_bytes(share_raw_hash);
        let share_hash_as_diff = share_hash_target.difficulty_float();
        let network_target = Target::from_compact(nbits);

        // print hash_as_target and self.target as human readable hex
        let share_hash_target_bytes = share_hash_target.to_be_bytes();
        let job_target_bytes = job_target.to_be_bytes();

        debug!(
            "share validation \nshare:\t\t{}\njob target:\t{}\nnetwork target:\t{}",
            bytes_to_hex(&share_hash_target_bytes),
            bytes_to_hex(&job_target_bytes),
            format!("{:x}", network_target)
        );

        // check if a block was found
        if network_target.is_met_by(share_hash) {
            if self
                .share_accounting
                .is_share_seen(share_hash.to_raw_hash())
            {
                return Err(ShareValidationError::DuplicateShare);
            }
            self.share_accounting.update_share_accounting(
                job_target.difficulty_float(),
                share.sequence_number,
                share_hash.to_raw_hash(),
            );
            self.share_accounting.increment_blocks_found();
            self.share_accounting.mark_batch_acknowledged();

            let coinbase = self
                .build_coinbase(&job, job.get_extranonce_prefix())
                .map_err(|_| ShareValidationError::InvalidCoinbase)?;
            let mut serialized_coinbase = Vec::new();
            coinbase
                .consensus_encode(&mut serialized_coinbase)
                .map_err(|_| ShareValidationError::InvalidCoinbase)?;

            // serialize the raw 80-byte header so the block-finding share carries a
            // verifiable PoW preimage as well: sha256d(header80) == share_hash
            let mut header80 = Vec::with_capacity(80);
            header
                .consensus_encode(&mut header80)
                .map_err(|_| ShareValidationError::Invalid)?;

            return Ok(ShareValidationResult::BlockFound(
                share_hash.to_raw_hash(),
                Some(job.get_template().template_id),
                serialized_coinbase,
                header80,
            ));
        }

        // check if the share hash meets the job target
        if share_hash_target <= *job_target {
            if self
                .share_accounting
                .is_share_seen(share_hash.to_raw_hash())
            {
                return Err(ShareValidationError::DuplicateShare);
            }

            self.share_accounting.update_share_accounting(
                job_target.difficulty_float(),
                share.sequence_number,
                share_hash.to_raw_hash(),
            );

            // update the best diff
            self.share_accounting.update_best_diff(share_hash_as_diff);

            // serialize the raw 80-byte header so a decentralised pool can re-verify
            // the share's PoW preimage independently: sha256d(header80) == share_hash
            let mut header80 = Vec::with_capacity(80);
            header
                .consensus_encode(&mut header80)
                .map_err(|_| ShareValidationError::Invalid)?;
            Ok(ShareValidationResult::Valid(
                share_hash.to_raw_hash(),
                header80,
            ))
        } else {
            Err(ShareValidationError::DoesNotMeetTarget)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        chain_tip::ChainTip,
        server::{
            error::StandardChannelError,
            jobs::{
                job_store::{DefaultJobStore, JobStore},
                standard::StandardJob,
            },
            share_accounting::{ShareValidationError, ShareValidationResult},
            standard::StandardChannel,
        },
    };
    use binary_sv2::Sv2Option;
    use bitcoin::{transaction::TxOut, Amount, ScriptBuf, Target};
    use mining_sv2::{NewMiningJob, SubmitSharesStandard};
    use std::convert::TryInto;
    use template_distribution_sv2::{NewTemplate, SetNewPrevHash as SetNewPrevHashTdp};

    const SATS_AVAILABLE_IN_TEMPLATE: u64 = 5000000000;

    /// **The property share crediting rests on.**
    ///
    /// A share is validated against the target its JOB was issued at, but the amount of work it is
    /// credited was being read from the channel's CURRENT target. Under vardiff those differ the
    /// moment the target is raised while a job is outstanding: the share is accepted (it beat the
    /// old target) and then credited at the new, harder one, claiming work its hash cannot prove.
    /// Any peer re-deriving difficulty from the hash rejects it.
    ///
    /// Observed in production: a hashrate burst drove the target 2,328 -> 815,982 across four
    /// rounds, and 20-60% of that hour's shares became permanently unacceptable to every peer.
    #[test]
    fn a_jobs_target_is_remembered_when_the_channel_target_moves() {
        let job_store = DefaultJobStore::<StandardJob>::new();
        let max_target = Target::from_le_bytes([0xff; 32]);
        let mut channel = StandardChannel::new(
            1,
            "user".to_string(),
            vec![7u8; 16],
            max_target,
            10.0,
            100,
            1.0,
            job_store,
            Some("GHOST PublicPool".to_string()),
            None,
        )
        .unwrap();
        channel.set_chain_tip(ChainTip::new(
            [
                200, 53, 253, 129, 214, 31, 43, 84, 179, 58, 58, 76, 128, 213, 24, 53, 38, 144,
                205, 88, 172, 20, 251, 22, 217, 141, 21, 221, 21, 0, 0, 0,
            ]
            .into(),
            503543726,
            1745596960,
        ));

        let template = NewTemplate {
            template_id: 1,
            future_template: false,
            version: 536870912,
            coinbase_tx_version: 2,
            coinbase_prefix: {
                let mut p = vec![0x03, 0x40, 0x1f, 0x0e];
                p.extend_from_slice(&[20u8; 21]);
                p.extend_from_slice(&[24u8; 25]);
                p.try_into().unwrap()
            },
            coinbase_tx_input_sequence: 4294967294,
            coinbase_tx_value_remaining: SATS_AVAILABLE_IN_TEMPLATE,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_locktime: 158,
            merkle_path: vec![].try_into().unwrap(),
        };
        let mut script_bytes = vec![0u8, 20];
        script_bytes.extend_from_slice(&[0xABu8; 20]);
        channel
            .on_new_template(
                template,
                vec![TxOut {
                    value: Amount::from_sat(SATS_AVAILABLE_IN_TEMPLATE),
                    script_pubkey: ScriptBuf::from(script_bytes),
                }],
            )
            .expect("template must be accepted");

        let job_id = channel.get_active_job().expect("active job").get_job_id();
        // Whatever the channel derived for itself — the point is the job pins it.
        let issued = channel.get_target().clone();
        assert_eq!(
            channel.job_target(job_id),
            Some(&issued),
            "the job must record the target it was issued at"
        );

        // Vardiff raises the target while that job is still outstanding.
        let harder = Target::from_le_bytes({
            let mut b = [0u8; 32];
            b[0] = 1; // little-endian: numerically tiny target == very high difficulty
            b
        });
        channel.set_target(harder.clone());

        assert_eq!(channel.get_target(), &harder, "channel target moves");
        assert_eq!(
            channel.job_target(job_id),
            Some(&issued),
            "the outstanding job must STILL be credited at the target it was issued at"
        );
        assert!(
            issued.difficulty_float() < harder.difficulty_float(),
            "the raise must be a raise, else this test proves nothing"
        );
    }

    /// **The property the receiver binding rests on.**
    ///
    /// `prefix ‖ extranonce ‖ suffix` must reproduce the coinbase byte-for-byte. If it does not,
    /// a validator rebuilding the coinbase gets a different txid, a different merkle root, and
    /// concludes the share does not match its own header — so an honest share reads as forged.
    ///
    /// The two halves are cut from a serialization; this asserts the cut is in the right place,
    /// which is the kind of off-by-one that is invisible until it rejects everything.
    #[test]
    fn the_coinbase_skeleton_reassembles_byte_for_byte() {
        use bitcoin::consensus::Encodable;

        let extranonce_prefix = vec![7u8; 16];
        let job_store = DefaultJobStore::<StandardJob>::new();
        let mut channel = StandardChannel::new(
            1,
            "user".to_string(),
            extranonce_prefix.clone(),
            Target::from_le_bytes([0xff; 32]),
            10.0,
            100,
            1.0,
            job_store,
            Some("GHOST PublicPool".to_string()),
            None,
        )
        .unwrap();

        // A non-future template needs a tip to hang off.
        channel.set_chain_tip(ChainTip::new(
            [
                200, 53, 253, 129, 214, 31, 43, 84, 179, 58, 58, 76, 128, 213, 24, 53, 38, 144,
                205, 88, 172, 20, 251, 22, 217, 141, 21, 221, 21, 0, 0, 0,
            ]
            .into(),
            503543726,
            1745596960,
        ));

        let template = NewTemplate {
            template_id: 1,
            future_template: false,
            version: 536870912,
            coinbase_tx_version: 2,
            // A realistic Ghost prefix: BIP34 height, then the payout and node tags.
            coinbase_prefix: {
                let mut p = vec![0x03, 0x40, 0x1f, 0x0e];
                p.extend_from_slice(&[20u8; 21]);
                p.extend_from_slice(&[24u8; 25]);
                p.try_into().unwrap()
            },
            coinbase_tx_input_sequence: 4294967294,
            coinbase_tx_value_remaining: SATS_AVAILABLE_IN_TEMPLATE,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_locktime: 158,
            merkle_path: vec![].try_into().unwrap(),
        };

        let mut script_bytes = vec![0u8, 20];
        script_bytes.extend_from_slice(&[0xABu8; 20]);
        let reward = vec![TxOut {
            value: Amount::from_sat(SATS_AVAILABLE_IN_TEMPLATE),
            script_pubkey: ScriptBuf::from(script_bytes),
        }];
        channel
            .on_new_template(template.clone(), reward)
            .expect("template must be accepted");

        let (prefix, suffix, _path) = channel
            .coinbase_skeleton()
            .expect("an active job must yield a skeleton");

        let job = channel.get_active_job().expect("active job");
        let real = channel
            .build_coinbase(&job, &extranonce_prefix)
            .expect("coinbase must build");
        let mut serialized = Vec::new();
        real.consensus_encode(&mut serialized).unwrap();

        let mut reassembled = prefix.clone();
        reassembled.extend_from_slice(&extranonce_prefix);
        reassembled.extend_from_slice(&suffix);

        assert_eq!(
            reassembled, serialized,
            "prefix + extranonce + suffix must be the coinbase exactly"
        );
        assert_eq!(
            &serialized[prefix.len()..prefix.len() + extranonce_prefix.len()],
            &extranonce_prefix[..],
            "the cut must land exactly on the extranonce, not a byte either side"
        );
    }

    /// A different extranonce must change only the extranonce — the skeleton is the part that does
    /// not move, which is what makes it worth storing once per job instead of once per share.
    #[test]
    fn the_skeleton_is_invariant_across_extranonces() {
        let job_store = DefaultJobStore::<StandardJob>::new();
        let mut channel = StandardChannel::new(
            1,
            "user".to_string(),
            vec![7u8; 16],
            Target::from_le_bytes([0xff; 32]),
            10.0,
            100,
            1.0,
            job_store,
            Some("GHOST PublicPool".to_string()),
            None,
        )
        .unwrap();

        // A non-future template needs a tip to hang off.
        channel.set_chain_tip(ChainTip::new(
            [
                200, 53, 253, 129, 214, 31, 43, 84, 179, 58, 58, 76, 128, 213, 24, 53, 38, 144,
                205, 88, 172, 20, 251, 22, 217, 141, 21, 221, 21, 0, 0, 0,
            ]
            .into(),
            503543726,
            1745596960,
        ));

        let template = NewTemplate {
            template_id: 1,
            future_template: false,
            version: 536870912,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![0x03, 0x40, 0x1f, 0x0e].try_into().unwrap(),
            coinbase_tx_input_sequence: 4294967294,
            coinbase_tx_value_remaining: SATS_AVAILABLE_IN_TEMPLATE,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_locktime: 158,
            merkle_path: vec![].try_into().unwrap(),
        };
        let mut script_bytes = vec![0u8, 20];
        script_bytes.extend_from_slice(&[0xABu8; 20]);
        channel
            .on_new_template(
                template,
                vec![TxOut {
                    value: Amount::from_sat(SATS_AVAILABLE_IN_TEMPLATE),
                    script_pubkey: ScriptBuf::from(script_bytes),
                }],
            )
            .unwrap();

        let first = channel.coinbase_skeleton().expect("skeleton");
        let second = channel.coinbase_skeleton().expect("skeleton");
        assert_eq!(first, second, "the skeleton must be stable for a given job");
    }

    #[test]
    fn test_future_job_activation_flow() {
        // note:
        // the messages on this test were collected from a sane message flow
        // we use them as test vectors to assert correct behavior of job creation
        let standard_channel_id = 1;
        let user_identity = "user_identity".to_string();

        let extranonce_prefix = [
            83, 116, 114, 97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]
        .to_vec();

        let max_target = Target::from_le_bytes([0xff; 32]);
        let nominal_hashrate = 10.0;
        let share_batch_size = 100;
        let expected_share_per_minute = 1.0;
        let job_store = DefaultJobStore::<StandardJob>::new();

        let mut standard_channel = StandardChannel::new(
            standard_channel_id,
            user_identity,
            extranonce_prefix.clone(),
            max_target,
            nominal_hashrate,
            share_batch_size,
            expected_share_per_minute,
            job_store,
            None,
            None,
        )
        .unwrap();

        let template = NewTemplate {
            template_id: 1,
            future_template: true,
            version: 536870912,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![2, 159, 0, 0].try_into().unwrap(),
            coinbase_tx_input_sequence: 4294967294,
            coinbase_tx_value_remaining: SATS_AVAILABLE_IN_TEMPLATE,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_locktime: 158,
            merkle_path: vec![].try_into().unwrap(),
        };

        // match the original script format used to generate the coinbase_reward_outputs for the
        // expected job
        let pubkey_hash = [
            235, 225, 183, 220, 194, 147, 204, 170, 14, 231, 67, 168, 111, 137, 223, 130, 88, 194,
            8, 252,
        ];
        let mut script_bytes = vec![0]; // SegWit version 0
        script_bytes.push(20); // Push 20 bytes (length of pubkey hash)
        script_bytes.extend_from_slice(&pubkey_hash);
        let script = ScriptBuf::from(script_bytes);
        let coinbase_reward_outputs = vec![TxOut {
            value: Amount::from_sat(SATS_AVAILABLE_IN_TEMPLATE),
            script_pubkey: script,
        }];

        assert!(!standard_channel.job_store.has_future_jobs());

        standard_channel
            .on_new_template(template.clone(), coinbase_reward_outputs)
            .unwrap();

        let expected_future_standard_job = NewMiningJob {
            channel_id: standard_channel_id,
            job_id: 1,
            merkle_root: [
                213, 241, 108, 144, 69, 96, 29, 8, 222, 2, 135, 14, 213, 87, 81, 21, 140, 98, 42,
                221, 221, 174, 219, 248, 106, 52, 168, 88, 18, 146, 186, 71,
            ]
            .into(),
            version: 536870912,
            min_ntime: Sv2Option::new(None),
        };

        let future_standard_job_from_channel = standard_channel.get_future_job(1).unwrap();
        assert_eq!(
            future_standard_job_from_channel.get_job_message(),
            &expected_future_standard_job
        );

        let ntime = 1747092633;
        let set_new_prev_hash = SetNewPrevHashTdp {
            template_id: template.template_id,
            prev_hash: [
                200, 53, 253, 129, 214, 31, 43, 84, 179, 58, 58, 76, 128, 213, 24, 53, 38, 144,
                205, 88, 172, 20, 251, 22, 217, 141, 21, 221, 21, 0, 0, 0,
            ]
            .into(),
            header_timestamp: ntime,
            n_bits: 503543726,
            target: [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                174, 119, 3, 0, 0,
            ]
            .into(),
        };

        standard_channel
            .on_set_new_prev_hash(set_new_prev_hash)
            .unwrap();
        let mut previously_future_job = future_standard_job_from_channel.clone();
        previously_future_job.activate(ntime);

        let activated_job = standard_channel.get_active_job().unwrap();

        // assert that the activated job is the same as the previously future job
        assert_eq!(
            activated_job.get_job_message(),
            previously_future_job.get_job_message()
        );
    }

    #[test]
    fn test_non_future_job_creation_flow() {
        // note:
        // the messages on this test were collected from a sane message flow
        // we use them as test vectors to assert correct behavior of job creation

        let standard_channel_id = 1;
        let user_identity = "user_identity".to_string();

        let extranonce_prefix = [
            83, 116, 114, 97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]
        .to_vec();

        let max_target = Target::from_le_bytes([0xff; 32]);
        let nominal_hashrate = 10.0;
        let share_batch_size = 100;
        let expected_share_per_minute = 1.0;

        let job_store = DefaultJobStore::<StandardJob>::new();

        let mut standard_channel = StandardChannel::new(
            standard_channel_id,
            user_identity,
            extranonce_prefix.clone(),
            max_target,
            nominal_hashrate,
            share_batch_size,
            expected_share_per_minute,
            job_store,
            None,
            None,
        )
        .unwrap();

        let ntime = 1747092633;
        let prev_hash = [
            200, 53, 253, 129, 214, 31, 43, 84, 179, 58, 58, 76, 128, 213, 24, 53, 38, 144, 205,
            88, 172, 20, 251, 22, 217, 141, 21, 221, 21, 0, 0, 0,
        ]
        .into();
        let nbits = 503543726;

        let chain_tip = ChainTip::new(prev_hash, nbits, ntime);
        let template = NewTemplate {
            template_id: 1,
            future_template: false,
            version: 536870912,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![2, 159, 0, 0].try_into().unwrap(),
            coinbase_tx_input_sequence: 4294967294,
            coinbase_tx_value_remaining: SATS_AVAILABLE_IN_TEMPLATE,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_locktime: 158,
            merkle_path: vec![].try_into().unwrap(),
        };

        // match the original script format used to generate the coinbase_reward_outputs for the
        // expected job
        let pubkey_hash = [
            235, 225, 183, 220, 194, 147, 204, 170, 14, 231, 67, 168, 111, 137, 223, 130, 88, 194,
            8, 252,
        ];
        let mut script_bytes = vec![0]; // SegWit version 0
        script_bytes.push(20); // Push 20 bytes (length of pubkey hash)
        script_bytes.extend_from_slice(&pubkey_hash);
        let script = ScriptBuf::from(script_bytes);
        let coinbase_reward_outputs = vec![TxOut {
            value: Amount::from_sat(SATS_AVAILABLE_IN_TEMPLATE),
            script_pubkey: script,
        }];

        standard_channel.set_chain_tip(chain_tip);
        standard_channel
            .on_new_template(template.clone(), coinbase_reward_outputs)
            .unwrap();

        let expected_active_standard_job = NewMiningJob {
            channel_id: standard_channel_id,
            job_id: 1,
            merkle_root: [
                213, 241, 108, 144, 69, 96, 29, 8, 222, 2, 135, 14, 213, 87, 81, 21, 140, 98, 42,
                221, 221, 174, 219, 248, 106, 52, 168, 88, 18, 146, 186, 71,
            ]
            .into(),
            version: 536870912,
            min_ntime: Sv2Option::new(Some(ntime)),
        };

        let active_standard_job_from_channel = standard_channel.get_active_job().unwrap().clone();

        assert_eq!(
            active_standard_job_from_channel.get_job_message(),
            &expected_active_standard_job
        );
    }

    #[test]
    fn test_share_validation_block_found() {
        // note:
        // the messages on this test were collected from a sane message flow
        // we use them as test vectors to assert correct behavior of job creation

        let standard_channel_id = 1;
        let user_identity = "user_identity".to_string();

        let extranonce_prefix = [
            83, 116, 114, 97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]
        .to_vec();
        let max_target = Target::from_le_bytes([0xff; 32]);
        let nominal_hashrate = 1.0;
        let share_batch_size = 100;
        let expected_share_per_minute = 1.0;

        let job_store = DefaultJobStore::<StandardJob>::new();

        let mut standard_channel = StandardChannel::new(
            standard_channel_id,
            user_identity,
            extranonce_prefix.clone(),
            max_target,
            nominal_hashrate,
            share_batch_size,
            expected_share_per_minute,
            job_store,
            None,
            None,
        )
        .unwrap();

        // channel target: 04325c53ef368eb04325c53ef368eb04325c53ef368eb04325c53ef368eb0431
        let template = NewTemplate {
            template_id: 1,
            future_template: false,
            version: 536870912,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![2, 159, 0, 0].try_into().unwrap(),
            coinbase_tx_input_sequence: 4294967294,
            coinbase_tx_value_remaining: SATS_AVAILABLE_IN_TEMPLATE,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_locktime: 158,
            merkle_path: vec![].try_into().unwrap(),
        };

        // match the original script format used to generate the coinbase_reward_outputs for the
        // expected job
        let pubkey_hash = [
            235, 225, 183, 220, 194, 147, 204, 170, 14, 231, 67, 168, 111, 137, 223, 130, 88, 194,
            8, 252,
        ];
        let mut script_bytes = vec![0]; // SegWit version 0
        script_bytes.push(20); // Push 20 bytes (length of pubkey hash)
        script_bytes.extend_from_slice(&pubkey_hash);
        let script = ScriptBuf::from(script_bytes);
        let coinbase_reward_outputs = vec![TxOut {
            value: Amount::from_sat(SATS_AVAILABLE_IN_TEMPLATE),
            script_pubkey: script,
        }];

        // network target: 7fffff0000000000000000000000000000000000000000000000000000000000
        let ntime = 1745596910;
        let prev_hash = [
            251, 175, 106, 40, 35, 87, 122, 90, 58, 51, 78, 32, 202, 236, 228, 36, 154, 174, 206,
            144, 147, 195, 21, 224, 195, 103, 214, 189, 51, 190, 24, 98,
        ]
        .into();
        let n_bits = 545259519;
        let chain_tip = ChainTip::new(prev_hash, n_bits, ntime);

        // prepare standard channel with non-future job
        standard_channel.set_chain_tip(chain_tip);
        standard_channel
            .on_new_template(template.clone(), coinbase_reward_outputs)
            .unwrap();

        let active_standard_job = standard_channel.get_active_job().unwrap();

        // this share has hash 3c34f63de61283c907b68e3127146d7d11f1fb14e50020a8317a292d11e2dab6
        // which satisfied the network target
        // 7fffff0000000000000000000000000000000000000000000000000000000000
        let share_valid_block = SubmitSharesStandard {
            channel_id: standard_channel_id,
            sequence_number: 0,
            job_id: active_standard_job.get_job_id(),
            nonce: 0,
            ntime: 1745596932,
            version: 536870912,
        };

        let res = standard_channel.validate_share(share_valid_block.clone());

        assert!(matches!(res, Ok(ShareValidationResult::BlockFound(..))));
        assert_eq!(
            standard_channel.get_share_accounting().get_blocks_found(),
            1
        );

        // re-submitting the same valid block must be rejected as duplicate
        let res = standard_channel.validate_share(share_valid_block);
        assert!(matches!(
            res.unwrap_err(),
            ShareValidationError::DuplicateShare
        ));
        assert_eq!(
            standard_channel.get_share_accounting().get_blocks_found(),
            1
        );
    }

    #[test]
    fn test_share_validation_does_not_meet_target() {
        // note:
        // the messages on this test were collected from a sane message flow
        // we use them as test vectors to assert correct behavior of job creation

        let standard_channel_id = 1;
        let user_identity = "user_identity".to_string();

        let extranonce_prefix = [
            83, 116, 114, 97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]
        .to_vec();
        let max_target = Target::from_le_bytes([0xff; 32]);
        let nominal_hashrate = 100.0; // bigger hashrate to get higher difficulty
        let share_batch_size = 100;
        let expected_share_per_minute = 1.0;

        let job_store = DefaultJobStore::<StandardJob>::new();

        let mut standard_channel = StandardChannel::new(
            standard_channel_id,
            user_identity,
            extranonce_prefix.clone(),
            max_target,
            nominal_hashrate,
            share_batch_size,
            expected_share_per_minute,
            job_store,
            None,
            None,
        )
        .unwrap();

        // channel target: 000aebbc990fff5144366f000aebbc990fff5144366f000aebbc990fff514435
        let template = NewTemplate {
            template_id: 1,
            future_template: false,
            version: 536870912,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![2, 159, 0, 0].try_into().unwrap(),
            coinbase_tx_input_sequence: 4294967294,
            coinbase_tx_value_remaining: SATS_AVAILABLE_IN_TEMPLATE,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_locktime: 158,
            merkle_path: vec![].try_into().unwrap(),
        };

        // match the original script format used to generate the coinbase_reward_outputs for the
        // expected job
        let pubkey_hash = [
            235, 225, 183, 220, 194, 147, 204, 170, 14, 231, 67, 168, 111, 137, 223, 130, 88, 194,
            8, 252,
        ];
        let mut script_bytes = vec![0]; // SegWit version 0
        script_bytes.push(20); // Push 20 bytes (length of pubkey hash)
        script_bytes.extend_from_slice(&pubkey_hash);
        let script = ScriptBuf::from(script_bytes);
        let coinbase_reward_outputs = vec![TxOut {
            value: Amount::from_sat(SATS_AVAILABLE_IN_TEMPLATE),
            script_pubkey: script,
        }];

        // network target: 000000000000d7c0000000000000000000000000000000000000000000000000
        let ntime = 1745596910;
        let prev_hash = [
            154, 124, 239, 231, 221, 122, 160, 173, 164, 175, 87, 33, 74, 214, 191, 107, 73, 34, 0,
            162, 227, 16, 44, 40, 33, 73, 0, 0, 0, 0, 0, 0,
        ]
        .into();
        let n_bits = 453040064;
        let chain_tip = ChainTip::new(prev_hash, n_bits, ntime);

        // prepare standard channel with non-future job
        standard_channel.set_chain_tip(chain_tip);
        standard_channel
            .on_new_template(template.clone(), coinbase_reward_outputs)
            .unwrap();

        let active_standard_job = standard_channel.get_active_job().unwrap();

        // this share has hash a5b65006d89dab9de2b23ececd3b0435f163607f7da1ba2f0bcde62b29e8cd44
        // which does not meet the channel target
        // 000aebbc990fff5144366f000aebbc990fff5144366f000aebbc990fff514435
        let share_low_diff = SubmitSharesStandard {
            channel_id: standard_channel_id,
            sequence_number: 0,
            job_id: active_standard_job.get_job_id(),
            nonce: 3,
            ntime: 1745596932,
            version: 536870912,
        };

        let res = standard_channel.validate_share(share_low_diff);

        assert!(matches!(
            res.unwrap_err(),
            ShareValidationError::DoesNotMeetTarget
        ));
    }

    #[test]
    fn test_share_validation_valid_share() {
        // note:
        // the messages on this test were collected from a sane message flow
        // we use them as test vectors to assert correct behavior of job creation

        let standard_channel_id = 1;
        let user_identity = "user_identity".to_string();

        let extranonce_prefix = [
            83, 116, 114, 97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]
        .to_vec();
        let max_target = Target::from_le_bytes([0xff; 32]);
        let nominal_hashrate = 1_000.0; // bigger hashrate to get higher difficulty
        let share_batch_size = 100;
        let expected_share_per_minute = 1.0;

        let job_store = DefaultJobStore::<StandardJob>::new();

        let mut standard_channel = StandardChannel::new(
            standard_channel_id,
            user_identity,
            extranonce_prefix.clone(),
            max_target,
            nominal_hashrate,
            share_batch_size,
            expected_share_per_minute,
            job_store,
            None,
            None,
        )
        .unwrap();

        // channel target is:
        // 0001179d9861a761ffdadd11c307c4fc04eea3a418f7d687584e4434af158205

        let template = NewTemplate {
            template_id: 1,
            future_template: false,
            version: 536870912,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![2, 159, 0, 0].try_into().unwrap(),
            coinbase_tx_input_sequence: 4294967294,
            coinbase_tx_value_remaining: SATS_AVAILABLE_IN_TEMPLATE,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_locktime: 158,
            merkle_path: vec![].try_into().unwrap(),
        };

        // match the original script format used to generate the coinbase_reward_outputs for the
        // expected job
        let pubkey_hash = [
            235, 225, 183, 220, 194, 147, 204, 170, 14, 231, 67, 168, 111, 137, 223, 130, 88, 194,
            8, 252,
        ];
        let mut script_bytes = vec![0]; // SegWit version 0
        script_bytes.push(20); // Push 20 bytes (length of pubkey hash)
        script_bytes.extend_from_slice(&pubkey_hash);
        let script = ScriptBuf::from(script_bytes);
        let coinbase_reward_outputs = vec![TxOut {
            value: Amount::from_sat(SATS_AVAILABLE_IN_TEMPLATE),
            script_pubkey: script,
        }];

        // network target: 000000000000d7c0000000000000000000000000000000000000000000000000
        let ntime = 1745596910;
        let prev_hash = [
            154, 124, 239, 231, 221, 122, 160, 173, 164, 175, 87, 33, 74, 214, 191, 107, 73, 34, 0,
            162, 227, 16, 44, 40, 33, 73, 0, 0, 0, 0, 0, 0,
        ]
        .into();
        let n_bits = 453040064;
        let chain_tip = ChainTip::new(prev_hash, n_bits, ntime);

        // prepare standard channel with non-future job
        standard_channel.set_chain_tip(chain_tip);
        standard_channel
            .on_new_template(template.clone(), coinbase_reward_outputs)
            .unwrap();

        // this share has hash 0000d603073772ba60af5922486242a6adb74cdf5baec768c7bd684977852cd8
        // which does meet the channel target
        // 0001179d9861a761ffdadd11c307c4fc04eea3a418f7d687584e4434af158205
        // but does not meet network target
        // 000000000000d7c0000000000000000000000000000000000000000000000000
        let valid_share = SubmitSharesStandard {
            channel_id: standard_channel_id,
            sequence_number: 1,
            job_id: 1,
            nonce: 134870,
            ntime: 1745611105,
            version: 536870912,
        };
        let res = standard_channel.validate_share(valid_share);

        assert!(matches!(res, Ok(ShareValidationResult::Valid(_, _))));
    }

    #[test]
    fn test_update_channel() {
        let channel_id = 1;
        let user_identity = "user_identity".to_string();
        let extranonce_prefix = [
            83, 116, 114, 97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]
        .to_vec();
        let expected_share_per_minute = 1.0;
        let initial_hashrate = 10.0;
        let share_batch_size = 100;
        let job_store = DefaultJobStore::<StandardJob>::new();
        // this is the most permissive possible max_target
        let max_target = Target::from_le_bytes([0xff; 32]);

        // Create a channel with initial hashrate
        let mut channel = StandardChannel::new(
            channel_id,
            user_identity,
            extranonce_prefix,
            max_target,
            initial_hashrate,
            share_batch_size,
            expected_share_per_minute,
            job_store,
            None,
            None,
        )
        .unwrap();

        // Get the initial target
        let initial_target = channel.get_target().clone();

        // Update the channel with a new hashrate (higher)
        let new_hashrate = 100.0;
        channel
            .update_channel(new_hashrate, Some(max_target))
            .unwrap();

        // Get the new target after update
        let new_target = channel.get_target().clone();

        // The target should be different after updating with a different hashrate
        // old target: 006d0b803685c01b42e00da17006d0b803685c01b42e00da17006d0b803685bf
        // new target: 000aebbc990fff5144366f000aebbc990fff5144366f000aebbc990fff514435
        assert_ne!(initial_target, new_target);

        // The nominal hashrate should be updated
        assert_eq!(channel.get_nominal_hashrate(), new_hashrate);

        // Test invalid hashrate (negative)
        let result = channel.update_channel(-1.0, Some(max_target));
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(StandardChannelError::InvalidNominalHashrate)
        ));

        // Create a not so permissive max_target so we can test a target that exceeds it
        let not_so_permissive_max_target = Target::from_le_bytes([
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x00,
        ]);

        // Try to update with a hashrate that would result in a target exceeding the max_target
        // new target: 2492492492492492492492492492492492492492492492492492492492492491
        // max target: 00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        let very_small_hashrate = 0.1;
        let result =
            channel.update_channel(very_small_hashrate, Some(not_so_permissive_max_target));
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(StandardChannelError::RequestedMaxTargetOutOfRange)
        ));

        // Test successful update with not_so_permissive_max_target
        // new target: 0001179d9861a761ffdadd11c307c4fc04eea3a418f7d687584e4434af158205
        // max target: 00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        let sufficiently_big_hashrate = 1000.0;
        let result = channel.update_channel(
            sufficiently_big_hashrate,
            Some(not_so_permissive_max_target),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_update_extranonce_prefix() {
        let channel_id = 1;
        let user_identity = "user_identity".to_string();
        let extranonce_prefix = [
            83, 116, 114, 97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]
        .to_vec();
        let max_target = Target::from_le_bytes([0xff; 32]);
        let expected_share_per_minute = 1.0;
        let nominal_hashrate = 1_000.0;
        let share_batch_size = 100;
        let job_store = DefaultJobStore::<StandardJob>::new();

        let mut channel = StandardChannel::new(
            channel_id,
            user_identity,
            extranonce_prefix.clone(),
            max_target,
            nominal_hashrate,
            share_batch_size,
            expected_share_per_minute,
            job_store,
            None,
            None,
        )
        .unwrap();

        let current_extranonce_prefix = channel.get_extranonce_prefix();
        assert_eq!(current_extranonce_prefix, &extranonce_prefix);

        let new_extranonce_prefix = [
            83, 116, 114, 97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ]
        .to_vec();

        channel
            .set_extranonce_prefix(new_extranonce_prefix.clone())
            .unwrap();
        let current_extranonce_prefix = channel.get_extranonce_prefix();
        assert_eq!(current_extranonce_prefix, &new_extranonce_prefix);

        let new_extranonce_prefix_too_long = [
            83, 116, 114, 97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 1,
        ]
        .to_vec();
        assert!(channel
            .set_extranonce_prefix(new_extranonce_prefix_too_long)
            .is_err());
    }
}

/// The difficulty-tier commitment (SHARE_TIER_BIND), at the channel level.
///
/// The Ghost semantics of the push bytes (`GHNT` + `sha256(node_id ‖ tier)[..20]`) live in the
/// pool layer; here the commitment is opaque bytes plus a tier label, and what these tests pin is
/// the MACHINERY: byte-identity when the commitment is absent, capture-at-build when it is
/// present, and reassembly from the job's own capture rather than the channel's current state.
#[cfg(test)]
mod tier_commitment_tests {
    use crate::{
        chain_tip::ChainTip,
        server::{
            jobs::{job_store::DefaultJobStore, standard::StandardJob},
            standard::StandardChannel,
        },
        target::tier_target,
    };
    use bitcoin::{transaction::TxOut, Amount, ScriptBuf, Target};
    use std::convert::TryInto;
    use template_distribution_sv2::NewTemplate;

    const SATS: u64 = 5_000_000_000;

    fn a_channel() -> StandardChannel<'static, DefaultJobStore<StandardJob<'static>>> {
        let mut channel = StandardChannel::new_for_pool(
            1,
            "user".to_string(),
            vec![7u8; 20],
            Target::from_le_bytes([0xff; 32]),
            10.0,
            100,
            1.0,
            DefaultJobStore::new(),
            "GHOST PublicPool".to_string(),
        )
        .unwrap();
        channel.set_chain_tip(ChainTip::new(
            [
                200, 53, 253, 129, 214, 31, 43, 84, 179, 58, 58, 76, 128, 213, 24, 53, 38, 144,
                205, 88, 172, 20, 251, 22, 217, 141, 21, 221, 21, 0, 0, 0,
            ]
            .into(),
            503543726,
            1745596960,
        ));
        channel
    }

    /// `coinbase_prefix` shaped like Ghost's TDP hand-off: BIP34 height + 21-byte payout tag,
    /// optionally followed by the 25-byte (plain) node tag.
    fn a_template(with_node_tag: bool) -> NewTemplate<'static> {
        let mut p = vec![0x03, 0x40, 0x1f, 0x0e];
        p.extend_from_slice(&[20u8; 21]);
        if with_node_tag {
            p.extend_from_slice(&[24u8; 25]);
        }
        NewTemplate {
            template_id: 1,
            future_template: false,
            version: 536870912,
            coinbase_tx_version: 2,
            coinbase_prefix: p.try_into().unwrap(),
            coinbase_tx_input_sequence: 4294967294,
            coinbase_tx_value_remaining: SATS,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_locktime: 158,
            merkle_path: vec![].try_into().unwrap(),
        }
    }

    fn reward() -> Vec<TxOut> {
        let mut script_bytes = vec![0u8, 20];
        script_bytes.extend_from_slice(&[0xABu8; 20]);
        vec![TxOut {
            value: Amount::from_sat(SATS),
            script_pubkey: ScriptBuf::from(script_bytes),
        }]
    }

    /// A 25-byte push shaped like an encoded node tag: `[0x18]["GHNT"][20 payload bytes]`.
    fn a_tier_push(fill: u8) -> Vec<u8> {
        let mut push = vec![0x18];
        push.extend_from_slice(b"GHNT");
        push.extend_from_slice(&[fill; 20]);
        push
    }

    /// **The acceptance bar: below-gate builds are byte-identical.** A channel that has been
    /// through the tier machinery (commitment set, then cleared) must produce exactly the bytes
    /// of a channel that has never touched it — compared on the serialized coinbase, not argued.
    #[test]
    fn a_cleared_commitment_restores_byte_identical_builds() {
        let mut untouched = a_channel();
        untouched
            .on_new_template(a_template(true), reward())
            .unwrap();
        let job = untouched.get_active_job().unwrap();
        let pristine = untouched.build_coinbase(&job, &[0u8; 20]).unwrap();

        let mut cycled = a_channel();
        cycled.set_tier_commitment(Some((13, a_tier_push(0x5A))));
        cycled.set_tier_commitment(None);
        cycled.on_new_template(a_template(true), reward()).unwrap();
        let job = cycled.get_active_job().unwrap();
        let rebuilt = cycled.build_coinbase(&job, &[0u8; 20]).unwrap();

        assert_eq!(
            bitcoin::consensus::serialize(&pristine),
            bitcoin::consensus::serialize(&rebuilt),
            "with no commitment the coinbase must be byte-identical to the pre-tier build"
        );
        assert_eq!(cycled.get_active_job().unwrap().get_tier_log2(), None);
    }

    /// Moving the node tag from the template prefix into the extra push costs ZERO scriptSig
    /// bytes: a stripped-prefix + tier-push build serializes to exactly the same length as
    /// today's full-prefix build. This is the budget claim the whole design rests on — the live
    /// scriptSig is at 99/100.
    #[test]
    fn the_tier_stamped_coinbase_is_the_same_length_as_todays() {
        let mut today = a_channel();
        today.on_new_template(a_template(true), reward()).unwrap();
        let job = today.get_active_job().unwrap();
        let todays_bytes =
            bitcoin::consensus::serialize(&today.build_coinbase(&job, &[0u8; 20]).unwrap());

        let mut tiered = a_channel();
        tiered.set_tier_commitment(Some((13, a_tier_push(0x5A))));
        tiered.on_new_template(a_template(false), reward()).unwrap();
        let job = tiered.get_active_job().unwrap();
        let tiered_bytes =
            bitcoin::consensus::serialize(&tiered.build_coinbase(&job, &[0u8; 20]).unwrap());

        assert_eq!(
            todays_bytes.len(),
            tiered_bytes.len(),
            "binding the tier must not change the coinbase length"
        );
        // And the push really is in there, as its own push after the pool tag.
        let needle = a_tier_push(0x5A);
        assert!(
            tiered_bytes
                .windows(needle.len())
                .any(|w| w == needle.as_slice()),
            "the tier push must appear in the tiered coinbase"
        );
        assert!(
            !todays_bytes
                .windows(needle.len())
                .any(|w| w == needle.as_slice()),
            "and must not appear in today's"
        );
    }

    /// **Capture at build.** The tier and its push are the JOB's, frozen at build time: moving
    /// the channel's commitment afterwards must change neither the job's label nor the bytes its
    /// coinbase reassembles to. Deriving either from channel state at share time was the failure
    /// mode this design exists to avoid — it would rebuild a coinbase the miner never hashed,
    /// discovered on a won block.
    #[test]
    fn a_jobs_tier_and_bytes_survive_the_channel_moving_on() {
        let mut channel = a_channel();
        channel.set_tier_commitment(Some((13, a_tier_push(0x5A))));
        channel
            .on_new_template(a_template(false), reward())
            .unwrap();
        let job = channel.get_active_job().unwrap();
        let job_id = job.get_job_id();
        let built =
            bitcoin::consensus::serialize(&channel.build_coinbase(&job, &[0u8; 20]).unwrap());
        let skeleton = channel.coinbase_skeleton().expect("skeleton");

        // The channel's tier moves on (vardiff crossed a boundary before the next build).
        channel.set_tier_commitment(Some((14, a_tier_push(0xA5))));

        assert_eq!(
            channel.job_tier_log2(job_id),
            Some(13),
            "the job keeps the tier its coinbase committed to"
        );
        let job_again = channel.get_active_job().unwrap();
        let rebuilt =
            bitcoin::consensus::serialize(&channel.build_coinbase(&job_again, &[0u8; 20]).unwrap());
        assert_eq!(
            built, rebuilt,
            "reassembly must use the job's captured push, not the channel's current one"
        );
        assert_eq!(
            channel.coinbase_skeleton().expect("skeleton"),
            skeleton,
            "the skeleton must be equally immune"
        );
    }

    /// A tier-stamped job validates against its TIER's exact target, not the channel target —
    /// the coinbase committed to `2^tier`, and the accounting layer credits exactly that, so the
    /// validation threshold has to be the same number.
    #[test]
    fn a_tier_stamped_job_binds_to_its_tiers_exact_target() {
        let mut channel = a_channel();
        channel.set_tier_commitment(Some((13, a_tier_push(0x5A))));
        channel
            .on_new_template(a_template(false), reward())
            .unwrap();
        let job_id = channel.get_active_job().unwrap().get_job_id();
        assert_eq!(
            channel.job_target(job_id),
            Some(&tier_target(13)),
            "a stamped job's validation target must be its tier's exact target"
        );
        assert_eq!(
            channel.job_target(job_id).unwrap().difficulty_float(),
            8192.0
        );
    }
}
