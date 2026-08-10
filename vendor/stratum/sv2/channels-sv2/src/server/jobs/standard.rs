//! Abstraction of a standard mining job for SV2 mining servers.
//!
//! This module provides the [`StandardJob`] struct, which encapsulates all the state and
//! protocol-relevant data for a standard mining job as handled by a mining server.
//!
//! ## Responsibilities
//!
//! - **Origin Tracking**: Captures the originating `NewTemplate` message and extranonce prefix at
//!   creation time.
//! - **Coinbase Outputs Management**: Combines spendable and unspendable coinbase outputs from the
//!   template and additional outputs.
//! - **Wire-format Message**: Stores the protocol wire-format `NewMiningJob` message for downstream
//!   communication.
//! - **Lifecycle Management**: Supports activation and state transitions of jobs, including
//!   future/non-future status.
//!
//! ## Usage
//!
//! Use this struct when creating, activating, or managing standard mining jobs in SV2-compliant
//! mining servers.

use crate::{
    outputs::deserialize_template_outputs,
    server::jobs::{error::StandardJobError, Job},
};
use binary_sv2::{Sv2Option, U256};
use bitcoin::transaction::TxOut;
use mining_sv2::NewMiningJob;
use template_distribution_sv2::NewTemplate;

/// Abstraction of a standard mining job with:
/// - the `NewTemplate` message that originated it
/// - the extranonce prefix associated with the channel at the time of job creation
/// - all coinbase outputs (spendable + unspendable) associated with the job
/// - the `NewMiningJob` message to be sent across the wire
#[derive(Debug, Clone)]
pub struct StandardJob<'a> {
    template: NewTemplate<'a>,
    extranonce_prefix: Vec<u8>,
    coinbase_outputs: Vec<TxOut>,
    job_message: NewMiningJob<'a>,
    /// The factory's extra scriptSig pushes in force when THIS job was built (empty below the
    /// tier gate). Captured per job because the factory's value moves between builds, and
    /// reassembling this job's coinbase with a later value would produce a transaction the
    /// miner never hashed — on the block-found path, a lost block.
    extra_script_sig: Vec<u8>,
    /// The power-of-two difficulty tier (`log2`) this job's coinbase committed to via its
    /// tier-bound node tag, when built at/above `SHARE_TIER_BIND`. `None` below the gate.
    ///
    /// Captured AT BUILD, deliberately not derived from `job_id_to_target` at share time: the
    /// coinbase is built when the (usually future) job is created, but `job_id_to_target` binds
    /// at ACTIVATION — by which point vardiff may have moved the channel target, and the tier
    /// read back would not be the one the coinbase committed to.
    tier_log2: Option<u32>,
}

impl Job for StandardJob<'_> {
    /// Returns the job ID for this job.
    fn get_job_id(&self) -> u32 {
        self.job_message.job_id
    }

    /// Activates the job by setting the minimum ntime field.
    fn activate(&mut self, min_ntime: u32) {
        self.activate(min_ntime);
    }
}

impl<'a> StandardJob<'a> {
    /// Creates a new standard job from a template.
    ///
    /// Combines coinbase outputs from the template and any additional outputs.
    /// Returns an error if coinbase outputs cannot be deserialized.
    pub fn from_template(
        template: NewTemplate<'a>,
        extranonce_prefix: Vec<u8>,
        additional_coinbase_outputs: Vec<TxOut>,
        job_message: NewMiningJob<'a>,
    ) -> Result<Self, StandardJobError> {
        let template_coinbase_outputs = deserialize_template_outputs(
            template.coinbase_tx_outputs.to_vec(),
            template.coinbase_tx_outputs_count,
        )
        .map_err(|_| StandardJobError::FailedToDeserializeCoinbaseOutputs)?;

        let mut coinbase_outputs = vec![];
        coinbase_outputs.extend(additional_coinbase_outputs);
        coinbase_outputs.extend(template_coinbase_outputs);

        Ok(Self {
            template,
            extranonce_prefix,
            coinbase_outputs,
            job_message,
            extra_script_sig: Vec::new(),
            tier_log2: None,
        })
    }
    /// Returns the job ID for this job.
    pub fn get_job_id(&self) -> u32 {
        self.job_message.job_id
    }
    /// The factory extra scriptSig pushes captured when this job was built.
    pub fn get_extra_script_sig(&self) -> &[u8] {
        &self.extra_script_sig
    }
    /// Records the factory extra scriptSig pushes this job's coinbase was built with.
    pub fn set_extra_script_sig(&mut self, extra: Vec<u8>) {
        self.extra_script_sig = extra;
    }
    /// The difficulty tier (`log2`) this job's coinbase committed to, if any.
    pub fn get_tier_log2(&self) -> Option<u32> {
        self.tier_log2
    }
    /// Labels this job with the tier its coinbase committed to. Set at build time by the channel
    /// that chose the tier; the tag bytes themselves travel in `extra_script_sig`.
    pub fn set_tier_log2(&mut self, tier_log2: Option<u32>) {
        self.tier_log2 = tier_log2;
    }
    /// Returns all coinbase outputs (spendable and unspendable) for this job.
    pub fn get_coinbase_outputs(&self) -> &Vec<TxOut> {
        &self.coinbase_outputs
    }
    /// Returns the extranonce prefix used for this job.
    pub fn get_extranonce_prefix(&self) -> &Vec<u8> {
        &self.extranonce_prefix
    }
    /// Returns the `NewMiningJob` message for this job.
    pub fn get_job_message(&self) -> &NewMiningJob<'a> {
        &self.job_message
    }
    /// Returns the originating `NewTemplate` message for this job.
    pub fn get_template(&self) -> &NewTemplate<'a> {
        &self.template
    }
    /// Returns the merkle root for this job.
    pub fn get_merkle_root(&self) -> &U256<'a> {
        &self.job_message.merkle_root
    }
    /// Returns true if the job is a future job (not yet activated).
    pub fn is_future(&self) -> bool {
        self.job_message.min_ntime.clone().into_inner().is_none()
    }
    /// Activates the job by setting the minimum ntime field.
    ///
    /// Should be called when activating future jobs.
    pub fn activate(&mut self, min_ntime: u32) {
        self.job_message.min_ntime = Sv2Option::new(Some(min_ntime));
    }
}
