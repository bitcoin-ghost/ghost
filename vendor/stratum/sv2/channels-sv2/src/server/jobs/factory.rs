//! Abstraction of a factory for creating Sv2 Extended or Standard Jobs.
//!
//! This module provides the [`JobFactory`] struct, which enables the creation
//! of uniquely identified Extended and Standard mining jobs as required by
//! Stratum V2 (SV2) mining servers. It manages job ID assignment, construction
//! of coinbase transactions, and correct association of template and custom job
//! parameters.
//!
//! ## Responsibilities
//!
//! - **Job ID Generation**: Ensures all jobs have unique IDs per factory instance.
//! - **Job Construction**: Builds Extended and Standard jobs from SV2 templates and custom job
//!   messages, assembling all required coinbase transaction data and metadata.
//! - **Coinbase Output Validation**: Verifies that coinbase outputs match SV2 template constraints
//!   and protocol rules.
//! - **Version Rolling**: Tracks version rolling allowance for created jobs.
//!
//! ## Usage
//!
//! Designed for mining server implementations. Use `JobFactory` to generate jobs in response to
//! incoming SV2 messages (`NewTemplate`, `SetCustomMiningJob`), ensuring protocol correctness and
//! uniqueness of job IDs.
use crate::{
    bip141::try_strip_bip141,
    chain_tip::ChainTip,
    merkle_root::merkle_root_from_path,
    outputs::deserialize_template_outputs,
    server::jobs::{error::*, extended::ExtendedJob, standard::StandardJob},
};
use binary_sv2::{Sv2Option, B0255};
use bitcoin::{
    absolute::LockTime,
    blockdata::witness::Witness,
    consensus::{serialize, Decodable},
    transaction::{OutPoint, Transaction, TxIn, TxOut, Version},
    Amount, Sequence,
};
use mining_sv2::{NewExtendedMiningJob, NewMiningJob, SetCustomMiningJob};
use std::convert::TryInto;
use template_distribution_sv2::NewTemplate;

#[derive(Debug, PartialEq, Eq, Clone)]
struct JobIdFactory {
    state: u32,
}

impl JobIdFactory {
    /// Creates a new [`Id`] instance initialized to `0`.
    fn new() -> Self {
        Self { state: 0 }
    }

    /// Increments then returns the internal state on a new ID.
    fn next(&mut self) -> u32 {
        self.state += 1;
        self.state
    }
}

/// Consensus limit on a coinbase scriptSig, in bytes.
pub const MAX_COINBASE_SCRIPT_SIG: usize = 100;

/// Bytes reserved for the BIP34 block-height push.
///
/// One opcode plus up to four bytes of height. Four is only needed above height 16,777,215, so this
/// is one byte generous today and stays correct for as long as the chain runs.
pub const BIP34_HEIGHT_RESERVE: usize = 5;

/// Fixed serialized-transaction bytes ahead of the scriptSig.
///
/// version(4) + segwit marker/flag(2) + input count(1) + prev outpoint(32) + index(4) +
/// script length(1). Named because it was previously six magic numbers added up inline, twice.
pub const COINBASE_HEADER_BYTES: usize = 4 + 2 + 1 + 32 + 4 + 1;

/// A Factory for creating Extended or Standard Jobs.
///
/// Ensures unique job ids.
///
/// Enables creation of new Extended Jobs from NewTemplate and SetCustomMiningJob messages.
///
/// Enables creation of new Standard Jobs from NewTemplate messages.
#[derive(Debug, Clone)]
pub struct JobFactory {
    job_id_factory: JobIdFactory,
    version_rolling_allowed: bool,
    pool_tag_string: Option<String>,
    miner_tag_string: Option<String>,
    /// Extra scriptSig pushes appended after the pool/miner tag, opaque to this factory.
    ///
    /// Ghost puts its payout-identity and node-identity tags here. They are passed in already
    /// encoded — including their `OP_PUSHBYTES` opcodes — rather than built here, because they are
    /// Ghost semantics and this is vendored upstream code: keeping the meaning out of the fork
    /// keeps the rebase diff to the budget arithmetic, which is the part upstream would want too.
    ///
    /// What the factory *does* owe them is room. See [`Self::pool_miner_tag_budget`].
    extra_script_sig: Vec<u8>,
}

impl JobFactory {
    /// Creates a new [`JobFactory`] instance.
    ///
    /// The `pool_tag_string` and `miner_tag_string` are optional and will be added to the coinbase
    /// scriptSig.
    ///
    /// Version rolling is always allowed for standard jobs, so the `version_rolling_allowed`
    /// parameter is only relevant for creating extended jobs.
    pub fn new(
        version_rolling_allowed: bool,
        pool_tag_string: Option<String>,
        miner_tag_string: Option<String>,
    ) -> Self {
        Self {
            job_id_factory: JobIdFactory::new(),
            version_rolling_allowed,
            pool_tag_string,
            miner_tag_string,
            extra_script_sig: Vec::new(),
        }
    }

    /// Append extra, already-encoded scriptSig pushes to every job this factory builds.
    ///
    /// They come out of the same 100-byte budget as everything else, so adding them *shrinks* what
    /// the pool and miner tags may occupy — which is the whole reason this is a setter on the
    /// factory rather than something spliced in by the caller afterwards. A caller that appended
    /// bytes itself would produce an over-length scriptSig, and the first time anyone found out
    /// would be a won block rejected by consensus.
    pub fn with_extra_script_sig(mut self, extra: Vec<u8>) -> Self {
        self.extra_script_sig = extra;
        self
    }

    /// How many bytes the pool+miner tag may occupy, given everything else in the scriptSig.
    ///
    /// Derived rather than written down. This was a literal `61` with the arithmetic in a comment
    /// beside it, which is fine until one of the terms changes — and then the guard passes while
    /// the coinbase it guards is over the consensus limit. The failure surfaces only on a won
    /// block, which is the most expensive place to discover anything.
    ///
    /// Saturating, so an extra push large enough to consume the whole budget yields zero rather
    /// than wrapping to an enormous allowance.
    pub fn pool_miner_tag_budget(&self, full_extranonce_size: usize) -> usize {
        MAX_COINBASE_SCRIPT_SIG
            .saturating_sub(BIP34_HEIGHT_RESERVE)
            .saturating_sub(1) // OP_PUSHBYTES for the pool/miner tag
            .saturating_sub(1 + full_extranonce_size)
            .saturating_sub(self.extra_script_sig.len())
    }

    /// Everything in the scriptSig before the extranonce bytes themselves, including the
    /// `OP_PUSHBYTES` that introduces them.
    ///
    /// **Four places used to assemble this independently** — two in this factory, and, most
    /// dangerously, `StandardChannel::validate_share` on the block-found path. That last one only
    /// runs when the pool wins, so a disagreement between them would produce a coinbase different
    /// from the one the miner actually hashed, and the block would be rejected. Nobody would find
    /// out until it cost a block.
    ///
    /// One assembler removes the whole class of that bug rather than the current instance of it.
    pub fn script_sig_before_extranonce(
        &self,
        template_coinbase_prefix: &[u8],
        full_extranonce_size: usize,
    ) -> Result<Vec<u8>, JobFactoryError> {
        let mut script_sig = template_coinbase_prefix.to_vec();
        script_sig.extend_from_slice(&self.op_pushbytes_pool_miner_tag(full_extranonce_size)?);
        script_sig.extend_from_slice(&self.extra_script_sig);
        // The extranonce stays last: the prefix/suffix split is "everything before it" and
        // "everything after it", so anything appended behind would land on the wrong side.
        script_sig.push(full_extranonce_size as u8);

        // The only check that sees the WHOLE scriptSig.
        //
        // `pool_miner_tag_budget` reserves a nominal `BIP34_HEIGHT_RESERVE` for the template's
        // prefix, which holds while the template provider sends a bare height push. Ghost's does
        // not — it carries the payout and node tags there, ten times that reserve — and no amount
        // of care in the tag guard can notice, because the template prefix arrives from another
        // program entirely.
        //
        // So the total is measured on the assembled bytes. An over-length scriptSig is not a
        // warning; it is a block the network rejects, found the one time it matters.
        let total = script_sig.len() + full_extranonce_size;
        if total > MAX_COINBASE_SCRIPT_SIG {
            return Err(JobFactoryError::CoinbaseTxPrefixError);
        }
        Ok(script_sig)
    }

    /// Returns a byte vector with the OP_PUSHBYTES opcode and the pool+miner tag.
    ///
    /// The character `/` is used as a delimiter.
    ///
    /// If no pool or miner tag is provided, the delimiters are still added.
    pub fn op_pushbytes_pool_miner_tag(
        &self,
        full_extranonce_size: usize,
    ) -> Result<Vec<u8>, JobFactoryError> {
        let mut pool_miner_tag = vec![];
        pool_miner_tag.extend_from_slice(b"/");
        if let Some(pool_tag_string) = &self.pool_tag_string {
            pool_miner_tag.extend_from_slice(pool_tag_string.as_bytes());
        }
        pool_miner_tag.extend_from_slice(b"/");
        if let Some(miner_tag_string) = &self.miner_tag_string {
            pool_miner_tag.extend_from_slice(miner_tag_string.as_bytes());
        }
        pool_miner_tag.extend_from_slice(b"/");

        // The budget is computed from the parts rather than hardcoded, because the miner tag is
        // caller-supplied: a long one plus the extra pushes would otherwise pass a stale literal
        // and produce a scriptSig over the 100-byte consensus limit. That is only discoverable on
        // a won block.
        let budget = self.pool_miner_tag_budget(full_extranonce_size);
        let op_pushbytes = match pool_miner_tag.len() {
            len if (1..=budget).contains(&len) => len as u8,
            _ => return Err(JobFactoryError::CoinbaseTxPrefixError),
        };

        let mut op_pushbytes_pool_miner_tag = vec![];
        op_pushbytes_pool_miner_tag.push(op_pushbytes);
        op_pushbytes_pool_miner_tag.extend_from_slice(&pool_miner_tag);

        Ok(op_pushbytes_pool_miner_tag)
    }

    /// Creates a new job from a template.
    ///
    /// This job (and related shares) is fully committed to:
    /// - The template
    /// - The additional coinbase outputs (added to the outputs coming from the template)
    /// - The extranonce prefix of the channel at the time of job creation
    ///
    /// The optional `ChainTip` defines whether the job will be future or not.
    ///
    /// Version rolling is always allowed for standard jobs, so the `version_rolling_allowed`
    /// parameter is ignored.
    ///
    /// It's up to the caller to ensure that the sum of `additional_coinbase_outputs` is equal to
    /// available template revenue. Returns an error otherwise.
    pub fn new_standard_job<'a>(
        &mut self,
        channel_id: u32,
        chain_tip: Option<ChainTip>,
        extranonce_prefix: Vec<u8>,
        template: NewTemplate<'a>,
        additional_coinbase_outputs: Vec<TxOut>,
    ) -> Result<StandardJob<'a>, JobFactoryError> {
        let coinbase_outputs_sum = additional_coinbase_outputs
            .iter()
            .map(|o| o.value.to_sat())
            .sum::<u64>();
        if coinbase_outputs_sum != template.coinbase_tx_value_remaining {
            return Err(JobFactoryError::InvalidCoinbaseOutputsSum);
        }

        let job_id = self.job_id_factory.next();

        let version = template.version;

        let coinbase_tx_prefix = self.coinbase_tx_prefix(
            template.clone(),
            additional_coinbase_outputs.clone(),
            extranonce_prefix.len(),
        )?;
        let coinbase_tx_suffix = self.coinbase_tx_suffix(
            template.clone(),
            additional_coinbase_outputs.clone(),
            extranonce_prefix.len(),
        )?;
        let merkle_path = template.merkle_path.clone();
        let merkle_root = merkle_root_from_path(
            &coinbase_tx_prefix,
            &coinbase_tx_suffix,
            &extranonce_prefix,
            &merkle_path.inner_as_ref(),
        )
        .expect("merkle root must be valid")
        .try_into()
        .expect("merkle root must be 32 bytes");

        let job_message = match template.future_template {
            true => NewMiningJob {
                channel_id,
                job_id,
                min_ntime: Sv2Option::new(None),
                version,
                merkle_root,
            },
            false => {
                let min_ntime = match chain_tip {
                    Some(chain_tip) => Some(chain_tip.min_ntime()),
                    None => return Err(JobFactoryError::ChainTipRequired),
                };

                NewMiningJob {
                    channel_id,
                    job_id,
                    min_ntime: Sv2Option::new(min_ntime),
                    version,
                    merkle_root,
                }
            }
        };

        let job = StandardJob::from_template(
            template,
            extranonce_prefix,
            additional_coinbase_outputs,
            job_message,
        )
        .map_err(|_| JobFactoryError::DeserializeCoinbaseOutputsError)?;

        Ok(job)
    }

    /// Creates a new job from a template.
    ///
    /// This job (and related shares) is fully committed to:
    /// - The template
    /// - The additional coinbase outputs (added to the outputs coming from the template)
    /// - The extranonce prefix of the channel at the time of job creation
    ///
    /// The optional `ChainTip` defines whether the job will be future or not.
    ///
    /// It's up to the caller to ensure that the sum of `additional_coinbase_outputs` is equal to
    /// available template revenue. Returns an error otherwise.
    pub fn new_extended_job<'a>(
        &mut self,
        channel_id: u32,
        chain_tip: Option<ChainTip>,
        extranonce_prefix: Vec<u8>,
        template: NewTemplate<'a>,
        additional_coinbase_outputs: Vec<TxOut>,
        full_extranonce_size: usize,
    ) -> Result<ExtendedJob<'a>, JobFactoryError> {
        let coinbase_outputs_sum = additional_coinbase_outputs
            .iter()
            .map(|o| o.value.to_sat())
            .sum::<u64>();
        if coinbase_outputs_sum != template.coinbase_tx_value_remaining {
            return Err(JobFactoryError::InvalidCoinbaseOutputsSum);
        }

        let job_id = self.job_id_factory.next();

        let version = template.version;

        let coinbase_tx_prefix = self.coinbase_tx_prefix(
            template.clone(),
            additional_coinbase_outputs.clone(),
            full_extranonce_size,
        )?;
        let coinbase_tx_suffix = self.coinbase_tx_suffix(
            template.clone(),
            additional_coinbase_outputs.clone(),
            full_extranonce_size,
        )?;

        // strip bip141 bytes from coinbase_tx_prefix and coinbase_tx_suffix
        let (coinbase_tx_prefix_stripped_bip141, coinbase_tx_suffix_stripped_bip141) =
            try_strip_bip141(&coinbase_tx_prefix, &coinbase_tx_suffix)
                .map_err(|_| JobFactoryError::FailedToStripBip141)?
                .ok_or(JobFactoryError::FailedToStripBip141)?;

        let merkle_path = template.merkle_path.clone();

        let job_message = match template.future_template {
            true => NewExtendedMiningJob {
                channel_id,
                job_id,
                min_ntime: Sv2Option::new(None),
                version,
                version_rolling_allowed: self.version_rolling_allowed,
                merkle_path,
                coinbase_tx_prefix: coinbase_tx_prefix_stripped_bip141
                    .try_into()
                    .map_err(|_| JobFactoryError::CoinbaseTxPrefixError)?,
                coinbase_tx_suffix: coinbase_tx_suffix_stripped_bip141
                    .try_into()
                    .map_err(|_| JobFactoryError::CoinbaseTxSuffixError)?,
            },
            false => {
                let min_ntime = match chain_tip {
                    Some(chain_tip) => Some(chain_tip.min_ntime()),
                    None => return Err(JobFactoryError::ChainTipRequired),
                };
                NewExtendedMiningJob {
                    channel_id,
                    job_id,
                    min_ntime: Sv2Option::new(min_ntime),
                    version,
                    version_rolling_allowed: self.version_rolling_allowed,
                    merkle_path,
                    coinbase_tx_prefix: coinbase_tx_prefix_stripped_bip141
                        .try_into()
                        .map_err(|_| JobFactoryError::CoinbaseTxPrefixError)?,
                    coinbase_tx_suffix: coinbase_tx_suffix_stripped_bip141
                        .try_into()
                        .map_err(|_| JobFactoryError::CoinbaseTxSuffixError)?,
                }
            }
        };

        let job = ExtendedJob::from_template(
            template,
            extranonce_prefix,
            additional_coinbase_outputs,
            coinbase_tx_prefix,
            coinbase_tx_suffix,
            job_message,
        )
        .map_err(|_| JobFactoryError::DeserializeCoinbaseOutputsError)?;

        Ok(job)
    }

    /// Creates a new coinbase_tx_prefix and coinbase_tx_suffix from a template.
    ///
    /// To be used by a Sv2 Job Declarator Client to create a `DeclareMiningJob` message.
    ///
    /// It's up to the caller to ensure that the sum of `additional_coinbase_outputs`
    /// is equal to available template revenue. Returns an error otherwise.
    pub fn new_coinbase_tx_prefix_and_suffix(
        &self,
        template: NewTemplate<'_>,
        additional_coinbase_outputs: Vec<TxOut>,
        full_extranonce_size: usize,
    ) -> Result<(Vec<u8>, Vec<u8>), JobFactoryError> {
        let coinbase_outputs_sum = additional_coinbase_outputs
            .iter()
            .map(|o| o.value.to_sat())
            .sum::<u64>();
        if coinbase_outputs_sum != template.coinbase_tx_value_remaining {
            return Err(JobFactoryError::InvalidCoinbaseOutputsSum);
        }

        let coinbase_tx_prefix = self.coinbase_tx_prefix(
            template.clone(),
            additional_coinbase_outputs.clone(),
            full_extranonce_size,
        )?;
        let coinbase_tx_suffix =
            self.coinbase_tx_suffix(template, additional_coinbase_outputs, full_extranonce_size)?;
        Ok((coinbase_tx_prefix, coinbase_tx_suffix))
    }

    /// Creates a new `SetCustomMiningJob` message from a template.
    ///
    /// To be used by a Sv2 Job Declarator Client.
    ///
    /// It's up to the caller to ensure that the sum of the additional coinbase outputs is equal to
    /// available template revenue.
    #[allow(clippy::too_many_arguments)]
    pub fn new_custom_job<'a>(
        &self,
        channel_id: u32,
        request_id: u32,
        token: B0255<'a>,
        chain_tip: ChainTip,
        template: NewTemplate<'a>,
        additional_coinbase_outputs: Vec<TxOut>,
        full_extranonce_size: usize,
    ) -> Result<SetCustomMiningJob<'a>, JobFactoryError> {
        let coinbase_outputs_sum = additional_coinbase_outputs
            .iter()
            .map(|o| o.value.to_sat())
            .sum::<u64>();
        if coinbase_outputs_sum != template.coinbase_tx_value_remaining {
            return Err(JobFactoryError::InvalidCoinbaseOutputsSum);
        }

        let template_outputs = deserialize_template_outputs(
            template.coinbase_tx_outputs.to_vec(),
            template.coinbase_tx_outputs_count,
        )
        .map_err(|_| JobFactoryError::DeserializeCoinbaseOutputsError)?;

        let mut coinbase_tx_outputs = vec![];
        coinbase_tx_outputs.extend_from_slice(additional_coinbase_outputs.as_slice());
        coinbase_tx_outputs.extend_from_slice(template_outputs.as_slice());

        let serialized_outputs = serialize(&coinbase_tx_outputs);

        let coinbase_prefix = self.script_sig_before_extranonce(
            &template.coinbase_prefix.to_vec(),
            full_extranonce_size,
        )?;

        let set_custom_mining_job = SetCustomMiningJob {
            channel_id,
            request_id,
            token,
            version: template.version,
            prev_hash: chain_tip.prev_hash(),
            min_ntime: chain_tip.min_ntime(),
            nbits: chain_tip.nbits(),
            coinbase_tx_version: template.coinbase_tx_version,
            coinbase_prefix: coinbase_prefix
                .try_into()
                .map_err(|_| JobFactoryError::FailedToSerializeCoinbasePrefix)?,
            coinbase_tx_input_n_sequence: template.coinbase_tx_input_sequence,
            coinbase_tx_outputs: serialized_outputs
                .try_into()
                .map_err(|_| JobFactoryError::FailedToSerializeCoinbaseOutputs)?,
            coinbase_tx_locktime: template.coinbase_tx_locktime,
            merkle_path: template.merkle_path.clone(),
        };

        Ok(set_custom_mining_job)
    }

    /// Creates a new Extended Job from a SetCustomMiningJob message.
    ///
    /// Assumes that the SetCustomMiningJob message has already been validated.
    ///
    /// To be used by Extended Channels on a Sv2 Pool Server.
    pub fn new_extended_job_from_custom_job<'a>(
        &mut self,
        set_custom_mining_job: SetCustomMiningJob<'a>,
        extranonce_prefix: Vec<u8>,
        full_extranonce_size: usize,
    ) -> Result<ExtendedJob<'a>, JobFactoryError> {
        let serialized_outputs = set_custom_mining_job
            .coinbase_tx_outputs
            .inner_as_ref()
            .to_vec();

        let coinbase_outputs = Vec::<TxOut>::consensus_decode(&mut serialized_outputs.as_slice())
            .map_err(|_| JobFactoryError::DeserializeCoinbaseOutputsError)?;

        let job_id = self.job_id_factory.next();

        let version = set_custom_mining_job.version;

        let coinbase_tx_prefix =
            self.custom_coinbase_tx_prefix(set_custom_mining_job.clone(), full_extranonce_size)?;
        let coinbase_tx_suffix =
            self.custom_coinbase_tx_suffix(set_custom_mining_job.clone(), full_extranonce_size)?;

        // strip bip141 bytes from coinbase_tx_prefix and coinbase_tx_suffix
        let (coinbase_tx_prefix_stripped_bip141, coinbase_tx_suffix_stripped_bip141) =
            try_strip_bip141(&coinbase_tx_prefix, &coinbase_tx_suffix)
                .map_err(|_| JobFactoryError::FailedToStripBip141)?
                .ok_or(JobFactoryError::FailedToStripBip141)?;

        let merkle_path = set_custom_mining_job.merkle_path.clone().into_static();

        let job_message = NewExtendedMiningJob {
            channel_id: set_custom_mining_job.channel_id,
            job_id,
            min_ntime: Sv2Option::new(Some(set_custom_mining_job.min_ntime)),
            version,
            version_rolling_allowed: self.version_rolling_allowed,
            coinbase_tx_prefix: coinbase_tx_prefix_stripped_bip141
                .clone()
                .try_into()
                .map_err(|_| JobFactoryError::CoinbaseTxPrefixError)?,
            coinbase_tx_suffix: coinbase_tx_suffix_stripped_bip141
                .clone()
                .try_into()
                .map_err(|_| JobFactoryError::CoinbaseTxSuffixError)?,
            merkle_path,
        };

        let job = ExtendedJob::from_custom_job(
            set_custom_mining_job,
            extranonce_prefix,
            coinbase_outputs,
            coinbase_tx_prefix,
            coinbase_tx_suffix,
            job_message,
        );

        Ok(job)
    }
}

// impl block with private methods
impl JobFactory {
    // build a coinbase transaction from a SetCustomMiningJob
    // this is only used to extract coinbase_tx_prefix and coinbase_tx_suffix from the custom
    // coinbase
    fn custom_coinbase(
        &self,
        m: SetCustomMiningJob<'_>,
        full_extranonce_size: usize,
    ) -> Result<Transaction, JobFactoryError> {
        let deserialized_outputs = Vec::<TxOut>::consensus_decode(
            &mut m.coinbase_tx_outputs.inner_as_ref().to_vec().as_slice(),
        )
        .map_err(|_| JobFactoryError::DeserializeCoinbaseOutputsError)?;

        let mut script_sig = vec![];
        script_sig.extend_from_slice(m.coinbase_prefix.inner_as_ref());
        script_sig.extend_from_slice(&vec![0; full_extranonce_size]);

        // Create transaction input
        let tx_in = TxIn {
            previous_output: OutPoint::null(),
            script_sig: script_sig.into(),
            sequence: Sequence(m.coinbase_tx_input_n_sequence),
            witness: Witness::from(vec![vec![0; 32]]), /* note: 32 bytes of zeros is only safe to
                                                        * assume now, this could change in future
                                                        * soft forks */
        };

        Ok(Transaction {
            version: Version::non_standard(m.coinbase_tx_version as i32),
            lock_time: LockTime::from_consensus(m.coinbase_tx_locktime),
            input: vec![tx_in],
            output: deserialized_outputs,
        })
    }

    fn custom_coinbase_tx_prefix(
        &self,
        m: SetCustomMiningJob<'_>,
        full_extranonce_size: usize,
    ) -> Result<Vec<u8>, JobFactoryError> {
        let coinbase = self.custom_coinbase(m.clone(), full_extranonce_size)?;
        let serialized_coinbase = serialize(&coinbase);

        let index = 4 // tx version
            + 2 // segwit
            + 1 // number of inputs
            + 32 // prev OutPoint
            + 4 // index
            + 1 // bytes in script
            + m.coinbase_prefix.inner_as_ref().len();

        let coinbase_tx_prefix = serialized_coinbase[0..index].to_vec();

        Ok(coinbase_tx_prefix)
    }

    fn custom_coinbase_tx_suffix(
        &self,
        m: SetCustomMiningJob<'_>,
        full_extranonce_size: usize,
    ) -> Result<Vec<u8>, JobFactoryError> {
        let coinbase = self.custom_coinbase(m.clone(), full_extranonce_size)?;
        let serialized_coinbase = serialize(&coinbase);

        let index = 4 // tx version
            + 2 // segwit
            + 1 // number of inputs
            + 32 // prev OutPoint
            + 4 // index
            + 1 // bytes in script
            + m.coinbase_prefix.inner_as_ref().len()
            + full_extranonce_size;

        let coinbase_tx_suffix = serialized_coinbase[index..].to_vec();

        Ok(coinbase_tx_suffix)
    }

    // build a coinbase transaction from some template in the JobFactory
    fn coinbase(
        &self,
        template: NewTemplate<'_>,
        coinbase_reward_outputs: Vec<TxOut>,
        full_extranonce_size: usize,
    ) -> Result<Transaction, JobFactoryError> {
        // check that the sum of the additional coinbase outputs is equal to the value remaining in
        // the active template
        let mut coinbase_reward_outputs_sum = Amount::from_sat(0);
        for output in coinbase_reward_outputs.iter() {
            coinbase_reward_outputs_sum = coinbase_reward_outputs_sum
                .checked_add(output.value)
                .ok_or(JobFactoryError::CoinbaseOutputsSumOverflow)?;
        }

        if template.coinbase_tx_value_remaining < coinbase_reward_outputs_sum.to_sat() {
            return Err(JobFactoryError::InvalidCoinbaseOutputsSum);
        }

        let mut outputs = vec![];

        for output in coinbase_reward_outputs.iter() {
            outputs.push(output.clone());
        }

        let mut template_outputs = deserialize_template_outputs(
            template.coinbase_tx_outputs.to_vec(),
            template.coinbase_tx_outputs_count,
        )
        .map_err(|_| JobFactoryError::DeserializeCoinbaseOutputsError)?;

        outputs.append(&mut template_outputs);

        let mut script_sig = self.script_sig_before_extranonce(
            &template.coinbase_prefix.to_vec(),
            full_extranonce_size,
        )?;
        script_sig.extend_from_slice(&vec![0; full_extranonce_size]);

        let tx_in = TxIn {
            previous_output: OutPoint::null(),
            script_sig: script_sig.into(),
            sequence: Sequence(template.coinbase_tx_input_sequence),
            witness: Witness::from(vec![vec![0; 32]]), /* note: 32 bytes of zeros is only safe to
                                                        * assume now, this could change in future
                                                        * soft forks */
        };

        Ok(Transaction {
            version: Version::non_standard(template.coinbase_tx_version as i32),
            lock_time: LockTime::from_consensus(template.coinbase_tx_locktime),
            input: vec![tx_in],
            output: outputs,
        })
    }

    /// Byte offset, within the serialized coinbase, at which the extranonce begins.
    ///
    /// The prefix ends here and the suffix starts `full_extranonce_size` later. It was computed
    /// twice — once in `coinbase_tx_prefix`, once in `coinbase_tx_suffix` — from a re-derived tag
    /// length rather than the tag actually emitted. Two copies of an offset is one copy too many:
    /// if they ever disagree the split lands mid-field, and the coinbase a miner reassembles is
    /// not the one whose hash it submits.
    ///
    /// Measured from the real bytes (`op_pushbytes_pool_miner_tag()`) instead of re-adding up the
    /// delimiters, so it cannot drift from what was written.
    fn extranonce_offset(
        &self,
        template: &NewTemplate<'_>,
        full_extranonce_size: usize,
    ) -> Result<usize, JobFactoryError> {
        let before = self.script_sig_before_extranonce(
            &template.coinbase_prefix.to_vec(),
            full_extranonce_size,
        )?;
        Ok(COINBASE_HEADER_BYTES + before.len())
    }

    fn coinbase_tx_prefix(
        &self,
        template: NewTemplate<'_>,
        coinbase_reward_outputs: Vec<TxOut>,
        full_extranonce_size: usize,
    ) -> Result<Vec<u8>, JobFactoryError> {
        let coinbase = self.coinbase(
            template.clone(),
            coinbase_reward_outputs,
            full_extranonce_size,
        )?;
        let serialized_coinbase = serialize(&coinbase);

        let index = self.extranonce_offset(&template, full_extranonce_size)?;

        let coinbase_tx_prefix = serialized_coinbase[0..index].to_vec();

        Ok(coinbase_tx_prefix)
    }

    fn coinbase_tx_suffix(
        &self,
        template: NewTemplate<'_>,
        coinbase_reward_outputs: Vec<TxOut>,
        full_extranonce_size: usize,
    ) -> Result<Vec<u8>, JobFactoryError> {
        let coinbase = self.coinbase(
            template.clone(),
            coinbase_reward_outputs,
            full_extranonce_size,
        )?;
        let serialized_coinbase = serialize(&coinbase);

        let coinbase_tx_suffix = serialized_coinbase
            [self.extranonce_offset(&template, full_extranonce_size)? + full_extranonce_size..]
            .to_vec();

        Ok(coinbase_tx_suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;
    use template_distribution_sv2::NewTemplate;

    /// Ghost's two coinbase tags, with their `OP_PUSHBYTES` opcodes: payout identity (4+16) and
    /// node identity (4+20).
    const GHOST_TAGS: usize = (1 + 4 + 16) + (1 + 4 + 20);

    /// The refactor must not have moved the limit. `61` was the literal this replaced, with the
    /// arithmetic written out beside it; deriving the same number from the same terms is the proof
    /// that nothing shifted while the duplication was removed.
    #[test]
    fn the_derived_budget_equals_the_literal_it_replaced() {
        let f = JobFactory::new(true, Some("pool".into()), None);
        assert_eq!(
            f.pool_miner_tag_budget(32),
            61,
            "at the 32-byte extranonce the old literal assumed, the derived budget must match it"
        );
    }

    /// The old literal assumed a 32-byte extranonce. The pool actually runs 20, and budgeting
    /// against the real size rather than a worst case is what makes room for Ghost's tags at all.
    #[test]
    fn budgeting_against_the_real_extranonce_recovers_the_unused_reserve() {
        let f = JobFactory::new(true, Some("pool".into()), None);
        assert_eq!(f.pool_miner_tag_budget(20), 61 + 12);
    }

    /// The live configuration, end to end: `/GHOST PublicPool/` alongside both Ghost tags, at the
    /// pool's real 20-byte extranonce. This is the sizing question the whole design hinged on.
    #[test]
    fn the_live_pool_tag_fits_beside_both_ghost_tags() {
        let f = JobFactory::new(true, Some("GHOST PublicPool".into()), None)
            .with_extra_script_sig(vec![0u8; GHOST_TAGS]);

        let budget = f.pool_miner_tag_budget(20);
        let needed = 3 + "GHOST PublicPool".len(); // three delimiters
        assert!(
            needed <= budget,
            "/GHOST PublicPool/ needs {needed} bytes, budget is {budget}"
        );
        assert_eq!(budget - needed, 8, "spare headroom, for the record");
        assert!(f.op_pushbytes_pool_miner_tag(20).is_ok());
    }

    /// **The check neither program could make alone.** Ghost's template provider puts 50 bytes in
    /// `coinbase_prefix` (height + payout tag + node tag), not the 5 the tag budget nominally
    /// reserves. The tag guard cannot see that — the prefix comes from another process — so only a
    /// measurement of the assembled bytes catches an overflow.
    #[test]
    fn an_oversized_template_prefix_is_caught_on_the_assembled_bytes() {
        let f = JobFactory::new(true, Some("- G H O S T - PublicPool".into()), None);

        // A realistic Ghost prefix: BIP34 height, payout tag, node tag.
        let mut ghost_prefix = vec![0x03, 0x40, 0x1f, 0x0e];
        ghost_prefix.extend_from_slice(&[21u8; 21]);
        ghost_prefix.extend_from_slice(&[25u8; 25]);
        assert_eq!(ghost_prefix.len(), 50);

        assert!(
            f.script_sig_before_extranonce(&ghost_prefix, 20).is_ok(),
            "the live configuration must still build — 99 of 100 bytes"
        );

        // Two more characters of pool tag and the same template prefix goes over.
        let longer = JobFactory::new(true, Some("- G H O S T - PublicPool!!".into()), None);
        assert!(
            matches!(
                longer.script_sig_before_extranonce(&ghost_prefix, 20),
                Err(JobFactoryError::CoinbaseTxPrefixError)
            ),
            "an over-length total must be refused, not mined"
        );
    }

    /// And the assembled scriptSig really is inside the consensus limit — asserted on the bytes,
    /// not on the arithmetic that was supposed to guarantee it.
    #[test]
    fn the_assembled_script_sig_stays_under_the_consensus_limit() {
        let f = JobFactory::new(true, Some("GHOST PublicPool".into()), None)
            .with_extra_script_sig(vec![0u8; GHOST_TAGS]);

        // BIP34 height push for ~960k: OP_PUSHBYTES_3 plus three bytes.
        let bip34 = vec![0x03, 0x40, 0x1f, 0x0e];
        let before = f
            .script_sig_before_extranonce(&bip34, 20)
            .expect("must assemble");
        let total = before.len() + 20;
        assert!(
            total <= MAX_COINBASE_SCRIPT_SIG,
            "scriptSig would be {total} bytes, over the {MAX_COINBASE_SCRIPT_SIG}-byte limit"
        );
        // 4 BIP34 + 20 pool tag + 46 Ghost tags + 1 OP_PUSHBYTES + 20 extranonce.
        // Nine bytes of headroom, pinned so anyone lengthening a tag sees what it costs.
        assert_eq!(total, 91);
        assert_eq!(MAX_COINBASE_SCRIPT_SIG - total, 9);
    }

    /// Extra pushes come out of the same 100 bytes, so they shrink what is left for the tags.
    #[test]
    fn extra_pushes_shrink_the_tag_budget() {
        let f = JobFactory::new(true, Some("pool".into()), None)
            .with_extra_script_sig(vec![0u8; GHOST_TAGS]);
        assert_eq!(f.pool_miner_tag_budget(32), 61 - GHOST_TAGS);
    }

    /// **The failure this guards.** A miner tag that fitted before the extra pushes must now be
    /// refused, not quietly emitted as an over-length scriptSig — which consensus rejects, and
    /// which nobody would discover until the pool won a block.
    #[test]
    fn a_tag_that_no_longer_fits_is_refused_rather_than_overflowing() {
        let long_tag = "x".repeat(50); // 50 + 3 delimiters = 53, inside the bare 61 budget
        let without = JobFactory::new(true, Some(long_tag.clone()), None);
        assert!(
            without.op_pushbytes_pool_miner_tag(32).is_ok(),
            "fixture must fit before the extra pushes, or the test proves nothing"
        );

        let with = JobFactory::new(true, Some(long_tag), None)
            .with_extra_script_sig(vec![0u8; GHOST_TAGS]);
        assert!(matches!(
            with.op_pushbytes_pool_miner_tag(32),
            Err(JobFactoryError::CoinbaseTxPrefixError)
        ));
    }

    /// A tag inside the reduced budget still works — the guard must be tighter, not broken.
    #[test]
    fn a_tag_within_the_reduced_budget_still_fits() {
        let f = JobFactory::new(true, Some("GHOST PublicPool".into()), None)
            .with_extra_script_sig(vec![0u8; GHOST_TAGS]);
        let tag = f.op_pushbytes_pool_miner_tag(20).expect("should fit");
        assert_eq!(tag.len(), 1 + 3 + "GHOST PublicPool".len());
    }

    /// An extra push big enough to swallow the whole budget yields zero, not a wrapped enormous
    /// allowance — and every tag is then refused rather than every tag being accepted.
    #[test]
    fn an_oversized_extra_push_saturates_to_no_budget() {
        let f = JobFactory::new(true, Some("p".into()), None).with_extra_script_sig(vec![0u8; 500]);
        assert_eq!(f.pool_miner_tag_budget(20), 0);
        assert!(f.op_pushbytes_pool_miner_tag(20).is_err());
    }

    #[test]
    fn test_new_pool_job() {
        let mut job_factory = JobFactory::new(true, Some("Stratum V2 SRI Pool".to_string()), None);

        // note:
        // the messages on this test were collected from a sane message flow
        // we use them as test vectors to assert correct behavior of job creation

        let template = NewTemplate {
            template_id: 1,
            future_template: true,
            version: 536870912,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![82, 0].try_into().unwrap(),
            coinbase_tx_input_sequence: 4294967295,
            coinbase_tx_value_remaining: 5000000000,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_locktime: 0,
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
            value: Amount::from_sat(5000000000),
            script_pubkey: script,
        }];

        // match the original extranonce_prefix used to generate the expected job
        let extranonce_prefix = [
            83, 116, 114, 97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 0,
            0, 0, 0, 0, 0, 0, 1,
        ]
        .to_vec();

        let job = job_factory
            .new_extended_job(
                1,
                None,
                extranonce_prefix,
                template,
                coinbase_reward_outputs,
                32,
            )
            .unwrap();

        // we know that the provided template should generate this job
        let expected_job = NewExtendedMiningJob {
            channel_id: 1,
            job_id: 1,
            min_ntime: Sv2Option::new(None),
            version: 536870912,
            version_rolling_allowed: true,
            // contains scriptSig with /Stratum V2 SRI Pool//
            coinbase_tx_prefix: vec![
                2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 58, 82, 0, 22, 47, 83, 116, 114, 97,
                116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 47, 47, 32,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_suffix: vec![
                255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 22, 0, 20, 235, 225, 183, 220,
                194, 147, 204, 170, 14, 231, 67, 168, 111, 137, 223, 130, 88, 194, 8, 252, 0, 0, 0,
                0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209, 222,
                253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180, 139,
                235, 216, 54, 151, 78, 140, 249, 0, 0, 0, 0,
            ]
            .try_into()
            .unwrap(),
            merkle_path: vec![].try_into().unwrap(),
        };

        assert_eq!(job.get_job_message(), &expected_job);
    }

    #[test]
    fn test_new_extended_job_from_custom_job() {
        let jdc_job_factory = JobFactory::new(
            true,
            Some("Stratum V2 SRI Pool".to_string()),
            Some("Stratum V2 SRI Miner".to_string()),
        );

        let extranonce_prefix = [
            83, 116, 114, 97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 0,
            0, 0, 0, 0, 0, 0, 1,
        ]
        .to_vec();

        let template = NewTemplate {
            template_id: 1,
            future_template: false,
            version: 536870912,
            coinbase_tx_version: 2,
            coinbase_prefix: vec![82, 0].try_into().unwrap(),
            coinbase_tx_input_sequence: 4294967295,
            coinbase_tx_value_remaining: 5000000000,
            coinbase_tx_outputs_count: 1,
            coinbase_tx_outputs: vec![
                0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209,
                222, 253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180,
                139, 235, 216, 54, 151, 78, 140, 249,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_locktime: 0,
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
            value: Amount::from_sat(5000000000),
            script_pubkey: script,
        }];

        let chain_tip = ChainTip::new(
            [
                200, 53, 253, 129, 214, 31, 43, 84, 179, 58, 58, 76, 128, 213, 24, 53, 38, 144,
                205, 88, 172, 20, 251, 22, 217, 141, 21, 221, 21, 0, 0, 0,
            ]
            .into(),
            503543726,
            1746839905,
        );

        let set_custom_mining_job = jdc_job_factory
            .new_custom_job(
                1,
                1,
                vec![0].try_into().unwrap(),
                chain_tip,
                template,
                coinbase_reward_outputs,
                32,
            )
            .unwrap();

        let mut pool_job_factory =
            JobFactory::new(true, Some("Stratum V2 SRI Pool".to_string()), None);

        let custom_job = pool_job_factory
            .new_extended_job_from_custom_job(set_custom_mining_job, extranonce_prefix, 32)
            .unwrap();

        let expected_job = NewExtendedMiningJob {
            channel_id: 1,
            job_id: 1,
            min_ntime: Sv2Option::new(Some(1746839905)),
            version: 536870912,
            version_rolling_allowed: true,
            // contains scriptSig with /Stratum V2 SRI Pool/Stratum V2 SRI Miner/
            coinbase_tx_prefix: vec![
                2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 78, 82, 0, 42, 47, 83, 116, 114, 97,
                116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 80, 111, 111, 108, 47, 83, 116, 114,
                97, 116, 117, 109, 32, 86, 50, 32, 83, 82, 73, 32, 77, 105, 110, 101, 114, 47, 32,
            ]
            .try_into()
            .unwrap(),
            coinbase_tx_suffix: vec![
                255, 255, 255, 255, 2, 0, 242, 5, 42, 1, 0, 0, 0, 22, 0, 20, 235, 225, 183, 220,
                194, 147, 204, 170, 14, 231, 67, 168, 111, 137, 223, 130, 88, 194, 8, 252, 0, 0, 0,
                0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 226, 246, 28, 63, 113, 209, 222,
                253, 63, 169, 153, 223, 163, 105, 83, 117, 92, 105, 6, 137, 121, 153, 98, 180, 139,
                235, 216, 54, 151, 78, 140, 249, 0, 0, 0, 0,
            ]
            .try_into()
            .unwrap(),
            merkle_path: vec![].try_into().unwrap(),
        };

        assert_eq!(custom_job.get_job_message(), &expected_job);
    }
}
