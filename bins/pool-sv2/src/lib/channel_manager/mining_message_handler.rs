use std::{convert::TryFrom, sync::atomic::Ordering};

use stratum_apps::stratum_core::{
    binary_sv2::Str0255,
    bitcoin::Target,
    channels_sv2::{
        server::{
            error::{ExtendedChannelError, StandardChannelError},
            extended::ExtendedChannel,
            jobs::job_store::DefaultJobStore,
            share_accounting::{ShareValidationError, ShareValidationResult},
            standard::StandardChannel,
        },
        target::hash_rate_to_target,
        Vardiff, VardiffState,
    },
    extensions_sv2::{
        UserIdentity, EXTENSION_TYPE_WORKER_HASHRATE_TRACKING, PROVISIONAL_CHANNEL_IDENTITY,
        TLV_FIELD_TYPE_USER_IDENTITY,
    },
    handlers_sv2::{HandleMiningMessagesFromClientAsync, SupportedChannelTypes},
    mining_sv2::*,
    parsers_sv2::{Mining, TemplateDistribution, Tlv, TlvField},
    template_distribution_sv2::SubmitSolution,
};
use stratum_apps::utils::types::SharesPerMinute;
use tracing::{error, info};

use jd_server_sv2::job_declarator::SetCustomMiningJobResponse;

use crate::{
    channel_manager::{ChannelManager, RouteMessageTo, CLIENT_SEARCH_SPACE_BYTES},
    error::{self, PoolError, PoolErrorKind},
    share_webhook::{now_ms, ShareData},
    utils::{create_close_channel_msg, PayoutMode},
};

/// Builds the `user_identity` string the share_webhook should report to the downstream
/// accounting service (ghost-pool).
///
/// Two shapes of channel identity reach this function:
///
/// - **A channel opened on `mining.authorize`** — the identity is the miner's own
///   `<addr>.<worker>`. The TLV carries only the worker segment, so splice that worker onto
///   the address portion of the channel identity. This is the long-standing path and is what
///   every currently-connected miner uses.
/// - **A channel opened on `mining.subscribe`** ([`PROVISIONAL_CHANNEL_IDENTITY`]) — the
///   identity has no payout target at all, so the TLV is authoritative and is used verbatim.
///   It carries the full `<addr>.<worker>`.
///
/// The caller distinguishes the two by the channel identity, never by inspecting the TLV.
/// A worker name may legitimately contain a `.` (`addr.farm1.rig1` yields worker `farm1.rig1`,
/// #481), so "the TLV looks dotted" does NOT imply it carries an address, and keying on that
/// would silently reassign `farm1` as a payout address.
///
/// Returns `None` when the share cannot be attributed — a provisional channel with no usable
/// TLV. Splicing a worker onto the sentinel would produce `sri/donate/provisional.worker`,
/// whose address portion is `sri`, so the share would be credited to nobody while looking
/// entirely normal. The caller must not credit a `None`.
///
/// The "address portion" is the prefix before the first `.` in the channel user_identity. If
/// the channel user_identity has no `.` we treat the whole thing as the address.
fn build_webhook_user_identity(channel_uid: String, tlv_worker: Option<&str>) -> Option<String> {
    let tlv = tlv_worker.filter(|s| !s.is_empty());

    if channel_uid == PROVISIONAL_CHANNEL_IDENTITY {
        // The TLV is the only source of a payout target on this channel. It must already be
        // the full `<addr>.<worker>`; a bare worker has no address and cannot be paid.
        return tlv.filter(|t| t.contains('.')).map(str::to_string);
    }

    Some(match tlv {
        Some(worker) => {
            let addr = channel_uid
                .split_once('.')
                .map(|(a, _)| a)
                .unwrap_or(&channel_uid);
            format!("{}.{}", addr, worker)
        }
        None => channel_uid,
    })
}

/// Error code returned when the extended extranonce allocator has no prefixes left.
///
/// The SV2 mining spec only enumerates `unknown-user` and `max-target-out-of-range` for
/// `OpenMiningChannel.Error`, and the field itself is a free-form human-readable `Str0255`,
/// so roles are expected to extend the set — this pool already sends
/// `invalid-user-identity`, `invalid-nominal-hashrate` and `min-extranonce-size-too-large`.
/// Exhaustion gets its own code because it is an upstream fault with an upstream remedy:
/// reporting it as `min-extranonce-size-too-large` blames the client's requested size and
/// sends whoever investigates in exactly the wrong direction.
pub(crate) const EXTRANONCE_SPACE_EXHAUSTED: &str = "extranonce-space-exhausted";

/// Validates an `OpenExtendedMiningChannel` request and, only if it is acceptable, mints the
/// extranonce prefix for the channel it will open.
///
/// The order here is the whole point. The extended allocator is `server_id || counter` over
/// `POOL_ALLOCATION_BYTES`, of which `POOL_STATIC_PREFIX_BYTES` is the fixed server id,
/// leaving a 24-bit counter — 16,777,215 prefixes for the lifetime of the process, measured
/// by `extended_prefix_space_matches_the_configured_split` — and a prefix is never handed
/// back. Any
/// check performed *after* `next_prefix_extended` therefore turns a rejected open into a
/// permanently burnt prefix, so an unauthenticated client looping deliberately invalid opens
/// can exhaust the space and stop every honest miner from opening a channel until `pool_sv2`
/// restarts. Validate first, allocate last: a rejection then costs the attacker nothing and
/// the pool nothing.
///
/// The nominal-hashrate and max-target checks duplicate the first two checks inside
/// `ExtendedChannel::new_for_pool` on purpose — those are the remaining client-controlled
/// fields that can reject a channel, and the constructor cannot run before the prefix exists
/// because it takes the prefix. The constructor's own branches stay in place as a backstop.
///
/// On rejection the returned `&'static str` is the `error_code` to put in the
/// `OpenMiningChannelError` sent back to the client.
fn validate_and_allocate_extended(
    extranonce_prefix_factory: &mut ExtendedExtranonce,
    user_identity: &str,
    nominal_hash_rate: f32,
    requested_max_target: &Target,
    shares_per_minute: SharesPerMinute,
    requested_min_rollable_extranonce_size: usize,
) -> Result<(PayoutMode, Vec<u8>), &'static str> {
    let payout_mode = PayoutMode::try_from(user_identity).map_err(|_| "invalid-user-identity")?;

    let target = hash_rate_to_target(nominal_hash_rate.into(), shares_per_minute.into())
        .map_err(|_| "invalid-nominal-hashrate")?;
    if &target > requested_max_target {
        return Err("max-target-out-of-range");
    }

    let extranonce_prefix = extranonce_prefix_factory
        .next_prefix_extended(requested_min_rollable_extranonce_size)
        .map_err(|e| match e {
            ExtendedExtranonceError::MaxValueReached => EXTRANONCE_SPACE_EXHAUSTED,
            _ => "min-extranonce-size-too-large",
        })?;

    Ok((payout_mode, extranonce_prefix.to_vec()))
}

#[cfg_attr(not(test), hotpath::measure_all)]
impl HandleMiningMessagesFromClientAsync for ChannelManager {
    type Error = PoolError<error::ChannelManager>;

    fn get_channel_type_for_client(&self, _client_id: Option<usize>) -> SupportedChannelTypes {
        SupportedChannelTypes::GroupAndExtended
    }

    fn is_work_selection_enabled_for_client(&self, _client_id: Option<usize>) -> bool {
        true
    }

    fn is_client_authorized(
        &self,
        _client_id: Option<usize>,
        _user_identity: &Str0255,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    fn get_negotiated_extensions_with_client(
        &self,
        client_id: Option<usize>,
    ) -> Result<Vec<u16>, Self::Error> {
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");
        let negotiated_extensions =
            self.channel_manager_data
                .super_safe_lock(|channel_manager_data| {
                    channel_manager_data
                        .downstream
                        .get(&downstream_id)
                        .map(|downstream| {
                            downstream
                                .downstream_data
                                .super_safe_lock(|data| data.negotiated_extensions.clone())
                        })
                        .expect("negotiated_extensions must be present")
                });
        Ok(negotiated_extensions)
    }

    async fn handle_close_channel(
        &mut self,
        client_id: Option<usize>,
        msg: CloseChannel<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received Close Channel: {msg}");
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");
        self.channel_manager_data
            .super_safe_lock(|channel_manager_data| {
                let Some(downstream) = channel_manager_data.downstream.get_mut(&downstream_id)
                else {
                    return Err(PoolError::disconnect(
                        PoolErrorKind::DownstreamNotFound(downstream_id),
                        downstream_id,
                    ));
                };

                downstream
                    .downstream_data
                    .super_safe_lock(|downstream_data| {
                        downstream_data.standard_channels.remove(&msg.channel_id);
                        downstream_data.extended_channels.remove(&msg.channel_id);
                    });
                channel_manager_data
                    .vardiff
                    .remove(&(downstream_id, msg.channel_id).into());
                Ok(())
            })
    }

    async fn handle_open_standard_mining_channel(
        &mut self,
        client_id: Option<usize>,
        msg: OpenStandardMiningChannel<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        let request_id = msg.get_request_id_as_u32();
        let user_identity = msg.user_identity.as_utf8_or_hex();
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");

        info!("Received OpenStandardMiningChannel: {}", msg);

        let messages = self.channel_manager_data.super_safe_lock(|channel_manager_data| {
            let Some(downstream) = channel_manager_data.downstream.get_mut(&downstream_id) else {
                return Err(PoolError::disconnect(PoolErrorKind::DownstreamIdNotFound, downstream_id));
            };

            if downstream.requires_custom_work.load(Ordering::SeqCst) {
                error!("OpenStandardMiningChannel: Standard Channels are not supported for this connection");
                let open_standard_mining_channel_error = OpenMiningChannelError {
                    request_id,
                    error_code: "standard-channels-not-supported-for-custom-work"
                        .to_string()
                        .try_into()
                        .expect("error code must be valid string"),
                };
                return Ok(vec![(downstream_id, Mining::OpenMiningChannelError(open_standard_mining_channel_error)).into()]);
            }

            let Some(last_future_template) = channel_manager_data.last_future_template.clone() else {
                return Err(PoolError::disconnect(PoolErrorKind::FutureTemplateNotPresent, downstream_id));
            };

            let Some(last_set_new_prev_hash_tdp) = channel_manager_data.last_new_prev_hash.clone() else {
                return Err(PoolError::disconnect(PoolErrorKind::LastNewPrevhashNotFound, downstream_id));
            };

            let payout_mode = match PayoutMode::try_from(user_identity.as_str()) {
                Ok(mode) => mode,
                Err(_) => {
                    error!("Invalid user_identity '{}': does not match any supported identity format", user_identity);
                    let open_standard_mining_channel_error = OpenMiningChannelError {
                        request_id,
                        error_code: "invalid-user-identity"
                            .to_string()
                            .try_into()
                            .expect("error code must be valid string"),
                    };
                    return Ok(vec![(downstream_id, Mining::OpenMiningChannelError(open_standard_mining_channel_error)).into()]);
                }
            };

            let coinbase_outputs = payout_mode.coinbase_outputs(
                last_future_template.coinbase_tx_value_remaining,
                &self.coinbase_reward_script,
            );

            downstream.downstream_data.super_safe_lock(|downstream_data| {
                downstream_data.payout_mode = Some(payout_mode);

                let nominal_hash_rate = msg.nominal_hash_rate;
                let requested_max_target = Target::from_le_bytes(msg.max_target.inner_as_ref().try_into().unwrap());
                let extranonce_prefix = channel_manager_data.extranonce_prefix_factory_standard.next_prefix_standard().map_err(PoolError::shutdown)?;

                let channel_id = downstream_data.channel_id_factory.fetch_add(1, Ordering::SeqCst);
                let job_store = DefaultJobStore::new();

                let mut standard_channel = match StandardChannel::new_for_pool(channel_id, user_identity.to_string(), extranonce_prefix.to_vec(), requested_max_target, nominal_hash_rate, self.share_batch_size, self.shares_per_minute, job_store, self.pool_tag_string.clone()) {
                    Ok(channel) => channel,
                    Err(e) => match e {
                        StandardChannelError::InvalidNominalHashrate => {
                            error!("OpenMiningChannelError: invalid-nominal-hashrate");
                            let open_standard_mining_channel_error = OpenMiningChannelError {
                                request_id,
                                error_code: "invalid-nominal-hashrate"
                                    .to_string()
                                    .try_into()
                                    .expect("error code must be valid string"),
                            };
                            return Ok(vec![(downstream_id, Mining::OpenMiningChannelError(open_standard_mining_channel_error)).into()]);
                        }
                        StandardChannelError::RequestedMaxTargetOutOfRange => {
                            error!("OpenMiningChannelError: max-target-out-of-range");
                            let open_standard_mining_channel_error = OpenMiningChannelError {
                                request_id,
                                error_code: "max-target-out-of-range"
                                    .to_string()
                                    .try_into()
                                    .expect("error code must be valid string"),
                            };
                            return Ok(vec![(downstream_id, Mining::OpenMiningChannelError(open_standard_mining_channel_error)).into()]);
                        }
                        _ => {
                            error!("error in handle_open_standard_mining_channel: {:?}", e);
                            return Err(PoolError::disconnect(PoolErrorKind::ChannelErrorSender, downstream_id) );
                        }
                    },
                };

                // SHARE_TIER_BIND: when the chain (as seen through the last future template's
                // BIP34 height) is at/above the activation height, this channel starts life
                // tiered — target quantised to its tier's exact target, tier commitment armed
                // for its first job build. Done BEFORE the success message so the target the
                // miner is told is the tier target it will be credited at.
                let tiering = self.tier_binding.clone().filter(|tb| tb.template_is_tiered(&last_future_template));
                if let Some(ref tb) = tiering {
                    let q = tb.quantise_target(
                        standard_channel.get_target(),
                        standard_channel.get_requested_max_target(),
                    );
                    standard_channel.set_target(q);
                    standard_channel.set_tier_commitment(Some(tb.stamp_for_target(&q)));
                }

                let group_channel_id = downstream_data.group_channel.get_group_channel_id();
                let extranonce_prefix_size = standard_channel.get_extranonce_prefix().len();

                let open_standard_mining_channel_success = OpenStandardMiningChannelSuccess {
                    request_id: msg.request_id,
                    channel_id,
                    target: standard_channel.get_target().to_le_bytes().into(),
                    extranonce_prefix: standard_channel.get_extranonce_prefix().clone().try_into().expect("Extranonce_prefix must be valid"),
                    group_channel_id
                }.into_static();

                let mut  messages: Vec<RouteMessageTo> = Vec::new();

                messages.push((downstream_id, Mining::OpenStandardMiningChannelSuccess(open_standard_mining_channel_success)).into());

                let template_id = last_future_template.template_id;

                // create a future standard job based on the last future template — the tiered
                // form (plain node tag stripped; the tier tag rides as the factory extra push)
                // when tiering is active, the template verbatim otherwise
                let channel_template = match tiering {
                    Some(_) => crate::tier_binding::strip_plain_node_tag(&last_future_template),
                    None => last_future_template,
                };
                standard_channel.on_new_template(channel_template, coinbase_outputs.clone()).map_err(PoolError::shutdown)?;
                let future_standard_job_id = standard_channel
                    .get_future_job_id_from_template_id(template_id)
                    .expect("future job id must exist");
                let future_standard_job = standard_channel
                    .get_future_job(future_standard_job_id)
                    .expect("future job must exist");
                let future_standard_job_message =
                    future_standard_job.get_job_message().clone().into_static();

                messages.push((downstream_id, Mining::NewMiningJob(future_standard_job_message)).into());
                let prev_hash = last_set_new_prev_hash_tdp.prev_hash.clone();
                let header_timestamp = last_set_new_prev_hash_tdp.header_timestamp;
                let n_bits = last_set_new_prev_hash_tdp.n_bits;
                let set_new_prev_hash_mining = SetNewPrevHash {
                    channel_id,
                    job_id: future_standard_job_id,
                    prev_hash,
                    min_ntime: header_timestamp,
                    nbits: n_bits,
                };

                standard_channel
                .on_set_new_prev_hash(last_set_new_prev_hash_tdp.clone()).map_err(PoolError::shutdown)?;

                messages.push((downstream_id, Mining::SetNewPrevHash(set_new_prev_hash_mining)).into());

                downstream_data.standard_channels.insert(channel_id, standard_channel);
                if !downstream.requires_standard_jobs.load(Ordering::SeqCst) {
                    downstream_data.group_channel.add_channel_id(channel_id, extranonce_prefix_size).map_err(|e| {
                        error!("Failed to add channel id to group channel: {:?}", e);
                        PoolError::shutdown(e)
                    })?;
                }
                let vardiff = VardiffState::new().map_err(PoolError::shutdown)?;
                channel_manager_data.vardiff.insert((downstream_id, channel_id).into(), vardiff);

                Ok(messages)
            })
        })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_channel).await {
                error!("Failed to forward message {e:?}");
            }
        }

        Ok(())
    }

    async fn handle_open_extended_mining_channel(
        &mut self,
        client_id: Option<usize>,
        msg: OpenExtendedMiningChannel<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        let request_id = msg.get_request_id_as_u32();
        let user_identity = msg.user_identity.as_utf8_or_hex();
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");
        info!("Received OpenExtendedMiningChannel: {}", msg);

        let nominal_hash_rate = msg.nominal_hash_rate;
        let requested_max_target =
            Target::from_le_bytes(msg.max_target.inner_as_ref().try_into().unwrap());
        let requested_min_rollable_extranonce_size = msg.min_extranonce_size;

        let messages = self
            .channel_manager_data
            .super_safe_lock(|channel_manager_data| {
                let Some(downstream) = channel_manager_data.downstream.get_mut(&downstream_id)
                else {
                    return Err(PoolError::disconnect(PoolErrorKind::DownstreamIdNotFound, downstream_id));
                };
                downstream
                    .downstream_data
                    .super_safe_lock(|downstream_data| {
                        let mut messages: Vec<RouteMessageTo> = Vec::new();

                        // Validate the request in full BEFORE any extranonce prefix is minted.
                        // See `validate_and_allocate_extended`: the extended allocator's
                        // counter is tiny and nothing ever hands a prefix back, so a rejected
                        // open must never consume one.
                        let (payout_mode, extranonce_prefix) =
                            match validate_and_allocate_extended(
                                &mut channel_manager_data.extranonce_prefix_factory_extended,
                                user_identity.as_str(),
                                nominal_hash_rate,
                                &requested_max_target,
                                self.shares_per_minute,
                                requested_min_rollable_extranonce_size.into(),
                            ) {
                                Ok(accepted) => accepted,
                                Err(error_code) => {
                                    error!(
                                        "OpenMiningChannelError: {} (user_identity: '{}')",
                                        error_code, user_identity
                                    );
                                    let open_extended_mining_channel_error =
                                        OpenMiningChannelError {
                                            request_id,
                                            error_code: error_code
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                    return Ok(vec![(
                                        downstream_id,
                                        Mining::OpenMiningChannelError(
                                            open_extended_mining_channel_error,
                                        ),
                                    )
                                        .into()]);
                                }
                            };

                        downstream_data.payout_mode = Some(payout_mode.clone());

                        let channel_id = downstream_data
                            .channel_id_factory
                            .fetch_add(1, Ordering::SeqCst);
                        let job_store = DefaultJobStore::new();

                        let mut extended_channel = match ExtendedChannel::new_for_pool(
                            channel_id,
                            user_identity.to_string(),
                            extranonce_prefix.clone(),
                            requested_max_target,
                            nominal_hash_rate,
                            true, // version rolling always allowed
                            CLIENT_SEARCH_SPACE_BYTES as u16,
                            self.share_batch_size,
                            self.shares_per_minute,
                            job_store,
                            self.pool_tag_string.clone(),
                        ) {
                            Ok(channel) => channel,
                            Err(e) => match e {
                                ExtendedChannelError::InvalidNominalHashrate => {
                                    error!("OpenMiningChannelError: invalid-nominal-hashrate");
                                    let open_extended_mining_channel_error =
                                        OpenMiningChannelError {
                                            request_id,
                                            error_code: "invalid-nominal-hashrate"
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                    return Ok(vec![(
                                        downstream_id,
                                        Mining::OpenMiningChannelError(
                                            open_extended_mining_channel_error,
                                        ),
                                    )
                                        .into()]);
                                }
                                ExtendedChannelError::RequestedMaxTargetOutOfRange => {
                                    error!("OpenMiningChannelError: max-target-out-of-range");
                                    let open_extended_mining_channel_error =
                                        OpenMiningChannelError {
                                            request_id,
                                            error_code: "max-target-out-of-range"
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                    return Ok(vec![(
                                        downstream_id,
                                        Mining::OpenMiningChannelError(
                                            open_extended_mining_channel_error,
                                        ),
                                    )
                                        .into()]);
                                }
                                ExtendedChannelError::RequestedMinExtranonceSizeTooLarge => {
                                    error!("OpenMiningChannelError: min-extranonce-size-too-large");
                                    let open_extended_mining_channel_error =
                                        OpenMiningChannelError {
                                            request_id,
                                            error_code: "min-extranonce-size-too-large"
                                                .to_string()
                                                .try_into()
                                                .expect("error code must be valid string"),
                                        };
                                    return Ok(vec![(
                                        downstream_id,
                                        Mining::OpenMiningChannelError(
                                            open_extended_mining_channel_error,
                                        ),
                                    )
                                        .into()]);
                                }
                                e => {
                                    error!("error in handle_open_extended_mining_channel: {:?}", e);
                                    return Err(PoolError::disconnect(e, downstream_id));
                                }
                            },
                        };

                        // SHARE_TIER_BIND: as for standard channels — quantise the target to
                        // its tier and arm the commitment BEFORE the success message, so the
                        // target the client is told is the tier target it will be credited at.
                        // Custom-work connections are excluded: their coinbases come from the
                        // declaring client and cannot carry this pool's tier commitment (an
                        // arming-scope limitation, logged where custom work is negotiated).
                        let tiering = if downstream.requires_custom_work.load(Ordering::SeqCst) {
                            None
                        } else {
                            self.tier_binding.clone().filter(|tb| {
                                channel_manager_data
                                    .last_future_template
                                    .as_ref()
                                    .is_some_and(|t| tb.template_is_tiered(t))
                            })
                        };
                        if let Some(ref tb) = tiering {
                            let q = tb.quantise_target(
                                extended_channel.get_target(),
                                extended_channel.get_requested_max_target(),
                            );
                            extended_channel.set_target(q);
                            extended_channel.set_tier_commitment(Some(tb.stamp_for_target(&q)));
                        }

                        let group_channel_id = downstream_data.group_channel.get_group_channel_id();

                        let open_extended_mining_channel_success =
                            OpenExtendedMiningChannelSuccess {
                                request_id,
                                channel_id,
                                target: extended_channel.get_target().to_le_bytes().into(),
                                extranonce_prefix: extended_channel
                                    .get_extranonce_prefix()
                                    .clone()
                                    .try_into().map_err(PoolError::shutdown)?,
                                extranonce_size: extended_channel.get_rollable_extranonce_size(),
                                group_channel_id,
                            }
                            .into_static();
                        info!("Sending OpenExtendedMiningChannel.Success (downstream_id: {downstream_id}): {open_extended_mining_channel_success}");

                        messages.push(
                            (
                                downstream_id,
                                Mining::OpenExtendedMiningChannelSuccess(
                                    open_extended_mining_channel_success,
                                ),
                            )
                                .into(),
                        );

                        let Some(last_set_new_prev_hash_tdp) =
                            channel_manager_data.last_new_prev_hash.clone()
                        else {
                            return Err(PoolError::disconnect(PoolErrorKind::LastNewPrevhashNotFound, downstream_id));
                        };

                        let Some(last_future_template) =
                            channel_manager_data.last_future_template.clone()
                        else {
                            return Err(PoolError::disconnect(PoolErrorKind::FutureTemplateNotPresent,downstream_id));
                        };

                        // if the client requires custom work, we don't need to send any extended
                        // jobs so we just process the SetNewPrevHash
                        // message
                        if downstream.requires_custom_work.load(Ordering::SeqCst) {
                            extended_channel.on_set_new_prev_hash(last_set_new_prev_hash_tdp).map_err(PoolError::shutdown)?;
                            // if the client does not require custom work, we need to send the
                            // future extended job
                            // and the SetNewPrevHash message
                        } else {
                            let coinbase_outputs = payout_mode.coinbase_outputs(
                                last_future_template.coinbase_tx_value_remaining,
                                &self.coinbase_reward_script,
                            );

                            // the tiered form (plain node tag stripped; the tier tag rides as
                            // the factory extra push) when tiering is active
                            let channel_template = match tiering {
                                Some(_) => crate::tier_binding::strip_plain_node_tag(&last_future_template),
                                None => last_future_template.clone(),
                            };
                            extended_channel.on_new_template(
                                channel_template,
                                coinbase_outputs,
                            ).map_err(PoolError::shutdown)?;

                            let future_extended_job_id = extended_channel
                                .get_future_job_id_from_template_id(last_future_template.template_id)
                                .expect("future job id must exist");
                            let future_extended_job = extended_channel
                                .get_future_job(future_extended_job_id)
                                .expect("future job must exist");

                            let future_extended_job_message =
                                future_extended_job.get_job_message().clone().into_static();

                            // send this future job as new job message
                            // to be immediately activated with the subsequent SetNewPrevHash
                            // message
                            messages.push(
                                (
                                    downstream_id,
                                    Mining::NewExtendedMiningJob(future_extended_job_message),
                                )
                                    .into(),
                            );

                            // SetNewPrevHash message activates the future job
                            let prev_hash = last_set_new_prev_hash_tdp.prev_hash.clone();
                            let header_timestamp = last_set_new_prev_hash_tdp.header_timestamp;
                            let n_bits = last_set_new_prev_hash_tdp.n_bits;
                            let set_new_prev_hash_mining = SetNewPrevHash {
                                channel_id,
                                job_id: future_extended_job_id,
                                prev_hash,
                                min_ntime: header_timestamp,
                                nbits: n_bits,
                            };

                            extended_channel.on_set_new_prev_hash(last_set_new_prev_hash_tdp).map_err(PoolError::shutdown)?;

                            messages.push(
                                (
                                    downstream_id,
                                    Mining::SetNewPrevHash(set_new_prev_hash_mining),
                                )
                                    .into(),
                            );

                            let full_extranonce_size = extended_channel.get_full_extranonce_size();
                            downstream_data.group_channel.add_channel_id(channel_id, full_extranonce_size).map_err(|e| {
                                error!("Failed to add channel id to group channel: {:?}", e);
                                PoolError::shutdown(e)
                            })?;
                        }

                        downstream_data
                            .extended_channels
                            .insert(channel_id, extended_channel);
                        let vardiff = VardiffState::new().map_err(PoolError::shutdown)?;
                        channel_manager_data
                            .vardiff
                            .insert((downstream_id, channel_id).into(), vardiff);

                        Ok(messages)
                    })
            })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_channel).await {
                error!("Failed to forward message {e:?}");
            }
        }
        Ok(())
    }

    async fn handle_submit_shares_standard(
        &mut self,
        client_id: Option<usize>,
        msg: SubmitSharesStandard,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received SubmitSharesStandard: {msg}");
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");

        let messages = self.channel_manager_data.super_safe_lock(|channel_manager_data| {
            let channel_id = msg.channel_id;

            let Some(downstream) = channel_manager_data.downstream.get(&downstream_id) else {
                return Err(PoolError::disconnect(PoolErrorKind::DownstreamNotFound(downstream_id), downstream_id));
            };

            downstream.downstream_data.super_safe_lock(|downstream_data| {
                let mut messages: Vec<RouteMessageTo> = Vec::new();
                let Some(standard_channel) = downstream_data.standard_channels.get_mut(&channel_id) else {
                    let submit_shares_error = SubmitSharesError {
                        channel_id,
                        sequence_number: msg.sequence_number,
                        error_code: "invalid-channel-id"
                            .to_string()
                            .try_into()
                            .expect("error code must be valid string"),
                    };
                    error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: invalid-channel-id ❌", downstream_id, channel_id, msg.sequence_number);
                    return Ok(vec![(downstream_id, Mining::SubmitSharesError(submit_shares_error)).into()]);
                };

                let Some(vardiff) = channel_manager_data.vardiff.get_mut(&(downstream_id, channel_id).into()) else {
                    return Ok(vec![(downstream_id, Mining::CloseChannel(create_close_channel_msg(channel_id, "invalid-channel-id"))).into()]);
                };

                let res = standard_channel.validate_share(msg.clone());
                vardiff.increment_shares_since_last_update();


                match res {
                    Ok(ShareValidationResult::Valid(share_hash, header80)) => {
                        // Credit the target the JOB was issued against, not the channel's current one.
                        // Vardiff moves the channel target while jobs are outstanding, so on a raise an accepted
                        // share would be credited more work than its hash proves — and every peer that
                        // re-derives difficulty from the hash then rejects it as below_difficulty.
                        let share_work = match standard_channel.job_target(msg.job_id) {
                            Some(t) => t.difficulty_float(),
                            None => standard_channel.get_target().difficulty_float(),
                        };
                        // SHARE_TIER_BIND: the tier this share's JOB committed to in its
                        // coinbase, captured at build time (never re-derived from the target
                        // map, which binds at activation). When present, the reported work IS
                        // the tier's exact credit — ghost-pool's verifier requires
                        // difficulty == 2^tier at/above the gate.
                        let tier_log2 = standard_channel.job_tier_log2(msg.job_id);
                        let share_work = match tier_log2 {
                            Some(t) => crate::tier_binding::tier_credit(t),
                            None => share_work,
                        };
                        if let Some(ref sender) = self.share_webhook_sender {
                            // Bind the share to the coinbase it was mined against, so the node
                            // that received it can be proved rather than asserted.
                            let (extranonce, skeleton_id) = standard_channel
                                .coinbase_skeleton()
                                .map(|(prefix, suffix, path)| {
                                    crate::binding::announce(
                                        sender,
                                        prefix,
                                        suffix,
                                        path,
                                        standard_channel.get_extranonce_prefix(),
                                    )
                                })
                                .unwrap_or((None, None));
                            sender.send(ShareData {
                                timestamp_ms: now_ms(),
                                share_hash: share_hash.to_string(),
                                share_work,
                                channel_id,
                                sequence_number: msg.sequence_number,
                                job_id: msg.job_id,
                                downstream_id,
                                is_block: false,
                                user_identity: standard_channel.get_user_identity().to_string(),
                                header: Some(hex::encode(&header80)),
                                extranonce,
                                skeleton_id,
                                tier_log2,
                            });
                        }
                        let share_accounting = standard_channel.get_share_accounting();
                        if share_accounting.should_acknowledge() {
                            let success = SubmitSharesSuccess {
                                channel_id,
                                last_sequence_number: share_accounting.get_last_share_sequence_number(),
                                new_submits_accepted_count: share_accounting.get_last_batch_accepted(),
                                new_shares_sum: share_accounting.get_last_batch_work_sum() as u64,
                            };
                            info!("SubmitSharesStandard: {} ✅", success);
                            messages.push((downstream_id, Mining::SubmitSharesSuccess(success)).into());
                        } else {
                            info!(
                                "SubmitSharesStandard: valid share | downstream_id: {}, channel_id: {}, sequence_number: {}, share_hash: {}, share_work: {} ✅",
                                downstream_id, channel_id, msg.sequence_number, share_hash, share_work
                            );
                        }

                    }
                    Ok(ShareValidationResult::BlockFound(share_hash, template_id, coinbase, header80)) => {
                        info!("SubmitSharesStandard: 💰 Block Found!!! 💰{share_hash}");
                        // Credit the target the JOB was issued against, not the channel's current one.
                        // Vardiff moves the channel target while jobs are outstanding, so on a raise an accepted
                        // share would be credited more work than its hash proves — and every peer that
                        // re-derives difficulty from the hash then rejects it as below_difficulty.
                        let share_work = match standard_channel.job_target(msg.job_id) {
                            Some(t) => t.difficulty_float(),
                            None => standard_channel.get_target().difficulty_float(),
                        };
                        // SHARE_TIER_BIND: build-time tier label; see the valid-share twin above.
                        let tier_log2 = standard_channel.job_tier_log2(msg.job_id);
                        let share_work = match tier_log2 {
                            Some(t) => crate::tier_binding::tier_credit(t),
                            None => share_work,
                        };
                        if let Some(ref sender) = self.share_webhook_sender {
                            // Bind the share to the coinbase it was mined against, so the node
                            // that received it can be proved rather than asserted.
                            let (extranonce, skeleton_id) = standard_channel
                                .coinbase_skeleton()
                                .map(|(prefix, suffix, path)| {
                                    crate::binding::announce(
                                        sender,
                                        prefix,
                                        suffix,
                                        path,
                                        standard_channel.get_extranonce_prefix(),
                                    )
                                })
                                .unwrap_or((None, None));
                            sender.send(ShareData {
                                timestamp_ms: now_ms(),
                                share_hash: share_hash.to_string(),
                                share_work,
                                channel_id,
                                sequence_number: msg.sequence_number,
                                job_id: msg.job_id,
                                downstream_id,
                                is_block: true,
                                user_identity: standard_channel.get_user_identity().to_string(),
                                header: Some(hex::encode(&header80)),
                                extranonce,
                                skeleton_id,
                                tier_log2,
                            });
                        }
                        // if we have a template id (i.e.: this was not a custom job)
                        // we can propagate the solution to the TP
                        if let Some(template_id) = template_id {
                            info!("SubmitSharesStandard: Propagating solution to the Template Provider.");
                            let solution = SubmitSolution {
                                template_id,
                                version: msg.version,
                                header_timestamp: msg.ntime,
                                header_nonce: msg.nonce,
                                coinbase_tx: coinbase.try_into().map_err(PoolError::shutdown)?,
                            };
                            messages.push(TemplateDistribution::SubmitSolution(solution).into());
                        }
                        let share_accounting = standard_channel.get_share_accounting();
                        let success = SubmitSharesSuccess {
                            channel_id,
                            last_sequence_number: share_accounting.get_last_share_sequence_number(),
                            new_submits_accepted_count: share_accounting.get_last_batch_accepted(),
                            new_shares_sum: share_accounting.get_last_batch_work_sum() as u64,
                        };
                        messages.push((downstream_id, Mining::SubmitSharesSuccess(success)).into());
                    }
                    Err(ShareValidationError::Invalid) => {
                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: invalid-share ❌", downstream_id, channel_id, msg.sequence_number);
                        let error = SubmitSharesError {
                            channel_id: msg.channel_id,
                            sequence_number: msg.sequence_number,
                            error_code: "invalid-share"
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };

                        messages.push((downstream_id, Mining::SubmitSharesError(error)).into());
                    }
                    Err(ShareValidationError::Stale) => {
                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: stale-share ❌", downstream_id, channel_id, msg.sequence_number);
                        let error = SubmitSharesError {
                            channel_id: msg.channel_id,
                            sequence_number: msg.sequence_number,
                            error_code: "stale-share"
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        messages.push((downstream_id, Mining::SubmitSharesError(error)).into());
                    }
                    Err(ShareValidationError::InvalidJobId) => {
                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: invalid-job-id ❌", downstream_id, channel_id, msg.sequence_number);
                        let error = SubmitSharesError {
                            channel_id: msg.channel_id,
                            sequence_number: msg.sequence_number,
                            error_code: "invalid-job-id"
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        messages.push((downstream_id, Mining::SubmitSharesError(error)).into());
                    }
                    Err(ShareValidationError::DoesNotMeetTarget) => {
                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: difficulty-too-low ❌", downstream_id, channel_id, msg.sequence_number);
                        let error = SubmitSharesError {
                            channel_id: msg.channel_id,
                            sequence_number: msg.sequence_number,
                            error_code: "difficulty-too-low"
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        messages.push((downstream_id, Mining::SubmitSharesError(error)).into());
                    }
                    Err(ShareValidationError::DuplicateShare) => {
                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: duplicate-share ❌", downstream_id, channel_id, msg.sequence_number);
                        let error = SubmitSharesError {
                            channel_id: msg.channel_id,
                            sequence_number: msg.sequence_number,
                            error_code: "duplicate-share"
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        messages.push((downstream_id, Mining::SubmitSharesError(error)).into());
                    }
                    Err(e) => {
                        return Err(PoolError::disconnect(e, downstream_id));
                    }
                }

                Ok(messages)
            })
        })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_channel).await {
                error!("Failed to forward message {e:?}");
            }
        }

        Ok(())
    }

    async fn handle_submit_shares_extended(
        &mut self,
        client_id: Option<usize>,
        msg: SubmitSharesExtended<'_>,
        tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received SubmitSharesExtended: {msg}");
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");

        // Extract user_identity from TLV fields if the extension is negotiated
        let negotiated_extensions = self.get_negotiated_extensions_with_client(client_id);
        let user_identity = if negotiated_extensions
            .as_ref()
            .is_ok_and(|exts| exts.contains(&EXTENSION_TYPE_WORKER_HASHRATE_TRACKING))
        {
            tlv_fields.and_then(|tlvs| {
                tlvs.iter()
                    .find(|tlv| {
                        tlv.r#type.extension_type == EXTENSION_TYPE_WORKER_HASHRATE_TRACKING
                            && tlv.r#type.field_type == TLV_FIELD_TYPE_USER_IDENTITY
                    })
                    .and_then(|tlv| UserIdentity::from_tlv(tlv).ok())
            })
        } else {
            None
        };

        let messages = self.channel_manager_data.super_safe_lock(|channel_manager_data| {
            let channel_id = msg.channel_id;
            let Some(downstream) = channel_manager_data.downstream.get(&downstream_id) else {
                return Err(PoolError::disconnect(PoolErrorKind::DownstreamNotFound(downstream_id), downstream_id));
            };

            downstream.downstream_data.super_safe_lock(|downstream_data| {
                let mut messages: Vec<RouteMessageTo> = Vec::new();
                let Some(extended_channel) = downstream_data.extended_channels.get_mut(&channel_id) else {
                    let error = SubmitSharesError {
                        channel_id,
                        sequence_number: msg.sequence_number,
                        error_code: "invalid-channel-id"
                            .to_string()
                            .try_into()
                            .expect("error code must be valid string"),
                    };
                    error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: invalid-channel-id ❌", downstream_id, channel_id, msg.sequence_number);
                    return Ok(vec![(downstream_id, Mining::SubmitSharesError(error)).into()]);
                };

                // The UserIdentity TLV (Worker-Specific Hashrate Tracking, ext 0x0002) is read
                // out into the local `user_identity` binding above. It's consumed below at the
                // share_webhook send sites via `build_webhook_user_identity`, which splices the
                // TLV's worker name onto the channel address so ghost-pool sees the per-miner
                // `<addr>.<worker>` form instead of one collapsed identity per channel.

                let Some(vardiff) = channel_manager_data.vardiff.get_mut(&(downstream_id, channel_id).into()) else {
                    return Ok(vec![(downstream_id, Mining::CloseChannel(create_close_channel_msg(channel_id, "invalid-channel-id"))).into()]);
                };

                let res = extended_channel.validate_share(msg.clone());
                vardiff.increment_shares_since_last_update();

                // Worker-Specific Hashrate Tracking TLV: when present, splice the per-miner
                // worker name onto the channel address for the share_webhook payload so
                // ghost-pool sees `<addr>.<worker>` and can distinguish individual miners
                // sharing one aggregated channel.
                let tlv_worker: Option<&str> =
                    user_identity.as_ref().and_then(|ui| ui.as_str());

                // FAIL CLOSED on a missing worker TLV when the extension IS negotiated.
                //
                // A client that negotiated Worker-Specific Hashrate Tracking is telling us its
                // channel identity is not the payout target — it is a translator or proxy
                // fronting other miners, and the per-miner identity travels in the TLV. If the
                // TLV is then absent, we do NOT know who earned this share, and crediting the
                // channel identity means silently paying the fronting operator's own address.
                // That is exactly how a duplicated length constant quietly misdirected shares:
                // encoding failed, the TLV vanished, and the fallback looked like normal
                // operation. Dropping the share is visible and costs one share; guessing is
                // invisible and costs someone their earnings.
                //
                // Clients that never negotiate the extension (direct SV2 miners) are unaffected
                // — their channel identity IS the payout target.
                let extension_negotiated = negotiated_extensions
                    .as_ref()
                    .is_ok_and(|exts| exts.contains(&EXTENSION_TYPE_WORKER_HASHRATE_TRACKING));

                // Resolve the payout target ONCE, and let that resolution decide
                // attributability. `build_webhook_user_identity` returns `None` for a channel
                // opened on `mining.subscribe` (identity `PROVISIONAL_CHANNEL_IDENTITY`) whose
                // TLV does not carry a full `<addr>.<worker>` — that channel has no payout
                // target of its own, so there is nothing to fall back to.
                let channel_identity = extended_channel.get_user_identity().to_string();
                let webhook_identity =
                    build_webhook_user_identity(channel_identity.clone(), tlv_worker);

                let attributable =
                    webhook_identity.is_some() && !(extension_negotiated && tlv_worker.is_none());
                if !attributable {
                    error!(
                        "share attribution FAILED: channel {} (identity {:?}) submitted a share \
                         with no usable worker TLV — share accepted for the miner but NOT \
                         credited, as the payout target is unknown",
                        channel_id, channel_identity
                    );
                }

                match res {
                    Ok(ShareValidationResult::Valid(share_hash, header80)) => {
                        // Credit the target the JOB was issued against, not the channel's current one.
                        // Vardiff moves the channel target while jobs are outstanding, so on a raise an accepted
                        // share would be credited more work than its hash proves — and every peer that
                        // re-derives difficulty from the hash then rejects it as below_difficulty.
                        let share_work = match extended_channel.job_target(msg.job_id) {
                            Some(t) => t.difficulty_float(),
                            None => extended_channel.get_target().difficulty_float(),
                        };
                        // SHARE_TIER_BIND: the tier this share's JOB committed to in its
                        // coinbase, captured at build time (never re-derived from the target
                        // map, which binds at activation). When present, the reported work IS
                        // the tier's exact credit — ghost-pool's verifier requires
                        // difficulty == 2^tier at/above the gate.
                        let tier_log2 = extended_channel.job_tier_log2(msg.job_id);
                        let share_work = match tier_log2 {
                            Some(t) => crate::tier_binding::tier_credit(t),
                            None => share_work,
                        };
                        if let (Some(ref sender), true) = (&self.share_webhook_sender, attributable) {
                            // The full extranonce on an extended channel is the channel's
                            // prefix followed by the miner's own bytes; the coinbase commits to
                            // both, so the binding needs both.
                            let (extranonce, skeleton_id) = extended_channel
                                .get_active_job()
                                .map(|job| {
                                    let mut full = job.get_extranonce_prefix().clone();
                                    full.extend_from_slice(msg.extranonce.inner_as_ref());
                                    crate::binding::announce(
                                        sender,
                                        // The NON-witness serialization: the txid that folds into
                                        // the merkle root is computed without BIP141 data, so the
                                        // with-BIP141 variant would never reproduce the root.
                                        job.get_coinbase_tx_prefix_without_bip141(),
                                        job.get_coinbase_tx_suffix_without_bip141(),
                                        job.get_merkle_path()
                                            .inner_as_ref()
                                            .iter()
                                            .map(|n| n.to_vec())
                                            .collect(),
                                        &full,
                                    )
                                })
                                .unwrap_or((None, None));
                            sender.send(ShareData {
                                timestamp_ms: now_ms(),
                                share_hash: share_hash.to_string(),
                                share_work,
                                channel_id,
                                sequence_number: msg.sequence_number,
                                job_id: msg.job_id,
                                downstream_id,
                                is_block: false,
                                // `attributable` above guarantees `Some` on the share path;
                                // the block path is deliberately ungated, so fall back to the
                                // raw channel identity rather than dropping the record.
                                user_identity: webhook_identity
                                    .clone()
                                    .unwrap_or_else(|| channel_identity.clone()),
                                header: Some(hex::encode(&header80)),
                                extranonce,
                                skeleton_id,
                                tier_log2,
                            });
                        }
                        let share_accounting = extended_channel.get_share_accounting();
                        if share_accounting.should_acknowledge() {
                            let success = SubmitSharesSuccess {
                                channel_id,
                                last_sequence_number: share_accounting.get_last_share_sequence_number(),
                                new_submits_accepted_count: share_accounting.get_last_batch_accepted(),
                                new_shares_sum: share_accounting.get_last_batch_work_sum() as u64,
                            };
                            info!("SubmitSharesExtended: {} ✅", success);
                            messages.push((downstream_id, Mining::SubmitSharesSuccess(success)).into());
                        } else {
                            info!(
                                "SubmitSharesExtended: valid share | downstream_id: {}, channel_id: {}, sequence_number: {}, share_hash: {}, share_work: {} ✅",
                                downstream_id, channel_id, msg.sequence_number, share_hash, share_work
                            );
                        }
                    }
                    Ok(ShareValidationResult::BlockFound(share_hash, template_id, coinbase, header80)) => {
                        info!("SubmitSharesExtended: 💰 Block Found!!! 💰{share_hash}");
                        // Deliberately NOT gated on `attributable`: a block is always reported,
                        // even if we cannot identify who found it. Losing a block to an
                        // attribution problem would be far worse than recording one whose finder
                        // needs resolving by hand afterwards.
                        if !attributable {
                            error!(
                                "BLOCK FOUND on channel {} but the worker TLV is missing — block \
                                 IS being reported; finder attribution needs manual resolution",
                                channel_id
                            );
                        }
                        // Credit the target the JOB was issued against, not the channel's current one.
                        // Vardiff moves the channel target while jobs are outstanding, so on a raise an accepted
                        // share would be credited more work than its hash proves — and every peer that
                        // re-derives difficulty from the hash then rejects it as below_difficulty.
                        let share_work = match extended_channel.job_target(msg.job_id) {
                            Some(t) => t.difficulty_float(),
                            None => extended_channel.get_target().difficulty_float(),
                        };
                        // SHARE_TIER_BIND: build-time tier label; see the valid-share twin above.
                        let tier_log2 = extended_channel.job_tier_log2(msg.job_id);
                        let share_work = match tier_log2 {
                            Some(t) => crate::tier_binding::tier_credit(t),
                            None => share_work,
                        };
                        if let Some(ref sender) = self.share_webhook_sender {
                            // The full extranonce on an extended channel is the channel's
                            // prefix followed by the miner's own bytes; the coinbase commits to
                            // both, so the binding needs both.
                            let (extranonce, skeleton_id) = extended_channel
                                .get_active_job()
                                .map(|job| {
                                    let mut full = job.get_extranonce_prefix().clone();
                                    full.extend_from_slice(msg.extranonce.inner_as_ref());
                                    crate::binding::announce(
                                        sender,
                                        // The NON-witness serialization: the txid that folds into
                                        // the merkle root is computed without BIP141 data, so the
                                        // with-BIP141 variant would never reproduce the root.
                                        job.get_coinbase_tx_prefix_without_bip141(),
                                        job.get_coinbase_tx_suffix_without_bip141(),
                                        job.get_merkle_path()
                                            .inner_as_ref()
                                            .iter()
                                            .map(|n| n.to_vec())
                                            .collect(),
                                        &full,
                                    )
                                })
                                .unwrap_or((None, None));
                            sender.send(ShareData {
                                timestamp_ms: now_ms(),
                                share_hash: share_hash.to_string(),
                                share_work,
                                channel_id,
                                sequence_number: msg.sequence_number,
                                job_id: msg.job_id,
                                downstream_id,
                                is_block: true,
                                // `attributable` above guarantees `Some` on the share path;
                                // the block path is deliberately ungated, so fall back to the
                                // raw channel identity rather than dropping the record.
                                user_identity: webhook_identity
                                    .clone()
                                    .unwrap_or_else(|| channel_identity.clone()),
                                header: Some(hex::encode(&header80)),
                                extranonce,
                                skeleton_id,
                                tier_log2,
                            });
                        }
                        // if we have a template id (i.e.: this was not a custom job)
                        // we can propagate the solution to the TP
                        if let Some(template_id) = template_id {
                            info!("SubmitSharesExtended: Propagating solution to the Template Provider.");
                            let solution = SubmitSolution {
                                template_id,
                                version: msg.version,
                                header_timestamp: msg.ntime,
                                header_nonce: msg.nonce,
                                coinbase_tx: coinbase.try_into().map_err(PoolError::shutdown)?,
                            };
                            messages.push(TemplateDistribution::SubmitSolution(solution).into());
                        }
                        let share_accounting = extended_channel.get_share_accounting();
                        let success = SubmitSharesSuccess {
                            channel_id,
                            last_sequence_number: share_accounting.get_last_share_sequence_number(),
                            new_submits_accepted_count: share_accounting.get_last_batch_accepted(),
                            new_shares_sum: share_accounting.get_last_batch_work_sum() as u64,
                        };
                        messages.push((downstream_id, Mining::SubmitSharesSuccess(success)).into());
                    }
                    Err(ShareValidationError::Invalid) => {
                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: invalid-share ❌", downstream_id, channel_id, msg.sequence_number);
                        let error = SubmitSharesError {
                            channel_id: msg.channel_id,
                            sequence_number: msg.sequence_number,
                            error_code: "invalid-share"
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        messages.push((downstream_id, Mining::SubmitSharesError(error)).into());
                    }
                    Err(ShareValidationError::Stale) => {
                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: stale-share ❌", downstream_id, channel_id, msg.sequence_number);
                        let error = SubmitSharesError {
                            channel_id: msg.channel_id,
                            sequence_number: msg.sequence_number,
                            error_code: "stale-share"
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        messages.push((downstream_id, Mining::SubmitSharesError(error)).into());
                    }
                    Err(ShareValidationError::InvalidJobId) => {
                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: invalid-job-id ❌", downstream_id, channel_id, msg.sequence_number);
                        let error = SubmitSharesError {
                            channel_id: msg.channel_id,
                            sequence_number: msg.sequence_number,
                            error_code: "invalid-job-id"
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        messages.push((downstream_id, Mining::SubmitSharesError(error)).into());
                    }
                    Err(ShareValidationError::DoesNotMeetTarget) => {
                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: difficulty-too-low ❌", downstream_id, channel_id, msg.sequence_number);
                        let error = SubmitSharesError {
                            channel_id: msg.channel_id,
                            sequence_number: msg.sequence_number,
                            error_code: "difficulty-too-low"
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        messages.push((downstream_id, Mining::SubmitSharesError(error)).into());
                    }
                    Err(ShareValidationError::DuplicateShare) => {
                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: duplicate-share ❌", downstream_id, channel_id, msg.sequence_number);
                        let error = SubmitSharesError {
                            channel_id: msg.channel_id,
                            sequence_number: msg.sequence_number,
                            error_code: "duplicate-share"
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        messages.push((downstream_id, Mining::SubmitSharesError(error)).into());
                    }
                    Err(ShareValidationError::BadExtranonceSize) => {
                        error!("SubmitSharesError: downstream_id: {}, channel_id: {}, sequence_number: {}, error_code: bad-extranonce-size ❌", downstream_id, channel_id, msg.sequence_number);
                        let error = SubmitSharesError {
                            channel_id: msg.channel_id,
                            sequence_number: msg.sequence_number,
                            error_code: "bad-extranonce-size"
                                .to_string()
                                .try_into()
                                .expect("error code must be valid string"),
                        };
                        messages.push((downstream_id, Mining::SubmitSharesError(error)).into());
                    }
                    Err(e) => {
                        return Err(PoolError::disconnect(e, downstream_id));
                    }
                }

                Ok(messages)
            })
        })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_channel).await {
                error!("Failed to forward message {e:?}");
            }
        }

        Ok(())
    }

    async fn handle_update_channel(
        &mut self,
        client_id: Option<usize>,
        msg: UpdateChannel<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);

        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");

        let messages: Vec<RouteMessageTo> = self.channel_manager_data.super_safe_lock(|channel_manager_data| {
            let Some(downstream) = channel_manager_data.downstream.get(&downstream_id) else {
                return Err(PoolError::disconnect(PoolErrorKind::DownstreamNotFound(downstream_id), downstream_id));
            };

            downstream.downstream_data.super_safe_lock(|downstream_data| {
                let mut messages = Vec::new();
                let channel_id = msg.channel_id;
                let new_nominal_hash_rate = msg.nominal_hash_rate;
                let requested_maximum_target = Target::from_le_bytes(msg.maximum_target.inner_as_ref().try_into().unwrap());

                // SHARE_TIER_BIND: is tiering active for the template era we are in?
                let tiering = self.tier_binding.clone().filter(|tb| {
                    channel_manager_data
                        .last_future_template
                        .as_ref()
                        .is_some_and(|t| tb.template_is_tiered(t))
                });

                // Make a half-armed deployment LOUD. The two halves of the gate live in two
                // separately-deployed binaries and nothing else would notice a desync:
                // - pool-on / translator-off: shares are validated and credited at tier targets
                //   the translator never told its miners about — visible here as a client max
                //   target that is NOT tier-shaped while tiering is active;
                // - translator-on / pool-off: tier-shaped difficulties arrive that nothing
                //   checks or commits to — visible here as a tier-shaped client max while this
                //   binary has no [share_tier_binding] at all.
                // Heuristic on real difficulties only (>= the 2^10 floor): a permissive
                // direct-miner max target sits far below it and never trips either arm.
                let max_is_tier_shaped = crate::tier_binding::is_tier_shaped(&requested_maximum_target);
                if tiering.is_some()
                    && requested_maximum_target.difficulty_float() >= 1024.0
                    && !max_is_tier_shaped
                {
                    error!(
                        channel_id,
                        "SHARE_TIER_BIND DESYNC? tiering is ACTIVE but this client's requested \
                         max target is not tier-shaped — if this client is the translator, it is \
                         running without quantise_to_tiers = true and its miners are being \
                         credited below the difficulty they mine at"
                    );
                } else if self.tier_binding.is_none() && max_is_tier_shaped {
                    error!(
                        channel_id,
                        "SHARE_TIER_BIND DESYNC? this client sends tier-shaped difficulties \
                         (translator quantise_to_tiers = true?) but pool_sv2 has no \
                         [share_tier_binding] config — nothing here commits to or checks those \
                         tiers"
                    );
                }

                if let Some(standard_channel) = downstream_data.standard_channels.get_mut(&channel_id) {
                    let res = standard_channel
                                    .update_channel(new_nominal_hash_rate, Some(requested_maximum_target));
                    match res {
                        Ok(_) => {}
                        Err(e) => {
                            error!("UpdateChannelError: {:?}", e);
                            match e {
                                StandardChannelError::InvalidNominalHashrate => {
                                    error!("UpdateChannelError: invalid-nominal-hashrate");
                                    let update_channel_error = UpdateChannelError {
                                        channel_id,
                                        error_code: "invalid-nominal-hashrate"
                                            .to_string()
                                            .try_into()
                                            .expect("error code must be valid string"),
                                    };
                                    messages.push((downstream_id, Mining::UpdateChannelError(update_channel_error)).into());
                                }
                                StandardChannelError::RequestedMaxTargetOutOfRange => {
                                    error!("UpdateChannelError: requested-max-target-out-of-range");
                                    let update_channel_error = UpdateChannelError {
                                        channel_id,
                                        error_code: "requested-max-target-out-of-range"
                                            .to_string()
                                            .try_into()
                                            .expect("error code must be valid string"),
                                    };
                                    messages.push((downstream_id, Mining::UpdateChannelError(update_channel_error)).into());
                                }
                                // We don't care about other variants as they are not
                                // associated to Update channel, and we will never
                                // encounter it.
                                _ => unreachable!()
                            }
                        }
                    }
                    // SHARE_TIER_BIND: the announced target must BE a tier's exact target while
                    // tiering is active — the tier the next job commits to is derived from it.
                    if let Some(ref tb) = tiering {
                        let q = tb.quantise_target(
                            standard_channel.get_target(),
                            standard_channel.get_requested_max_target(),
                        );
                        standard_channel.set_target(q);
                    }
                    let new_target = standard_channel.get_target();
                    let set_target = SetTarget {
                        channel_id,
                        maximum_target: new_target.to_le_bytes().into(),
                    };
                    messages.push((downstream_id, Mining::SetTarget(set_target)).into());
                } else if let Some(extended_channel) = downstream_data.extended_channels.get_mut(&channel_id) {
                    let res = extended_channel
                                    .update_channel(new_nominal_hash_rate, Some(requested_maximum_target));
                    match res {
                        Ok(_) => {}
                        Err(e) => {
                            error!("UpdateChannelError: {:?}", e);
                            match e {
                                ExtendedChannelError::InvalidNominalHashrate => {
                                    error!("UpdateChannelError: invalid-nominal-hashrate");
                                    let update_channel_error = UpdateChannelError {
                                        channel_id,
                                        error_code: "invalid-nominal-hashrate"
                                            .to_string()
                                            .try_into()
                                            .expect("error code must be valid string"),
                                    };
                                    messages.push((downstream_id, Mining::UpdateChannelError(update_channel_error)).into());
                                }
                                ExtendedChannelError::RequestedMaxTargetOutOfRange => {
                                    error!("UpdateChannelError: max-target-out-of-range");
                                    let update_channel_error = UpdateChannelError {
                                        channel_id,
                                        error_code: "max-target-out-of-range"
                                            .to_string()
                                            .try_into()
                                            .expect("error code must be valid string"),
                                    };
                                    messages.push((downstream_id, Mining::UpdateChannelError(update_channel_error)).into());
                                }
                                // We don't care about other variants as they are not
                                // associated to Update channel, and we will never
                                // encounter it.
                                _ => unreachable!()
                            }
                        }
                    }
                    // SHARE_TIER_BIND: as for standard channels above.
                    if let Some(ref tb) = tiering {
                        let q = tb.quantise_target(
                            extended_channel.get_target(),
                            extended_channel.get_requested_max_target(),
                        );
                        extended_channel.set_target(q);
                    }
                    let new_target = extended_channel.get_target();
                    let set_target = SetTarget {
                        channel_id,
                        maximum_target: new_target.to_le_bytes().into(),
                    };
                    messages.push((downstream_id, Mining::SetTarget(set_target)).into());
                } else {
                    error!("UpdateChannelError: invalid-channel-id");
                    let update_channel_error = UpdateChannelError {
                        channel_id,
                        error_code: "invalid-channel-id"
                            .to_string()
                            .try_into()
                            .expect("error code must be valid string"),
                    };
                    messages.push((downstream_id, Mining::UpdateChannelError(update_channel_error)).into());
                }

                Ok(messages)
            })
        })?;

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_channel).await {
                error!("Failed to forward message {e:?}");
            }
        }

        Ok(())
    }

    async fn handle_set_custom_mining_job(
        &mut self,
        client_id: Option<usize>,
        msg: SetCustomMiningJob<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);
        let downstream_id =
            client_id.expect("client_id must be present for downstream_id extraction");

        let Some(ref mut job_declarator) = self.job_declarator else {
            let error = SetCustomMiningJobError {
                request_id: msg.request_id,
                channel_id: msg.channel_id,
                error_code: "jd-not-supported"
                    .to_string()
                    .try_into()
                    .expect("error code must be valid string"),
            };
            let message: RouteMessageTo =
                (downstream_id, Mining::SetCustomMiningJobError(error)).into();
            message
                .forward(&self.channel_manager_channel)
                .await
                .map_err(|e| PoolError::disconnect(e, downstream_id))?;
            return Ok(());
        };

        let msg_static = msg.clone().into_static();

        // Step 1: Validate the custom job via JDS (token + job validation).
        let jds_response = job_declarator
            .handle_set_custom_mining_job(msg_static.clone(), _tlv_fields)
            .await
            .map_err(|e| PoolError::shutdown(PoolErrorKind::Jds(e.into())))?;

        if let SetCustomMiningJobResponse::Error(jds_err) = jds_response {
            let message: RouteMessageTo = (
                downstream_id,
                Mining::SetCustomMiningJobError(jds_err.into_static()),
            )
                .into();
            message
                .forward(&self.channel_manager_channel)
                .await
                .map_err(|e| PoolError::disconnect(e, downstream_id))?;
            return Ok(());
        }

        // Step 2: JDS validated successfully — commit the job to the extended channel.
        let message: RouteMessageTo =
            self.channel_manager_data
                .super_safe_lock(|channel_manager_data| {
                    let Some(downstream) = channel_manager_data.downstream.get_mut(&downstream_id)
                    else {
                        return Err(PoolError::disconnect(
                            PoolErrorKind::DownstreamNotFound(downstream_id),
                            downstream_id,
                        ));
                    };

                    downstream
                        .downstream_data
                        .super_safe_lock(|downstream_data| {
                            let Some(extended_channel) = downstream_data
                                .extended_channels
                                .get_mut(&msg_static.channel_id)
                            else {
                                error!("SetCustomMiningJobError: invalid-channel-id");
                                let error = SetCustomMiningJobError {
                                    request_id: msg_static.request_id,
                                    channel_id: msg_static.channel_id,
                                    error_code: "invalid-channel-id"
                                        .to_string()
                                        .try_into()
                                        .expect("error code must be valid string"),
                                };
                                return Ok(
                                    (downstream_id, Mining::SetCustomMiningJobError(error)).into()
                                );
                            };

                            let job_id = extended_channel
                                .on_set_custom_mining_job(msg_static.clone())
                                .map_err(|error| PoolError::disconnect(error, downstream_id))?;

                            let success = SetCustomMiningJobSuccess {
                                channel_id: msg_static.channel_id,
                                request_id: msg_static.request_id,
                                job_id,
                            };
                            Ok((downstream_id, Mining::SetCustomMiningJobSuccess(success)).into())
                        })
                })?;

        message
            .forward(&self.channel_manager_channel)
            .await
            .map_err(|e| PoolError::disconnect(e, downstream_id))?;

        Ok(())
    }
}

#[cfg(test)]
mod extranonce_allocation_tests {
    use super::*;
    use crate::channel_manager::{POOL_ALLOCATION_BYTES, POOL_STATIC_PREFIX_BYTES};

    /// A `user_identity` this pool rejects: `sri/<mode>` with an unrecognised mode.
    const INVALID_IDENTITY: &str = "sri/nonsense";
    /// A `user_identity` this pool accepts (empty means full donation to the pool).
    const VALID_IDENTITY: &str = "";
    const SHARES_PER_MINUTE: SharesPerMinute = 6.0;
    const NOMINAL_HASH_RATE: f32 = 1e12;

    /// Builds the extranonce factory with exactly the geometry `ChannelManager::new` uses, so
    /// these tests exercise the real allocation space rather than a convenient toy one.
    fn pool_factory() -> ExtendedExtranonce {
        // Built through the same helper the pool uses, so a change to the split cannot pass
        // the tests while shipping something else.
        ExtendedExtranonce::new(
            0..0,
            0..POOL_ALLOCATION_BYTES,
            POOL_ALLOCATION_BYTES..POOL_ALLOCATION_BYTES + CLIENT_SEARCH_SPACE_BYTES,
            Some(crate::channel_manager::server_static_prefix(0).expect("0 fits")),
        )
        .expect("valid ranges")
    }

    fn open(
        factory: &mut ExtendedExtranonce,
        user_identity: &str,
    ) -> Result<(PayoutMode, Vec<u8>), &'static str> {
        validate_and_allocate_extended(
            factory,
            user_identity,
            NOMINAL_HASH_RATE,
            &Target::MAX,
            SHARES_PER_MINUTE,
            CLIENT_SEARCH_SPACE_BYTES,
        )
    }

    /// Positive control plus the number the DoS turns on: how many extended channels the pool
    /// can ever open, derived from the split rather than hardcoded so it tracks
    /// `POOL_STATIC_PREFIX_BYTES` instead of silently disagreeing with it.
    ///
    /// Was 16 bits — 65,535, about ten days of uptime at the ~250/h measured on vm1, after
    /// which every open fails while the pool still reports healthy. Now 24.
    #[test]
    fn extended_prefix_space_matches_the_configured_split() {
        let counter_bits = (POOL_ALLOCATION_BYTES - POOL_STATIC_PREFIX_BYTES) * 8;
        let capacity = 1usize << counter_bits;
        assert_eq!(counter_bits, 24, "the split changed — is that deliberate?");

        let mut factory = pool_factory();
        let mut minted = 0usize;
        loop {
            match open(&mut factory, VALID_IDENTITY) {
                Ok(_) => minted += 1,
                Err(code) => {
                    assert_eq!(code, EXTRANONCE_SPACE_EXHAUSTED);
                    break;
                }
            }
            assert!(minted <= capacity, "allocator did not run out");
        }
        assert_eq!(minted, capacity - 1);
    }

    /// The static prefix must fail closed rather than truncate: servers configured 1 and 257
    /// truncating to the same octet would mint identical prefixes on two different pools.
    #[test]
    fn server_id_that_does_not_fit_the_prefix_is_refused() {
        use crate::channel_manager::server_static_prefix;
        assert_eq!(server_static_prefix(0).unwrap(), vec![0]);
        assert_eq!(server_static_prefix(1).unwrap(), vec![1]);
        assert_eq!(server_static_prefix(255).unwrap(), vec![255]);
        assert!(server_static_prefix(256).is_err());
        assert!(server_static_prefix(257).is_err());
    }

    /// The regression test for #744.
    ///
    /// A client that loops `OpenExtendedMiningChannel` with an identity the pool rejects must
    /// not consume anything, so an honest miner arriving afterwards still gets a channel. The
    /// loop deliberately runs past the size of the whole allocation space: with the identity
    /// check performed after allocation, this test fails long before it finishes.
    #[test]
    fn rejected_identities_never_consume_a_prefix() {
        let mut factory = pool_factory();

        let attempts = (1 << 16) + 1_000;
        for attempt in 0..attempts {
            match open(&mut factory, INVALID_IDENTITY) {
                Err("invalid-user-identity") => {}
                other => panic!(
                    "attempt {attempt} of {attempts} did not fail cleanly on identity: \
                     {:?}",
                    other.map(|(_, prefix)| prefix)
                ),
            }
        }

        let (_, prefix) = open(&mut factory, VALID_IDENTITY)
            .expect("an honest miner must still be able to open a channel");
        assert_eq!(prefix.len(), POOL_ALLOCATION_BYTES);
    }

    /// Same property for the other two client-controlled fields that can reject an open.
    #[test]
    fn rejected_hashrate_and_target_never_consume_a_prefix() {
        let mut factory = pool_factory();

        let attempts = ((1 << 16) + 1_000) / 2;
        for attempt in 0..attempts {
            assert_eq!(
                validate_and_allocate_extended(
                    &mut factory,
                    VALID_IDENTITY,
                    -1.0,
                    &Target::MAX,
                    SHARES_PER_MINUTE,
                    CLIENT_SEARCH_SPACE_BYTES,
                )
                .err(),
                Some("invalid-nominal-hashrate"),
                "attempt {attempt}"
            );
            assert_eq!(
                validate_and_allocate_extended(
                    &mut factory,
                    VALID_IDENTITY,
                    NOMINAL_HASH_RATE,
                    &Target::from_le_bytes([0u8; 32]),
                    SHARES_PER_MINUTE,
                    CLIENT_SEARCH_SPACE_BYTES,
                )
                .err(),
                Some("max-target-out-of-range"),
                "attempt {attempt}"
            );
        }

        open(&mut factory, VALID_IDENTITY)
            .expect("an honest miner must still be able to open a channel");
    }

    /// The runtime tests above prove the helper allocates last. They cannot see whether the
    /// handler still goes through the helper, and re-inlining an allocation ahead of the
    /// validation is exactly how #744 was written in the first place — so assert the call
    /// site against the source: the extended allocator must be unreachable except from
    /// inside `validate_and_allocate_extended`.
    ///
    /// The needles are assembled at run time so this test's own text cannot match them.
    #[test]
    fn the_extended_allocator_has_exactly_one_call_site() {
        let src = include_str!("mining_message_handler.rs");
        let allocator = format!("next_prefix{}", "_extended(");
        let helper = format!("fn validate_and_allocate{}(", "_extended");

        let call_sites: Vec<_> = src.match_indices(&allocator).map(|(i, _)| i).collect();
        assert_eq!(
            call_sites.len(),
            1,
            "the extended extranonce allocator is called from {} places",
            call_sites.len()
        );

        let helper_start = src.find(&helper).expect("the helper must still exist");
        let helper_end = helper_start
            + src[helper_start..]
                .find("\n}\n")
                .expect("the helper must be a top-level fn");
        assert!(
            (helper_start..helper_end).contains(&call_sites[0]),
            "an extranonce prefix is minted outside the validating helper"
        );
    }

    /// Exhaustion and "you asked for too many rollable bytes" are different faults with
    /// different remedies, so they must not share an error code.
    #[test]
    fn exhaustion_and_oversized_request_report_different_codes() {
        let mut oversized = pool_factory();
        assert_eq!(
            validate_and_allocate_extended(
                &mut oversized,
                VALID_IDENTITY,
                NOMINAL_HASH_RATE,
                &Target::MAX,
                SHARES_PER_MINUTE,
                CLIENT_SEARCH_SPACE_BYTES + 1,
            )
            .err(),
            Some("min-extranonce-size-too-large")
        );

        let mut drained = pool_factory();
        while open(&mut drained, VALID_IDENTITY).is_ok() {}
        assert_eq!(
            open(&mut drained, VALID_IDENTITY).err(),
            Some(EXTRANONCE_SPACE_EXHAUSTED)
        );
    }

    // ---- build_webhook_user_identity -------------------------------------------------
    //
    // Two channel-identity shapes reach this function and they are told apart by the
    // CHANNEL identity, never by inspecting the TLV. A worker name may legitimately contain
    // a dot (#481), so "the TLV looks dotted" proves nothing about whether it holds an
    // address.

    #[test]
    fn webhook_identity_splices_worker_onto_channel_address() {
        // Channel opened on mining.authorize: the channel identity owns the address, the TLV
        // owns the worker. This is what every currently-connected miner does.
        assert_eq!(
            build_webhook_user_identity("bc1qAAA.rig1".to_string(), Some("bitaxe1")),
            Some("bc1qAAA.bitaxe1".to_string())
        );
    }

    #[test]
    fn webhook_identity_falls_back_to_channel_when_no_tlv() {
        // A direct SV2 miner never negotiates the extension; its channel identity IS the
        // payout target and must pass through untouched.
        assert_eq!(
            build_webhook_user_identity("bc1qAAA.rig1".to_string(), None),
            Some("bc1qAAA.rig1".to_string())
        );
        assert_eq!(
            build_webhook_user_identity("bc1qAAA.rig1".to_string(), Some("")),
            Some("bc1qAAA.rig1".to_string())
        );
    }

    #[test]
    fn webhook_identity_keeps_a_dotted_worker_on_a_real_channel() {
        // `addr.farm1.rig1` yields worker `farm1.rig1`. The dot must NOT be read as an
        // address separator, or `farm1` silently becomes the payout target.
        assert_eq!(
            build_webhook_user_identity("bc1qAAA.farm1.rig1".to_string(), Some("farm1.rig1")),
            Some("bc1qAAA.farm1.rig1".to_string())
        );
    }

    #[test]
    fn webhook_identity_uses_a_provisional_channels_tlv_verbatim() {
        // Channel opened on mining.subscribe: the TLV is authoritative and already carries
        // the full `<addr>.<worker>`.
        assert_eq!(
            build_webhook_user_identity(
                PROVISIONAL_CHANNEL_IDENTITY.to_string(),
                Some("bc1qAAA.rig1")
            ),
            Some("bc1qAAA.rig1".to_string())
        );
    }

    #[test]
    fn webhook_identity_fails_closed_on_a_provisional_channel_without_a_full_tlv() {
        // Splicing would yield `sri/donate/provisional.rig1`, whose address portion is `sri`
        // — a share credited to nobody while looking entirely normal. Refuse instead.
        for tlv in [None, Some(""), Some("rig1")] {
            assert_eq!(
                build_webhook_user_identity(PROVISIONAL_CHANNEL_IDENTITY.to_string(), tlv),
                None,
                "provisional channel must not resolve a payout target from {tlv:?}"
            );
        }
    }

    #[test]
    fn provisional_identity_parses_as_a_payout_mode_the_pool_accepts() {
        // The channel open is rejected outright if `PayoutMode::try_from` errors, so the
        // sentinel has to be a shape the pool already parses. It must also NOT be reachable
        // by a miner authorising as plain `sri/donate`.
        assert!(PayoutMode::try_from(PROVISIONAL_CHANNEL_IDENTITY).is_ok());
        assert_ne!(PROVISIONAL_CHANNEL_IDENTITY, "sri/donate");
    }
}
