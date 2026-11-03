use stratum_apps::stratum_core::{
    bitcoin::{Amount, TxOut},
    handlers_sv2::HandleTemplateDistributionMessagesFromServerAsync,
    mining_sv2::{SetNewPrevHash as SetNewPrevHashMp, SetTarget},
    parsers_sv2::{Mining, Tlv},
    template_distribution_sv2::*,
};
use tracing::{error, info, warn};

use crate::{
    channel_manager::{ChannelManager, RouteMessageTo},
    error::{self, PoolError, PoolErrorKind},
    node_pool::ChannelKind,
};

#[cfg_attr(not(test), hotpath::measure_all)]
impl HandleTemplateDistributionMessagesFromServerAsync for ChannelManager {
    type Error = PoolError<error::ChannelManager>;

    fn get_negotiated_extensions_with_server(
        &self,
        _server_id: Option<usize>,
    ) -> Result<Vec<u16>, Self::Error> {
        Ok(vec![])
    }

    async fn handle_new_template(
        &mut self,
        _server_id: Option<usize>,
        msg: NewTemplate<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);
        let np = self.node_pool.clone();

        // The template provider hands over the whole coinbase value and the witness commitment
        // as its only output; anything else cannot carry a canonical coinbase. That is a
        // misconfigured template provider, not a bad block: refuse to mine on it.
        if let Err(e) = np.template_parts(&msg) {
            error!(
                template_id = msg.template_id,
                "NODE_POOL: the template cannot carry a canonical coinbase: {e}"
            );
            return Err(PoolError::shutdown(PoolErrorKind::Custom(format!(
                "template {} cannot carry a canonical coinbase: {e}",
                msg.template_id
            ))));
        }

        np.on_new_template(&msg);
        // While a tip is held, a future template is kept for the replay after it is served
        // (`node_pool_serve_held_tip`): serving the held tip drops every other future job.
        np.note_future_template(&msg);
        // The table this template's jobs pay, fetched before the channel locks are taken, and
        // the anchor they build on. No table in time: the template is not served (see
        // `NodePool::prepare_job_basis`), and miners keep their current job.
        let served = np.prepare_job_basis(&msg).await;
        if let Some(h) = crate::node_pool::NodePool::template_height(&msg) {
            np.note_job_height(h);
        }
        if served {
            np.mark_served(msg.template_id);
        } else {
            np.mark_unserved(msg.template_id);
        }
        // A template on the current tip while that tip is held for its table: its jobs would
        // build on a prev hash the channels were never given. The held tip is served from the
        // active template once the table arrives (`node_pool_serve_held_tip`).
        let held = !msg.future_template && np.pending_tip().is_some();
        let serve = served && !held;
        // The template's Ghost tags taken out of the prefix, making room, byte for byte, for
        // what each channel's factory stamps back in.
        let prepared = np.prepare_template(&msg.clone().into_static());
        let template_id = msg.template_id;

        // No channel error on this path shuts the pool down: a channel that cannot take this
        // template is logged and skipped, and keeps its current job (#898's rule, on the
        // template side). Only a template no coinbase can be built from (above) is fatal.
        let messages = self
            .channel_manager_data
            .super_safe_lock(|channel_manager_data| {
                if msg.future_template {
                    channel_manager_data.last_future_template = Some(msg.clone().into_static());
                }

                let mut messages: Vec<RouteMessageTo> = Vec::new();
                let mut skipped = 0usize;
                let mut failed = 0usize;

                // The group channel tracks every template so its state stays coherent, but its job
                // is never sent: one coinbase cannot carry every channel's share tag and slot class.
                let group_outputs = vec![TxOut {
                    value: Amount::from_sat(msg.coinbase_tx_value_remaining),
                    script_pubkey: self.coinbase_reward_script.script_pubkey(),
                }];

                for (downstream_id, downstream) in channel_manager_data.downstream.iter_mut() {
                    downstream.downstream_data.super_safe_lock(|data| {
                        if let Err(e) = data
                            .group_channel
                            .on_new_template(msg.clone().into_static(), group_outputs.clone())
                        {
                            error!(
                                downstream_id = *downstream_id,
                                template_id,
                                error = ?e,
                                "NODE_POOL_TEMPLATE_MISMATCH: the group channel did not take this \
                                 template; skipped (its job is never sent)"
                            );
                        }

                        // Per-channel jobs: each channel's own factory builds its job, target
                        // quantised to its tier, share tag stamped as the factory's extra push, the
                        // canonical outputs of its slot class.
                        if !serve {
                            skipped += data.standard_channels.len() + data.extended_channels.len();
                            return;
                        }

                        for (channel_id, standard_channel) in data.standard_channels.iter_mut() {
                            let q = np.quantise_target(
                                standard_channel.get_target(),
                                standard_channel.get_requested_max_target(),
                            );
                            if &q != standard_channel.get_target() {
                                standard_channel.set_target(q);
                                messages.push(
                                    (
                                        *downstream_id,
                                        Mining::SetTarget(SetTarget {
                                            channel_id: *channel_id,
                                            maximum_target: q.to_le_bytes().into(),
                                        }),
                                    )
                                        .into(),
                                );
                            }
                            let key = (*downstream_id, *channel_id);
                            standard_channel.set_tier_commitment(Some(np.stamp(
                                key,
                                ChannelKind::Standard,
                                standard_channel.get_user_identity(),
                                standard_channel.get_target(),
                            )));
                            let built = np.job_outputs(key, &msg).and_then(|outputs| {
                                standard_channel
                                    .on_new_template(prepared.clone(), outputs)
                                    .map_err(|e| format!("{e:?}"))?;
                                let job = match msg.future_template {
                                    true => standard_channel
                                        .get_future_job_id_from_template_id(template_id)
                                        .and_then(|id| standard_channel.get_future_job(id)),
                                    false => standard_channel.get_active_job(),
                                };
                                job.map(|j| j.get_job_message().clone()).ok_or_else(|| {
                                    "the job just built is not in the channel".into()
                                })
                            });
                            match built {
                                Ok(job_message) => {
                                    np.bind_job(key, job_message.job_id);
                                    messages.push(
                                        (
                                            *downstream_id,
                                            Mining::NewMiningJob(job_message.into_static()),
                                        )
                                            .into(),
                                    );
                                }
                                Err(e) => {
                                    failed += 1;
                                    error!(
                                    ?key,
                                    template_id,
                                    "NODE_POOL_TEMPLATE_MISMATCH: no job on this template for a \
                                     standard channel; it keeps its current job: {e}"
                                );
                                }
                            }
                        }

                        for (channel_id, extended_channel) in data.extended_channels.iter_mut() {
                            // A provisional channel gets its first job when its payee is bound.
                            if np.awaits_payee((*downstream_id, *channel_id)) {
                                continue;
                            }
                            let q = np.quantise_target(
                                extended_channel.get_target(),
                                extended_channel.get_requested_max_target(),
                            );
                            if &q != extended_channel.get_target() {
                                extended_channel.set_target(q);
                                messages.push(
                                    (
                                        *downstream_id,
                                        Mining::SetTarget(SetTarget {
                                            channel_id: *channel_id,
                                            maximum_target: q.to_le_bytes().into(),
                                        }),
                                    )
                                        .into(),
                                );
                            }
                            let key = (*downstream_id, *channel_id);
                            extended_channel.set_tier_commitment(Some(np.stamp(
                                key,
                                ChannelKind::Extended,
                                extended_channel.get_user_identity(),
                                extended_channel.get_target(),
                            )));
                            let built = np.job_outputs(key, &msg).and_then(|outputs| {
                                extended_channel
                                    .on_new_template(prepared.clone(), outputs)
                                    .map_err(|e| format!("{e:?}"))?;
                                let job = match msg.future_template {
                                    true => extended_channel
                                        .get_future_job_id_from_template_id(template_id)
                                        .and_then(|id| extended_channel.get_future_job(id)),
                                    false => extended_channel.get_active_job(),
                                };
                                job.map(|j| j.get_job_message().clone()).ok_or_else(|| {
                                    "the job just built is not in the channel".into()
                                })
                            });
                            match built {
                                Ok(job_message) => {
                                    np.bind_job(key, job_message.job_id);
                                    messages.push(
                                        (
                                            *downstream_id,
                                            Mining::NewExtendedMiningJob(job_message.into_static()),
                                        )
                                            .into(),
                                    );
                                }
                                Err(e) => {
                                    failed += 1;
                                    error!(
                                    ?key,
                                    template_id,
                                    "NODE_POOL_TEMPLATE_MISMATCH: no job on this template for an \
                                     extended channel; it keeps its current job: {e}"
                                );
                                }
                            }
                        }
                    });
                }
                if skipped > 0 {
                    warn!(
                        template_id,
                        channels = skipped,
                        served,
                        "NODE_POOL: no job sent on this template; miners keep their current job"
                    );
                }
                if failed > 0 {
                    error!(
                        template_id,
                        channels = failed,
                        "NODE_POOL_TEMPLATE_MISMATCH: channels left on their current job"
                    );
                }
                messages
            });

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_channel).await {
                tracing::error!("Failed to forward message {e:?}");
            }
        }

        Ok(())
    }

    async fn handle_request_tx_data_error(
        &mut self,
        _server_id: Option<usize>,
        msg: RequestTransactionDataError<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        warn!("Received: {}", msg);
        Ok(())
    }

    async fn handle_request_tx_data_success(
        &mut self,
        _server_id: Option<usize>,
        msg: RequestTransactionDataSuccess<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);
        Ok(())
    }

    async fn handle_set_new_prev_hash(
        &mut self,
        _server_id: Option<usize>,
        msg: SetNewPrevHash<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);

        let np = self.node_pool.clone();
        np.on_set_new_prev_hash(msg.template_id);
        let template_id = msg.template_id;

        // The new tip's template was not served (no snapshot table in time): no channel has a
        // job on it, so nothing is activated or sent. The tip is held and served, with its jobs,
        // as soon as the table arrives (`node_pool_serve_held_tip`); until then miners keep
        // their current job.
        if np.is_unserved(template_id) {
            error!(
                template_id,
                "NODE_POOL_NO_TABLE: the new Bitcoin tip is held: its jobs wait for their \
                 snapshot table"
            );
            np.hold_tip(msg.clone().into_static());
            self.channel_manager_data.super_safe_lock(|data| {
                data.last_new_prev_hash = Some(msg.clone().into_static());
                for (downstream_id, downstream) in data.downstream.iter_mut() {
                    downstream.downstream_data.super_safe_lock(|d| {
                        if let Err(e) = d
                            .group_channel
                            .on_set_new_prev_hash(msg.clone().into_static())
                        {
                            error!(
                                downstream_id = *downstream_id,
                                template_id,
                                error = ?e,
                                "NODE_POOL_TIP_MISMATCH: the group channel does not hold the \
                                 held tip's template; skipped (the held tip's replay rebuilds it)"
                            );
                        }
                    });
                }
            });
            return Ok(());
        }
        np.clear_pending_tip();

        // ⛔ No channel error here shuts the pool down (#898's rule, on the template side). A
        // channel that does not hold the template this prev hash names is NOT activated: its
        // job store would mark every job stale, or activate a job on another height, and it
        // keeps its current job instead. The tip is then held for repair, so the next tick
        // rebuilds it for every channel from the active template.
        let mut mismatched = 0usize;
        let messages = self.channel_manager_data.super_safe_lock(|data| {
            data.last_new_prev_hash = Some(msg.clone().into_static());

            let mut messages: Vec<RouteMessageTo> = vec![];

            for (downstream_id, downstream) in data.downstream.iter_mut() {
                downstream.downstream_data.super_safe_lock(|data| {
                    // call on_set_new_prev_hash on the group channel to update the channel state;
                    // its job was never sent, so neither is its SetNewPrevHash: every channel mines
                    // its own job and gets its own below.
                    if let Err(e) = data.group_channel.on_set_new_prev_hash(msg.clone().into_static()) {
                        mismatched += 1;
                        error!(
                            downstream_id = *downstream_id,
                            template_id,
                            error = ?e,
                            "NODE_POOL_TIP_MISMATCH: the group channel does not hold this tip's \
                             template; skipped"
                        );
                    }

                    for (channel_id, extended_channel) in data.extended_channels.iter_mut() {
                        let key = (*downstream_id, *channel_id);
                        // A provisional channel has no job yet: the new tip is recorded, nothing
                        // is sent.
                        if np.awaits_payee(key) {
                            if let Err(e) = extended_channel.on_set_new_prev_hash(msg.clone().into_static()) {
                                error!(?key, template_id, error = ?e, "NODE_POOL_TIP_MISMATCH: a provisional channel did not take the new tip");
                            }
                            continue;
                        }
                        let activated = match extended_channel.get_future_job_id_from_template_id(template_id) {
                            None => Err("the channel holds no job on this template".to_string()),
                            Some(_) => extended_channel
                                .on_set_new_prev_hash(msg.clone().into_static())
                                .map_err(|e| format!("{e:?}"))
                                .and_then(|()| {
                                    extended_channel
                                        .get_active_job()
                                        .map(|j| j.get_job_id())
                                        .ok_or_else(|| "no active job after activation".to_string())
                                }),
                        };
                        match activated {
                            // This channel mines its OWN job, so it gets its own SetNewPrevHash
                            // naming that job.
                            Ok(job_id) => messages.push((*downstream_id, Mining::SetNewPrevHash(SetNewPrevHashMp {
                                channel_id: *channel_id,
                                job_id,
                                prev_hash: msg.prev_hash.clone(),
                                min_ntime: msg.header_timestamp,
                                nbits: msg.n_bits,
                            })).into()),
                            Err(e) => {
                                mismatched += 1;
                                error!(
                                    ?key,
                                    template_id,
                                    "NODE_POOL_TIP_MISMATCH: an extended channel was not moved to \
                                     the new tip; it keeps its current job: {e}"
                                );
                            }
                        }
                    }

                    for (channel_id, standard_channel) in data.standard_channels.iter_mut() {
                        let key = (*downstream_id, *channel_id);
                        let activated = match standard_channel.get_future_job_id_from_template_id(template_id) {
                            None => Err("the channel holds no job on this template".to_string()),
                            Some(_) => standard_channel
                                .on_set_new_prev_hash(msg.clone().into_static())
                                .map_err(|e| format!("{e:?}"))
                                .and_then(|()| {
                                    standard_channel
                                        .get_active_job()
                                        .map(|j| j.get_job_id())
                                        .ok_or_else(|| "no active job after activation".to_string())
                                }),
                        };
                        match activated {
                            // Every channel mines its own job, so each gets its own SetNewPrevHash.
                            Ok(job_id) => messages.push((*downstream_id, Mining::SetNewPrevHash(SetNewPrevHashMp {
                                channel_id: *channel_id,
                                job_id,
                                prev_hash: msg.prev_hash.clone(),
                                min_ntime: msg.header_timestamp,
                                nbits: msg.n_bits,
                            })).into()),
                            Err(e) => {
                                mismatched += 1;
                                error!(
                                    ?key,
                                    template_id,
                                    "NODE_POOL_TIP_MISMATCH: a standard channel was not moved to \
                                     the new tip; it keeps its current job: {e}"
                                );
                            }
                        }
                    }
                });
            }

            messages
        });

        for message in messages {
            // A send can only fail if the receiver side of the channel is closed.
            // Since this is an unbounded channel, it cannot fail due to capacity
            // limits (which would only apply to bounded channels).
            if let Err(e) = message.forward(&self.channel_manager_channel).await {
                tracing::error!("Failed to forward message {e:?}");
            }
        }

        if mismatched > 0 {
            if np.hold_tip_for_repair(msg.clone().into_static()) {
                error!(
                    template_id,
                    channels = mismatched,
                    "NODE_POOL_TIP_MISMATCH: channels did not hold this tip's template; the tip is \
                     held and rebuilt for every channel from the active template on the next tick"
                );
            } else {
                error!(
                    template_id,
                    channels = mismatched,
                    "NODE_POOL_TIP_MISMATCH: channels did not hold this tip's template and it \
                     cannot be rebuilt; they keep their current job until the next template"
                );
            }
        }

        Ok(())
    }
}
