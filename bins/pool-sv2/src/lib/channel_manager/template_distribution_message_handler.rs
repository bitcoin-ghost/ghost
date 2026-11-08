use stratum_apps::stratum_core::{
    bitcoin::{Amount, TxOut},
    handlers_sv2::HandleTemplateDistributionMessagesFromServerAsync,
    mining_sv2::SetNewPrevHash as SetNewPrevHashMp,
    parsers_sv2::{Mining, Tlv},
    template_distribution_sv2::*,
};
use tracing::{error, info, warn};

use crate::{
    channel_manager::{ChannelManager, RouteMessageTo},
    error::{self, PoolError, PoolErrorKind},
    solo::ChannelKind,
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
        let solo = self.solo.clone();

        // The template provider hands over the whole coinbase value and only zero-value outputs
        // (the witness commitment); anything else cannot carry a solo coinbase. That is a
        // misconfigured template provider, not a bad block: refuse to mine on it.
        if let Err(e) = solo.template_parts(&msg) {
            error!(
                template_id = msg.template_id,
                "SOLO: the template cannot carry a solo coinbase: {e}"
            );
            return Err(PoolError::shutdown(PoolErrorKind::Custom(format!(
                "template {} cannot carry a solo coinbase: {e}",
                msg.template_id
            ))));
        }

        solo.on_new_template(&msg);
        // The template's Ghost tags taken out of the prefix: a solo coinbase carries neither.
        let prepared = solo.prepare_template(&msg.clone().into_static());
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
                let mut failed = 0usize;

                // The group channel tracks every template so its state stays coherent, but its job
                // is never sent: one coinbase cannot pay every channel's miner.
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
                                "SOLO_TEMPLATE_MISMATCH: the group channel did not take this \
                                 template; skipped (its job is never sent)"
                            );
                        }

                        // Per-channel jobs: each channel's own factory builds its job, paying the
                        // treasury and that channel's miner.
                        for (channel_id, standard_channel) in data.standard_channels.iter_mut() {
                            let key = (*downstream_id, *channel_id);
                            let identity = standard_channel.get_user_identity().clone();
                            let built = solo
                                .job_outputs(key, ChannelKind::Standard, &identity, &msg)
                                .and_then(|outputs| {
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
                                    solo.bind_job(key, job_message.job_id);
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
                                        "SOLO_TEMPLATE_MISMATCH: no job on this template for a \
                                         standard channel; it keeps its current job: {e}"
                                    );
                                }
                            }
                        }

                        for (channel_id, extended_channel) in data.extended_channels.iter_mut() {
                            let key = (*downstream_id, *channel_id);
                            // A provisional channel gets its first job when its payee is bound.
                            if solo.awaits_payee(key) {
                                continue;
                            }
                            let identity = extended_channel.get_user_identity().clone();
                            let built = solo
                                .job_outputs(key, ChannelKind::Extended, &identity, &msg)
                                .and_then(|outputs| {
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
                                    solo.bind_job(key, job_message.job_id);
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
                                        "SOLO_TEMPLATE_MISMATCH: no job on this template for an \
                                         extended channel; it keeps its current job: {e}"
                                    );
                                }
                            }
                        }
                    });
                }
                if failed > 0 {
                    error!(
                        template_id,
                        channels = failed,
                        "SOLO_TEMPLATE_MISMATCH: channels left on their current job"
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
        self.solo
            .on_transaction_data_error(msg.template_id, &msg.error_code.as_utf8_or_hex());
        Ok(())
    }

    async fn handle_request_tx_data_success(
        &mut self,
        _server_id: Option<usize>,
        msg: RequestTransactionDataSuccess<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!(
            template_id = msg.template_id,
            transactions = msg.transaction_list.to_vec().len(),
            "Received RequestTransactionDataSuccess"
        );
        // A found block's transactions: the whole block goes to the other configured nodes.
        self.solo
            .on_transaction_data(msg.template_id, msg.transaction_list.to_vec());
        Ok(())
    }

    async fn handle_set_new_prev_hash(
        &mut self,
        _server_id: Option<usize>,
        msg: SetNewPrevHash<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);

        let solo = self.solo.clone();
        solo.on_set_new_prev_hash(&msg);
        let template_id = msg.template_id;

        // ⛔ No channel error here shuts the pool down (#898's rule, on the template side). A
        // channel that does not hold the template this prev hash names is NOT activated: its
        // job store would mark every job stale, or activate a job on another height, and it
        // keeps its current job until the next template instead.
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
                            "SOLO_TIP_MISMATCH: the group channel does not hold this tip's \
                             template; skipped"
                        );
                    }

                    for (channel_id, extended_channel) in data.extended_channels.iter_mut() {
                        let key = (*downstream_id, *channel_id);
                        // A provisional channel has no job yet: the new tip is recorded, nothing
                        // is sent.
                        if solo.awaits_payee(key) {
                            if let Err(e) = extended_channel.on_set_new_prev_hash(msg.clone().into_static()) {
                                error!(?key, template_id, error = ?e, "SOLO_TIP_MISMATCH: a provisional channel did not take the new tip");
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
                                    "SOLO_TIP_MISMATCH: an extended channel was not moved to \
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
                                    "SOLO_TIP_MISMATCH: a standard channel was not moved to \
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
            error!(
                template_id,
                channels = mismatched,
                "SOLO_TIP_MISMATCH: channels did not hold this tip's template; they keep their \
                 current job until the next template"
            );
        }

        Ok(())
    }
}
