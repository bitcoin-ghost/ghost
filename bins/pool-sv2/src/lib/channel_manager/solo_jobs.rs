//! The channel manager's side of the solo layer that is not a message handler: binding a channel
//! the translator opened on `mining.subscribe` to its miner once the miner authorises. See
//! `crate::solo`.

use stratum_apps::{
    stratum_core::{
        mining_sv2::{CloseChannel, SetNewPrevHash},
        parsers_sv2::Mining,
    },
    utils::types::{ChannelId, DownstreamId},
};
use tracing::{error, info, warn};

use crate::{
    channel_manager::{ChannelManager, RouteMessageTo},
    solo::{ChannelKind, Solo},
};

impl ChannelManager {
    /// Bind a channel opened under the provisional identity to its miner's payee (the Ghost payee
    /// TLV on an `UpdateChannel`, sent by the translator when a miner that waited for its
    /// subscribe reply authorises), and give it its first job, as a channel opened on authorize
    /// gets one. A payee the pool refuses closes that channel only.
    pub(crate) async fn solo_bind_payee(
        &self,
        downstream_id: DownstreamId,
        channel_id: ChannelId,
        identity: String,
    ) {
        let solo = self.solo.clone();
        let key = (downstream_id, channel_id);
        if !solo.awaits_payee(key) {
            warn!(
                downstream_id,
                channel_id, "SOLO: a payee for a channel that is not waiting for one; ignored"
            );
            return;
        }
        let refused = Solo::payee_for_identity(&identity).err();
        let messages: Vec<RouteMessageTo> = self.channel_manager_data.super_safe_lock(|cm| {
            let mut out: Vec<RouteMessageTo> = vec![];
            let tip = cm.last_new_prev_hash.clone();
            let future = cm.last_future_template.clone();
            let Some(downstream) = cm.downstream.get_mut(&downstream_id) else {
                return out;
            };
            downstream.downstream_data.super_safe_lock(|data| {
                if let Some(code) = refused {
                    error!(
                        downstream_id,
                        channel_id, identity, code, "SOLO: payee refused; closing that channel"
                    );
                    data.extended_channels.remove(&channel_id);
                    data.group_channel.remove_channel_id(channel_id);
                    solo.payee_bound(key);
                    out.push(
                        (
                            downstream_id,
                            Mining::CloseChannel(CloseChannel {
                                channel_id,
                                reason_code: code.to_string().try_into().expect("short code"),
                            }),
                        )
                            .into(),
                    );
                    return;
                }
                let (Some(channel), Some(t)) =
                    (data.extended_channels.get_mut(&channel_id), future.as_ref())
                else {
                    return;
                };
                channel.set_user_identity(identity.clone());
                solo.payee_bound(key);
                let outputs = match solo.job_outputs(key, ChannelKind::Extended, &identity, t) {
                    Ok(o) => o,
                    Err(e) => {
                        error!(?key, "SOLO: no job outputs for a bound channel: {e}");
                        return;
                    }
                };
                if let Err(e) = channel.on_new_template(solo.prepare_template(t), outputs) {
                    error!(?key, ?e, "SOLO: the bound channel's first job failed");
                    return;
                }
                let Some(job_id) = channel.get_future_job_id_from_template_id(t.template_id) else {
                    return;
                };
                solo.bind_job(key, job_id);
                let Some(job) = channel.get_future_job(job_id) else {
                    return;
                };
                out.push(
                    (
                        downstream_id,
                        Mining::NewExtendedMiningJob(job.get_job_message().clone().into_static()),
                    )
                        .into(),
                );
                // Activated on the current tip, as at an open (#898: only when the cached prev
                // hash is this template's).
                if let Some(tip) = tip.filter(|tip| tip.template_id == t.template_id) {
                    let snph = SetNewPrevHash {
                        channel_id,
                        job_id,
                        prev_hash: tip.prev_hash.clone(),
                        min_ntime: tip.header_timestamp,
                        nbits: tip.n_bits,
                    };
                    if let Err(e) = channel.on_set_new_prev_hash(tip) {
                        error!(?key, ?e, "SOLO: activating the bound channel's job failed");
                        return;
                    }
                    out.push((downstream_id, Mining::SetNewPrevHash(snph)).into());
                }
                info!(
                    downstream_id,
                    channel_id, identity, "SOLO: provisional channel bound to its payee"
                );
            });
            out
        });
        for message in messages {
            if let Err(e) = message.forward(&self.channel_manager_channel).await {
                error!("Failed to forward message {e:?}");
            }
        }
    }
}
