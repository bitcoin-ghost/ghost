//! The channel manager's side of the node pool job layer: rebuilding jobs when an anchor
//! arrives or a miner's slot class changes. See `crate::node_pool`.

use std::{collections::HashSet, sync::Arc};

use stratum_apps::stratum_core::parsers_sv2::Mining;
use tracing::error;

use crate::{
    channel_manager::{ChannelManager, RouteMessageTo},
    node_pool::{changed_keys, AnchorDriver, ChannelKey, ChannelKind, NodePool},
};

impl ChannelManager {
    /// The node pool job layer.
    pub fn node_pool(&self) -> Arc<NodePool> {
        self.node_pool.clone()
    }

    /// The handle the relay layer (W2.5) publishes anchors through.
    pub fn anchor_driver(&self) -> AnchorDriver {
        self.node_pool.anchor_driver()
    }

    /// Run the sensing clocks and rebuild the jobs of channels whose class changed.
    pub(crate) async fn node_pool_tick(&self) {
        let keys = changed_keys(&self.node_pool.tick());
        if !keys.is_empty() {
            self.node_pool_rebuild(Some(&keys)).await;
        }
    }

    /// Re-stamp channels and push each a fresh job built on the active template: every channel
    /// after an anchor publish, `only` those after a class change.
    ///
    /// The new job is a non-future job on the current prev hash, so it is active at once; the
    /// channel's previous jobs stay valid until the next prev hash, as for any job update. A
    /// channel that fails to rebuild keeps its current job and the error is logged: this path
    /// never disconnects or shuts down.
    pub(crate) async fn node_pool_rebuild(&self, only: Option<&HashSet<ChannelKey>>) {
        let np = self.node_pool.clone();
        let Some(active) = np.active_template() else {
            return;
        };
        // The new anchor's table, fetched before the channel locks are taken.
        np.prepare_tables(&active).await;
        let prepared = np.prepare_template(&active);
        let wanted = |key: &ChannelKey| only.is_none_or(|keys| keys.contains(key));

        let messages: Vec<RouteMessageTo> = self.channel_manager_data.super_safe_lock(|cm| {
            let mut messages = vec![];
            for (downstream_id, downstream) in cm.downstream.iter_mut() {
                downstream.downstream_data.super_safe_lock(|data| {
                    for (channel_id, channel) in data.extended_channels.iter_mut() {
                        let key = (*downstream_id, *channel_id);
                        if !wanted(&key) {
                            continue;
                        }
                        let stamp = np.stamp(
                            key,
                            ChannelKind::Extended,
                            channel.get_user_identity(),
                            channel.get_target(),
                        );
                        channel.set_tier_commitment(Some(stamp));
                        let outputs = match np.job_outputs(key, &active) {
                            Ok(o) => o,
                            Err(e) => {
                                error!(?key, "NODE_POOL: no canonical outputs for a rebuild: {e}");
                                continue;
                            }
                        };
                        if let Err(e) = channel.on_new_template(prepared.clone(), outputs) {
                            error!(?key, ?e, "NODE_POOL: extended job rebuild failed");
                            continue;
                        }
                        if let Some(job) = channel.get_active_job() {
                            np.bind_job(key, job.get_job_id());
                            let message = job.get_job_message().clone().into_static();
                            messages.push(
                                (*downstream_id, Mining::NewExtendedMiningJob(message)).into(),
                            );
                        }
                    }
                    for (channel_id, channel) in data.standard_channels.iter_mut() {
                        let key = (*downstream_id, *channel_id);
                        if !wanted(&key) {
                            continue;
                        }
                        let stamp = np.stamp(
                            key,
                            ChannelKind::Standard,
                            channel.get_user_identity(),
                            channel.get_target(),
                        );
                        channel.set_tier_commitment(Some(stamp));
                        let outputs = match np.job_outputs(key, &active) {
                            Ok(o) => o,
                            Err(e) => {
                                error!(?key, "NODE_POOL: no canonical outputs for a rebuild: {e}");
                                continue;
                            }
                        };
                        if let Err(e) = channel.on_new_template(prepared.clone(), outputs) {
                            error!(?key, ?e, "NODE_POOL: standard job rebuild failed");
                            continue;
                        }
                        if let Some(job) = channel.get_active_job() {
                            np.bind_job(key, job.get_job_id());
                            let message = job.get_job_message().clone().into_static();
                            messages.push((*downstream_id, Mining::NewMiningJob(message)).into());
                        }
                    }
                });
            }
            messages
        });

        for message in messages {
            if let Err(e) = message.forward(&self.channel_manager_channel).await {
                error!("Failed to forward message {e:?}");
            }
        }
    }
}
