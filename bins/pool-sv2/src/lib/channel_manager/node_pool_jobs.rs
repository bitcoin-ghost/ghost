//! The channel manager's side of the node pool job layer: choosing how per-channel jobs are
//! stamped, and rebuilding jobs when an anchor arrives or a miner's slot class changes.
//!
//! Every function here is inert unless `[node_pool]` is configured and the active template is at
//! or above the activation height. See `crate::node_pool`.

use std::{collections::HashSet, sync::Arc};

use core::sync::atomic::Ordering;
use stratum_apps::stratum_core::{parsers_sv2::Mining, template_distribution_sv2::NewTemplate};
use tracing::{error, warn};

use crate::{
    channel_manager::{ChannelManager, RouteMessageTo},
    node_pool::{changed_keys, AnchorDriver, ChannelKey, ChannelKind, NodePool, PerChannelMode},
};

impl ChannelManager {
    /// How jobs for `template` are built per channel, if they are: the node pool when it is
    /// configured and the template is at/above its activation height, else SHARE_TIER_BIND when
    /// that is configured and armed for the template, else `None` (one group job, as today).
    ///
    /// With `[node_pool]` absent this is exactly the old `tier_binding.filter(template_is_tiered)`.
    pub(crate) fn per_channel_mode(
        &self,
        template: Option<&NewTemplate<'_>>,
    ) -> Option<PerChannelMode> {
        let template = template?;
        if let Some(np) = self
            .node_pool
            .as_ref()
            .filter(|np| np.template_is_active(template))
        {
            return Some(PerChannelMode::NodePool(np.clone()));
        }
        self.tier_binding
            .clone()
            .filter(|tb| tb.template_is_tiered(template))
            .map(PerChannelMode::Tier)
    }

    /// The node pool job layer, when configured.
    pub fn node_pool(&self) -> Option<Arc<NodePool>> {
        self.node_pool.clone()
    }

    /// The handle the relay layer (W2.5) publishes anchors through, when configured.
    pub fn anchor_driver(&self) -> Option<AnchorDriver> {
        self.node_pool.as_ref().map(|np| np.anchor_driver())
    }

    /// Run the sensing clocks and rebuild the jobs of channels whose class changed.
    pub(crate) async fn node_pool_tick(&self) {
        let Some(np) = &self.node_pool else {
            return;
        };
        let keys = changed_keys(&np.tick());
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
        let Some(np) = self.node_pool.clone() else {
            return;
        };
        let Some(active) = np.active_template() else {
            return;
        };
        if !np.template_is_active(&active) {
            return;
        }
        let mode = PerChannelMode::NodePool(np.clone());
        let prepared = mode.prepare_template(&active);
        let tp_owns_coinbase = active.coinbase_tx_value_remaining == 0;
        let wanted = |key: &ChannelKey| only.is_none_or(|keys| keys.contains(key));

        let messages: Vec<RouteMessageTo> = self.channel_manager_data.super_safe_lock(|cm| {
            let mut messages = vec![];
            for (downstream_id, downstream) in cm.downstream.iter_mut() {
                if downstream.requires_custom_work.load(Ordering::SeqCst) {
                    continue;
                }
                downstream.downstream_data.super_safe_lock(|data| {
                    let outputs = match (&data.payout_mode, tp_owns_coinbase) {
                        (_, true) => vec![],
                        (Some(pm), false) => pm.coinbase_outputs(
                            active.coinbase_tx_value_remaining,
                            &self.coinbase_reward_script,
                        ),
                        (None, false) => {
                            warn!(downstream_id, "NODE_POOL: no payout mode; not rebuilding");
                            return;
                        }
                    };
                    for (channel_id, channel) in data.extended_channels.iter_mut() {
                        let key = (*downstream_id, *channel_id);
                        if !wanted(&key) {
                            continue;
                        }
                        let stamp = mode.stamp(
                            key,
                            ChannelKind::Extended,
                            channel.get_user_identity(),
                            channel.get_target(),
                        );
                        channel.set_tier_commitment(Some(stamp));
                        if let Err(e) = channel.on_new_template(prepared.clone(), outputs.clone()) {
                            error!(?key, ?e, "NODE_POOL: extended job rebuild failed");
                            continue;
                        }
                        if let Some(job) = channel.get_active_job() {
                            mode.bind_job(key, job.get_job_id());
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
                        let stamp = mode.stamp(
                            key,
                            ChannelKind::Standard,
                            channel.get_user_identity(),
                            channel.get_target(),
                        );
                        channel.set_tier_commitment(Some(stamp));
                        if let Err(e) = channel.on_new_template(prepared.clone(), outputs.clone()) {
                            error!(?key, ?e, "NODE_POOL: standard job rebuild failed");
                            continue;
                        }
                        if let Some(job) = channel.get_active_job() {
                            mode.bind_job(key, job.get_job_id());
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
