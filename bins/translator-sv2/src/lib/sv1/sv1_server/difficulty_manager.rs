use std::sync::Arc;

use crate::{is_aggregated, is_non_aggregated, sv1::sv1_server::sv1_server::PendingTargetUpdate};

use stratum_apps::{
    stratum_core::{
        bitcoin::Target,
        channels_sv2::{target::hash_rate_to_target, Vardiff},
        mining_sv2::{SetTarget, UpdateChannel},
        parsers_sv2::Mining,
        stratum_translation::sv2_to_sv1::build_sv1_set_difficulty_from_sv2_target,
    },
    utils::types::{ChannelId, DownstreamId, Hashrate},
};
use tracing::{debug, error, info, trace, warn};

use crate::sv1::Sv1Server;

enum AggregatedSnapshot {
    Active {
        total_hashrate: Hashrate,
        min_target: Target,
    },
    NoDownstreams,
}

/// Floor tier exponent for difficulty quantisation (SHARE_TIER_BIND): no assigned difficulty may
/// sit below `2^10 = 1024`.
///
/// ⚠ AUTHORITY: `ghost_common::coinbase_tags::MIN_DIFFICULTY_TIER_LOG2`. Duplicated here as a
/// literal because this crate is an SRI fork that deliberately does not link the ghost workspace
/// crates. If the authority moves (it is re-derived against the live vardiff floor before the
/// gate arms), this constant MUST move with it — the arming checklist on
/// `SHARE_TIER_BIND_HEIGHT` (ghost-pool `lib.rs`) is what enforces the coupling.
pub(crate) const MIN_DIFFICULTY_TIER_LOG2: u32 = 10;

/// Ceiling tier exponent, clamping the shift below. Mirrors
/// `ghost_common::coinbase_tags::MAX_DIFFICULTY_TIER_LOG2`.
pub(crate) const MAX_DIFFICULTY_TIER_LOG2: u32 = 63;

/// The exact target of a difficulty tier: `diff1_target / 2^tier` = `0xFFFF * 2^(208 - tier)`.
///
/// Built directly in bytes rather than through floats: `0xFFFF * 2^208` and every power of two
/// are exact, so the tier target is the same 32 bytes on every platform — which matters, because
/// these bytes end up committed inside a hashed coinbase.
fn tier_target(tier_log2: u32) -> Target {
    let tier = tier_log2.min(MAX_DIFFICULTY_TIER_LOG2);
    // 0xFFFF occupies bits s..s+16 of the 256-bit target, where s = 208 - tier ∈ [145, 208].
    let s = (208 - tier) as usize;
    let v: u32 = 0xFFFFu32 << (s % 8);
    let idx = s / 8;
    let mut le = [0u8; 32];
    le[idx] = (v & 0xFF) as u8;
    le[idx + 1] = ((v >> 8) & 0xFF) as u8;
    le[idx + 2] = ((v >> 16) & 0xFF) as u8;
    Target::from_le_bytes(le)
}

/// Quantise a vardiff-computed target to its power-of-two difficulty tier (SHARE_TIER_BIND).
///
/// Difficulty rounds DOWN to `2^floor(log2(d))` — the target gets easier, never harder, so a
/// miner sized by vardiff keeps finding shares — except below the floor tier, which rounds UP to
/// `2^MIN_DIFFICULTY_TIER_LOG2`: the floor is the smallest tier any node may assign, and it sits
/// just below the smallest difficulty the fleet serves, so in practice nothing lands there.
///
/// This mirrors `ghost_common::coinbase_tags::difficulty_to_tier_log2` (the verifying side's
/// derivation); the two must agree or a share would be assigned one tier and credited another.
pub(crate) fn quantise_target_to_tier(target: &Target) -> Target {
    let d = target.difficulty_float();
    let tier = if !d.is_finite() || d < 1.0 {
        MIN_DIFFICULTY_TIER_LOG2
    } else {
        let raw = d.log2().floor();
        if !raw.is_finite() || raw < MIN_DIFFICULTY_TIER_LOG2 as f64 {
            MIN_DIFFICULTY_TIER_LOG2
        } else if raw >= MAX_DIFFICULTY_TIER_LOG2 as f64 {
            MAX_DIFFICULTY_TIER_LOG2
        } else {
            raw as u32
        }
    };
    tier_target(tier)
}

#[cfg_attr(not(test), hotpath::measure_all)]
impl Sv1Server {
    /// Spawns the variable difficulty adjustment loop.
    ///
    /// This method implements the SV1 server's variable difficulty logic for all downstreams.
    /// Every 60 seconds, this method updates the difficulty state for each downstream.
    pub async fn spawn_vardiff_loop(self: Arc<Self>) {
        info!("Variable difficulty adjustment enabled - starting vardiff loop");

        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            ticker.tick().await;
            info!("Starting vardiff loop for downstreams");

            self.handle_vardiff_updates().await;
        }
    }

    /// Handles variable difficulty adjustments for all connected downstreams.
    ///
    /// This method implements the core vardiff logic:
    /// 1. For each downstream, calculate if a target update is needed
    /// 2. Always send UpdateChannel to keep upstream informed
    /// 3. Compare new target with upstream target to decide when to send set_difficulty:
    ///    - If new_target >= upstream_target: send set_difficulty immediately
    ///    - If new_target < upstream_target: wait for SetTarget response before sending
    ///      set_difficulty
    /// 4. Handle aggregated vs non-aggregated modes for UpdateChannel messages
    async fn handle_vardiff_updates(&self) {
        let mut immediate_updates = Vec::new();
        let mut all_updates = Vec::new(); // All updates will generate UpdateChannel messages

        for vardiff_key_pair in self.vardiff.iter() {
            let downstream_id = vardiff_key_pair.key();
            let vardiff = vardiff_key_pair.value();
            debug!("Updating vardiff for downstream_id: {}", downstream_id);
            let Some(downstream) = self.downstreams.get(downstream_id) else {
                continue;
            };
            let (channel_id, hashrate, target, upstream_target, on_farm_tier) =
                downstream.downstream_data.super_safe_lock(|data| {
                    // It's safe to unwrap hashrate because we know that
                    // the downstream has a hashrate (we are
                    // doing vardiff)
                    (
                        data.channel_id,
                        data.hashrate.unwrap(),
                        data.target,
                        data.upstream_target,
                        data.on_farm_tier,
                    )
                });

            // Capacity nudge: a miner far larger than the hobby port is sized for costs this
            // node share validation, bandwidth and database writes out of proportion to what it
            // needs — the same database growth that caused the hourly OOM kills. It is NOT
            // earning more by being here: payout is proportional to work and a share's work IS
            // its difficulty, so the same hashrate earns the same on either port.
            //
            // So this warns rather than disconnects. Vardiff raises them to a sane difficulty
            // within a few ticks regardless; the log is for the operator to follow up.
            if !on_farm_tier {
                if let Some(tier) = self.config.farm_tier.as_ref() {
                    if let Some(ceiling) = tier.hobby_max_individual_miner_hashrate {
                        if hashrate > ceiling {
                            warn!(
                                downstream_id = %downstream_id,
                                measured_hs = hashrate,
                                ceiling_hs = ceiling,
                                farm_port = tier.port,
                                "miner on the hobby port is above the hobby ceiling — it should \
                                 connect to the farm port instead; it earns the same either way, \
                                 but costs this node far more share validation here"
                            );
                        }
                    }
                }
            }

            let Some(channel_id) = channel_id else {
                // Unreachable in normal operation: vardiff entries are now inserted only at
                // channel-open (see the OpenExtendedMiningChannelSuccess handler in sv1_server),
                // so every vardiff entry has a channel_id. Kept as a defensive guard and demoted
                // from error! to debug! so a transient race can never spam the logs.
                debug!(
                    "vardiff: skipping downstream {} with no channel_id (channel not yet open)",
                    downstream_id
                );
                continue;
            };
            let new_hashrate_opt = vardiff.super_safe_lock(|state| {
                state.try_vardiff(hashrate, &target, self.shares_per_minute)
            });

            if let Ok(Some(new_hashrate)) = new_hashrate_opt {
                // Calculate new target based on new hashrate
                let new_target: Target =
                    match hash_rate_to_target(new_hashrate as f64, self.shares_per_minute as f64) {
                        Ok(target) => target,
                        Err(e) => {
                            error!(
                                "Failed to calculate target for hashrate {}: {:?}",
                                new_hashrate, e
                            );
                            continue;
                        }
                    };
                // SHARE_TIER_BIND: snap the retargeted difficulty to its power-of-two tier, so
                // the difficulty a share is assigned is a tier its coinbase can commit to.
                // Dormant: `quantise_to_tiers` defaults false and ships false until the gate
                // arms, leaving every target byte-identical to today's.
                let new_target = if self.config.downstream_difficulty_config.quantise_to_tiers {
                    quantise_target_to_tier(&new_target)
                } else {
                    new_target
                };
                // Always update the downstream's pending target and hashrate
                if let Some(d) = self.downstreams.get(downstream_id) {
                    _ = d.downstream_data.safe_lock(|data| {
                        data.set_pending_target(new_target, d.downstream_id);
                        data.set_pending_hashrate(Some(new_hashrate), d.downstream_id);
                    });
                }
                // All updates will be sent as UpdateChannel messages
                all_updates.push((*downstream_id, channel_id, new_target, new_hashrate));
                // Determine if we should send set_difficulty immediately or wait
                match upstream_target {
                    Some(upstream_target) => {
                        if new_target >= upstream_target {
                            // Case 1: new_target >= upstream_target, send set_difficulty
                            // immediately
                            trace!(
                                "✅ Target comparison: new_target ({}) >= upstream_target ({}) for downstream {}, will send set_difficulty immediately",
                                new_target, upstream_target, downstream_id
                            );
                            immediate_updates.push((channel_id, Some(*downstream_id), new_target));
                        } else {
                            // Case 2: new_target < upstream_target, delay set_difficulty until
                            // SetTarget
                            trace!(
                                "⏳ Target comparison: new_target ({}) < upstream_target ({}) for downstream {}, will delay set_difficulty until SetTarget",
                                new_target, upstream_target, downstream_id
                            );
                            self.pending_target_updates.super_safe_lock(|data| {
                                data.push(PendingTargetUpdate {
                                    downstream_id: *downstream_id,
                                    new_target,
                                    new_hashrate,
                                })
                            });
                        }
                    }
                    None => {
                        // No upstream target set yet, send set_difficulty immediately as fallback
                        trace!(
                            "No upstream target set for downstream {}, will send set_difficulty immediately",
                            downstream_id
                        );
                        immediate_updates.push((channel_id, Some(*downstream_id), new_target));
                    }
                }
            }
        }

        // Send UpdateChannel messages for ALL updates (both immediate and delayed)
        if !all_updates.is_empty() {
            self.send_update_channel_messages(all_updates).await;
        }

        // Process immediate set_difficulty updates (for new_target >= upstream_target)
        for (_channel_id, downstream_id, target) in immediate_updates {
            // Send set_difficulty message immediately
            if let Ok(set_difficulty_msg) = build_sv1_set_difficulty_from_sv2_target(target) {
                let downstream_id = downstream_id.unwrap_or(0);
                if let Some(sender) = self
                    .sv1_server_channel_state
                    .sv1_server_to_downstream_sender
                    .super_safe_lock(|downstream| downstream.get(&downstream_id).cloned())
                {
                    if let Err(e) = sender.send(set_difficulty_msg).await {
                        error!(
                            "Failed to send immediate SetDifficulty message to downstream {}: {:?}",
                            downstream_id, e
                        );
                    } else {
                        trace!(
                            "Sent immediate SetDifficulty to downstream {} (new_target >= upstream_target)",
                            downstream_id
                        );
                    }
                }
            }
        }
    }

    /// Push a miner-declared difficulty to the wire NOW, instead of waiting for vardiff.
    ///
    /// `record_suggested_difficulty` stages the target when the channel is already open, but
    /// staging alone strands it: this loop ticks every 60s, and `try_vardiff` returns `None`
    /// for a downstream that has not submitted a share yet — so the staged value can wait far
    /// longer than one tick, or never arrive at all.
    ///
    /// That is invisible on a fast link, because `mining.authorize` (carrying `d=`) wins the
    /// race against channel open and the open path sizes the channel directly. At 320ms RTT on
    /// vm4 the 300ms subscribe debounce opens the channel FIRST, so the miner was told the
    /// 2,048 floor and never the 1,000,000 it asked for. Rented-hashrate marketplaces declare
    /// their size exactly this way, so it hits the clients the feature exists for.
    ///
    /// Uses the SAME upstream-target rule as `handle_vardiff_updates` — send `set_difficulty`
    /// only when `new_target >= upstream_target`, otherwise queue it for the `SetTarget`
    /// response — because sending a target the pool has not yet acknowledged makes the miner
    /// submit against a target upstream will reject.
    pub(super) async fn push_declared_target(&self, downstream_id: DownstreamId) {
        let Some(downstream) = self.downstreams.get(&downstream_id) else {
            return;
        };
        let (channel_id, target, hashrate, upstream_target) =
            downstream.downstream_data.super_safe_lock(|d| {
                (
                    d.channel_id,
                    d.pending_target.unwrap_or(d.target),
                    d.pending_hashrate.or(d.hashrate),
                    d.upstream_target,
                )
            });
        let (Some(channel_id), Some(hashrate)) = (channel_id, hashrate) else {
            // No channel: the open path will size itself from the staged hashrate instead,
            // which is the fast-link case and needs nothing here.
            return;
        };

        // Keep upstream's view in step first, exactly as the vardiff path does.
        self.send_update_channel_messages(vec![(downstream_id, channel_id, target, hashrate)])
            .await;

        let send_now = match upstream_target {
            Some(upstream) => target >= upstream,
            None => true,
        };
        if !send_now {
            trace!(
                "declared difficulty for downstream {} is below the upstream target — queued for SetTarget",
                downstream_id
            );
            self.pending_target_updates.super_safe_lock(|updates| {
                updates.push(PendingTargetUpdate {
                    downstream_id,
                    new_target: target,
                    new_hashrate: hashrate,
                })
            });
            return;
        }

        let Ok(set_difficulty_msg) = build_sv1_set_difficulty_from_sv2_target(target) else {
            error!(
                "failed to build set_difficulty for declared target on downstream {}",
                downstream_id
            );
            return;
        };
        let sender = self
            .sv1_server_channel_state
            .sv1_server_to_downstream_sender
            .super_safe_lock(|map| map.get(&downstream_id).cloned());
        if let Some(sender) = sender {
            if let Err(e) = sender.send(set_difficulty_msg).await {
                error!(
                    "failed to send declared set_difficulty to downstream {}: {:?}",
                    downstream_id, e
                );
            } else {
                info!(
                    "pushed miner-declared difficulty to downstream {} immediately (no vardiff wait)",
                    downstream_id
                );
            }
        }
    }

    /// Sends UpdateChannel messages for all target updates.
    ///
    /// Always sends UpdateChannel to keep upstream informed about target changes.
    /// Handles both aggregated and non-aggregated modes:
    /// - Aggregated: Send single UpdateChannel with minimum target and sum of hashrates
    /// - Non-aggregated: Send individual UpdateChannel for each downstream
    async fn send_update_channel_messages(
        &self,
        all_updates: Vec<(DownstreamId, ChannelId, Target, Hashrate)>, /* (downstream_id,
                                                                        * channel_id,
                                                                        * new_target,
                                                                        * new_hashrate) */
    ) {
        if is_aggregated() {
            // Aggregated mode: Send single UpdateChannel with minimum target and total hashrate of
            // ALL downstreams
            self.send_aggregated_update_channel(all_updates).await;
        } else {
            // Non-aggregated mode: Send individual UpdateChannel for each downstream
            self.send_non_aggregated_update_channels(all_updates).await;
        }
    }

    async fn send_aggregated_update_channel(
        &self,
        all_updates: Vec<(DownstreamId, ChannelId, Target, Hashrate)>,
    ) {
        // Nothing to do if we received no updates
        let Some((_, channel_id, _, _)) = all_updates.first() else {
            return;
        };

        if self.downstreams.is_empty() {
            return;
        }

        let mut min_target: Option<Target> = None;
        let mut total_hashrate: Hashrate = 0.0;

        for downstream in self.downstreams.iter() {
            let downstream = downstream.value();
            downstream.downstream_data.super_safe_lock(|d| {
                let target = *d.pending_target.as_ref().unwrap_or(&d.target);
                let hashrate = d
                    .pending_hashrate
                    .unwrap_or_else(|| d.hashrate.expect("vardiff implies hashrate"));

                min_target = Some(match min_target {
                    Some(current) => current.min(target),
                    None => target,
                });

                total_hashrate += hashrate;
            });
        }

        let min_target = min_target.expect("at least one downstream must exist");
        let downstream_count = self.downstreams.len();

        let update_channel = UpdateChannel {
            channel_id: *channel_id,
            nominal_hash_rate: total_hashrate,
            maximum_target: min_target.to_le_bytes().into(),
        };

        debug!(
            "Sending aggregated UpdateChannel: channel_id={}, total_hashrate={}, min_target={}, downstreams={}, vardiff_updates={}",
            channel_id,
            total_hashrate,
            min_target,
            downstream_count,
            all_updates.len()
        );

        if let Err(e) = self
            .sv1_server_channel_state
            .channel_manager_sender
            .send((Mining::UpdateChannel(update_channel), None))
            .await
        {
            error!("Failed to send aggregated UpdateChannel: {:?}", e);
        }
    }

    async fn send_non_aggregated_update_channels(
        &self,
        all_updates: Vec<(DownstreamId, ChannelId, Target, Hashrate)>,
    ) {
        for (downstream_id, channel_id, new_target, new_hashrate) in all_updates {
            let update_channel = UpdateChannel {
                channel_id,
                nominal_hash_rate: new_hashrate,
                maximum_target: new_target.to_le_bytes().into(),
            };

            debug!(
                "Sending UpdateChannel for downstream {}: channel_id={}, hashrate={}, target={}",
                downstream_id, channel_id, new_hashrate, new_target
            );

            if let Err(e) = self
                .sv1_server_channel_state
                .channel_manager_sender
                .send((Mining::UpdateChannel(update_channel), None))
                .await
            {
                error!(
                    "Failed to send UpdateChannel for downstream {}: {:?}",
                    downstream_id, e
                );
            }
        }
    }

    /// Handles SetTarget messages from the ChannelManager.
    ///
    /// Aggregated mode: Single SetTarget updates all downstreams and processes all pending updates
    /// Non-aggregated mode: Each SetTarget updates one specific downstream and processes its
    /// pending update
    pub async fn handle_set_target_message(&self, set_target: SetTarget<'_>) {
        let new_upstream_target =
            Target::from_le_bytes(set_target.maximum_target.inner_as_ref().try_into().unwrap());
        debug!(
            "Received SetTarget for channel {}: new_upstream_target = {}",
            set_target.channel_id, new_upstream_target
        );

        if is_aggregated() {
            return self
                .handle_aggregated_set_target(new_upstream_target, set_target.channel_id)
                .await;
        }

        self.handle_non_aggregated_set_target(set_target.channel_id, new_upstream_target)
            .await;
    }

    /// Handles SetTarget in aggregated mode.
    /// Updates all downstreams and processes all pending set_difficulty messages.
    async fn handle_aggregated_set_target(
        &self,
        new_upstream_target: Target,
        channel_id: ChannelId,
    ) {
        debug!("Aggregated mode: Updating upstream target for all downstreams");

        for downstream in self.downstreams.iter() {
            let downstream = downstream.value();
            downstream.downstream_data.super_safe_lock(|d| {
                d.set_upstream_target(new_upstream_target, downstream.downstream_id);
            });
        }

        // Process ALL pending difficulty updates that can now be sent downstream
        let applicable_updates =
            self.get_pending_difficulty_updates(new_upstream_target, None, channel_id);

        self.send_pending_set_difficulty_messages_to_downstream(applicable_updates)
            .await;
    }

    /// Handles SetTarget in non-aggregated mode.
    /// Updates the specific downstream and processes its pending set_difficulty message.
    async fn handle_non_aggregated_set_target(
        &self,
        channel_id: ChannelId,
        new_upstream_target: Target,
    ) {
        debug!(
            "Non-aggregated mode: Processing SetTarget for channel {}",
            channel_id
        );

        let Some(downstream_id) = self
            .channel_id_to_downstream_id
            .super_safe_lock(|map| map.get(&channel_id).cloned())
        else {
            warn!("No downstream found for channel {}", channel_id);
            return;
        };

        {
            let Some(downstream) = self.downstreams.get(&downstream_id) else {
                warn!("No downstream found for downstream_id {}", downstream_id);
                return;
            };
            downstream.downstream_data.super_safe_lock(|d| {
                d.set_upstream_target(new_upstream_target, downstream_id);
            });
        }

        trace!("Updated upstream target for downstream {}", downstream_id);

        let applicable_updates = self.get_pending_difficulty_updates(
            new_upstream_target,
            Some(downstream_id),
            channel_id,
        );

        self.send_pending_set_difficulty_messages_to_downstream(applicable_updates)
            .await;
    }

    /// Gets pending updates that can now be applied based on the new upstream target.
    /// If downstream_id is provided, only returns updates for that specific downstream.
    /// Logs a warning if the upstream target is higher than any requested target.
    fn get_pending_difficulty_updates(
        &self,
        new_upstream_target: Target,
        downstream_id: Option<DownstreamId>,
        channel_id: ChannelId,
    ) -> Vec<PendingTargetUpdate> {
        let mut applicable_updates = Vec::new();

        self.pending_target_updates.super_safe_lock(|data| {
            data.retain(|pending_update| {
                // Check if we should process this update
                let should_process = match downstream_id {
                    Some(downstream_id) => pending_update.downstream_id == downstream_id,
                    None => true, // Process all in aggregated mode
                };

                if !should_process {
                    return true; // keep in pending list (not relevant for this SetTarget)
                }

                if pending_update.new_target >= new_upstream_target {
                    // Target is acceptable, can apply immediately
                    applicable_updates.push(pending_update.clone());
                    false // remove from pending list
                } else {
                    // WARNING: Upstream gave us a target higher than what we requested
                    error!(
                        "❌ Protocol issue: SetTarget response has target ({}) which is higher than requested target ({}) in UpdateChannel for channel {}. Ignoring this pending update for downstream {}.",
                        new_upstream_target, pending_update.new_target, channel_id, pending_update.downstream_id
                    );
                    false // remove from pending list (don't keep invalid requests)
                }
            });
        });
        applicable_updates
    }

    /// Sends set_difficulty messages for all applicable pending updates.
    async fn send_pending_set_difficulty_messages_to_downstream(
        &self,
        difficulty_updates: Vec<PendingTargetUpdate>,
    ) {
        for update in difficulty_updates {
            let set_difficulty_msg =
                match build_sv1_set_difficulty_from_sv2_target(update.new_target) {
                    Ok(msg) => msg,
                    Err(e) => {
                        error!(
                            "Failed to build SetDifficulty for downstream {}: {:?}",
                            update.downstream_id, e
                        );
                        continue;
                    }
                };

            if let Some(sender) = self
                .sv1_server_channel_state
                .sv1_server_to_downstream_sender
                .super_safe_lock(|downstream| downstream.get(&update.downstream_id).cloned())
            {
                if let Err(e) = sender.send(set_difficulty_msg).await {
                    error!(
                        "Failed to send SetDifficulty to downstream {}: {:?}",
                        update.downstream_id, e
                    );
                } else {
                    trace!("Sent SetDifficulty to downstream {}", update.downstream_id);
                }
            }
        }
    }

    /// Sends an UpdateChannel message for aggregated mode when downstream state changes
    /// (e.g., disconnect). Calculates total hashrate and minimum target among all remaining
    /// downstreams.
    pub async fn send_update_channel_on_downstream_state_change(&self) {
        if is_non_aggregated() {
            return;
        }

        let is_empty = self.downstreams.is_empty();

        let snapshot = if is_empty {
            AggregatedSnapshot::NoDownstreams
        } else {
            let mut total_hashrate: Hashrate = 0.0;
            let mut min_target: Option<Target> = None;

            for downstream in self.downstreams.iter() {
                let downstream = downstream.value();
                downstream.downstream_data.super_safe_lock(|d| {
                    let hashrate = d.pending_hashrate.unwrap_or_else(|| {
                        d.hashrate
                            .expect("vardiff implies downstream must have a hashrate")
                    });

                    let target = *d.pending_target.as_ref().unwrap_or(&d.target);

                    total_hashrate += hashrate;
                    min_target = Some(match min_target {
                        Some(current) => current.min(target),
                        None => target,
                    });
                });
            }

            AggregatedSnapshot::Active {
                total_hashrate,
                min_target: min_target.expect("downstreams is non-empty"),
            }
        };

        let update = match snapshot {
            AggregatedSnapshot::Active {
                total_hashrate,
                min_target,
            } => UpdateChannel {
                channel_id: 0, // ChannelManager will rewrite to upstream extended channel id
                nominal_hash_rate: total_hashrate,
                maximum_target: min_target.to_le_bytes().into(),
            },

            AggregatedSnapshot::NoDownstreams => UpdateChannel {
                channel_id: 0,
                nominal_hash_rate: 0.0,
                maximum_target: [0xFF; 32].into(),
            },
        };

        if let Err(e) = self
            .sv1_server_channel_state
            .channel_manager_sender
            .send((Mining::UpdateChannel(update), None))
            .await
        {
            error!(
                "Failed to send UpdateChannel after downstream state change: {:?}",
                e
            );
        }
    }
}

#[cfg(test)]
mod tier_quantisation_tests {
    use super::*;

    /// A tier's target must be EXACT: `0xFFFF * 2^(208 - tier)`, whose difficulty is exactly
    /// `2^tier`. Both factors are exact in f64, so equality here is legitimate, not tolerance.
    #[test]
    fn tier_targets_are_exact_powers_of_two() {
        for tier in [MIN_DIFFICULTY_TIER_LOG2, 11, 13, 16, 20, 33, 40, 63] {
            let d = tier_target(tier).difficulty_float();
            assert_eq!(
                d,
                2.0_f64.powi(tier as i32),
                "tier {tier} target must stand for exactly 2^{tier}"
            );
        }
    }

    /// Quantisation floors difficulty to the tier below (the target gets easier, never harder),
    /// and a tier target is a fixed point.
    #[test]
    fn quantisation_rounds_difficulty_down_and_is_idempotent() {
        // ~1.5x the tier-13 target's hashrate: difficulty lands between 2^13 and 2^14.
        // hash_rate_to_target(h, spm) sizes difficulty ∝ hashrate, so pick a hashrate whose
        // difficulty is comfortably inside a tier rather than on its boundary.
        let raw = hash_rate_to_target(6.0e11, 6.0).expect("valid inputs");
        let d_raw = raw.difficulty_float();
        assert!(
            d_raw > 1024.0,
            "fixture must sit above the floor tier, got {d_raw}"
        );

        let q = quantise_target_to_tier(&raw);
        let d_q = q.difficulty_float();
        let expected = 2.0_f64.powi(d_raw.log2().floor() as i32);
        assert_eq!(d_q, expected, "must floor to the tier below");
        assert!(
            d_q <= d_raw,
            "quantised difficulty must never exceed the assigned one"
        );
        assert!(
            q >= raw,
            "the quantised target must be easier (larger), never harder"
        );

        // Idempotent: a tier is its own tier.
        assert_eq!(quantise_target_to_tier(&q), q);
    }

    /// The floor: nothing may be assigned below `2^10 = 1024`.
    ///
    /// ⚠ 1024 is `ghost_common::coinbase_tags::MIN_DIFFICULTY_TIER_LOG2`'s target; this crate
    /// cannot link that crate, so this test pins the duplicated constant to the agreed value.
    #[test]
    fn sub_floor_difficulties_clamp_up_to_the_floor_tier() {
        // A tiny hashrate produces a difficulty far below 1024.
        let raw = hash_rate_to_target(1.0e6, 6.0).expect("valid inputs");
        assert!(raw.difficulty_float() < 1024.0);
        let q = quantise_target_to_tier(&raw);
        assert_eq!(
            q.difficulty_float(),
            1024.0,
            "sub-floor difficulty must clamp UP to the floor tier"
        );
        assert_eq!(
            tier_target(MIN_DIFFICULTY_TIER_LOG2).difficulty_float(),
            1024.0
        );
    }

    /// The production shape: a ~500 GH/s bitaxe at the live vardiff floor lands near difficulty
    /// ~1164 (see `ACTIVE_MINER_WINDOW_SECS` in ghost-common), which must quantise to the floor
    /// tier itself — the coupling `MIN_DIFFICULTY_TIER_LOG2` was chosen for.
    #[test]
    fn the_smallest_fleet_difficulty_lands_on_the_floor_tier() {
        let raw = hash_rate_to_target(5.0e11, 6.0).expect("valid inputs");
        let d = raw.difficulty_float();
        assert!(
            (1024.0..2048.0).contains(&d),
            "expected the bitaxe-shaped difficulty in tier 10's band, got {d}"
        );
        assert_eq!(quantise_target_to_tier(&raw).difficulty_float(), 1024.0);
    }
}
