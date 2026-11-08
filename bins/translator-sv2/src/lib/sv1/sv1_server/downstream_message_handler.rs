use std::sync::atomic::Ordering;

/// How long a superseded target keeps accepting shares after a difficulty change.
///
/// Covers the miner's round trip plus its own submission pipeline. Long enough that work in
/// flight when `mining.set_difficulty` went out is not thrown away; short enough that it cannot
/// become a standing discount — vardiff on a busy node changes target roughly every 25 seconds,
/// so a window near that would never close (#811).
const SUPERSEDED_TARGET_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

use stratum_apps::stratum_core::sv1_api::{
    client_to_server, json_rpc,
    server_to_client::{self, Notify},
    utils::{Extranonce, HexU32Be},
    IsServer,
};
use tracing::{debug, info, warn};

use crate::{
    error, is_aggregated,
    sv1::{downstream::SubmitShareWithChannelId, sv1_server::tlv_compatible_username, Sv1Server},
    utils::{validate_sv1_share, AGGREGATED_CHANNEL_ID},
};

// Implements `IsServer` for `Sv1Server` to handle the Sv1 messages.
#[cfg_attr(not(test), hotpath::measure_all)]
impl IsServer<'static> for Sv1Server {
    fn handle_configure(
        &mut self,
        client_id: Option<usize>,
        request: &client_to_server::Configure,
    ) -> (Option<server_to_client::VersionRollingParams>, Option<bool>) {
        let Some(downstream_id) = client_id else {
            warn!("mining.configure with no client id — ignoring");
            return (None, None);
        };

        info!("Received mining.configure from SV1 downstream");
        debug!("Downstream {downstream_id}: mining.configure = {}", request);

        // A downstream that has just disconnected is REMOVED from `self.downstreams` by
        // `handle_downstream_disconnect`, while messages already in flight from that same
        // downstream are still being handled. So absence here is an ordinary race, not a broken
        // invariant — and `.expect()` on it took ghost-vm2 dark for ~45 minutes (#812).
        //
        // Worse than losing the message: `super_safe_lock` wraps `std::sync::Mutex`, which
        // POISONS on panic, so one panic here makes every later access to that mutex panic in
        // turn. A single lost race cascaded into a node that held no listener while systemd
        // still reported `active`.
        let Some(downstream) = self.downstreams.get(&downstream_id) else {
            debug!("Downstream {downstream_id} disconnected before its configure was handled — ignoring");
            return (None, None);
        };

        downstream.downstream_data.super_safe_lock(|data| {
            data.version_rolling_mask = request
                .version_rolling_mask()
                .map(|mask| HexU32Be(mask & 0x1FFFE000));

            data.version_rolling_min_bit = request.version_rolling_min_bit_count();

            // Record the `subscribe-extranonce` opt-in so the channel-open path can tell
            // whether a post-hoc `mining.set_extranonce` is welcome or fatal.
            data.extranonce_subscribe_negotiated = request.subscribes_extranonce();

            debug!(
                "Negotiated version_rolling_mask: {:?}",
                data.version_rolling_mask
            );

            let params = server_to_client::VersionRollingParams::new(
                data.version_rolling_mask.clone().unwrap_or(HexU32Be(0)),
                data.version_rolling_min_bit.clone().unwrap_or(HexU32Be(0)),
            )
            .expect(
                "Invalid version rolling params: \
                 automatic mask selection is not supported",
            );

            (Some(params), Some(false))
        })
    }

    fn handle_subscribe(
        &self,
        client_id: Option<usize>,
        request: &client_to_server::Subscribe,
    ) -> Vec<(String, String)> {
        let Some(downstream_id) = client_id else {
            warn!("mining.subscribe with no client id — returning no subscriptions");
            return vec![];
        };

        info!("Received mining.subscribe from Sv1 downstream");
        debug!("Down: Handling mining.subscribe: {}", request);

        // Keep the agent for the node pool's slot-class sensing. It only leaves this process
        // when the upstream negotiated the Ghost agent extension; see `ghost_agent_tlv`.
        if let Some(downstream) = self.downstreams.get(&downstream_id) {
            let agent = super::clamp_agent(&request.agent_signature).to_string();
            downstream
                .downstream_data
                .super_safe_lock(|data| data.user_agent = Some(agent));
        }

        let set_difficulty_sub = (
            "mining.set_difficulty".to_string(),
            downstream_id.to_string(),
        );

        let notify_sub = (
            "mining.notify".to_string(),
            "ae6812eb4cd7735a302a8a9dd95cf71f".to_string(),
        );

        vec![set_difficulty_sub, notify_sub]
    }

    fn handle_authorize(
        &self,
        client_id: Option<usize>,
        request: &client_to_server::Authorize,
    ) -> bool {
        let Some(downstream_id) = client_id else {
            warn!("mining.authorize with no client id — rejecting");
            return false;
        };
        info!("Received mining.authorize from Sv1 downstream {downstream_id}");
        debug!("Down: Handling mining.authorize: {}", request);

        // Public-pool requirement: SV1 username MUST be `<bitcoin_address>.<worker_name>`.
        // The address part determines where the miner's coinbase share is paid; without an
        // address we have no payout target and the miner would mine for nobody. We reject
        // bare-worker (no `.`) authorize attempts with a clear failure response so the miner
        // can fix their config rather than silently lose earnings to whatever fallback the
        // pool happened to set. This is the same convention every public Bitcoin mining pool
        // enforces.
        // A trailing `.d=<difficulty>` is stripped here so the rest of the checks — and the
        // payout address / worker attribution downstream — see the plain `<address>.<worker>`.
        // A bare payout address is accepted as `<address>.default` (the worker is optional).
        let (name, username_difficulty) = super::normalize_username(request.name.as_str());
        let name = name.as_ref();
        if let Err(rejection) = super::check_username_attributable(name) {
            warn!(
                "Down: Rejecting mining.authorize from downstream {} — username '{}' has a missing or empty {} half; expected `<bitcoin_address>.<worker_name>`. Shares from this username could not be attributed and would earn nothing (#479).",
                downstream_id,
                name,
                rejection.half()
            );
            return false;
        }

        // Honour a `d=<difficulty>` in the password. This is the convention rented-hashrate
        // marketplaces use to declare their size up front, and it arrives with authorize —
        // i.e. before the channel opens — so it can size the initial target rather than
        // leaving vardiff to ramp there over several minutes.
        // Password first, then the username suffix as a fallback for order forms that expose no
        // password field at all (Braiins' marketplace being the case in point).
        if let Some(difficulty) = super::parse_password_difficulty(&request.password) {
            self.record_suggested_difficulty(downstream_id, difficulty, "authorize password");
        } else if let Some(difficulty) = username_difficulty {
            self.record_suggested_difficulty(downstream_id, difficulty, "username suffix");
        }
        true
    }

    fn handle_submit(
        &self,
        client_id: Option<usize>,
        request: &client_to_server::Submit<'static>,
    ) -> bool {
        let Some(downstream_id) = client_id else {
            warn!("mining.submit with no client id — rejecting");
            return false;
        };

        // A downstream that has just disconnected is REMOVED from `self.downstreams` by
        // `handle_downstream_disconnect`, while messages already in flight from that same
        // downstream are still being handled. So absence here is an ordinary race, not a broken
        // invariant — and `.expect()` on it took ghost-vm2 dark for ~45 minutes (#812).
        //
        // Worse than losing the message: `super_safe_lock` wraps `std::sync::Mutex`, which
        // POISONS on panic, so one panic here makes every later access to that mutex panic in
        // turn. A single lost race cascaded into a node that held no listener while systemd
        // still reported `active`.
        let Some(downstream) = self.downstreams.get(&downstream_id) else {
            debug!("Downstream {downstream_id} disconnected before its share was handled — dropping it");
            return false;
        };

        let job_id = &request.job_id;

        let Some(channel_id) = downstream
            .downstream_data
            .super_safe_lock(|data| data.channel_id)
        else {
            return false;
        };

        let channel_id = if is_aggregated() {
            AGGREGATED_CHANNEL_ID
        } else {
            channel_id
        };

        let find_job =
            |jobs: &[Notify<'static>]| jobs.iter().find(|j| j.job_id == *job_id).cloned();

        let job = self
            .valid_sv1_jobs
            .get(&channel_id)
            .and_then(|jobs| find_job(jobs.as_ref()));

        let Some(job) = job else {
            // Silently dropped before this: no log, no counter, indistinguishable from a share
            // that was never sent. A share arriving for a job we no longer hold is ordinary
            // (the job rolled), but it is not nothing — if it becomes the dominant reason a
            // channel is refusing work, that is a fact worth being able to see (#810).
            let n = self.shares_for_unknown_job.fetch_add(1, Ordering::Relaxed) + 1;
            debug!(
                "share for channel {channel_id} referenced job {job_id}, which is no longer held \
                 — dropping it (total dropped for unknown jobs: {n})"
            );
            return false;
        };

        downstream.downstream_data.super_safe_lock(|data| {
            let channel_id = match data.channel_id {
                Some(id) => id,
                None => {
                    error!(
                        "Cannot submit share: channel_id is None \
                         (waiting for OpenExtendedMiningChannelSuccess)"
                    );
                    return false;
                }
            };

            info!(
                "Received mining.submit from SV1 downstream for channel id: {}",
                channel_id
            );

            // THREE outcomes, and they are not the same thing. `.unwrap_or(false)` used to
            // collapse them into one `error!`, so a node failing every merkle root looked
            // exactly like one doing routine vardiff convergence (#810).
            let validated = validate_sv1_share(
                request,
                data.target,
                data.extranonce1.clone().into(),
                data.version_rolling_mask.clone(),
                job.clone(),
            );

            let is_valid = match validated {
                Ok(true) => true,
                Ok(false) => {
                    // Below the CURRENT target — but the miner may have computed this against
                    // the previous, easier one. `target` is swapped the instant
                    // `mining.set_difficulty` is SENT, so everything already in flight was made
                    // against a target that no longer applies. That is real work, and
                    // discarding it was ~20% of submissions on the busiest nodes (#811).
                    //
                    // Only this arm retries. An `Err` below is a FAULT, not a target question,
                    // and re-running it against a different target would just fail identically
                    // while making a validation bug look like routine vardiff churn.
                    let late = data
                        .target_within_grace(SUPERSEDED_TARGET_GRACE)
                        .map(|previous| {
                            // Validate against whichever is HARDER. An accepted share is
                            // forwarded upstream, where `pool_sv2` judges it against the channel
                            // target and answers `difficulty-too-low`; accepting one the pool
                            // will refuse relocates the rejection rather than fixing it.
                            let bar = match data.upstream_target {
                                Some(upstream) => previous.min(upstream),
                                None => previous,
                            };
                            validate_sv1_share(
                                request,
                                bar,
                                data.extranonce1.clone().into(),
                                data.version_rolling_mask.clone(),
                                job.clone(),
                            )
                            .unwrap_or(false)
                        })
                        .unwrap_or(false);

                    if late {
                        let n = self.shares_accepted_late.fetch_add(1, Ordering::Relaxed) + 1;
                        debug!(
                            "channel {channel_id}: share met the SUPERSEDED target — accepted \
                             (total late accepts: {n}); it was computed before the miner saw \
                             the new difficulty"
                        );
                        // Yields the ARM's value rather than returning: this runs inside the
                        // `super_safe_lock` closure, and an early `return` would skip the
                        // `pending_share` assignment below — accepting the share and then never
                        // forwarding it upstream, which is worse than the reject it replaces.
                        true
                    } else {
                        // Genuinely below target, on both the current and the superseded value.
                        // EXPECTED and routine, so not an error and not logged per share — at
                        // 1 PH/s that is a great deal of journal for a normal condition.
                        let n = self.shares_below_target.fetch_add(1, Ordering::Relaxed) + 1;
                        debug!("share below target on channel {channel_id} (total: {n})");
                        if n.is_multiple_of(500) {
                            info!(
                                "channel {channel_id}: {n} shares below target so far — routine \
                                 during difficulty changes; compare against \
                                 shares_failed_validation, which is not routine, and against \
                                 shares_accepted_late, which is work this node recovered"
                            );
                        }
                        false
                    }
                }
                Err(e) => {
                    // A FAULT. The share could not be validated at all — the merkle root could
                    // not be built from the job, or prev_hash would not deserialise. This is the
                    // outcome that was invisible, and the one worth waking someone for.
                    let n = self
                        .shares_failed_validation
                        .fetch_add(1, Ordering::Relaxed)
                        + 1;
                    error!(
                        "share validation FAILED on channel {channel_id}: {e:?} \
                         (total validation failures: {n}) — this is NOT a below-target share"
                    );
                    false
                }
            };

            // A share that misses the CURRENT target may still have satisfied the one the miner
            // was working against when it computed it. `target` is swapped the instant
            // `mining.set_difficulty` is SENT, so everything already in flight was made against
            // the previous, easier value — real work, declined because the goalposts moved.
            //
            // Measured under a 1 PH/s farm-tier test: ~20% of all submitted shares on the two
            // busiest nodes, tracking target-change frequency almost exactly (#811).
            //
            // Bounded by SUPERSEDED_TARGET_GRACE so this cannot become a permanent difficulty
            // discount: outside the window there is no previous target to fall back to.
            let is_valid = if is_valid {
                true
            } else if let Some(previous) = data.target_within_grace(SUPERSEDED_TARGET_GRACE) {
                // Validate against whichever of the two is HARDER. An accepted share is
                // forwarded upstream, where `pool_sv2` judges it against the channel target and
                // answers `difficulty-too-low`; accepting something upstream will refuse would
                // relocate the rejection rather than fix it, and cost a round trip doing so.
                //
                // `upstream_target` is the pool's own assignment via `SetTarget`, and is the
                // same value the difficulty manager already gates `set_difficulty` on. Harder
                // is the numerically smaller target, hence `min`.
                let bar = match data.upstream_target {
                    Some(upstream) => previous.min(upstream),
                    None => previous,
                };
                let accepted_late = validate_sv1_share(
                    request,
                    bar,
                    data.extranonce1.clone().into(),
                    data.version_rolling_mask.clone(),
                    job,
                )
                .unwrap_or(false);
                if accepted_late {
                    debug!(
                        "channel {channel_id}: share met the SUPERSEDED target — accepted; it \
                         was computed before the miner saw the new difficulty"
                    );
                }
                accepted_late
            } else {
                false
            };

            if !is_valid {
                return false;
            }

            data.pending_share = Some(SubmitShareWithChannelId {
                channel_id,
                downstream_id,
                share: request.clone(),
                extranonce: data.extranonce1.clone().into(),
                extranonce2_len: data.extranonce2_len,
                version_rolling_mask: data.version_rolling_mask.clone(),
                job_version: data.last_job_version_field,
            });

            true
        })
    }

    /// Indicates to the server that the client supports the mining.set_extranonce method.
    fn handle_extranonce_subscribe(&self) {}

    /// Checks if a Downstream role is authorized.
    fn is_authorized(&self, client_id: Option<usize>, name: &str) -> bool {
        // A downstream that has just disconnected is REMOVED from `self.downstreams` by
        // `handle_downstream_disconnect`, while messages already in flight from that same
        // downstream are still being handled. So absence here is an ordinary race, not a broken
        // invariant — and `.expect()` on it took ghost-vm2 dark for ~45 minutes (#812).
        //
        // Worse than losing the message: `super_safe_lock` wraps `std::sync::Mutex`, which
        // POISONS on panic, so one panic here makes every later access to that mutex panic in
        // turn. A single lost race cascaded into a node that held no listener while systemd
        // still reported `active`.
        let Some(downstream_id) = client_id else {
            warn!("mining.authorize check with no client id — treating as unauthorized");
            return false;
        };
        let Some(downstream) = self.downstreams.get(&downstream_id) else {
            debug!(
                "Downstream {downstream_id} disconnected before its authorize check — unauthorized"
            );
            return false;
        };
        // Compare against the stored name: `.d=` stripped, a bare address given its worker.
        let (name, _) = super::normalize_username(name);
        downstream
            .downstream_data
            .super_safe_lock(|data| data.authorized_worker_name == name.as_ref())
    }

    /// Authorizes a Downstream role.
    fn authorize(&mut self, client_id: Option<usize>, name: &str) {
        // A downstream that has just disconnected is REMOVED from `self.downstreams` by
        // `handle_downstream_disconnect`, while messages already in flight from that same
        // downstream are still being handled. So absence here is an ordinary race, not a broken
        // invariant — and `.expect()` on it took ghost-vm2 dark for ~45 minutes (#812).
        //
        // Worse than losing the message: `super_safe_lock` wraps `std::sync::Mutex`, which
        // POISONS on panic, so one panic here makes every later access to that mutex panic in
        // turn. A single lost race cascaded into a node that held no listener while systemd
        // still reported `active`.
        let Some(downstream_id) = client_id else {
            warn!("mining.authorize with no client id — ignoring");
            return;
        };
        let Some(downstream) = self.downstreams.get(&downstream_id) else {
            debug!("Downstream {downstream_id} disconnected before authorize completed — ignoring");
            return;
        };

        // Store the username WITHOUT any trailing `.d=<difficulty>` directive: this string
        // becomes the channel `user_identity`, from which the pool derives the miner's payout
        // address and worker name. Leaving the directive on would corrupt attribution.
        let (name, _) = super::normalize_username(name);
        let name = name.as_ref();
        let is_authorized = self.is_authorized(client_id, name);
        let bind_after = !is_authorized;
        downstream.downstream_data.super_safe_lock(|data| {
            if !is_authorized {
                data.authorized_worker_name = name.to_string();
            }
            // What the per-share TLV carries depends on what the CHANNEL identity carries,
            // because the pool recombines the two and exactly one of them must hold the
            // payout address:
            //
            //   - channel opened on authorize → the channel already holds `<addr>.<worker>`,
            //     so the TLV carries the worker segment alone and the pool splices them.
            //   - channel opened on subscribe → the channel holds only the provisional
            //     sentinel, so the TLV must carry the FULL `<addr>.<worker>`; it is the sole
            //     source of a payout target and the pool uses it verbatim.
            //
            // Sending the worker alone in the second case is not a lesser form of correct —
            // the pool cannot resolve an address from it and refuses to credit the share.
            // Key this on how THIS channel actually opened, never on the config flag. With
            // the subscribe-open debounced, a pipelining miner opens on authorize and its
            // channel identity already holds the address; sending the full identity as well
            // makes the pool splice one onto the other and credit `<addr>.<addr>.<worker>`.
            let tlv_identity = if data.channel_opened_provisionally {
                name
            } else {
                super::extract_worker_name(name)
            };
            // `None` here means the identity is over the wire ceiling. Leave the field empty
            // rather than truncating: the share submit path omits the TLV, and the pool
            // declines to credit rather than paying an address nobody holds.
            data.user_identity = tlv_compatible_username(tlv_identity)
                .unwrap_or_default()
                .to_string();
            debug!(
                "Down: Set user_identity to '{}' for downstream {}",
                data.user_identity, downstream_id
            );
        });
        // A channel already opened on subscribe gets its payee now (a serialising miner
        // authorises only after its subscribe was answered).
        if bind_after {
            self.bind_provisional_payee(downstream_id);
        }
    }

    /// Sets the `extranonce1` field sent in the SV1 `mining.notify` message to the value specified
    /// by the SV2 `OpenExtendedMiningChannelSuccess` message sent from the Upstream role.
    fn set_extranonce1(
        &mut self,
        client_id: Option<usize>,
        _extranonce1: Option<Extranonce<'static>>,
    ) -> Extranonce<'static> {
        // Gone means the downstream disconnected mid-message (#812). Whatever we return is
        // discarded — the connection it would answer is already closed — so a default is safe
        // here and a panic is not: it poisons the mutex and takes the whole node down.
        let Some(downstream) = client_id.and_then(|id| self.downstreams.get(&id)) else {
            debug!("set_extranonce1 for a downstream that has gone — returning a placeholder");
            // Same construction DownstreamData::new uses for a fresh downstream, and safe for
            // the same reason. It is never sent: the connection this would answer is closed.
            return vec![0; 8]
                .try_into()
                .expect("8-byte extranonce is always valid");
        };
        downstream
            .downstream_data
            .super_safe_lock(|data| data.extranonce1.clone())
    }

    /// Returns the `Downstream`'s `extranonce1` value.
    fn extranonce1(&self, client_id: Option<usize>) -> Extranonce<'static> {
        let Some(downstream) = client_id.and_then(|id| self.downstreams.get(&id)) else {
            debug!("extranonce1 for a downstream that has gone — returning a placeholder");
            return vec![0; 8]
                .try_into()
                .expect("8-byte extranonce is always valid");
        };
        downstream
            .downstream_data
            .super_safe_lock(|data| data.extranonce1.clone())
    }

    /// Sets the `extranonce2_size` field sent in the SV1 `mining.notify` message to the value
    /// specified by the SV2 `OpenExtendedMiningChannelSuccess` message sent from the Upstream role.
    fn set_extranonce2_size(
        &mut self,
        client_id: Option<usize>,
        _extra_nonce2_size: Option<usize>,
    ) -> usize {
        // Gone means the downstream disconnected mid-message (#812). Whatever we return is
        // discarded — the connection it would answer is already closed — so a default is safe
        // here and a panic is not: it poisons the mutex and takes the whole node down.
        let Some(downstream) = client_id.and_then(|id| self.downstreams.get(&id)) else {
            debug!("set_extranonce2_size for a downstream that has gone — returning 0");
            return 0;
        };
        downstream
            .downstream_data
            .super_safe_lock(|data| data.extranonce2_len)
    }

    /// Returns the `Downstream`'s `extranonce2_size` value.
    fn extranonce2_size(&self, client_id: Option<usize>) -> usize {
        let Some(downstream) = client_id.and_then(|id| self.downstreams.get(&id)) else {
            debug!("extranonce2_size for a downstream that has gone — returning 0");
            return 0;
        };
        downstream
            .downstream_data
            .super_safe_lock(|data| data.extranonce2_len)
    }

    /// Returns the version rolling mask.
    fn version_rolling_mask(&self, client_id: Option<usize>) -> Option<HexU32Be> {
        let downstream = self.downstreams.get(&client_id?)?;
        downstream
            .downstream_data
            .super_safe_lock(|data| data.version_rolling_mask.clone())
    }

    /// Sets the version rolling mask.
    fn set_version_rolling_mask(&mut self, client_id: Option<usize>, mask: Option<HexU32Be>) {
        // Gone means the downstream disconnected mid-message (#812). Whatever we return is
        // discarded — the connection it would answer is already closed — so a default is safe
        // here and a panic is not: it poisons the mutex and takes the whole node down.
        let Some(downstream) = client_id.and_then(|id| self.downstreams.get(&id)) else {
            debug!("set_version_rolling_mask for a downstream that has gone — ignoring");
            return;
        };

        downstream
            .downstream_data
            .super_safe_lock(|data| data.version_rolling_mask = mask)
    }

    /// Sets the minimum version rolling bit.
    fn set_version_rolling_min_bit(&mut self, client_id: Option<usize>, mask: Option<HexU32Be>) {
        let Some(downstream) = client_id.and_then(|id| self.downstreams.get(&id)) else {
            debug!("set_version_rolling_min_bit for a downstream that has gone — ignoring");
            return;
        };
        downstream
            .downstream_data
            .super_safe_lock(|data| data.version_rolling_min_bit = mask)
    }

    fn notify(
        &'_ mut self,
        _client_id: Option<usize>,
    ) -> Result<json_rpc::Message, stratum_apps::stratum_core::sv1_api::error::Error<'_>> {
        warn!("notify() called on Sv1Server - this method is not implemented for Sv1Server");
        Err(
            stratum_apps::stratum_core::sv1_api::error::Error::UnexpectedMessage(
                "notify".to_string(),
            ),
        )
    }
}

#[cfg(test)]
mod vanished_downstream_tests {
    use super::*;
    use async_channel::unbounded;
    use std::net::SocketAddr;
    use std::str::FromStr;

    // #812: a downstream that disconnects is removed from `self.downstreams` while its own
    // in-flight SV1 messages are still being handled. Every handler here used to `.expect()`
    // that lookup, and one such panic took ghost-vm2 dark for ~45 minutes — because
    // `super_safe_lock` wraps `std::sync::Mutex`, which POISONS, so the first panic makes every
    // later access to that mutex panic in turn.
    //
    // These drive each handler against an EMPTY downstreams map, which is exactly the state the
    // race produces. Before the fix every one of them panicked.

    // Built locally rather than reaching into sv1_server.rs's private test module — a test that
    // depends on another module's test-only internals breaks on refactors that change nothing
    // it is actually testing.
    fn server() -> Sv1Server {
        use crate::config::{DownstreamDifficultyConfig, TranslatorConfig, Upstream};
        use stratum_apps::key_utils::Secp256k1PublicKey;

        let pubkey =
            Secp256k1PublicKey::from_str("9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnan")
                .expect("valid test pubkey");
        let config = TranslatorConfig::new(
            vec![Upstream::new("127.0.0.1".to_string(), 4444, pubkey)],
            "0.0.0.0".to_string(),
            3333,
            DownstreamDifficultyConfig::new(100.0, 5.0, true, 60),
            2,
            1,
            4,
            "test_user".to_string(),
            true,
            vec![],
            vec![],
            None,
            None,
        );

        let (_tx_a, rx) = unbounded();
        let (tx, _rx_b) = unbounded();
        Sv1Server::new(
            SocketAddr::from_str("127.0.0.1:0").expect("valid addr"),
            rx,
            tx,
            config,
        )
    }

    #[test]
    fn is_authorized_on_a_vanished_downstream_returns_false_instead_of_panicking() {
        let s = server();
        assert!(!s.is_authorized(Some(4242), "bc1qexample.worker"));
    }

    #[test]
    fn authorize_on_a_vanished_downstream_is_a_no_op() {
        let mut s = server();
        s.authorize(Some(4242), "bc1qexample.worker");
    }

    #[test]
    fn accessors_on_a_vanished_downstream_return_defaults() {
        let mut s = server();
        assert_eq!(s.extranonce2_size(Some(4242)), 0);
        assert_eq!(s.set_extranonce2_size(Some(4242), None), 0);
        assert!(s.version_rolling_mask(Some(4242)).is_none());
        // Placeholder, never sent — the connection it would answer is closed.
        assert_eq!(s.extranonce1(Some(4242)).len(), 8);
        assert_eq!(s.set_extranonce1(Some(4242), None).len(), 8);
        s.set_version_rolling_mask(Some(4242), None);
        s.set_version_rolling_min_bit(Some(4242), None);
    }

    // #810: the three refusal reasons must be counted separately. Before this they were
    // collapsed by `.unwrap_or(false)` into one `error!("Invalid share")`, so a node failing
    // every merkle root was indistinguishable from one doing routine vardiff convergence —
    // which is why the 15-20% on ghost-vm2 could not be diagnosed from logs at all.

    #[test]
    fn the_three_refusal_counters_start_at_zero_and_are_separate() {
        let s = server();
        assert_eq!(s.shares_below_target.load(Ordering::Relaxed), 0);
        assert_eq!(s.shares_failed_validation.load(Ordering::Relaxed), 0);
        assert_eq!(s.shares_for_unknown_job.load(Ordering::Relaxed), 0);

        // They must be distinct counters, not aliases of one another — the whole point is that
        // "below target" and "failed validation" can be told apart.
        s.shares_below_target.fetch_add(3, Ordering::Relaxed);
        assert_eq!(s.shares_below_target.load(Ordering::Relaxed), 3);
        assert_eq!(
            s.shares_failed_validation.load(Ordering::Relaxed),
            0,
            "a below-target share must not increment the validation-failure counter"
        );
        assert_eq!(
            s.shares_for_unknown_job.load(Ordering::Relaxed),
            0,
            "a below-target share must not increment the unknown-job counter"
        );
    }

    #[test]
    fn a_missing_client_id_is_handled_too() {
        // The other half of the same assumption: `client_id.expect(...)`. A None id must not
        // panic either.
        let mut s = server();
        assert!(!s.is_authorized(None, "x"));
        assert!(s.version_rolling_mask(None).is_none());
        assert_eq!(s.extranonce2_size(None), 0);
        s.authorize(None, "x");
        s.set_version_rolling_min_bit(None, None);
    }
}

/// Phase 3 harness finding C: the pool refusing one SV1 miner's channel dropped every miner on
/// the translator, and a serialising miner's channel opened on subscribe under the provisional
/// identity, which the node pool cannot credit. Now one refusal drops one miner, and the
/// provisional channel is bound to the miner's payee when it authorises.
#[cfg(test)]
mod one_miner_channel_tests {
    use super::*;
    use crate::sv1::downstream::downstream::Downstream;
    use async_channel::{unbounded, Receiver};
    use std::{net::SocketAddr, str::FromStr};
    use stratum_apps::stratum_core::{
        bitcoin::Target,
        mining_sv2::OpenMiningChannelError,
        parsers_sv2::{Mining, Tlv},
    };
    use tokio_util::sync::CancellationToken;

    const ADDR: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

    /// What the SV1 server sends the channel manager.
    type ToChannelManager = Receiver<(Mining<'static>, Option<Vec<Tlv>>)>;

    /// A server, and what it sends the channel manager.
    fn server() -> (Sv1Server, ToChannelManager) {
        use crate::config::{DownstreamDifficultyConfig, TranslatorConfig, Upstream};
        use stratum_apps::key_utils::Secp256k1PublicKey;
        let pubkey =
            Secp256k1PublicKey::from_str("9bDuixKmZqAJnrmP746n8zU1wyAQRrus7th9dxnkPg6RzQvCnan")
                .unwrap();
        let config = TranslatorConfig::new(
            vec![Upstream::new("127.0.0.1".to_string(), 4444, pubkey)],
            "0.0.0.0".to_string(),
            3333,
            DownstreamDifficultyConfig::new(100.0, 5.0, true, 60),
            2,
            1,
            4,
            "test_user".to_string(),
            false,
            vec![],
            vec![],
            None,
            None,
        );
        let (_tx_a, rx) = unbounded();
        let (tx, to_cm) = unbounded();
        let s = Sv1Server::new(SocketAddr::from_str("127.0.0.1:0").unwrap(), rx, tx, config);
        (s, to_cm)
    }

    /// A connected downstream `id`, registered as the server registers one.
    fn connect(s: &Sv1Server, id: usize) {
        let (to_miner, _from_server) = unbounded();
        let (_to_server, from_miner) = unbounded();
        let (srv_tx, srv_rx) = unbounded();
        let (d_tx, _d_rx) = unbounded();
        s.sv1_server_channel_state
            .sv1_server_to_downstream_sender
            .super_safe_lock(|m| m.insert(id, srv_tx));
        let d = Downstream::new(
            id,
            SocketAddr::from_str("127.0.0.1:1").unwrap(),
            to_miner,
            from_miner,
            d_tx,
            srv_rx,
            Target::from_le_bytes([0xff; 32]),
            Some(1.0e12),
            8,
            CancellationToken::new(),
        );
        s.downstreams.insert(id, d);
    }

    #[test]
    fn a_provisional_channel_is_bound_to_its_miner_on_authorize() {
        let (mut s, to_cm) = server();
        connect(&s, 7);
        s.downstreams
            .get(&7)
            .unwrap()
            .downstream_data
            .super_safe_lock(|d| {
                d.channel_opened_provisionally = true;
                d.channel_id = Some(3);
            });
        // A bare payout address (finding G): bound as `<address>.default`.
        s.authorize(Some(7), ADDR);
        let (msg, tlvs) = to_cm.try_recv().expect("an UpdateChannel to the pool");
        let Mining::UpdateChannel(u) = msg else {
            panic!("not an UpdateChannel: {msg:?}")
        };
        assert_eq!(u.channel_id, 3);
        let tlvs = tlvs.expect("the payee TLV");
        assert_eq!(tlvs.len(), 1);
        assert_eq!(tlvs[0].r#type.extension_type, 0x4748);
        assert_eq!(tlvs[0].r#type.field_type, 0x02);
        assert_eq!(tlvs[0].value, format!("{ADDR}.default").into_bytes());
        s.downstreams
            .get(&7)
            .unwrap()
            .downstream_data
            .super_safe_lock(|d| {
                assert!(d.payee_bound && !d.channel_opened_provisionally);
                assert_eq!(
                    d.user_identity, "default",
                    "the share TLV is the worker now"
                );
            });
        // Once only.
        s.bind_provisional_payee(7);
        assert!(to_cm.try_recv().is_err());
    }

    #[test]
    fn a_channel_opened_on_authorize_sends_no_payee() {
        let (mut s, to_cm) = server();
        connect(&s, 8);
        s.downstreams
            .get(&8)
            .unwrap()
            .downstream_data
            .super_safe_lock(|d| d.channel_id = Some(4));
        s.authorize(Some(8), &format!("{ADDR}.rig1"));
        assert!(to_cm.try_recv().is_err());
    }

    /// Authorised while the open was in flight: bound when the channel id arrives.
    #[test]
    fn a_provisional_channel_opened_after_authorize_is_bound_then() {
        let (mut s, to_cm) = server();
        connect(&s, 9);
        s.downstreams
            .get(&9)
            .unwrap()
            .downstream_data
            .super_safe_lock(|d| d.channel_opened_provisionally = true);
        s.authorize(Some(9), &format!("{ADDR}.rig2"));
        assert!(to_cm.try_recv().is_err(), "no channel yet");
        s.downstreams
            .get(&9)
            .unwrap()
            .downstream_data
            .super_safe_lock(|d| d.channel_id = Some(5));
        s.bind_provisional_payee(9);
        let (msg, tlvs) = to_cm.try_recv().unwrap();
        assert!(matches!(msg, Mining::UpdateChannel(ref u) if u.channel_id == 5));
        assert_eq!(tlvs.unwrap()[0].value, format!("{ADDR}.rig2").into_bytes());
    }

    #[tokio::test]
    async fn a_refused_channel_drops_that_miner_only() {
        let (s, _to_cm) = server();
        connect(&s, 1);
        connect(&s, 2);
        s.request_id_to_downstream_id.insert(1, 1);
        s.request_id_to_downstream_id.insert(2, 2);
        let refusal = Mining::OpenMiningChannelError(OpenMiningChannelError {
            request_id: 1,
            error_code: "no-payout-address".to_string().try_into().unwrap(),
        });
        s.process_upstream_message(Target::from_le_bytes([0xff; 32]), refusal, None)
            .await
            .expect("not an error for the translator");
        assert!(
            s.downstreams.get(&1).is_none(),
            "the refused miner is dropped"
        );
        assert!(s.downstreams.get(&2).is_some(), "the other miner stays");
        assert!(s
            .sv1_server_channel_state
            .sv1_server_to_downstream_sender
            .super_safe_lock(|m| !m.contains_key(&1) && m.contains_key(&2)));
    }
}
