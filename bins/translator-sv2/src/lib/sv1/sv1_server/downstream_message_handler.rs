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
        let downstream_id = client_id.expect("Downstream id should exist");

        info!("Received mining.configure from SV1 downstream");
        debug!("Downstream {downstream_id}: mining.configure = {}", request);

        let downstream = self
            .downstreams
            .get(&downstream_id)
            .expect("Downstream should exist");

        downstream.downstream_data.super_safe_lock(|data| {
            data.version_rolling_mask = request
                .version_rolling_mask()
                .map(|mask| HexU32Be(mask & 0x1FFFE000));

            data.version_rolling_min_bit = request.version_rolling_min_bit_count();

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
        let downstream_id = client_id.expect("Downstream id should exist");

        info!("Received mining.subscribe from Sv1 downstream");
        debug!("Down: Handling mining.subscribe: {}", request);

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
        let downstream_id = client_id.expect("Downstream id should exist");
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
        let (name, username_difficulty) = super::split_username_difficulty(request.name.as_str());
        if !name.contains('.') {
            warn!(
                "Down: Rejecting mining.authorize from downstream {} — username '{}' has no '.' separator; expected `<bitcoin_address>.<worker_name>`",
                downstream_id, name
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
        let downstream_id = client_id.expect("Downstream id should exist");

        let downstream = self
            .downstreams
            .get(&downstream_id)
            .expect("Downstream should exist");

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

            let is_valid = validate_sv1_share(
                request,
                data.target,
                data.extranonce1.clone().into(),
                data.version_rolling_mask.clone(),
                job,
            )
            .unwrap_or(false);

            if !is_valid {
                error!("Invalid share for channel id: {}", channel_id);
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
        let downstream_id = client_id.expect("Downstream id should exist");
        let downstream = self
            .downstreams
            .get(&downstream_id)
            .expect("Downstream should exist");
        // Compare against the stored name, which has any `.d=` directive stripped.
        let (name, _) = super::split_username_difficulty(name);
        downstream
            .downstream_data
            .super_safe_lock(|data| data.authorized_worker_name == *name)
    }

    /// Authorizes a Downstream role.
    fn authorize(&mut self, client_id: Option<usize>, name: &str) {
        let downstream_id = client_id.expect("Downstream id should exist");
        let downstream = self
            .downstreams
            .get(&downstream_id)
            .expect("Downstream should exist");

        // Store the username WITHOUT any trailing `.d=<difficulty>` directive: this string
        // becomes the channel `user_identity`, from which the pool derives the miner's payout
        // address and worker name. Leaving the directive on would corrupt attribution.
        let (name, _) = super::split_username_difficulty(name);
        let is_authorized = self.is_authorized(client_id, name);
        downstream.downstream_data.super_safe_lock(|data| {
            if !is_authorized {
                data.authorized_worker_name = name.to_string();
            }
            // Extract the worker-name portion of `<addr>.<worker>` so the TLV carries the
            // per-device identifier (which fits in 32 bytes) rather than the wallet address
            // (which doesn't and would duplicate the channel-level user_identity anyway).
            data.user_identity =
                tlv_compatible_username(super::extract_worker_name(name)).to_string();
            debug!(
                "Down: Set user_identity to '{}' for downstream {}",
                data.user_identity, downstream_id
            );
        });
    }

    /// Sets the `extranonce1` field sent in the SV1 `mining.notify` message to the value specified
    /// by the SV2 `OpenExtendedMiningChannelSuccess` message sent from the Upstream role.
    fn set_extranonce1(
        &mut self,
        client_id: Option<usize>,
        _extranonce1: Option<Extranonce<'static>>,
    ) -> Extranonce<'static> {
        let downstream_id = client_id.expect("Downstream id should exist");
        let downstream = self.downstreams.get(&downstream_id).unwrap();
        downstream
            .downstream_data
            .super_safe_lock(|data| data.extranonce1.clone())
    }

    /// Returns the `Downstream`'s `extranonce1` value.
    fn extranonce1(&self, client_id: Option<usize>) -> Extranonce<'static> {
        let downstream_id = client_id.expect("Downstream id should exist");
        let downstream = self.downstreams.get(&downstream_id).unwrap();
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
        let downstream_id = client_id.expect("Downstream id should exist");
        let downstream = self.downstreams.get(&downstream_id).unwrap();
        downstream
            .downstream_data
            .super_safe_lock(|data| data.extranonce2_len)
    }

    /// Returns the `Downstream`'s `extranonce2_size` value.
    fn extranonce2_size(&self, client_id: Option<usize>) -> usize {
        let downstream_id = client_id.expect("Downstream id should exist");
        let downstream = self.downstreams.get(&downstream_id).unwrap();
        downstream
            .downstream_data
            .super_safe_lock(|data| data.extranonce2_len)
    }

    /// Returns the version rolling mask.
    fn version_rolling_mask(&self, client_id: Option<usize>) -> Option<HexU32Be> {
        let downstream_id = client_id.expect("Downstream id should exist");
        let downstream = self.downstreams.get(&downstream_id)?;
        downstream
            .downstream_data
            .super_safe_lock(|data| data.version_rolling_mask.clone())
    }

    /// Sets the version rolling mask.
    fn set_version_rolling_mask(&mut self, client_id: Option<usize>, mask: Option<HexU32Be>) {
        let downstream_id = client_id.expect("Downstream id should exist");
        let downstream = self
            .downstreams
            .get(&downstream_id)
            .expect("Downstream should exist");

        downstream
            .downstream_data
            .super_safe_lock(|data| data.version_rolling_mask = mask)
    }

    /// Sets the minimum version rolling bit.
    fn set_version_rolling_min_bit(&mut self, client_id: Option<usize>, mask: Option<HexU32Be>) {
        let downstream_id = client_id.expect("Downstream id should exist");
        let downstream = self
            .downstreams
            .get(&downstream_id)
            .expect("Downstream should exist");
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
