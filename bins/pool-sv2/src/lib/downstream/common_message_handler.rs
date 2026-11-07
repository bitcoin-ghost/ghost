use crate::{
    downstream::Downstream,
    error::{self, PoolError, PoolErrorKind},
};
use std::{convert::TryInto, sync::atomic::Ordering};
use stratum_apps::{
    stratum_core::{
        common_messages_sv2::{
            has_requires_std_job, has_work_selection, Protocol, SetupConnection,
            SetupConnectionError, SetupConnectionSuccess,
        },
        handlers_sv2::HandleCommonMessagesFromClientAsync,
        parsers_sv2::{AnyMessage, Tlv},
    },
    utils::types::Sv2Frame,
};
use tracing::info;

#[cfg_attr(not(test), hotpath::measure_all)]
impl HandleCommonMessagesFromClientAsync for Downstream {
    type Error = PoolError<error::Downstream>;

    fn get_negotiated_extensions_with_client(
        &self,
        _client_id: Option<usize>,
    ) -> Result<Vec<u16>, Self::Error> {
        Ok(self
            .downstream_data
            .super_safe_lock(|data| data.negotiated_extensions.clone()))
    }

    async fn handle_setup_connection(
        &mut self,
        client_id: Option<usize>,
        msg: SetupConnection<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!(
            "Received `SetupConnection`: version={}, flags={:b}",
            msg.min_version, msg.flags
        );

        let downstream_id = client_id.expect("downstream id should be present");

        if msg.protocol != Protocol::MiningProtocol {
            info!("Rejecting connection from {downstream_id}: SetupConnection asking for other protocols than mining protocol.");
            let response = SetupConnectionError {
                flags: 0,
                error_code: "unsupported-protocol"
                    .to_string()
                    .try_into()
                    .expect("error code must be valid string"),
            };
            let frame: Sv2Frame = AnyMessage::Common(response.into_static().into())
                .try_into()
                .map_err(PoolError::shutdown)?;
            self.downstream_channel
                .downstream_sender
                .send(frame)
                .await
                .map_err(|_| {
                    PoolError::disconnect(PoolErrorKind::ChannelErrorSender, downstream_id)
                })?;

            return Err(PoolError::disconnect(
                PoolErrorKind::UnsupportedProtocol,
                downstream_id,
            ));
        }

        // Kept for the node pool's sensing loop (native SV2 miners have no SV1 agent).
        let setup_device = ghost_common::slot_class_sensing::Sv2Device::new(
            &msg.vendor.as_utf8_or_hex(),
            &msg.hardware_version.as_utf8_or_hex(),
            &msg.firmware.as_utf8_or_hex(),
        );
        self.downstream_data
            .super_safe_lock(|data| data.setup_device = setup_device);

        // Work selection (job declaration) is refused: a declared job's coinbase comes from the
        // client and cannot pay the node pool's canonical outputs.
        if has_work_selection(msg.flags) {
            info!("Rejecting connection from {downstream_id}: work selection is not supported.");
            let response = SetupConnectionError {
                // REQUIRES_WORK_SELECTION, the flag this server does not support.
                flags: 0b10,
                error_code: "unsupported-feature-flags"
                    .to_string()
                    .try_into()
                    .expect("error code must be valid string"),
            };
            let frame: Sv2Frame = AnyMessage::Common(response.into_static().into())
                .try_into()
                .map_err(PoolError::shutdown)?;
            self.downstream_channel
                .downstream_sender
                .send(frame)
                .await
                .map_err(|_| {
                    PoolError::disconnect(PoolErrorKind::ChannelErrorSender, downstream_id)
                })?;
            return Err(PoolError::disconnect(
                PoolErrorKind::UnsupportedProtocol,
                downstream_id,
            ));
        }
        self.requires_standard_jobs
            .store(has_requires_std_job(msg.flags), Ordering::SeqCst);

        // SetupConnection.Success.flags for Mining Protocol (server -> client): none are set.
        let response = SetupConnectionSuccess {
            used_version: 2,
            flags: 0,
        };
        let frame: Sv2Frame = AnyMessage::Common(response.into_static().into())
            .try_into()
            .map_err(PoolError::shutdown)?;
        self.downstream_channel
            .downstream_sender
            .send(frame)
            .await
            .map_err(|_| {
                PoolError::disconnect(PoolErrorKind::ChannelErrorSender, self.downstream_id)
            })?;

        Ok(())
    }
}
