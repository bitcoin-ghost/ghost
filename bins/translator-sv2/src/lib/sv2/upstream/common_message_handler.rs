use crate::{
    error::{self, TproxyError, TproxyErrorKind},
    sv2::Upstream,
};
use stratum_apps::stratum_core::{
    common_messages_sv2::{
        ChannelEndpointChanged, Reconnect, SetupConnectionError, SetupConnectionSuccess,
    },
    handlers_sv2::HandleCommonMessagesFromServerAsync,
    parsers_sv2::Tlv,
};
use tracing::{error, info, warn};

#[cfg_attr(not(test), hotpath::measure_all)]
impl HandleCommonMessagesFromServerAsync for Upstream {
    type Error = TproxyError<error::Upstream>;

    fn get_negotiated_extensions_with_server(
        &self,
        _server_id: Option<usize>,
    ) -> Result<Vec<u16>, Self::Error> {
        Ok(vec![])
    }

    async fn handle_setup_connection_error(
        &mut self,
        _server_id: Option<usize>,
        msg: SetupConnectionError<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        error!("Received: {}", msg);
        Err(TproxyError::fallback(TproxyErrorKind::SetupConnectionError))
    }

    async fn handle_setup_connection_success(
        &mut self,
        _server_id: Option<usize>,
        msg: SetupConnectionSuccess,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        info!("Received: {}", msg);
        Ok(())
    }

    async fn handle_channel_endpoint_changed(
        &mut self,
        _server_id: Option<usize>,
        msg: ChannelEndpointChanged,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        // Informational for a non-Job-Declaration proxy: the upstream pushes jobs
        // (SetNewPrevHash / NewExtendedMiningJob) for every channel regardless, so
        // there is nothing to reconcile here. Log and continue — this must NOT be
        // treated as an error or trigger a fallback/disconnect.
        warn!(
            "Received {} — no-op (translator does not use Job Declaration)",
            msg
        );
        Ok(())
    }

    async fn handle_reconnect(
        &mut self,
        _server_id: Option<usize>,
        msg: Reconnect<'_>,
        _tlv_fields: Option<&[Tlv]>,
    ) -> Result<(), Self::Error> {
        // SECURITY: do NOT follow the server-supplied new_host/new_port. Honouring
        // an arbitrary redirect would let a compromised/malicious upstream point the
        // translator — and all of its miners — at an attacker's pool. Instead, drop
        // and reconnect to our OWN configured upstream(s): returning a Fallback error
        // tears down this connection and lets the FallbackCoordinator re-establish it
        // (the same path `handle_setup_connection_error` uses). The requested target
        // is logged for diagnostics only.
        warn!(
            "Received {} — reconnecting to configured upstream (ignoring server redirect target)",
            msg
        );
        Err(TproxyError::fallback(
            TproxyErrorKind::UpstreamRequestedReconnect,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_apps::stratum_core::binary_sv2::Str0255;

    // Regression: these two handlers used to be `todo!()` and would PANIC the
    // translator if the upstream ever sent the message. They must now return
    // gracefully.

    #[tokio::test]
    async fn channel_endpoint_changed_is_noop_not_error() {
        let mut up = Upstream::for_test();
        let res = up
            .handle_channel_endpoint_changed(None, ChannelEndpointChanged { channel_id: 7 }, None)
            .await;
        assert!(
            res.is_ok(),
            "ChannelEndpointChanged must be a no-op (translator has no Job Declaration), not an error/disconnect"
        );
    }

    #[tokio::test]
    async fn reconnect_returns_fallback_error_not_panic() {
        let mut up = Upstream::for_test();
        let msg = Reconnect {
            new_host: Str0255::try_from(String::new()).unwrap(),
            new_port: 0,
        };
        let res = up.handle_reconnect(None, msg, None).await;
        // Returning an Err triggers the FallbackCoordinator to reconnect to our
        // configured upstream — it must not panic and must not silently succeed.
        assert!(
            res.is_err(),
            "Reconnect must return a (fallback) error so the upstream is re-established"
        );
    }
}
