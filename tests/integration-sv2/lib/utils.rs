use crate::{
    interceptor::{InterceptAction, MessageDirection},
    message_aggregator::MessagesAggregator,
    sniffer_error::SnifferError,
    types::{MessageFrame, MsgType},
};
use async_channel::{Receiver, Sender};
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    convert::TryInto,
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex},
};
use stratum_apps::{
    key_utils::{Secp256k1PublicKey, Secp256k1SecretKey},
    network_helpers::noise_connection::Connection,
    stratum_core::{
        codec_sv2::{HandshakeRole, StandardEitherFrame},
        framing_sv2::framing::{Frame, Sv2Frame},
        noise_sv2::{Initiator, Responder},
        parsers_sv2::{
            message_type_to_name, parse_message_frame_with_tlvs, AnyMessage, CommonMessages,
            IsSv2Message,
            JobDeclaration::{
                AllocateMiningJobToken, AllocateMiningJobTokenSuccess, DeclareMiningJob,
                DeclareMiningJobError, DeclareMiningJobSuccess, ProvideMissingTransactions,
                ProvideMissingTransactionsSuccess, PushSolution,
            },
            TemplateDistribution,
            TemplateDistribution::CoinbaseOutputConstraints,
            Tlv,
        },
    },
};

/// Ports reserved by [`get_available_address`], still BOUND, awaiting [`bind_listener`].
///
/// The old approach bound `127.0.0.1:0`, read the port, and dropped the listener — releasing
/// the port before anything re-bound it. Between release and re-bind any other process could
/// take it, and `bind_listener` then panicked on `expect("Impossible to listen on given
/// address")`. That is #612: three `mock_roles` tests failing intermittently under the full
/// workspace run, blocking `record-tests.sh` and therefore deploys. `cargo llvm-cov` widens
/// the window enough to make it frequent (#408).
///
/// De-duplicating the port numbers (the previous `UNIQUE_PORTS` set) could not fix this: it
/// only stopped THIS process handing the same port out twice, and the port was still
/// unbound in the interval.
///
/// Holding the listener removes the interval entirely — the port is never free between being
/// chosen and being used, so nothing can take it.
static RESERVED: Lazy<Mutex<HashMap<SocketAddr, TcpListener>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Reserve a free loopback address, keeping it bound until [`bind_listener`] claims it.
pub fn get_available_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("read the bound address");
    RESERVED
        .lock()
        .expect("reserved-port registry")
        .insert(addr, listener);
    addr
}
pub async fn wait_for_client(listen_socket: SocketAddr) -> tokio::net::TcpStream {
    accept_one(bind_listener(listen_socket).await).await
}

/// Bind the listener, separately from accepting on it.
///
/// Callers that spawn their accept loop MUST bind before returning, or nothing guarantees the
/// socket exists when the peer dials it. `MockUpstream::start` used to do both inside
/// `tokio::spawn`, so a test could connect to an address nobody was listening on yet — and the
/// port had already been probed-and-released by the caller, so a third party could take it in
/// between (#408).
///
/// The window is invisible on a fast machine and wide under `cargo llvm-cov`, which is exactly
/// where the hang showed up: 5h38m in one test under instrumentation, 22 minutes without.
/// Claim the listener [`get_available_address`] reserved for `listen_socket`, or bind fresh.
///
/// EVERY path that listens on a reserved address must go through this. A caller that binds
/// the address itself will now FAIL, because the reservation still holds the port — which is
/// exactly what happened to `Sniffer::start`, whose own `std::net::TcpListener::bind` broke
/// the moment reservations started being held.
///
/// Returned non-blocking, ready for `tokio::net::TcpListener::from_std`.
pub fn claim_listener(listen_socket: SocketAddr) -> TcpListener {
    let reserved = RESERVED
        .lock()
        .expect("reserved-port registry")
        .remove(&listen_socket);

    let listener = match reserved {
        Some(l) => l,
        // Not reserved — an address the caller chose. Bind it directly; this path still races
        // with the rest of the machine, which is why callers should use
        // `get_available_address`.
        None => TcpListener::bind(listen_socket).expect("Impossible to listen on given address"),
    };

    listener
        .set_nonblocking(true)
        .expect("set the listener non-blocking");
    listener
}

pub async fn bind_listener(listen_socket: SocketAddr) -> tokio::net::TcpListener {
    tokio::net::TcpListener::from_std(claim_listener(listen_socket))
        .expect("adopt the reserved listener")
}

/// Accept a single connection from an already-bound listener.
pub async fn accept_one(listener: tokio::net::TcpListener) -> tokio::net::TcpStream {
    if let Ok((stream, _)) = listener.accept().await {
        stream
    } else {
        panic!("Impossible to accept downstream connection")
    }
}

pub async fn create_downstream(
    stream: tokio::net::TcpStream,
) -> Option<(Receiver<MessageFrame>, Sender<MessageFrame>)> {
    let pub_key = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72"
        .to_string()
        .parse::<Secp256k1PublicKey>()
        .unwrap()
        .into_bytes();
    let prv_key = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n"
        .to_string()
        .parse::<Secp256k1SecretKey>()
        .unwrap()
        .into_bytes();
    let responder =
        Responder::from_authority_kp(&pub_key, &prv_key, std::time::Duration::from_secs(10000))
            .unwrap();

    if let Ok((receiver_from_client, sender_to_client)) =
        Connection::new::<AnyMessage<'static>>(stream, HandshakeRole::Responder(responder)).await
    {
        Some((receiver_from_client, sender_to_client))
    } else {
        None
    }
}

pub async fn create_upstream(
    stream: tokio::net::TcpStream,
) -> Option<(Receiver<MessageFrame>, Sender<MessageFrame>)> {
    let initiator = Initiator::without_pk().expect("This fn call can not fail");
    if let Ok((receiver_from_server, sender_to_server)) =
        Connection::new::<AnyMessage<'static>>(stream, HandshakeRole::Initiator(initiator)).await
    {
        Some((receiver_from_server, sender_to_server))
    } else {
        None
    }
}

pub async fn recv_from_down_send_to_up(
    recv: Receiver<MessageFrame>,
    send: Sender<MessageFrame>,
    downstream_messages: MessagesAggregator,
    action: Vec<InterceptAction>,
    identifier: &str,
    negotiated_extensions: Arc<Mutex<Vec<u16>>>,
) -> Result<(), SnifferError> {
    while let Ok(mut frame) = recv.recv().await {
        let extensions = negotiated_extensions.lock().unwrap().clone();
        let (msg_type, msg, tlv_fields) = message_from_frame_with_tlvs(&mut frame, &extensions);

        // Track extension negotiation
        if let AnyMessage::Extensions(ref ext_msg) = msg {
            use stratum_apps::stratum_core::parsers_sv2::{Extensions, ExtensionsNegotiation};
            if let Extensions::ExtensionsNegotiation(
                ExtensionsNegotiation::RequestExtensionsSuccess(ref success),
            ) = ext_msg
            {
                let mut exts = negotiated_extensions.lock().unwrap();
                *exts = success.supported_extensions.clone().into_inner();
                tracing::info!(
                    "🔍 Sniffer {} | Tracked negotiated extensions: {:?}",
                    identifier,
                    *exts
                );
            }
        }

        let action = action.iter().find(|action| {
            action
                .find_matching_action(msg_type, MessageDirection::ToUpstream)
                .is_some()
        });
        if let Some(action) = action {
            match action {
                InterceptAction::IgnoreMessage(_) => {
                    tracing::info!(
                        "🔍 Sv2 Sniffer {} | Ignored: {} | Direction: ⬆",
                        identifier,
                        message_type_to_name(msg_type)
                    );
                    continue;
                }
                InterceptAction::ReplaceMessage(intercept_message) => {
                    let intercept_frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                        Sv2Frame::from_message(
                            intercept_message.replacement_message.clone(),
                            intercept_message.replacement_message.message_type(),
                            0,
                            false,
                        )
                        .expect("Failed to create the frame"),
                    );
                    downstream_messages.add_message_with_tlvs(
                        intercept_message.replacement_message.message_type(),
                        intercept_message.replacement_message.clone(),
                        None,
                    );
                    send.send(intercept_frame)
                        .await
                        .map_err(|_| SnifferError::UpstreamClosed)?;
                    tracing::info!(
                        "🔍 Sv2 Sniffer {} | Replaced: {} with {} | Direction: ⬆",
                        identifier,
                        message_type_to_name(msg_type),
                        message_type_to_name(intercept_message.replacement_message.message_type())
                    );
                }
            }
        } else {
            downstream_messages.add_message_with_tlvs(msg_type, msg.clone(), tlv_fields);
            send.send(frame)
                .await
                .map_err(|_| SnifferError::UpstreamClosed)?;
            tracing::info!(
                "🔍 Sv2 Sniffer {} | Forwarded: {} | Direction: ⬆ | Data: {}",
                identifier,
                message_type_to_name(msg_type),
                msg
            );
        }
    }
    Err(SnifferError::DownstreamClosed)
}

pub async fn recv_from_up_send_to_down(
    recv: Receiver<MessageFrame>,
    send: Sender<MessageFrame>,
    upstream_messages: MessagesAggregator,
    action: Vec<InterceptAction>,
    identifier: &str,
    negotiated_extensions: std::sync::Arc<std::sync::Mutex<Vec<u16>>>,
) -> Result<(), SnifferError> {
    while let Ok(mut frame) = recv.recv().await {
        let extensions = negotiated_extensions.lock().unwrap().clone();
        let (msg_type, msg, tlv_fields) = message_from_frame_with_tlvs(&mut frame, &extensions);

        // Track extension negotiation
        if let AnyMessage::Extensions(ref ext_msg) = msg {
            use stratum_apps::stratum_core::parsers_sv2::{Extensions, ExtensionsNegotiation};
            if let Extensions::ExtensionsNegotiation(
                ExtensionsNegotiation::RequestExtensionsSuccess(ref success),
            ) = ext_msg
            {
                let mut exts = negotiated_extensions.lock().unwrap();
                *exts = success.supported_extensions.clone().into_inner();
                tracing::info!(
                    "🔍 Sniffer {} | Tracked negotiated extensions: {:?}",
                    identifier,
                    *exts
                );
            }
        }

        let action = action.iter().find(|action| {
            action
                .find_matching_action(msg_type, MessageDirection::ToDownstream)
                .is_some()
        });

        if let Some(action) = action {
            match action {
                InterceptAction::IgnoreMessage(_) => {
                    tracing::info!(
                        "🔍 Sv2 Sniffer {} | Ignored: {} | Direction: ⬇",
                        identifier,
                        message_type_to_name(msg_type)
                    );
                    continue;
                }
                InterceptAction::ReplaceMessage(intercept_message) => {
                    let intercept_frame = StandardEitherFrame::<AnyMessage<'_>>::Sv2(
                        Sv2Frame::from_message(
                            intercept_message.replacement_message.clone(),
                            intercept_message.replacement_message.message_type(),
                            0,
                            false,
                        )
                        .expect("Failed to create the frame"),
                    );
                    upstream_messages.add_message_with_tlvs(
                        intercept_message.replacement_message.message_type(),
                        intercept_message.replacement_message.clone(),
                        None,
                    );
                    send.send(intercept_frame)
                        .await
                        .map_err(|_| SnifferError::DownstreamClosed)?;
                    tracing::info!(
                        "🔍 Sv2 Sniffer {} | Replaced: {} with {} | Direction: ⬇",
                        identifier,
                        message_type_to_name(msg_type),
                        message_type_to_name(intercept_message.replacement_message.message_type())
                    );
                }
            }
        } else {
            upstream_messages.add_message_with_tlvs(msg_type, msg.clone(), tlv_fields);
            send.send(frame)
                .await
                .map_err(|_| SnifferError::DownstreamClosed)?;
            tracing::info!(
                "🔍 Sv2 Sniffer {} | Forwarded: {} | Direction: ⬇ | Data: {}",
                identifier,
                message_type_to_name(msg_type),
                msg
            );
        }
    }
    Err(SnifferError::UpstreamClosed)
}

pub fn message_from_frame(frame: &mut MessageFrame) -> (MsgType, AnyMessage<'static>) {
    let (msg_type, msg, _) = message_from_frame_with_tlvs(frame, &[]);
    (msg_type, msg)
}

pub fn message_from_frame_with_tlvs(
    frame: &mut MessageFrame,
    negotiated_extensions: &[u16],
) -> (MsgType, AnyMessage<'static>, Option<Vec<Tlv>>) {
    match frame {
        Frame::Sv2(frame) => {
            if let Some(header) = frame.get_header() {
                let payload = frame.payload();

                // Try to parse with TLV support if extensions are negotiated
                if !negotiated_extensions.is_empty() {
                    match parse_message_frame_with_tlvs(header, payload, negotiated_extensions) {
                        Ok((message, tlv_fields)) => {
                            let message = into_static(message);
                            return (header.msg_type(), message, tlv_fields);
                        }
                        Err(e) => {
                            println!("Failed to parse frame with TLVs: {e:?}, falling back to standard parsing");
                        }
                    }
                }

                // Fallback to standard parsing without TLV support
                let mut payload = frame.payload().to_vec();
                let message: Result<AnyMessage<'_>, _> =
                    (header, payload.as_mut_slice()).try_into();
                match message {
                    Ok(message) => {
                        let message = into_static(message);
                        (header.msg_type(), message, None)
                    }
                    _ => {
                        println!("Received frame with invalid payload or message type: {frame:?}");
                        panic!();
                    }
                }
            } else {
                println!("Received frame with invalid header: {frame:?}");
                panic!();
            }
        }
        Frame::HandShake(f) => {
            println!("Received unexpected handshake frame: {f:?}");
            panic!();
        }
    }
}

pub fn into_static(m: AnyMessage<'_>) -> AnyMessage<'static> {
    match m {
        AnyMessage::Mining(m) => AnyMessage::Mining(m.into_static()),
        AnyMessage::Common(m) => match m {
            CommonMessages::ChannelEndpointChanged(m) => {
                AnyMessage::Common(CommonMessages::ChannelEndpointChanged(m.into_static()))
            }
            CommonMessages::SetupConnection(m) => {
                AnyMessage::Common(CommonMessages::SetupConnection(m.into_static()))
            }
            CommonMessages::SetupConnectionError(m) => {
                AnyMessage::Common(CommonMessages::SetupConnectionError(m.into_static()))
            }
            CommonMessages::SetupConnectionSuccess(m) => {
                AnyMessage::Common(CommonMessages::SetupConnectionSuccess(m.into_static()))
            }
            CommonMessages::Reconnect(m) => {
                AnyMessage::Common(CommonMessages::Reconnect(m.into_static()))
            }
        },
        AnyMessage::JobDeclaration(m) => match m {
            AllocateMiningJobToken(m) => {
                AnyMessage::JobDeclaration(AllocateMiningJobToken(m.into_static()))
            }
            AllocateMiningJobTokenSuccess(m) => {
                AnyMessage::JobDeclaration(AllocateMiningJobTokenSuccess(m.into_static()))
            }
            DeclareMiningJob(m) => AnyMessage::JobDeclaration(DeclareMiningJob(m.into_static())),
            DeclareMiningJobError(m) => {
                AnyMessage::JobDeclaration(DeclareMiningJobError(m.into_static()))
            }
            DeclareMiningJobSuccess(m) => {
                AnyMessage::JobDeclaration(DeclareMiningJobSuccess(m.into_static()))
            }
            ProvideMissingTransactions(m) => {
                AnyMessage::JobDeclaration(ProvideMissingTransactions(m.into_static()))
            }
            ProvideMissingTransactionsSuccess(m) => {
                AnyMessage::JobDeclaration(ProvideMissingTransactionsSuccess(m.into_static()))
            }
            PushSolution(m) => AnyMessage::JobDeclaration(PushSolution(m.into_static())),
        },
        AnyMessage::TemplateDistribution(m) => match m {
            CoinbaseOutputConstraints(m) => {
                AnyMessage::TemplateDistribution(CoinbaseOutputConstraints(m.into_static()))
            }
            TemplateDistribution::NewTemplate(m) => {
                AnyMessage::TemplateDistribution(TemplateDistribution::NewTemplate(m.into_static()))
            }
            TemplateDistribution::RequestTransactionData(m) => AnyMessage::TemplateDistribution(
                TemplateDistribution::RequestTransactionData(m.into_static()),
            ),
            TemplateDistribution::RequestTransactionDataError(m) => {
                AnyMessage::TemplateDistribution(TemplateDistribution::RequestTransactionDataError(
                    m.into_static(),
                ))
            }
            TemplateDistribution::RequestTransactionDataSuccess(m) => {
                AnyMessage::TemplateDistribution(
                    TemplateDistribution::RequestTransactionDataSuccess(m.into_static()),
                )
            }
            TemplateDistribution::SetNewPrevHash(m) => AnyMessage::TemplateDistribution(
                TemplateDistribution::SetNewPrevHash(m.into_static()),
            ),
            TemplateDistribution::SubmitSolution(m) => AnyMessage::TemplateDistribution(
                TemplateDistribution::SubmitSolution(m.into_static()),
            ),
        },
        AnyMessage::Extensions(extensions) => AnyMessage::Extensions(extensions.into_static()),
    }
}

pub mod http {
    use std::io::Read;

    // Uses `ureq` (rustls 0.23 / rustls-webpki 0.103) rather than `minreq`,
    // whose `https` feature pins the vulnerable rustls-webpki 0.101.
    pub fn make_get_request(download_url: &str, retries: usize) -> Vec<u8> {
        for attempt in 1..=retries {
            match ureq::get(download_url).call() {
                Ok(response) => {
                    let mut buf = Vec::new();
                    match response.into_reader().read_to_end(&mut buf) {
                        Ok(_) => return buf,
                        Err(err) => eprintln!(
                            "Attempt {attempt}: failed reading body from {download_url}: {err:?}"
                        ),
                    }
                }
                Err(ureq::Error::Status(status_code, _)) => {
                    if (500..600).contains(&status_code) {
                        eprintln!(
                            "Attempt {attempt}: URL {download_url} returned a server error code {status_code}"
                        );
                    } else {
                        panic!(
                            "URL {download_url} returned unexpected status code {status_code}. Aborting."
                        );
                    }
                }
                Err(err) => {
                    eprintln!("Attempt {attempt}: Failed to fetch URL {download_url}: {err:?}");
                }
            }

            if attempt < retries {
                let delay = 1u64 << (attempt - 1);
                eprintln!("Retrying in {delay} seconds (exponential backoff)...");
                std::thread::sleep(std::time::Duration::from_secs(delay));
            }
        }
        // If all retries fail, panic with an error message
        panic!("Cannot reach URL {download_url} after {retries} attempts");
    }
}

pub mod tarball {
    use std::{
        fs::File,
        io::{BufReader, Read},
        path::Path,
    };

    pub fn read_from_file(path: &str) -> Vec<u8> {
        let file = File::open(path).unwrap_or_else(|_| {
            panic!("Cannot find {path:?} specified with env var BITCOIND_TARBALL_FILE")
        });
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).unwrap();
        buffer
    }

    pub fn unpack(tarball_bytes: &[u8], destination: &Path) {
        use std::{io::Write as IoWrite, process::Command};

        // Write tarball bytes to a temp file
        let temp_tarball = destination.join("temp.tar.gz");
        let mut temp_file = File::create(&temp_tarball).unwrap();
        temp_file.write_all(tarball_bytes).unwrap();
        drop(temp_file);

        // Use system tar command to extract, which properly handles GNU sparse files
        let output = Command::new("tar")
            .arg("-xzf")
            .arg(&temp_tarball)
            .arg("-C")
            .arg(destination)
            .arg("--strip-components=0")
            .output()
            .expect("Failed to execute tar command");

        if !output.status.success() {
            eprintln!("tar stderr: {}", String::from_utf8_lossy(&output.stderr));
            panic!("tar extraction failed");
        }

        // Clean up temp tarball
        std::fs::remove_file(&temp_tarball).ok();
    }
}

pub mod fs_utils {
    use std::{fs, path::Path};

    /// Recursively copy all contents from source directory to destination directory
    pub fn copy_dir_contents(src: &Path, dst: &Path) -> std::io::Result<()> {
        if !dst.exists() {
            fs::create_dir_all(dst)?;
        }

        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let src_path = entry.path();
            let dst_path = dst.join(entry.file_name());

            if src_path.is_dir() {
                copy_dir_contents(&src_path, &dst_path)?;
            } else {
                fs::copy(&src_path, &dst_path)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod reserved_port_tests {
    use super::*;

    /// #612: the port must NEVER be unbound between being chosen and being used.
    ///
    /// The old helper bound `127.0.0.1:0`, read the port and dropped the listener, so the port
    /// sat free until `bind_listener` re-bound it. Anything on the machine could take it in
    /// that window, and `bind_listener` panicked when it did.
    ///
    /// This asserts the invariant directly: right after reserving, the address is already
    /// bound, so an independent bind FAILS. Against the old implementation this test fails —
    /// the port was free and the bind would succeed.
    #[test]
    fn a_reserved_address_is_already_bound_so_nothing_can_take_it() {
        let addr = get_available_address();
        assert!(
            TcpListener::bind(addr).is_err(),
            "reserved address {addr} was free — the race window is open"
        );
    }

    /// And the reservation must be usable: `bind_listener` adopts it rather than re-binding.
    #[tokio::test]
    async fn bind_listener_adopts_the_reservation() {
        let addr = get_available_address();
        let listener = bind_listener(addr).await;
        assert_eq!(
            listener.local_addr().expect("local addr"),
            addr,
            "bind_listener must serve the address that was reserved"
        );
    }

    /// Two reservations never collide, and neither is released by the other.
    #[test]
    fn reservations_are_distinct_and_both_held() {
        let a = get_available_address();
        let b = get_available_address();
        assert_ne!(a, b, "two reservations returned the same address");
        assert!(
            TcpListener::bind(a).is_err(),
            "first reservation was released"
        );
        assert!(
            TcpListener::bind(b).is_err(),
            "second reservation was released"
        );
    }
}
