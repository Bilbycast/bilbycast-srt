// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT listener for accepting incoming connections.
//!
//! Maps to C++ listen/accept flow. Binds to a UDP port and accepts
//! incoming SRT connections via the HSv5 handshake process.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, BytesMut};
use tokio::sync::mpsc;

use srt_protocol::access_control::{
    AccessControl, AccessControlFn, AcceptAll, HandshakeInfo, SRT_CMD_SID, parse_stream_id,
};
use srt_protocol::config::{KeySize, SrtConfig, SRT_VERSION};
use srt_protocol::config::srt_options::SrtFlags;
use srt_protocol::crypto::KeyIndex;
use srt_protocol::crypto::km_exchange::{CipherType, KeyMaterialMessage};
use srt_protocol::crypto::key_material;
use srt_protocol::error::{RejectReason, SrtError};
use srt_protocol::protocol::connection::ConnectionState;
use srt_protocol::protocol::handshake::{
    HS_EXT_HSREQ, HS_EXT_KMREQ, HS_VERSION_SRT1, Handshake, HandshakeExtension,
    HandshakeType, SrtHsExtension, SRT_MAGIC_CODE,
};

use crate::channel::UdpChannel;
use crate::connection::SrtConnection;
use crate::connector::build_handshake_packet_with_extensions;
use crate::multiplexer::Multiplexer;
use crate::recv_loop;
use crate::send_loop;
use crate::socket::SrtSocket;

/// Builder for creating an SRT listener.
pub struct SrtListenerBuilder {
    config: SrtConfig,
    backlog: usize,
    access_control: Arc<dyn AccessControl>,
}

impl SrtListenerBuilder {
    /// Create a new listener builder.
    pub fn new() -> Self {
        Self {
            config: SrtConfig::default(),
            backlog: 5,
            access_control: Arc::new(AcceptAll),
        }
    }

    /// Set the latency for accepted connections.
    pub fn latency(mut self, latency: Duration) -> Self {
        let ms = latency.as_millis() as u32;
        self.config.recv_latency = ms;
        self.config.peer_latency = ms;
        self
    }

    /// Enable encryption for accepted connections.
    pub fn encryption(mut self, passphrase: &str, key_size: KeySize) -> Self {
        self.config.passphrase = passphrase.to_string();
        self.config.key_size = key_size;
        self
    }

    /// Set the connection backlog.
    pub fn backlog(mut self, backlog: usize) -> Self {
        self.backlog = backlog;
        self
    }

    /// Set the transport type to LIVE mode.
    pub fn live_mode(mut self) -> Self {
        self.config.live_defaults();
        self
    }

    /// Set the transport type to FILE mode.
    pub fn file_mode(mut self) -> Self {
        self.config.file_defaults();
        self
    }

    /// Set the maximum segment size.
    pub fn mss(mut self, mss: u32) -> Self {
        self.config.mss = mss;
        self
    }

    /// Set the peer idle timeout.
    pub fn peer_idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.peer_idle_timeout = timeout;
        self
    }

    /// Set the maximum payload size per packet.
    pub fn payload_size(mut self, size: u32) -> Self {
        self.config.payload_size = size;
        self
    }

    /// Set the maximum retransmission bandwidth in bytes per second.
    ///
    /// Uses a token bucket shaper to limit retransmission bandwidth.
    /// - `-1` (default): unlimited retransmission bandwidth
    /// - `0`: disable retransmissions entirely
    /// - `> 0`: limit to this many bytes per second
    pub fn max_rexmit_bw(mut self, bw: i64) -> Self {
        self.config.max_rexmit_bw = bw;
        self
    }

    /// Set an access control handler that inspects incoming connections.
    ///
    /// The handler receives a [`HandshakeInfo`] with the peer address,
    /// Stream ID, encryption state, etc. and returns `Ok(())` to accept
    /// or `Err(RejectReason)` to reject. Rejected connections receive a
    /// handshake failure response with the given reason code.
    ///
    /// By default, all connections are accepted.
    pub fn access_control(mut self, ac: impl AccessControl) -> Self {
        self.access_control = Arc::new(ac);
        self
    }

    /// Set an access control callback using a closure.
    ///
    /// Convenience alternative to [`access_control()`](Self::access_control).
    ///
    /// # Example
    /// ```ignore
    /// SrtListener::builder()
    ///     .access_control_fn(|info| {
    ///         if info.stream_id.starts_with("#!::r=live/") {
    ///             Ok(())
    ///         } else {
    ///             Err(RejectReason::Peer)
    ///         }
    ///     })
    ///     .bind("0.0.0.0:4200".parse().unwrap())
    ///     .await?;
    /// ```
    pub fn access_control_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&HandshakeInfo) -> Result<(), RejectReason> + Send + Sync + 'static,
    {
        self.access_control = Arc::new(AccessControlFn(f));
        self
    }

    /// Bind and start listening.
    pub async fn bind(self, addr: SocketAddr) -> Result<SrtListener, SrtError> {
        let channel = UdpChannel::bind(addr).await
            .map_err(|_| SrtError::ConnectionSetup)?;
        let local_addr = channel.local_addr();

        let mux = Arc::new(Multiplexer::new(channel));

        // Create the listener "socket" that receives initial handshakes (dest_id=0)
        let listener_socket_id = 0u32;
        let listener_conn = Arc::new(SrtConnection::new(
            self.config.clone(),
            local_addr,
            listener_socket_id,
        ));
        listener_conn.set_state(ConnectionState::Listening).await;
        mux.set_listener(listener_conn.clone()).await;

        // Channel for accepted connections
        let (accept_tx, accept_rx) = mpsc::channel(self.backlog);

        // Start receive loop
        let mux_recv = mux.clone();
        tokio::spawn(async move {
            recv_loop::run(mux_recv).await;
        });

        // Spawn the accept loop that processes handshakes and creates connections
        let mux_accept = mux.clone();
        let config_accept = self.config.clone();
        let listener_conn_accept = listener_conn.clone();
        let ac = self.access_control.clone();
        tokio::spawn(async move {
            accept_loop(
                mux_accept,
                config_accept,
                listener_conn_accept,
                accept_tx,
                ac,
            )
            .await;
        });

        Ok(SrtListener {
            config: self.config,
            multiplexer: mux,
            listener_conn,
            local_addr,
            accept_rx,
        })
    }
}

impl Default for SrtListenerBuilder {
    fn default() -> Self {
        Self::new()
    }
}


/// An SRT listener that accepts incoming connections.
pub struct SrtListener {
    /// Configuration template for accepted connections.
    #[allow(dead_code)]
    config: SrtConfig,
    /// The multiplexer for this listener.
    multiplexer: Arc<Multiplexer>,
    /// The listener connection state.
    listener_conn: Arc<SrtConnection>,
    /// Local address.
    local_addr: SocketAddr,
    /// Receiver end for accepted connections.
    accept_rx: mpsc::Receiver<SrtSocket>,
}

impl SrtListener {
    /// Create a listener builder.
    pub fn builder() -> SrtListenerBuilder {
        SrtListenerBuilder::new()
    }

    /// Accept an incoming SRT connection.
    ///
    /// Blocks until a new connection is established.
    pub async fn accept(&mut self) -> Result<SrtSocket, SrtError> {
        self.accept_rx.recv().await
            .ok_or(SrtError::SocketClosed)
    }

    /// Get the local address this listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Close the listener.
    pub async fn close(&self) -> Result<(), SrtError> {
        self.listener_conn.set_state(ConnectionState::Closed).await;
        self.multiplexer.clear_listener().await;
        Ok(())
    }
}

/// Background task that processes incoming handshakes on the listener connection.
///
/// Implements the listener side of the HSv5 handshake:
/// 1. Receive INDUCTION from caller → respond with INDUCTION (cookie, version=5)
/// 2. Receive CONCLUSION from caller → create connection, respond with CONCLUSION
/// 3. Send the accepted SrtSocket through accept_tx
async fn accept_loop(
    mux: Arc<Multiplexer>,
    config: SrtConfig,
    listener_conn: Arc<SrtConnection>,
    accept_tx: mpsc::Sender<SrtSocket>,
    access_control: Arc<dyn AccessControl>,
) {
    loop {
        // Check if listener is still active
        let state = listener_conn.get_state().await;
        if state.is_closed() {
            log::debug!("Listener accept loop stopping (listener closed)");
            break;
        }

        // Wait for an INDUCTION handshake from a caller
        let (induction_hs, caller_addr) = {
            let mut rx = listener_conn.handshake_rx.lock().await;
            match rx.recv().await {
                Some((hs, addr, _ext)) => (hs, addr),
                None => {
                    log::debug!("Listener handshake channel closed");
                    break;
                }
            }
        };

        if induction_hs.req_type != HandshakeType::Induction {
            log::debug!(
                "Listener: expected INDUCTION, got {:?} from {}",
                induction_hs.req_type,
                caller_addr
            );
            continue;
        }

        log::debug!(
            "Listener: received INDUCTION from {} (socket_id={})",
            caller_addr,
            induction_hs.socket_id
        );

        // Generate a cookie from the caller's address for validation
        let cookie = generate_cookie(&caller_addr);

        // Build INDUCTION response: version=5, SRT_MAGIC_CODE in ext_flags, our cookie
        let listener_socket_id = rand::random::<u32>() & 0x3FFF_FFFF;
        let induction_response = Handshake {
            version: HS_VERSION_SRT1,
            ext_flags: SRT_MAGIC_CODE as i32,
            isn: 0,
            mss: config.mss as i32,
            flight_flag_size: config.flight_flag_size as i32,
            req_type: HandshakeType::Induction,
            socket_id: listener_socket_id as i32,
            cookie: cookie as i32,
            peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };

        // Send INDUCTION response (dest_socket_id = caller's socket_id)
        let pkt = build_handshake_packet(&induction_response, induction_hs.socket_id as u32);
        if let Err(e) = mux.send_to(&pkt, caller_addr).await {
            log::error!("Listener: failed to send INDUCTION response: {}", e);
            continue;
        }

        log::debug!(
            "Listener: sent INDUCTION response to {} (cookie={:#x})",
            caller_addr,
            cookie
        );

        // Temporarily register the listener_socket_id in the multiplexer so
        // the CONCLUSION packet (which targets this ID) gets routed to our
        // listener connection where we can receive it.
        mux.add_connection(listener_socket_id, listener_conn.clone()).await;

        // Wait for CONCLUSION from the caller
        let (conclusion_hs, conclusion_addr, conclusion_ext_bytes) = {
            let mut rx = listener_conn.handshake_rx.lock().await;
            match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
                Ok(Some(msg)) => msg,
                Ok(None) => {
                    log::debug!("Listener: handshake channel closed during CONCLUSION wait");
                    break;
                }
                Err(_) => {
                    log::warn!("Listener: CONCLUSION timeout from {}", caller_addr);
                    mux.remove_connection(listener_socket_id).await;
                    continue;
                }
            }
        };

        if conclusion_hs.req_type != HandshakeType::Conclusion {
            log::debug!(
                "Listener: expected CONCLUSION, got {:?} from {}",
                conclusion_hs.req_type,
                conclusion_addr
            );
            mux.remove_connection(listener_socket_id).await;
            continue;
        }

        // Validate cookie
        if conclusion_hs.cookie as u32 != cookie {
            log::warn!(
                "Listener: invalid cookie from {} (expected {:#x}, got {:#x})",
                conclusion_addr,
                cookie,
                conclusion_hs.cookie
            );
            mux.remove_connection(listener_socket_id).await;
            continue;
        }

        log::debug!(
            "Listener: received CONCLUSION from {} (valid cookie)",
            conclusion_addr
        );

        // Parse extensions from caller's CONCLUSION (KMREQ, Stream ID)
        let mut km_response: Option<KeyMaterialMessage> = None;
        let mut peer_sek: Option<Vec<u8>> = None;
        let mut peer_salt: Option<[u8; 16]> = None;
        let mut peer_stream_id = String::new();
        let mut is_encrypted = false;
        if !conclusion_ext_bytes.is_empty() {
            let extensions = HandshakeExtension::parse_extensions(&conclusion_ext_bytes);
            for ext in &extensions {
                match ext.ext_type {
                    3 if config.encryption_enabled() => {
                        // KmReq — convert u32 data to bytes
                        let km_bytes: Vec<u8> = ext.data.iter().flat_map(|w| w.to_be_bytes()).collect();
                        if let Some(km_msg) = KeyMaterialMessage::deserialize(&km_bytes) {
                            // Derive KEK from our passphrase + caller's salt
                            let kek = key_material::derive_kek(
                                &config.passphrase, &km_msg.salt, km_msg.key_size
                            );
                            // Unwrap the SEK
                            if let Ok(sek) = key_material::unwrap_key(&kek, &km_msg.wrapped_keys) {
                                log::debug!("Listener: KMREQ received, SEK unwrapped successfully");
                                let cipher = match km_msg.cipher {
                                    CipherType::AesGcm => CipherType::AesGcm,
                                    _ => CipherType::AesCtr,
                                };
                                if let Ok(wrapped) = key_material::wrap_key(&kek, &sek) {
                                    km_response = Some(KeyMaterialMessage::new_single(
                                        KeyIndex::Even, km_msg.key_size, cipher,
                                        km_msg.salt, wrapped,
                                    ));
                                }
                                peer_sek = Some(sek);
                                peer_salt = Some(km_msg.salt);
                                is_encrypted = true;
                            } else {
                                log::warn!("Listener: KMREQ key unwrap failed (wrong passphrase?)");
                            }
                        }
                    }
                    SRT_CMD_SID => {
                        // Stream ID extension
                        peer_stream_id = parse_stream_id(&ext.data);
                        log::debug!("Listener: received Stream ID: {:?}", peer_stream_id);
                    }
                    _ => {}
                }
            }
        }

        // Access control check — let the callback decide whether to accept
        let hs_info = HandshakeInfo {
            peer_addr: conclusion_addr,
            stream_id: peer_stream_id.clone(),
            is_encrypted,
            peer_socket_id: conclusion_hs.socket_id as u32,
            peer_version: conclusion_hs.version,
        };
        if let Err(reason) = access_control.on_accept(&hs_info) {
            log::info!(
                "Listener: rejected connection from {} (stream_id={:?}, reason={:?})",
                conclusion_addr, peer_stream_id, reason
            );
            // Send rejection handshake
            let rejection = Handshake {
                version: HS_VERSION_SRT1,
                ext_flags: 0,
                isn: 0,
                mss: config.mss as i32,
                flight_flag_size: config.flight_flag_size as i32,
                req_type: HandshakeType::Failure(reason),
                socket_id: listener_socket_id as i32,
                cookie: cookie as i32,
                peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            };
            let pkt = build_handshake_packet(&rejection, conclusion_hs.socket_id as u32);
            let _ = mux.send_to(&pkt, conclusion_addr).await;
            mux.remove_connection(listener_socket_id).await;
            continue;
        }

        // Create a new connection for the accepted peer, storing the caller's Stream ID
        let mut conn_config = config.clone();
        conn_config.stream_id = peer_stream_id;
        let new_conn = Arc::new(SrtConnection::new(
            conn_config,
            mux.local_addr(),
            listener_socket_id,
        ));
        *new_conn.peer_addr.lock().await = Some(conclusion_addr);
        *new_conn.peer_socket_id.lock().await = conclusion_hs.socket_id as u32;
        // Initialize receive buffer with the peer's ISN so ACKs use the correct sequence range.
        new_conn.set_peer_isn(srt_protocol::packet::seq::SeqNo::new(conclusion_hs.isn)).await;
        // Our send buffer starts at SeqNo(0) (set in SrtConnection::new).
        // Advertise ISN=0 in CONCLUSION so the peer's receive buffer is aligned.
        let listener_isn: i32 = 0;

        // If caller sent KMREQ, set the shared SEK on this connection's crypto
        if let (Some(sek), Some(salt)) = (&peer_sek, &peer_salt) {
            let mut crypto_guard = new_conn.crypto.lock().await;
            if let Some(crypto) = crypto_guard.as_mut() {
                crypto.keys.set_key(KeyIndex::Even, sek.clone());
                crypto.salt = *salt;
                crypto.km_exchanged = true;
                log::debug!("Listener: set shared SEK on new connection");
            }
        }

        new_conn.set_state(ConnectionState::Connected).await;

        // Register the new connection in the multiplexer for data routing
        mux.add_connection(listener_socket_id, new_conn.clone()).await;

        // Start send loop for the new connection
        let mux_send = mux.clone();
        let conn_send = new_conn.clone();
        tokio::spawn(async move {
            send_loop::run(mux_send, conn_send).await;
        });

        // Build CONCLUSION response with HSRSP extension
        let mut srt_ext = SrtHsExtension::new();
        srt_ext.srt_version = SRT_VERSION;
        srt_ext.srt_flags = SrtFlags::TSBPD_SND
            | SrtFlags::TSBPD_RCV
            | SrtFlags::TLPKT_DROP
            | SrtFlags::NAK_REPORT
            | SrtFlags::REXMIT_FLG;
        srt_ext.set_recv_tsbpd_delay(config.recv_latency as u16);
        srt_ext.set_send_tsbpd_delay(config.peer_latency as u16);

        // Serialize HSRSP extension block (type=2=HsRsp, size=4 words)
        let mut ext_buf = BytesMut::new();
        ext_buf.extend_from_slice(&((2u32 << 16) | 4u32).to_be_bytes());
        srt_ext.serialize(&mut ext_buf);

        // Add KMRSP extension if we processed a KMREQ
        let mut resp_ext_flags = HS_EXT_HSREQ;
        if let Some(km_msg) = &km_response {
            let mut km_buf = BytesMut::new();
            km_msg.serialize(&mut km_buf);
            let size_words = (km_buf.len() + 3) / 4;
            ext_buf.put_u32((4u32 << 16) | size_words as u32); // type=KmRsp(4)
            ext_buf.extend_from_slice(&km_buf);
            while ext_buf.len() % 4 != 0 {
                ext_buf.put_u8(0);
            }
            resp_ext_flags |= HS_EXT_KMREQ;
        }

        let conclusion_response = Handshake {
            version: HS_VERSION_SRT1,
            ext_flags: resp_ext_flags,
            isn: listener_isn,
            mss: config.mss as i32,
            flight_flag_size: config.flight_flag_size as i32,
            req_type: HandshakeType::Conclusion,
            socket_id: listener_socket_id as i32,
            cookie: cookie as i32,
            peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };

        let pkt = build_handshake_packet_with_extensions(
            &conclusion_response,
            conclusion_hs.socket_id as u32,
            &ext_buf,
        );
        if let Err(e) = mux.send_to(&pkt, conclusion_addr).await {
            log::error!("Listener: failed to send CONCLUSION response: {}", e);
            continue;
        }

        log::info!(
            "Listener: accepted connection from {} (socket_id={})",
            conclusion_addr,
            listener_socket_id
        );

        // Create the SrtSocket handle and deliver via accept channel
        let state_rx = new_conn.state_watch.subscribe();
        let socket = SrtSocket::new(new_conn, mux.clone(), state_rx);

        if accept_tx.send(socket).await.is_err() {
            log::debug!("Listener: accept channel closed");
            break;
        }
    }
}

/// Generate a cookie from the caller's address for handshake validation.
fn generate_cookie(addr: &SocketAddr) -> u32 {
    // Simple hash of IP + port — not cryptographically secure, but sufficient
    // for connection validation in the SRT handshake context.
    let ip_bytes = match addr.ip() {
        IpAddr::V4(v4) => u32::from(v4),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]])
        }
    };
    let port = addr.port() as u32;
    ip_bytes.wrapping_mul(2654435761) ^ port.wrapping_mul(40503)
}

/// Build a serialized handshake control packet (base handshake only, no extensions).
fn build_handshake_packet(hs: &Handshake, dest_socket_id: u32) -> Vec<u8> {
    use srt_protocol::packet::SrtPacket;
    use srt_protocol::packet::control::ControlType;
    use srt_protocol::packet::header::HEADER_SIZE;

    let mut hs_payload = BytesMut::with_capacity(64);
    hs.serialize(&mut hs_payload);

    let pkt = SrtPacket::new_control(
        ControlType::Handshake,
        0,
        0,
        0,
        dest_socket_id,
        hs_payload.freeze(),
    );

    let mut buf = BytesMut::with_capacity(HEADER_SIZE + pkt.payload_len());
    pkt.serialize(&mut buf);
    buf.to_vec()
}
