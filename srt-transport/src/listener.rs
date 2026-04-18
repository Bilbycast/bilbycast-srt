// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT listener for accepting incoming connections.
//!
//! Binds to a UDP port and accepts incoming SRT connections via the
//! HSv5 handshake process. Each accepted connection spawns a
//! [`ConnTask`](crate::conn_task::ConnTask) that owns all protocol state.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{BufMut, BytesMut};
use tokio::sync::{mpsc, watch, Notify};

use srt_protocol::access_control::{
    AccessControl, AccessControlFn, AcceptAll, HandshakeInfo, SRT_CMD_SID, parse_stream_id,
};
use srt_protocol::fec::{self, ArqMode};
use srt_protocol::fec::decoder::FecDecoder;
use srt_protocol::fec::encoder::FecEncoder;
use srt_protocol::config::{CryptoModeConfig, KeySize, SrtConfig, SocketStatus, SRT_VERSION};
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
use srt_protocol::stats::SrtStats;

use crate::channel::UdpChannel;
use crate::conn_task::ConnTask;
use crate::connection::SrtConnection;
use crate::connector::build_handshake_packet_with_extensions;
use crate::multiplexer::Multiplexer;
use crate::recv_loop;
use crate::socket::SrtSocket;

/// Bounded capacity for the app → ConnTask send channel.
const APP_SEND_CAPACITY: usize = 64;
/// Bounded capacity for the ConnTask → app receive channel.
const APP_RECV_CAPACITY: usize = 256;

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

    pub fn latency(mut self, latency: Duration) -> Self {
        let ms = latency.as_millis() as u32;
        self.config.recv_latency = ms;
        self.config.peer_latency = ms;
        self
    }

    pub fn sender_latency(mut self, latency: Duration) -> Self {
        self.config.peer_latency = latency.as_millis() as u32;
        self
    }

    pub fn receiver_latency(mut self, latency: Duration) -> Self {
        self.config.recv_latency = latency.as_millis() as u32;
        self
    }

    pub fn encryption(mut self, passphrase: &str, key_size: KeySize) -> Self {
        self.config.passphrase = passphrase.to_string();
        self.config.key_size = key_size;
        self
    }

    pub fn crypto_mode(mut self, mode: CryptoModeConfig) -> Self {
        self.config.crypto_mode = mode;
        self
    }

    pub fn backlog(mut self, backlog: usize) -> Self {
        self.backlog = backlog;
        self
    }

    pub fn live_mode(mut self) -> Self {
        self.config.live_defaults();
        self
    }

    pub fn file_mode(mut self) -> Self {
        self.config.file_defaults();
        self
    }

    pub fn mss(mut self, mss: u32) -> Self {
        self.config.mss = mss;
        self
    }

    pub fn peer_idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.peer_idle_timeout = timeout;
        self
    }

    pub fn payload_size(mut self, size: u32) -> Self {
        self.config.payload_size = size;
        self
    }

    pub fn max_rexmit_bw(mut self, bw: i64) -> Self {
        self.config.max_rexmit_bw = bw;
        self
    }

    pub fn packet_filter(mut self, filter: String) -> Self {
        self.config.packet_filter = filter;
        self
    }

    pub fn max_bw(mut self, bw: i64) -> Self {
        self.config.max_bw = bw;
        self
    }

    pub fn input_bw(mut self, bw: i64) -> Self {
        self.config.input_bw = bw;
        self
    }

    pub fn overhead_bw(mut self, pct: i32) -> Self {
        self.config.overhead_bw = pct;
        self
    }

    pub fn enforced_encryption(mut self, enforce: bool) -> Self {
        self.config.enforced_encryption = enforce;
        self
    }

    pub fn flight_flag_size(mut self, size: u32) -> Self {
        self.config.flight_flag_size = size;
        self
    }

    pub fn send_buffer_size(mut self, size: u32) -> Self {
        self.config.send_buffer_size = size;
        self
    }

    pub fn recv_buffer_size(mut self, size: u32) -> Self {
        self.config.recv_buffer_size = size;
        self
    }

    pub fn ip_tos(mut self, tos: i32) -> Self {
        self.config.ip_tos = tos;
        self
    }

    pub fn retransmit_algo(mut self, algo: srt_protocol::config::RetransmitAlgo) -> Self {
        self.config.retransmit_algo = algo;
        self
    }

    pub fn send_drop_delay(mut self, delay: i32) -> Self {
        self.config.send_drop_delay = delay;
        self
    }

    pub fn loss_max_ttl(mut self, ttl: i32) -> Self {
        self.config.loss_max_ttl = ttl;
        self
    }

    pub fn km_refresh_rate(mut self, rate: u32) -> Self {
        self.config.km_refresh_rate = rate;
        self
    }

    pub fn km_pre_announce(mut self, count: u32) -> Self {
        self.config.km_pre_announce = count;
        self
    }

    pub fn tlpkt_drop(mut self, enabled: bool) -> Self {
        self.config.tlpkt_drop = enabled;
        self
    }

    pub fn ip_ttl(mut self, ttl: i32) -> Self {
        self.config.ip_ttl = ttl;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    pub fn access_control(mut self, ac: impl AccessControl) -> Self {
        self.access_control = Arc::new(ac);
        self
    }

    /// Set an access control callback using a closure.
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

        // Create the listener routing handle (dest_id=0)
        let (listener_conn, _listener_net_rx) = SrtConnection::new(
            self.config.clone(), local_addr, 0u32,
        );
        let listener_conn = Arc::new(listener_conn);
        listener_conn.set_state(ConnectionState::Listening);
        mux.set_listener(listener_conn.clone()).await;

        // Channel for accepted connections
        let (accept_tx, accept_rx) = mpsc::channel(self.backlog);

        // Start recv_loop
        let mux_recv = mux.clone();
        tokio::spawn(async move { recv_loop::run(mux_recv).await; });

        // Spawn accept loop
        let mux_accept = mux.clone();
        let config_accept = self.config.clone();
        let listener_conn_accept = listener_conn.clone();
        let ac = self.access_control.clone();
        tokio::spawn(async move {
            accept_loop(mux_accept, config_accept, listener_conn_accept, accept_tx, ac).await;
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
    #[allow(dead_code)]
    config: SrtConfig,
    multiplexer: Arc<Multiplexer>,
    listener_conn: Arc<SrtConnection>,
    local_addr: SocketAddr,
    accept_rx: mpsc::Receiver<SrtSocket>,
}

impl SrtListener {
    /// Create a listener builder.
    pub fn builder() -> SrtListenerBuilder {
        SrtListenerBuilder::new()
    }

    /// Accept an incoming SRT connection.
    pub async fn accept(&mut self) -> Result<SrtSocket, SrtError> {
        self.accept_rx.recv().await
            .ok_or(SrtError::SocketClosed)
    }

    /// Get the local address this listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Close the listener and release the UDP port.
    pub async fn close(&self) -> Result<(), SrtError> {
        self.listener_conn.set_state(ConnectionState::Closed);
        self.multiplexer.clear_listener().await;
        self.multiplexer.clear_all_routes().await;
        self.multiplexer.shutdown();
        Ok(())
    }
}

/// Background task that processes incoming handshakes and creates connections.
async fn accept_loop(
    mux: Arc<Multiplexer>,
    config: SrtConfig,
    listener_conn: Arc<SrtConnection>,
    accept_tx: mpsc::Sender<SrtSocket>,
    access_control: Arc<dyn AccessControl>,
) {
    loop {
        if listener_conn.status() == SocketStatus::Closed {
            log::debug!("Listener accept loop stopping (listener closed)");
            break;
        }

        // Wait for INDUCTION handshake
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
            log::debug!("Listener: expected INDUCTION, got {:?} from {}", induction_hs.req_type, caller_addr);
            continue;
        }

        log::debug!("Listener: received INDUCTION from {} (socket_id={})", caller_addr, induction_hs.socket_id);

        let cookie = generate_cookie(&caller_addr);
        let listener_socket_id = rand::random::<u32>() & 0x3FFF_FFFF;

        // Send INDUCTION response
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
        let pkt = build_handshake_packet(&induction_response, induction_hs.socket_id as u32);
        if let Err(e) = mux.send_to(&pkt, caller_addr).await {
            log::error!("Listener: failed to send INDUCTION response: {}", e);
            continue;
        }

        // Temporarily register listener_socket_id for CONCLUSION routing
        mux.add_connection(listener_socket_id, listener_conn.clone()).await;

        // Wait for CONCLUSION
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
            log::debug!("Listener: expected CONCLUSION, got {:?} from {}", conclusion_hs.req_type, conclusion_addr);
            mux.remove_connection(listener_socket_id).await;
            continue;
        }

        if conclusion_hs.cookie as u32 != cookie {
            log::warn!("Listener: invalid cookie from {}", conclusion_addr);
            mux.remove_connection(listener_socket_id).await;
            continue;
        }

        // Parse extensions
        let mut km_response: Option<KeyMaterialMessage> = None;
        let mut peer_sek: Option<Vec<u8>> = None;
        let mut peer_salt: Option<[u8; 16]> = None;
        let mut peer_stream_id = String::new();
        let mut peer_filter_config = String::new();
        let mut is_encrypted = false;
        if !conclusion_ext_bytes.is_empty() {
            let extensions = HandshakeExtension::parse_extensions(&conclusion_ext_bytes);
            for ext in &extensions {
                match ext.ext_type {
                    7 => {
                        peer_filter_config = fec::parse_filter_extension(&ext.data);
                    }
                    3 if config.encryption_enabled() => {
                        let km_bytes: Vec<u8> = ext.data.iter().flat_map(|w| w.to_be_bytes()).collect();
                        if let Some(km_msg) = KeyMaterialMessage::deserialize(&km_bytes) {
                            let kek = key_material::derive_kek(&config.passphrase, &km_msg.salt, km_msg.key_size);
                            if let Ok(sek) = key_material::unwrap_key(&kek, &km_msg.wrapped_keys) {
                                let cipher = match km_msg.cipher {
                                    CipherType::AesGcm => CipherType::AesGcm,
                                    _ => CipherType::AesCtr,
                                };
                                if let Ok(wrapped) = key_material::wrap_key(&kek, &sek) {
                                    km_response = Some(KeyMaterialMessage::new_single(
                                        KeyIndex::Even, km_msg.key_size, cipher, km_msg.salt, wrapped,
                                    ));
                                }
                                peer_sek = Some(sek);
                                peer_salt = Some(km_msg.salt);
                                is_encrypted = true;
                            }
                        }
                    }
                    SRT_CMD_SID => {
                        peer_stream_id = parse_stream_id(&ext.data);
                    }
                    _ => {}
                }
            }
        }

        // Access control
        let hs_info = HandshakeInfo {
            peer_addr: conclusion_addr,
            stream_id: peer_stream_id.clone(),
            is_encrypted,
            peer_socket_id: conclusion_hs.socket_id as u32,
            peer_version: conclusion_hs.version,
        };
        if let Err(reason) = access_control.on_accept(&hs_info) {
            log::info!("Listener: rejected connection from {} (reason={:?})", conclusion_addr, reason);
            let rejection = Handshake {
                version: HS_VERSION_SRT1, ext_flags: 0, isn: 0,
                mss: config.mss as i32, flight_flag_size: config.flight_flag_size as i32,
                req_type: HandshakeType::Failure(reason),
                socket_id: listener_socket_id as i32, cookie: cookie as i32,
                peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            };
            let pkt = build_handshake_packet(&rejection, conclusion_hs.socket_id as u32);
            let _ = mux.send_to(&pkt, conclusion_addr).await;
            mux.remove_connection(listener_socket_id).await;
            continue;
        }

        // Negotiate FEC
        let negotiated_filter = match fec::negotiate_filter(&config.packet_filter, &peer_filter_config) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("Listener: FEC negotiation failed: {}", e);
                let rejection = Handshake {
                    version: HS_VERSION_SRT1, ext_flags: 0, isn: 0,
                    mss: config.mss as i32, flight_flag_size: config.flight_flag_size as i32,
                    req_type: HandshakeType::Failure(RejectReason::Filter),
                    socket_id: listener_socket_id as i32, cookie: cookie as i32,
                    peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                };
                let pkt = build_handshake_packet(&rejection, conclusion_hs.socket_id as u32);
                let _ = mux.send_to(&pkt, conclusion_addr).await;
                mux.remove_connection(listener_socket_id).await;
                continue;
            }
        };

        // Build crypto for the new connection
        let conn_crypto = if config.encryption_enabled() {
            let mut cc = srt_protocol::crypto::CryptoControl::new(
                config.key_size, config.crypto_mode.into(),
            );
            if let (Some(sek), Some(salt)) = (&peer_sek, &peer_salt) {
                cc.keys.set_key(KeyIndex::Even, sek.clone());
                cc.salt = *salt;
                cc.km_exchanged = true;
            }
            Some(cc)
        } else {
            None
        };

        let peer_isn = srt_protocol::packet::seq::SeqNo::new(conclusion_hs.isn);
        let own_isn = srt_protocol::packet::seq::SeqNo::new(0);
        let tsbpd_base_time = Instant::now();

        // Build FEC
        let mut conn_config = config.clone();
        conn_config.stream_id = peer_stream_id;
        conn_config.packet_filter = negotiated_filter.clone();

        let fec_config = if !negotiated_filter.is_empty() {
            fec::FecConfig::parse(&negotiated_filter).ok()
        } else {
            None
        };

        let (fec_encoder, fec_decoder, fec_arq_mode) = if let Some(ref fc) = fec_config {
            (Some(FecEncoder::new(fc.clone())), Some(FecDecoder::new(fc.clone(), peer_isn)), fc.arq)
        } else {
            (None, None, ArqMode::Always)
        };

        if fec_config.is_some() {
            log::info!("Listener: FEC initialized with config: {}", negotiated_filter);
        }

        // Create routing handle for the new connection
        let (new_conn, net_rx) = SrtConnection::new(conn_config.clone(), mux.local_addr(), listener_socket_id);
        let new_conn = Arc::new(new_conn);
        new_conn.set_state(ConnectionState::Connected);

        // Register in multiplexer (replaces the temp listener route)
        mux.add_connection(listener_socket_id, new_conn.clone()).await;

        // Create app channels and ConnTask
        let (app_send_tx, app_data_rx) = mpsc::channel(APP_SEND_CAPACITY);
        let (app_recv_tx, app_recv_rx) = mpsc::channel(APP_RECV_CAPACITY);
        let (state_tx, state_rx) = watch::channel(SocketStatus::Connected);
        let (stats_tx, stats_rx) = watch::channel(SrtStats::default());
        let close_signal = Arc::new(Notify::new());

        let conn_task = ConnTask::new(
            conn_config.clone(),
            new_conn.start_time,
            listener_socket_id,
            conclusion_addr,
            conclusion_hs.socket_id as u32,
            peer_isn,
            own_isn,
            conn_crypto,
            fec_encoder,
            fec_decoder,
            fec_arq_mode,
            tsbpd_base_time,
            mux.clone(),
            net_rx,
            app_data_rx,
            app_recv_tx,
            state_tx.clone(),
            stats_tx,
            close_signal.clone(),
        );
        tokio::spawn(conn_task.run());

        // Build CONCLUSION response
        let mut srt_ext = SrtHsExtension::new();
        srt_ext.srt_version = SRT_VERSION;
        srt_ext.srt_flags = SrtFlags::TSBPD_SND
            | SrtFlags::TSBPD_RCV
            | SrtFlags::TLPKT_DROP
            | SrtFlags::NAK_REPORT
            | SrtFlags::REXMIT_FLG;
        srt_ext.set_recv_tsbpd_delay(config.recv_latency as u16);
        srt_ext.set_send_tsbpd_delay(config.peer_latency as u16);

        let mut ext_buf = BytesMut::new();
        ext_buf.extend_from_slice(&((2u32 << 16) | 4u32).to_be_bytes());
        srt_ext.serialize(&mut ext_buf);

        let mut resp_ext_flags = HS_EXT_HSREQ;
        if let Some(km_msg) = &km_response {
            let mut km_buf = BytesMut::new();
            km_msg.serialize(&mut km_buf);
            let size_words = (km_buf.len() + 3) / 4;
            ext_buf.put_u32((4u32 << 16) | size_words as u32);
            ext_buf.extend_from_slice(&km_buf);
            while ext_buf.len() % 4 != 0 { ext_buf.put_u8(0); }
            resp_ext_flags |= HS_EXT_KMREQ;
        }

        if !negotiated_filter.is_empty() {
            let filter_words = fec::serialize_filter_extension(&negotiated_filter);
            for word in &filter_words { ext_buf.put_u32(*word); }
        }

        let conclusion_response = Handshake {
            version: HS_VERSION_SRT1,
            ext_flags: resp_ext_flags,
            isn: 0, // listener ISN = 0
            mss: config.mss as i32,
            flight_flag_size: config.flight_flag_size as i32,
            req_type: HandshakeType::Conclusion,
            socket_id: listener_socket_id as i32,
            cookie: cookie as i32,
            peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };

        let pkt = build_handshake_packet_with_extensions(
            &conclusion_response, conclusion_hs.socket_id as u32, &ext_buf,
        );
        if let Err(e) = mux.send_to(&pkt, conclusion_addr).await {
            log::error!("Listener: failed to send CONCLUSION response: {}", e);
            continue;
        }

        log::info!("Listener: accepted connection from {} (socket_id={})", conclusion_addr, listener_socket_id);

        let socket = SrtSocket::new(
            Arc::new(conn_config),
            mux.local_addr(),
            Some(conclusion_addr),
            listener_socket_id,
            mux.clone(),
            app_send_tx,
            app_recv_rx,
            state_rx,
            stats_rx,
            close_signal,
        );

        if accept_tx.send(socket).await.is_err() {
            log::debug!("Listener: accept channel closed");
            break;
        }
    }
}

fn generate_cookie(addr: &SocketAddr) -> u32 {
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

fn build_handshake_packet(hs: &Handshake, dest_socket_id: u32) -> Vec<u8> {
    use srt_protocol::packet::SrtPacket;
    use srt_protocol::packet::control::ControlType;
    use srt_protocol::packet::header::HEADER_SIZE;

    let mut hs_payload = BytesMut::with_capacity(64);
    hs.serialize(&mut hs_payload);

    let pkt = SrtPacket::new_control(
        ControlType::Handshake, 0, 0, 0,
        dest_socket_id, hs_payload.freeze(),
    );

    let mut buf = BytesMut::with_capacity(HEADER_SIZE + pkt.payload_len());
    pkt.serialize(&mut buf);
    buf.to_vec()
}
