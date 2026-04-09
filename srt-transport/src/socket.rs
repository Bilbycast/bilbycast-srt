// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT socket handle with builder pattern.
//!
//! Provides the main user-facing interface for SRT connections.
//! Communicates with the [`ConnTask`](crate::conn_task::ConnTask)
//! via channels — zero mutex acquisitions on send/recv hot paths.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::{mpsc, watch, Notify};

use srt_protocol::config::{CryptoModeConfig, KeySize, SrtConfig, SocketStatus};
use srt_protocol::crypto::CryptoControl;
use srt_protocol::error::SrtError;
use srt_protocol::fec::ArqMode;
use srt_protocol::fec::decoder::FecDecoder;
use srt_protocol::fec::encoder::FecEncoder;
use srt_protocol::stats::SrtStats;

use crate::channel::UdpChannel;
use crate::conn_task::ConnTask;
use crate::connection::SrtConnection;
use crate::connector;
use crate::connector_rendezvous;
use crate::multiplexer::Multiplexer;
use crate::recv_loop;

/// Bounded capacity for the app → ConnTask send channel.
const APP_SEND_CAPACITY: usize = 64;
/// Bounded capacity for the ConnTask → app receive channel.
const APP_RECV_CAPACITY: usize = 256;

/// Builder for configuring and creating SRT sockets.
pub struct SrtSocketBuilder {
    config: SrtConfig,
    bind_addr: Option<SocketAddr>,
}

impl SrtSocketBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: SrtConfig::default(),
            bind_addr: None,
        }
    }

    /// Set the receiver-side latency in milliseconds.
    pub fn latency(mut self, latency: Duration) -> Self {
        let ms = latency.as_millis() as u32;
        self.config.recv_latency = ms;
        self.config.peer_latency = ms;
        self
    }

    /// Set the sender-side latency in milliseconds.
    pub fn sender_latency(mut self, latency: Duration) -> Self {
        self.config.peer_latency = latency.as_millis() as u32;
        self
    }

    /// Set the receiver-side latency in milliseconds.
    pub fn receiver_latency(mut self, latency: Duration) -> Self {
        self.config.recv_latency = latency.as_millis() as u32;
        self
    }

    /// Enable encryption with the given passphrase and key size.
    pub fn encryption(mut self, passphrase: &str, key_size: KeySize) -> Self {
        self.config.passphrase = passphrase.to_string();
        self.config.key_size = key_size;
        self
    }

    /// Set the encryption cipher mode (AES-CTR or AES-GCM).
    pub fn crypto_mode(mut self, mode: CryptoModeConfig) -> Self {
        self.config.crypto_mode = mode;
        self
    }

    /// Set the maximum segment size (MSS).
    pub fn mss(mut self, mss: u32) -> Self {
        self.config.mss = mss;
        self
    }

    /// Set the flight flag size (flow control window).
    pub fn flight_flag_size(mut self, size: u32) -> Self {
        self.config.flight_flag_size = size;
        self
    }

    /// Set the send buffer size in bytes.
    pub fn send_buffer_size(mut self, size: u32) -> Self {
        self.config.send_buffer_size = size;
        self
    }

    /// Set the receive buffer size in bytes.
    pub fn recv_buffer_size(mut self, size: u32) -> Self {
        self.config.recv_buffer_size = size;
        self
    }

    /// Set the transport type to LIVE mode (default).
    pub fn live_mode(mut self) -> Self {
        self.config.live_defaults();
        self
    }

    /// Set the transport type to FILE mode.
    pub fn file_mode(mut self) -> Self {
        self.config.file_defaults();
        self
    }

    /// Set the local bind address.
    pub fn bind(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = Some(addr);
        self
    }

    /// Set the peer idle timeout.
    pub fn peer_idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.peer_idle_timeout = timeout;
        self
    }

    /// Set the stream ID (for access control).
    pub fn stream_id(mut self, id: String) -> Self {
        self.config.stream_id = id;
        self
    }

    /// Set the connection timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Set the maximum payload size per packet.
    pub fn payload_size(mut self, size: u32) -> Self {
        self.config.payload_size = size;
        self
    }

    /// Set the maximum retransmission bandwidth in bytes per second.
    pub fn max_rexmit_bw(mut self, bw: i64) -> Self {
        self.config.max_rexmit_bw = bw;
        self
    }

    /// Set the SRT packet filter configuration string.
    pub fn packet_filter(mut self, filter: String) -> Self {
        self.config.packet_filter = filter;
        self
    }

    /// Set the maximum bandwidth in bytes per second.
    pub fn max_bw(mut self, bw: i64) -> Self {
        self.config.max_bw = bw;
        self
    }

    /// Set the estimated input bandwidth in bytes per second.
    pub fn input_bw(mut self, bw: i64) -> Self {
        self.config.input_bw = bw;
        self
    }

    /// Set the overhead bandwidth as a percentage over the input rate (5-100).
    pub fn overhead_bw(mut self, pct: i32) -> Self {
        self.config.overhead_bw = pct;
        self
    }

    /// Set whether to enforce encryption (reject unencrypted peers).
    pub fn enforced_encryption(mut self, enforce: bool) -> Self {
        self.config.enforced_encryption = enforce;
        self
    }

    /// Set the IP Type of Service / DSCP value.
    pub fn ip_tos(mut self, tos: i32) -> Self {
        self.config.ip_tos = tos;
        self
    }

    /// Set the retransmission algorithm.
    pub fn retransmit_algo(mut self, algo: srt_protocol::config::RetransmitAlgo) -> Self {
        self.config.retransmit_algo = algo;
        self
    }

    /// Set the extra delay in ms before the sender drops a packet (-1 = off).
    pub fn send_drop_delay(mut self, delay: i32) -> Self {
        self.config.send_drop_delay = delay;
        self
    }

    /// Set the maximum packet reorder tolerance (0 = adaptive).
    pub fn loss_max_ttl(mut self, ttl: i32) -> Self {
        self.config.loss_max_ttl = ttl;
        self
    }

    /// Set the key material refresh rate in packets.
    pub fn km_refresh_rate(mut self, rate: u32) -> Self {
        self.config.km_refresh_rate = rate;
        self
    }

    /// Set the key material pre-announce count (packets before refresh).
    pub fn km_pre_announce(mut self, count: u32) -> Self {
        self.config.km_pre_announce = count;
        self
    }

    /// Enable or disable too-late packet drop in live mode.
    pub fn tlpkt_drop(mut self, enabled: bool) -> Self {
        self.config.tlpkt_drop = enabled;
        self
    }

    /// Set the IP Time To Live (1-255, default: 64).
    pub fn ip_ttl(mut self, ttl: i32) -> Self {
        self.config.ip_ttl = ttl;
        self
    }

    /// Enable or disable rendezvous mode.
    pub fn rendezvous(mut self, enabled: bool) -> Self {
        self.config.rendezvous = enabled;
        self
    }

    /// Connect to a remote SRT peer.
    pub async fn connect(self, addr: SocketAddr) -> Result<SrtSocket, SrtError> {
        let bind_addr = self.bind_addr
            .unwrap_or_else(|| {
                if addr.is_ipv6() {
                    "[::]:0".parse().unwrap()
                } else {
                    "0.0.0.0:0".parse().unwrap()
                }
            });

        let channel = UdpChannel::bind(bind_addr).await
            .map_err(|_| SrtError::ConnectionSetup)?;
        let local_addr = channel.local_addr();

        let mux = Arc::new(Multiplexer::new(channel));
        let socket_id = rand::random::<u32>() & 0x3FFF_FFFF;

        // Initialize crypto from config
        let initial_crypto = init_crypto(&self.config);

        // Create thin connection handle for routing
        let (conn, net_rx) = SrtConnection::new(self.config.clone(), local_addr, socket_id);
        let conn = Arc::new(conn);
        mux.add_connection(socket_id, conn.clone()).await;

        // Spawn recv_loop
        let mux_recv = mux.clone();
        tokio::spawn(async move { recv_loop::run(mux_recv).await; });

        // Perform handshake
        let hs_result = {
            let mut hs_rx = conn.handshake_rx.lock().await;
            connector::connect(
                &mux, &self.config, socket_id,
                &conn.state_watch, initial_crypto,
                &mut hs_rx, addr,
            ).await?
        };

        // Build and spawn ConnTask
        let (app_send_tx, app_data_rx) = mpsc::channel(APP_SEND_CAPACITY);
        let (app_recv_tx, app_recv_rx) = mpsc::channel(APP_RECV_CAPACITY);
        let (state_tx, state_rx) = watch::channel(SocketStatus::Connected);
        let (stats_tx, stats_rx) = watch::channel(SrtStats::default());
        let close_signal = Arc::new(Notify::new());

        // Build FEC encoder/decoder
        let (fec_encoder, fec_decoder, fec_arq_mode) = if let Some(ref fc) = hs_result.fec_config {
            (
                Some(FecEncoder::new(fc.clone())),
                Some(FecDecoder::new(fc.clone(), hs_result.peer_isn)),
                fc.arq,
            )
        } else {
            (None, None, ArqMode::Always)
        };

        let conn_task = ConnTask::new(
            self.config.clone(),
            conn.start_time,
            socket_id,
            hs_result.peer_addr,
            hs_result.peer_socket_id,
            hs_result.peer_isn,
            srt_protocol::packet::seq::SeqNo::new(0), // own ISN
            hs_result.crypto,
            fec_encoder,
            fec_decoder,
            fec_arq_mode,
            hs_result.tsbpd_base_time,
            mux.clone(),
            net_rx,
            app_data_rx,
            app_recv_tx,
            state_tx.clone(),
            stats_tx,
            close_signal.clone(),
        );
        tokio::spawn(conn_task.run());

        Ok(SrtSocket {
            config: Arc::new(self.config),
            local_addr,
            peer_addr: Some(hs_result.peer_addr),
            socket_id,
            multiplexer: mux,
            app_send_tx,
            app_recv_rx: tokio::sync::Mutex::new(app_recv_rx),
            state_rx,
            stats_rx,
            close_signal,
        })
    }

    /// Connect in rendezvous mode (peer-to-peer, no caller/listener).
    pub async fn connect_rendezvous(
        self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<SrtSocket, SrtError> {
        if local_addr.port() == 0 {
            return Err(SrtError::ConnectionSetup);
        }

        let channel = UdpChannel::bind(local_addr).await
            .map_err(|_| SrtError::ConnectionSetup)?;
        let actual_local = channel.local_addr();

        let mux = Arc::new(Multiplexer::new(channel));
        let socket_id = rand::random::<u32>() & 0x3FFF_FFFF;

        let initial_crypto = init_crypto(&self.config);

        let (conn, net_rx) = SrtConnection::new(self.config.clone(), actual_local, socket_id);
        let conn = Arc::new(conn);
        mux.add_connection(socket_id, conn.clone()).await;
        mux.set_rendezvous(conn.clone()).await;

        // Spawn recv_loop
        let mux_recv = mux.clone();
        tokio::spawn(async move { recv_loop::run(mux_recv).await; });

        // Perform rendezvous handshake
        let hs_result = {
            let mut hs_rx = conn.handshake_rx.lock().await;
            connector_rendezvous::connect_rendezvous(
                &mux, &self.config, socket_id,
                &conn.state_watch, initial_crypto,
                &mut hs_rx, remote_addr,
            ).await?
        };

        mux.clear_rendezvous().await;

        // Build and spawn ConnTask
        let (app_send_tx, app_data_rx) = mpsc::channel(APP_SEND_CAPACITY);
        let (app_recv_tx, app_recv_rx) = mpsc::channel(APP_RECV_CAPACITY);
        let (state_tx, state_rx) = watch::channel(SocketStatus::Connected);
        let (stats_tx, stats_rx) = watch::channel(SrtStats::default());
        let close_signal = Arc::new(Notify::new());

        let (fec_encoder, fec_decoder, fec_arq_mode) = if let Some(ref fc) = hs_result.fec_config {
            (
                Some(FecEncoder::new(fc.clone())),
                Some(FecDecoder::new(fc.clone(), hs_result.peer_isn)),
                fc.arq,
            )
        } else {
            (None, None, ArqMode::Always)
        };

        let conn_task = ConnTask::new(
            self.config.clone(),
            conn.start_time,
            socket_id,
            hs_result.peer_addr,
            hs_result.peer_socket_id,
            hs_result.peer_isn,
            srt_protocol::packet::seq::SeqNo::new(0),
            hs_result.crypto,
            fec_encoder,
            fec_decoder,
            fec_arq_mode,
            hs_result.tsbpd_base_time,
            mux.clone(),
            net_rx,
            app_data_rx,
            app_recv_tx,
            state_tx.clone(),
            stats_tx,
            close_signal.clone(),
        );
        tokio::spawn(conn_task.run());

        Ok(SrtSocket {
            config: Arc::new(self.config),
            local_addr: actual_local,
            peer_addr: Some(hs_result.peer_addr),
            socket_id,
            multiplexer: mux,
            app_send_tx,
            app_recv_rx: tokio::sync::Mutex::new(app_recv_rx),
            state_rx,
            stats_rx,
            close_signal,
        })
    }
}

impl Default for SrtSocketBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// An established SRT socket.
///
/// Communicates with the connection task via channels.
/// Implements RAII: dropping the socket closes the connection.
pub struct SrtSocket {
    /// Connection configuration (read-only).
    config: Arc<SrtConfig>,
    /// Local socket address.
    local_addr: SocketAddr,
    /// Peer address (set once after handshake).
    peer_addr: Option<SocketAddr>,
    /// Socket ID.
    #[allow(dead_code)]
    socket_id: u32,
    /// The multiplexer (kept alive for the recv_loop).
    #[allow(dead_code)]
    pub(crate) multiplexer: Arc<Multiplexer>,
    /// Channel to push data to the connection task.
    app_send_tx: mpsc::Sender<Bytes>,
    /// Channel to receive data from the connection task.
    app_recv_rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    /// Watch receiver for state changes.
    state_rx: watch::Receiver<SocketStatus>,
    /// Watch receiver for statistics.
    stats_rx: watch::Receiver<SrtStats>,
    /// Signal to initiate graceful close.
    close_signal: Arc<Notify>,
}

impl SrtSocket {
    /// Create a socket builder.
    pub fn builder() -> SrtSocketBuilder {
        SrtSocketBuilder::new()
    }

    /// Create a socket from pre-built channels (used by listener accept).
    pub(crate) fn new(
        config: Arc<SrtConfig>,
        local_addr: SocketAddr,
        peer_addr: Option<SocketAddr>,
        socket_id: u32,
        multiplexer: Arc<Multiplexer>,
        app_send_tx: mpsc::Sender<Bytes>,
        app_recv_rx: mpsc::Receiver<Bytes>,
        state_rx: watch::Receiver<SocketStatus>,
        stats_rx: watch::Receiver<SrtStats>,
        close_signal: Arc<Notify>,
    ) -> Self {
        Self {
            config,
            local_addr,
            peer_addr,
            socket_id,
            multiplexer,
            app_send_tx,
            app_recv_rx: tokio::sync::Mutex::new(app_recv_rx),
            state_rx,
            stats_rx,
            close_signal,
        }
    }

    /// Send data over the SRT connection.
    ///
    /// Blocks asynchronously when the send buffer is full, providing
    /// natural backpressure via the bounded channel to the connection task.
    pub async fn send(&self, data: &[u8]) -> Result<usize, SrtError> {
        if *self.state_rx.borrow() == SocketStatus::Broken
            || *self.state_rx.borrow() == SocketStatus::Closed
        {
            return Err(SrtError::NoConnection);
        }

        self.app_send_tx
            .send(Bytes::copy_from_slice(data))
            .await
            .map_err(|_| SrtError::NoConnection)?;

        Ok(data.len())
    }

    /// Receive data from the SRT connection.
    ///
    /// Blocks until data is available or the connection is closed.
    pub async fn recv(&self) -> Result<Bytes, SrtError> {
        let mut rx = self.app_recv_rx.lock().await;
        match rx.recv().await {
            Some(data) => Ok(data),
            None => Err(SrtError::NoConnection),
        }
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the peer address.
    pub async fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Get the Stream ID for this connection.
    pub fn stream_id(&self) -> &str {
        &self.config.stream_id
    }

    /// Get connection statistics.
    pub async fn stats(&self) -> SrtStats {
        self.stats_rx.borrow().clone()
    }

    /// Get the current socket status.
    pub fn status(&self) -> SocketStatus {
        *self.state_rx.borrow()
    }

    /// Wait for the socket to reach a specific state.
    pub async fn wait_for_state(&mut self, target: SocketStatus) {
        while *self.state_rx.borrow() != target {
            if self.state_rx.changed().await.is_err() {
                break;
            }
        }
    }

    /// Close the connection gracefully.
    pub async fn close(&self) -> Result<(), SrtError> {
        self.close_signal.notify_one();

        // Wait for the connection task to reach Closed state
        let mut state_rx = self.state_rx.clone();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let status = *state_rx.borrow();
            if status == SocketStatus::Closed || status == SocketStatus::Broken {
                break;
            }
            tokio::select! {
                result = state_rx.changed() => {
                    if result.is_err() { break; }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    break;
                }
            }
        }

        Ok(())
    }
}

impl Drop for SrtSocket {
    fn drop(&mut self) {
        // Signal close — ConnTask will detect and clean up
        self.close_signal.notify_one();
    }
}

/// Initialize crypto state from config.
fn init_crypto(config: &SrtConfig) -> Option<CryptoControl> {
    if config.encryption_enabled() {
        use srt_protocol::crypto::key_material;
        let salt = key_material::generate_salt();
        let kek = key_material::derive_kek(&config.passphrase, &salt, config.key_size);
        let sek = key_material::generate_sek(config.key_size);

        let mut cc = CryptoControl::new(config.key_size, config.crypto_mode.into());
        cc.kek = Some(kek);
        cc.salt = salt;
        cc.keys.set_key(srt_protocol::crypto::KeyIndex::Even, sek);
        Some(cc)
    } else {
        None
    }
}
