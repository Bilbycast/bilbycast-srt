// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT connection state.
//!
//! Combines protocol-level state (handshake, buffers, crypto) with
//! transport-level resources (channel, addresses).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, Notify, mpsc, watch};

use srt_protocol::buffer::loss_list::{ReceiveLossList, SendLossList};
use srt_protocol::buffer::receive::ReceiveBuffer;
use srt_protocol::buffer::send::SendBuffer;
use srt_protocol::config::{SrtConfig, SocketStatus};
use srt_protocol::congestion::CongestionControl;
use srt_protocol::congestion::live::LiveCC;
use srt_protocol::congestion::token_bucket::TokenBucket;
use srt_protocol::crypto::CryptoControl;
use srt_protocol::fec::{ArqMode, FecConfig};
use srt_protocol::fec::decoder::FecDecoder;
use srt_protocol::fec::encoder::FecEncoder;
use srt_protocol::packet::seq::SeqNo;
use srt_protocol::protocol::ack::AckState;
use srt_protocol::protocol::connection::ConnectionState;
use srt_protocol::protocol::handshake::Handshake;
use srt_protocol::protocol::timer::SrtTimers;
use srt_protocol::protocol::tsbpd::TsbpdTime;
use srt_protocol::stats::SrtStats;
use srt_protocol::window::{AckWindow, PktTimeWindow};

/// An SRT connection combining protocol state and transport resources.
pub struct SrtConnection {
    /// Connection configuration.
    pub config: SrtConfig,
    /// Connection start time — used as the epoch for SRT packet timestamps.
    /// SRT timestamps are relative to connection start (like C++ SRT's m_StartTime).
    pub start_time: Instant,
    /// Current connection state.
    pub state: Mutex<ConnectionState>,
    /// Local socket address.
    pub local_addr: SocketAddr,
    /// Remote peer address (set after handshake).
    pub peer_addr: Mutex<Option<SocketAddr>>,
    /// SRT socket ID assigned to this connection.
    pub socket_id: u32,
    /// Peer's socket ID (learned during handshake).
    pub peer_socket_id: Mutex<u32>,
    /// Send buffer.
    pub send_buf: Mutex<SendBuffer>,
    /// Receive buffer.
    pub recv_buf: Mutex<ReceiveBuffer>,
    /// ACK processing state.
    pub ack_state: Mutex<AckState>,
    /// Timer management.
    pub timers: Mutex<SrtTimers>,
    /// Congestion control.
    pub cc: Mutex<Box<dyn CongestionControl + Send>>,
    /// TSBPD time management.
    pub tsbpd: Mutex<TsbpdTime>,
    /// Performance statistics.
    pub stats: Mutex<SrtStats>,
    /// Send-side loss list (populated from NAK reports).
    pub send_loss_list: Mutex<SendLossList>,
    /// Receive-side loss list (gaps detected in received sequence).
    pub recv_loss_list: Mutex<ReceiveLossList>,
    /// ACK window for RTT measurement via ACKACK.
    pub ack_window: Mutex<AckWindow>,
    /// Highest sequence number received (for gap detection).
    pub highest_recv_seq: Mutex<SeqNo>,
    /// Peer's advertised flow window (updated from ACK packets).
    pub peer_flow_window: Mutex<u32>,
    /// Packet arrival time window for bandwidth estimation.
    pub pkt_time_window: Mutex<PktTimeWindow>,
    /// Crypto control for encryption/decryption (None if no passphrase configured).
    pub crypto: Mutex<Option<CryptoControl>>,
    /// Token bucket shaper for retransmission bandwidth control (SRTO_MAXREXMITBW).
    pub rexmit_shaper: Mutex<TokenBucket>,
    /// FEC encoder state (sender side). None if FEC not negotiated.
    pub fec_encoder: Mutex<Option<FecEncoder>>,
    /// FEC decoder state (receiver side). None if FEC not negotiated.
    pub fec_decoder: Mutex<Option<FecDecoder>>,
    /// Negotiated FEC ARQ mode. Always by default (normal ARQ).
    pub fec_arq_mode: Mutex<ArqMode>,
    /// Sequence numbers that FEC reported as uncoverable (for ARQ OnReq mode).
    pub fec_uncoverable: Mutex<Vec<SeqNo>>,
    /// Whether TSBPD base_time has been calibrated from the first data packet.
    pub tsbpd_calibrated: Mutex<bool>,

    /// Set to true once the app calls recv(), indicating it is actively draining
    /// the receive buffer without TSBPD timing. When true, the send_loop skips
    /// drop_too_late to avoid racing with the app's recv() calls.
    pub app_recv_active: AtomicBool,

    /// Cached `recv_buf.ack_seq().value()`, updated atomically after every recv_buf mutation.
    /// Allows send_loop to read ack_seq without locking recv_buf.
    pub cached_ack_seq: AtomicI32,
    /// Cached `recv_buf.len()`, updated atomically after every recv_buf mutation.
    pub cached_recv_buf_len: AtomicUsize,
    /// Cached `recv_buf.available()`, updated atomically after every recv_buf mutation.
    pub cached_recv_buf_avail: AtomicUsize,

    /// Notify when data is available to read.
    pub recv_data_ready: Notify,
    /// Notify when send buffer has space.
    pub send_space_ready: Notify,
    /// Watch channel for connection state changes.
    pub state_watch: watch::Sender<SocketStatus>,

    /// Channel for delivering handshake packets from recv_loop to connector.
    /// The connector awaits on the receiver; the recv_loop sends parsed handshakes.
    /// (Handshake, peer address, raw extension bytes after 48-byte header)
    pub handshake_tx: mpsc::Sender<(Handshake, std::net::SocketAddr, bytes::Bytes)>,
    pub handshake_rx: Mutex<mpsc::Receiver<(Handshake, std::net::SocketAddr, bytes::Bytes)>>,
}

impl SrtConnection {
    /// Create a new connection with default state.
    pub fn new(config: SrtConfig, local_addr: SocketAddr, socket_id: u32) -> Self {
        let (state_tx, _) = watch::channel(SocketStatus::Init);
        let (hs_tx, hs_rx) = mpsc::channel(4);

        let initial_seq = SeqNo::new(0);
        let max_payload = config.max_payload_size();
        let send_buf_pkts = (config.send_buffer_size as usize) / max_payload.max(1);
        let recv_buf_pkts = (config.recv_buffer_size as usize) / max_payload.max(1);
        let latency_ms = config.recv_latency;
        let flow_window = config.flight_flag_size;
        let max_rexmit_bw = config.max_rexmit_bw;
        let mss = config.mss;

        // Initialize crypto if passphrase is configured
        let crypto = if config.encryption_enabled() {
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
        };

        Self {
            config,
            start_time: Instant::now(),
            state: Mutex::new(ConnectionState::Init),
            local_addr,
            peer_addr: Mutex::new(None),
            socket_id,
            peer_socket_id: Mutex::new(0),
            send_buf: Mutex::new(SendBuffer::new(send_buf_pkts, max_payload, initial_seq)),
            recv_buf: Mutex::new(ReceiveBuffer::new(recv_buf_pkts, initial_seq)),
            ack_state: Mutex::new(AckState::new(initial_seq)),
            timers: Mutex::new(SrtTimers::new()),
            cc: Mutex::new(Box::new(LiveCC::new())),
            tsbpd: Mutex::new(TsbpdTime::new(Duration::from_millis(latency_ms as u64))),
            stats: Mutex::new(SrtStats::default()),
            send_loss_list: Mutex::new(SendLossList::new()),
            recv_loss_list: Mutex::new(ReceiveLossList::new()),
            ack_window: Mutex::new(AckWindow::new(1024)),
            highest_recv_seq: Mutex::new(initial_seq),
            peer_flow_window: Mutex::new(flow_window),
            pkt_time_window: Mutex::new(PktTimeWindow::new()),
            crypto: Mutex::new(crypto),
            rexmit_shaper: Mutex::new(TokenBucket::new(max_rexmit_bw, mss)),
            fec_encoder: Mutex::new(None),
            fec_decoder: Mutex::new(None),
            fec_arq_mode: Mutex::new(ArqMode::Always),
            fec_uncoverable: Mutex::new(Vec::new()),
            tsbpd_calibrated: Mutex::new(false),
            app_recv_active: AtomicBool::new(false),
            cached_ack_seq: AtomicI32::new(initial_seq.value()),
            cached_recv_buf_len: AtomicUsize::new(0),
            cached_recv_buf_avail: AtomicUsize::new(recv_buf_pkts),
            recv_data_ready: Notify::new(),
            send_space_ready: Notify::new(),
            state_watch: state_tx,
            handshake_tx: hs_tx,
            handshake_rx: Mutex::new(hs_rx),
        }
    }

    /// Update the connection state and broadcast change.
    /// When transitioning to a non-active state (Broken, Closing, Closed),
    /// wakes up any callers blocked on recv() so they can observe the error.
    pub async fn set_state(&self, new_state: ConnectionState) {
        let mut state = self.state.lock().await;
        *state = new_state;
        let _ = self.state_watch.send(new_state.to_socket_status());

        // Wake up any blocked recv() so it can see the state change and return an error.
        if !new_state.is_active() {
            self.recv_data_ready.notify_waiters();
        }
    }

    /// Get current connection state.
    pub async fn get_state(&self) -> ConnectionState {
        *self.state.lock().await
    }

    /// Check if the connection is active (connected and not broken).
    pub async fn is_active(&self) -> bool {
        self.state.lock().await.is_active()
    }

    /// Update the atomic recv_buf cache. Must be called while holding recv_buf lock.
    pub fn update_recv_buf_cache(&self, recv_buf: &ReceiveBuffer) {
        self.cached_ack_seq.store(recv_buf.ack_seq().value(), Ordering::Release);
        self.cached_recv_buf_len.store(recv_buf.len(), Ordering::Release);
        self.cached_recv_buf_avail.store(recv_buf.available(), Ordering::Release);
    }

    /// Set the peer's Initial Sequence Number (ISN) on the receive buffer
    /// and ACK state. Must be called after handshake, before data flows.
    pub async fn set_peer_isn(&self, isn: SeqNo) {
        {
            let mut recv_buf = self.recv_buf.lock().await;
            recv_buf.set_start_seq(isn);
            self.update_recv_buf_cache(&recv_buf);
        }
        *self.ack_state.lock().await = AckState::new(isn);
        *self.highest_recv_seq.lock().await = isn;
        self.recv_loss_list.lock().await.clear();
    }

    /// Initialize FEC encoder and decoder from a negotiated config.
    /// Called after handshake completes if FEC was negotiated.
    pub async fn init_fec(&self, config: FecConfig) {
        *self.fec_arq_mode.lock().await = config.arq;
        *self.fec_encoder.lock().await = Some(FecEncoder::new(config.clone()));
        let base_seq = *self.highest_recv_seq.lock().await;
        *self.fec_decoder.lock().await = Some(FecDecoder::new(config, base_seq));
    }

    /// Set our own ISN on the send buffer. Used by the listener to align the
    /// send buffer with the ISN advertised in the CONCLUSION response.
    pub async fn set_own_isn(&self, isn: SeqNo) {
        let max_payload = self.config.max_payload_size();
        let capacity = (self.config.send_buffer_size as usize) / max_payload.max(1);
        *self.send_buf.lock().await = SendBuffer::new(capacity, max_payload, isn);
    }
}
