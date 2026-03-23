// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT connection state.
//!
//! Combines protocol-level state (handshake, buffers, crypto) with
//! transport-level resources (channel, addresses).

use std::net::SocketAddr;
use std::time::Duration;

use tokio::sync::{Mutex, Notify, mpsc, watch};

use srt_protocol::buffer::receive::ReceiveBuffer;
use srt_protocol::buffer::send::SendBuffer;
use srt_protocol::config::{SrtConfig, SocketStatus};
use srt_protocol::congestion::CongestionControl;
use srt_protocol::congestion::live::LiveCC;
use srt_protocol::packet::seq::SeqNo;
use srt_protocol::protocol::ack::AckState;
use srt_protocol::protocol::connection::ConnectionState;
use srt_protocol::protocol::handshake::Handshake;
use srt_protocol::protocol::timer::SrtTimers;
use srt_protocol::protocol::tsbpd::TsbpdTime;
use srt_protocol::stats::SrtStats;

/// An SRT connection combining protocol state and transport resources.
pub struct SrtConnection {
    /// Connection configuration.
    pub config: SrtConfig,
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

    /// Notify when data is available to read.
    pub recv_data_ready: Notify,
    /// Notify when send buffer has space.
    pub send_space_ready: Notify,
    /// Watch channel for connection state changes.
    pub state_watch: watch::Sender<SocketStatus>,

    /// Channel for delivering handshake packets from recv_loop to connector.
    /// The connector awaits on the receiver; the recv_loop sends parsed handshakes.
    pub handshake_tx: mpsc::Sender<(Handshake, std::net::SocketAddr)>,
    pub handshake_rx: Mutex<mpsc::Receiver<(Handshake, std::net::SocketAddr)>>,
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

        Self {
            config,
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

    /// Set the peer's Initial Sequence Number (ISN) on the receive buffer
    /// and ACK state. Must be called after handshake, before data flows.
    pub async fn set_peer_isn(&self, isn: SeqNo) {
        self.recv_buf.lock().await.set_start_seq(isn);
        *self.ack_state.lock().await = AckState::new(isn);
    }

    /// Set our own ISN on the send buffer. Used by the listener to align the
    /// send buffer with the ISN advertised in the CONCLUSION response.
    pub async fn set_own_isn(&self, isn: SeqNo) {
        let max_payload = self.config.max_payload_size();
        let capacity = (self.config.send_buffer_size as usize) / max_payload.max(1);
        *self.send_buf.lock().await = SendBuffer::new(capacity, max_payload, isn);
    }
}
