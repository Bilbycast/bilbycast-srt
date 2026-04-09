// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT connection routing handle.
//!
//! Thin struct stored in the Multiplexer for packet routing.
//! Contains only read-only config and channel senders — all mutable
//! protocol state lives in [`ConnTask`](crate::conn_task::ConnTask).

use std::net::SocketAddr;
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::{Mutex, mpsc, watch};

use srt_protocol::config::{SrtConfig, SocketStatus};
use srt_protocol::protocol::handshake::Handshake;

use crate::conn_task::NetEvent;

/// Routing handle for an SRT connection.
///
/// Stored in the [`Multiplexer`](crate::multiplexer::Multiplexer)
/// routing table. The recv_loop uses the channel senders to forward
/// parsed packets to the appropriate handler (connector during
/// handshake, ConnTask during data transfer).
pub struct SrtConnection {
    /// Connection configuration (read-only after creation).
    pub config: SrtConfig,
    /// Connection start time — epoch for SRT packet timestamps.
    pub start_time: Instant,
    /// Local socket address.
    pub local_addr: SocketAddr,
    /// SRT socket ID assigned to this connection.
    pub socket_id: u32,

    /// Channel for delivering handshake packets from recv_loop to
    /// the connector or listener accept loop.
    pub handshake_tx: mpsc::Sender<(Handshake, SocketAddr, Bytes)>,
    /// Receiver end — read by the connector/listener during handshake.
    /// Uses Mutex because the connector needs exclusive read access.
    pub handshake_rx: Mutex<mpsc::Receiver<(Handshake, SocketAddr, Bytes)>>,

    /// Channel for delivering non-handshake network events to the
    /// ConnTask. Unbounded so the recv_loop never blocks.
    pub net_tx: mpsc::UnboundedSender<NetEvent>,

    /// Watch channel for broadcasting connection state changes.
    pub state_watch: watch::Sender<SocketStatus>,
}

impl SrtConnection {
    /// Create a new connection routing handle.
    ///
    /// The `net_rx` end of the unbounded channel is returned separately
    /// so the caller can pass it to the connector (during handshake) and
    /// then to the ConnTask.
    pub fn new(
        config: SrtConfig,
        local_addr: SocketAddr,
        socket_id: u32,
    ) -> (Self, mpsc::UnboundedReceiver<NetEvent>) {
        let (state_tx, _) = watch::channel(SocketStatus::Init);
        let (hs_tx, hs_rx) = mpsc::channel(4);
        let (net_tx, net_rx) = mpsc::unbounded_channel();

        let conn = Self {
            config,
            start_time: Instant::now(),
            local_addr,
            socket_id,
            handshake_tx: hs_tx,
            handshake_rx: Mutex::new(hs_rx),
            net_tx,
            state_watch: state_tx,
        };
        (conn, net_rx)
    }

    /// Update the connection state and broadcast change.
    pub fn set_state(&self, new_state: srt_protocol::protocol::connection::ConnectionState) {
        let _ = self.state_watch.send(new_state.to_socket_status());
    }

    /// Get current socket status.
    pub fn status(&self) -> SocketStatus {
        *self.state_watch.borrow()
    }
}
