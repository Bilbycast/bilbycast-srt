// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Multiplexer: multiple SRT sockets sharing one UDP port.
//!
//! Maps to C++ `CMultiplexer`. Routes incoming packets to the correct
//! SRT connection based on the destination socket ID in the SRT header.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::channel::UdpChannel;
use crate::connection::SrtConnection;

/// Multiplexer routing incoming packets to SRT connections.
///
/// A single multiplexer owns one UDP channel (port) and routes
/// packets to connections based on the destination socket ID
/// in the SRT packet header.
pub struct Multiplexer {
    /// The UDP channel (shared, immutable after creation).
    pub channel: Arc<UdpChannel>,
    /// Routing table: destination socket ID → connection.
    routes: RwLock<HashMap<u32, Arc<SrtConnection>>>,
    /// Listener socket (if any) for handling new connections.
    listener: RwLock<Option<Arc<SrtConnection>>>,
    /// Rendezvous socket (if any) for receiving WAVEAHAND packets at dest_socket_id=0.
    /// Mutually exclusive with listener — a multiplexer is either in listener or rendezvous mode.
    rendezvous: RwLock<Option<Arc<SrtConnection>>>,
    /// Shutdown flag — when true, recv_loop should exit.
    shutdown: std::sync::atomic::AtomicBool,
}

impl Multiplexer {
    /// Create a new multiplexer with the given UDP channel.
    pub fn new(channel: UdpChannel) -> Self {
        Self {
            channel: Arc::new(channel),
            routes: RwLock::new(HashMap::new()),
            listener: RwLock::new(None),
            rendezvous: RwLock::new(None),
            shutdown: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Register a connection for packet routing.
    pub async fn add_connection(&self, socket_id: u32, conn: Arc<SrtConnection>) {
        let mut routes = self.routes.write().await;
        routes.insert(socket_id, conn);
    }

    /// Remove a connection from routing.
    pub async fn remove_connection(&self, socket_id: u32) {
        let mut routes = self.routes.write().await;
        routes.remove(&socket_id);
    }

    /// Set the listener socket for this multiplexer.
    pub async fn set_listener(&self, conn: Arc<SrtConnection>) {
        let mut listener = self.listener.write().await;
        *listener = Some(conn);
    }

    /// Clear the listener.
    pub async fn clear_listener(&self) {
        let mut listener = self.listener.write().await;
        *listener = None;
    }

    /// Set the rendezvous socket for this multiplexer.
    /// In rendezvous mode, WAVEAHAND packets arrive at dest_socket_id=0
    /// and need to be routed to the rendezvous connection.
    pub async fn set_rendezvous(&self, conn: Arc<SrtConnection>) {
        let mut rdv = self.rendezvous.write().await;
        *rdv = Some(conn);
    }

    /// Clear the rendezvous socket (called after handshake completes).
    pub async fn clear_rendezvous(&self) {
        let mut rdv = self.rendezvous.write().await;
        *rdv = None;
    }

    /// Look up the connection for a given destination socket ID.
    pub async fn route(&self, dest_socket_id: u32) -> Option<Arc<SrtConnection>> {
        // If dest_socket_id is 0, route to listener or rendezvous connection.
        // Listener and rendezvous are mutually exclusive modes.
        if dest_socket_id == 0 {
            let listener = self.listener.read().await;
            if listener.is_some() {
                return listener.clone();
            }
            let rdv = self.rendezvous.read().await;
            return rdv.clone();
        }

        let routes = self.routes.read().await;
        routes.get(&dest_socket_id).cloned()
    }

    /// Send raw packet data to the given address.
    pub async fn send_to(
        &self,
        data: &[u8],
        target: SocketAddr,
    ) -> std::io::Result<usize> {
        self.channel.send_to(data, target).await
    }

    /// Get the local address of this multiplexer's UDP channel.
    pub fn local_addr(&self) -> SocketAddr {
        self.channel.local_addr()
    }

    /// Get the number of registered routes.
    pub async fn connection_count(&self) -> usize {
        let routes = self.routes.read().await;
        routes.len()
    }

    /// Remove all connections from the routing table.
    pub async fn clear_all_routes(&self) {
        let mut routes = self.routes.write().await;
        routes.clear();
    }

    /// Signal shutdown. recv_loop checks this flag and exits, allowing
    /// the UDP socket to be released.
    pub fn shutdown(&self) {
        self.shutdown.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Check if shutdown has been signalled.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(std::sync::atomic::Ordering::Acquire)
    }
}
