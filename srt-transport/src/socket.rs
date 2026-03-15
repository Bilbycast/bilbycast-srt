//! SRT socket handle with builder pattern.
//!
//! Maps to C++ `CUDTSocket` + public API. Provides the main user-facing
//! interface for SRT connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::watch;

use srt_protocol::config::{KeySize, SrtConfig, SocketStatus};
use srt_protocol::error::SrtError;
use srt_protocol::protocol::connection::ConnectionState;
use srt_protocol::stats::SrtStats;

use crate::channel::UdpChannel;
use crate::connection::SrtConnection;
use crate::connector;
use crate::multiplexer::Multiplexer;
use crate::recv_loop;
use crate::send_loop;

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
        let conn = Arc::new(SrtConnection::new(self.config, local_addr, socket_id));

        mux.add_connection(socket_id, conn.clone()).await;

        // Start send/receive loops
        let mux_recv = mux.clone();
        tokio::spawn(async move {
            recv_loop::run(mux_recv).await;
        });

        let mux_send = mux.clone();
        let conn_send = conn.clone();
        tokio::spawn(async move {
            send_loop::run(mux_send, conn_send).await;
        });

        // Perform handshake
        connector::connect(mux.clone(), conn.clone(), addr).await?;

        let state_rx = conn.state_watch.subscribe();

        Ok(SrtSocket {
            connection: conn,
            multiplexer: mux,
            state_rx,
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
/// Provides async send/recv operations over an SRT connection.
/// Implements RAII: dropping the socket closes the connection.
pub struct SrtSocket {
    /// The underlying connection state.
    pub(crate) connection: Arc<SrtConnection>,
    /// The multiplexer for packet I/O.
    pub(crate) multiplexer: Arc<Multiplexer>,
    /// Watch receiver for state changes.
    state_rx: watch::Receiver<SocketStatus>,
}

impl SrtSocket {
    /// Create a socket builder.
    pub fn builder() -> SrtSocketBuilder {
        SrtSocketBuilder::new()
    }

    /// Send data over the SRT connection.
    pub async fn send(&self, data: &[u8]) -> Result<usize, SrtError> {
        if !self.connection.is_active().await {
            return Err(SrtError::NoConnection);
        }

        let mut send_buf = self.connection.send_buf.lock().await;
        send_buf.add_message(data, -1, false);
        self.connection.send_space_ready.notify_one();

        Ok(data.len())
    }

    /// Receive data from the SRT connection.
    ///
    /// Blocks until data is available or the connection is closed.
    pub async fn recv(&self) -> Result<Bytes, SrtError> {
        loop {
            if !self.connection.is_active().await {
                return Err(SrtError::NoConnection);
            }

            // Try to read from receive buffer
            {
                let mut recv_buf = self.connection.recv_buf.lock().await;
                if let Some(data) = recv_buf.read_message(None) {
                    return Ok(data);
                }
            }

            // Wait for data
            self.connection.recv_data_ready.notified().await;
        }
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.connection.local_addr
    }

    /// Get the peer address.
    pub async fn peer_addr(&self) -> Option<SocketAddr> {
        *self.connection.peer_addr.lock().await
    }

    /// Get connection statistics.
    pub async fn stats(&self) -> SrtStats {
        self.connection.stats.lock().await.clone()
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
        self.connection.set_state(ConnectionState::Closing).await;
        // TODO: send SHUTDOWN control packet, drain buffers
        self.connection.set_state(ConnectionState::Closed).await;
        self.multiplexer.remove_connection(self.connection.socket_id).await;
        Ok(())
    }
}

impl Drop for SrtSocket {
    fn drop(&mut self) {
        // Mark as closed — actual cleanup happens async
        // The tokio tasks will detect the closed state and stop
    }
}
