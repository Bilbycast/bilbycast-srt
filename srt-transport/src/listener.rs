//! SRT listener for accepting incoming connections.
//!
//! Maps to C++ listen/accept flow. Binds to a UDP port and accepts
//! incoming SRT connections via the handshake process.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use srt_protocol::config::{KeySize, SrtConfig};
use srt_protocol::error::SrtError;
use srt_protocol::protocol::connection::ConnectionState;

use crate::channel::UdpChannel;
use crate::connection::SrtConnection;
use crate::multiplexer::Multiplexer;
use crate::recv_loop;
use crate::socket::SrtSocket;

/// Builder for creating an SRT listener.
pub struct SrtListenerBuilder {
    config: SrtConfig,
    backlog: usize,
}

impl SrtListenerBuilder {
    /// Create a new listener builder.
    pub fn new() -> Self {
        Self {
            config: SrtConfig::default(),
            backlog: 5,
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

    /// Bind and start listening.
    pub async fn bind(self, addr: SocketAddr) -> Result<SrtListener, SrtError> {
        let channel = UdpChannel::bind(addr).await
            .map_err(|_| SrtError::ConnectionSetup)?;
        let local_addr = channel.local_addr();

        let mux = Arc::new(Multiplexer::new(channel));

        // Create the listener "socket" that receives initial handshakes
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
        let mux_clone = mux.clone();
        tokio::spawn(async move {
            recv_loop::run(mux_clone).await;
        });

        Ok(SrtListener {
            config: self.config,
            multiplexer: mux,
            listener_conn,
            local_addr,
            accept_tx,
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
#[allow(dead_code)]
pub struct SrtListener {
    /// Configuration template for accepted connections.
    config: SrtConfig,
    /// The multiplexer for this listener.
    multiplexer: Arc<Multiplexer>,
    /// The listener connection state.
    listener_conn: Arc<SrtConnection>,
    /// Local address.
    local_addr: SocketAddr,
    /// Channel for accepted connections.
    accept_tx: mpsc::Sender<SrtSocket>,
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
