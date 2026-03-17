//! Async I/O transport layer for the SRT protocol.
//!
//! This crate provides ready-to-use [`SrtSocket`] and [`SrtListener`] types
//! for building SRT applications on top of [tokio](https://tokio.rs/). It handles
//! UDP networking, packet dispatch, congestion-controlled send scheduling,
//! connection multiplexing, and event notification.
//!
//! # Quick Start
//!
//! ```no_run
//! use srt_transport::SrtSocket;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect to a remote SRT peer
//! let socket = SrtSocket::builder()
//!     .latency(Duration::from_millis(120))
//!     .live_mode()
//!     .connect("127.0.0.1:4200".parse()?)
//!     .await?;
//!
//! // Send data
//! socket.send(b"Hello SRT!").await?;
//!
//! // Receive data
//! let data = socket.recv().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Architecture
//!
//! Each SRT connection spawns two tokio tasks:
//! - [`send_loop`] - Paces outgoing packets according to congestion control
//! - [`recv_loop`] - Receives and dispatches incoming UDP packets
//!
//! Multiple connections can share a single UDP port via the [`multiplexer`],
//! which routes packets by destination socket ID.
//!
//! # Modules
//!
//! - [`socket`] - `SrtSocket` and `SrtSocketBuilder` (main client API)
//! - [`listener`] - `SrtListener` for accepting incoming connections
//! - [`connector`] - HSv5 caller-side handshake implementation
//! - [`connector_rendezvous`] - HSv5 rendezvous (peer-to-peer) handshake
//! - [`channel`] - UDP channel wrapper over `tokio::net::UdpSocket`
//! - [`multiplexer`] - Routes packets across connections on one UDP port
//! - [`connection`] - Internal connection state (protocol + transport)
//! - [`send_loop`] / [`recv_loop`] - Async send/receive tasks
//! - [`epoll`] - Event notification for socket multiplexing
//! - [`manager`] - Global socket registry

pub mod channel;
pub mod connection;
pub mod connector;
pub mod connector_rendezvous;
pub mod epoll;
pub mod listener;
pub mod manager;
pub mod multiplexer;
pub mod recv_loop;
pub mod send_loop;
pub mod socket;

pub use srt_protocol;

// Re-exports for convenience
pub use socket::{SrtSocket, SrtSocketBuilder};
pub use listener::{SrtListener, SrtListenerBuilder};
pub use epoll::{SrtEpoll, SrtEpollOpt, SrtEpollEvent};
