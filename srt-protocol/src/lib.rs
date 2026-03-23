// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Pure Rust implementation of the SRT (Secure Reliable Transport) protocol.
//!
//! This crate provides all SRT protocol logic without any I/O or async runtime
//! dependencies. It can be used to build custom SRT transports or to embed SRT
//! protocol handling in other networking frameworks.
//!
//! # Modules
//!
//! - [`packet`] - SRT packet header serialization, sequence/message numbers
//! - [`protocol`] - Handshake, connection state machine, ACK/NAK, timers, TSBPD
//! - [`buffer`] - Send/receive buffers with loss tracking
//! - [`congestion`] - Pluggable congestion control (Live and File modes)
//! - [`crypto`] - AES-CTR/GCM encryption, PBKDF2 key derivation, key rotation
//! - [`fec`] - Forward Error Correction (XOR-based recovery)
//! - [`config`] - Socket options and configuration
//! - [`error`] - Error types matching SRT_ERRNO
//! - [`stats`] - Performance statistics counters
//! - [`window`] - ACK window and packet timing measurement
//!
//! # Feature Flags
//!
//! - `encryption` (default) - Enables AES-CTR/GCM encryption support via RustCrypto crates.
//!   Disable with `default-features = false` for a smaller binary without crypto.

pub mod config;
pub mod error;
pub mod packet;
pub mod stats;
pub mod window;

pub mod protocol;
pub mod buffer;
pub mod congestion;

#[cfg(feature = "encryption")]
pub mod crypto;

pub mod fec;

// Re-exports for convenience
pub use config::{KeySize, SrtConfig, SocketStatus, TransType};
pub use error::{RejectReason, SrtError};
pub use packet::SrtPacket;
pub use packet::seq::SeqNo;
pub use packet::msg::MsgNo;
pub use stats::SrtStats;
