// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT protocol state machines and timing.
//!
//! This module contains the core protocol logic that drives an SRT connection
//! through its lifecycle: handshake negotiation, data transfer with reliability,
//! and graceful shutdown.
//!
//! # Submodules
//!
//! - [`handshake`] - HSv5 handshake with INDUCTION/CONCLUSION phases and SRT extensions
//! - [`connection`] - Connection state machine (Init -> Connected -> Broken -> Closed)
//! - [`ack`] - ACK/ACKACK/NAK generation, RTT estimation, flow window management
//! - [`timer`] - Periodic timers for ACK (10ms), NAK, keepalive (1s), and expiration
//! - [`tsbpd`] - Timestamp-Based Packet Delivery with clock drift tracking

pub mod handshake;
pub mod connection;
pub mod ack;
pub mod timer;
pub mod tsbpd;
