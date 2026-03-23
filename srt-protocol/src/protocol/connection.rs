// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT connection state machine.
//!
//! Tracks the lifecycle of an SRT connection from initialization through
//! handshake, data transfer, and teardown.

use crate::config::SocketStatus;

/// Connection role during handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    /// The side that initiates the connection (caller or rendezvous initiator).
    Initiator,
    /// The side that responds to the connection (listener or rendezvous responder).
    Responder,
}

/// Internal connection state (more granular than SocketStatus).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Socket created, not yet opened.
    Init,
    /// Socket opened (bound).
    Opened,
    /// Listening for incoming connections.
    Listening,
    /// Handshake in progress.
    Connecting,
    /// Connection established, data transfer active.
    Connected,
    /// Connection broken.
    Broken,
    /// Socket closing (graceful shutdown in progress).
    Closing,
    /// Socket fully closed.
    Closed,
}

impl ConnectionState {
    pub fn to_socket_status(self) -> SocketStatus {
        match self {
            Self::Init => SocketStatus::Init,
            Self::Opened => SocketStatus::Opened,
            Self::Listening => SocketStatus::Listening,
            Self::Connecting => SocketStatus::Connecting,
            Self::Connected => SocketStatus::Connected,
            Self::Broken => SocketStatus::Broken,
            Self::Closing => SocketStatus::Closing,
            Self::Closed => SocketStatus::Closed,
        }
    }

    pub fn is_active(self) -> bool {
        matches!(self, Self::Connected | Self::Connecting)
    }

    pub fn is_closed(self) -> bool {
        matches!(self, Self::Broken | Self::Closing | Self::Closed)
    }
}
