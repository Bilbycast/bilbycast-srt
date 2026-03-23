// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! ACK/ACKACK/NAK generation and processing.
//!
//! Manages acknowledgment state for reliable delivery: periodic ACK
//! generation, ACKACK-based RTT estimation, and light ACK support.

use crate::packet::seq::SeqNo;

/// ACK processing state for an SRT connection.
///
/// Tracks the ACK sequence number (separate from data sequence numbers),
/// and manages periodic/light ACK generation.
pub struct AckState {
    /// Next ACK sequence number to use.
    next_ack_seq: i32,
    /// Last acknowledged data sequence number (sent to peer).
    last_ack: SeqNo,
    /// Last data ACK (the most recent ACK for actual data, not light ACK).
    last_data_ack: SeqNo,
    /// Number of packets received since last ACK.
    pkt_count_since_ack: u32,
    /// Number of light ACKs sent since last full ACK.
    light_ack_count: u32,
}

/// Maximum number of packets between ACKs.
pub const ACK_MAX_PACKETS: u32 = 64;

/// ACK interval in microseconds (COMM_SYN_INTERVAL_US = 10ms).
pub const ACK_INTERVAL_US: u64 = 10_000;

/// Self-clock ACK interval (every 64 packets triggers a light ACK).
pub const SELF_CLOCK_INTERVAL: u32 = 64;

/// Number of light ACKs between full ACKs.
pub const LIGHT_ACK_THRESHOLD: u32 = 1;

impl AckState {
    pub fn new(initial_seq: SeqNo) -> Self {
        Self {
            next_ack_seq: 0,
            last_ack: initial_seq,
            last_data_ack: initial_seq,
            pkt_count_since_ack: 0,
            light_ack_count: 0,
        }
    }

    /// Get the next ACK sequence number and increment it.
    pub fn next_ack_seq_no(&mut self) -> i32 {
        let seq = self.next_ack_seq;
        self.next_ack_seq = self.next_ack_seq.wrapping_add(1);
        seq
    }

    /// Get the last acknowledged sequence number.
    pub fn last_ack(&self) -> SeqNo {
        self.last_ack
    }

    /// Get the last data ACK.
    pub fn last_data_ack(&self) -> SeqNo {
        self.last_data_ack
    }

    /// Update last ACK to a new sequence number.
    /// Returns true if the ACK advanced.
    pub fn update_ack(&mut self, seq: SeqNo) -> bool {
        if seq.is_after(self.last_ack) {
            self.last_ack = seq;
            true
        } else {
            false
        }
    }

    /// Update last data ACK.
    pub fn update_data_ack(&mut self, seq: SeqNo) {
        if seq.is_after(self.last_data_ack) {
            self.last_data_ack = seq;
        }
    }

    /// Record that a packet was received. Returns true if an ACK should be triggered.
    pub fn on_pkt_received(&mut self) -> bool {
        self.pkt_count_since_ack += 1;
        if self.pkt_count_since_ack >= SELF_CLOCK_INTERVAL {
            self.pkt_count_since_ack = 0;
            self.light_ack_count += 1;
            true
        } else {
            false
        }
    }

    /// Check if a full ACK should be sent (vs light ACK).
    pub fn should_send_full_ack(&mut self) -> bool {
        if self.light_ack_count >= LIGHT_ACK_THRESHOLD {
            self.light_ack_count = 0;
            true
        } else {
            false
        }
    }

    /// Reset packet counter after sending an ACK.
    pub fn ack_sent(&mut self) {
        self.pkt_count_since_ack = 0;
    }
}
