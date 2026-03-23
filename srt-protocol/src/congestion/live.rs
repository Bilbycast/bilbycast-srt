// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Live mode congestion control.
//!
//! Constant-rate sending optimized for real-time streaming. Packets that
//! cannot be delivered within the TSBPD latency window are dropped rather
//! than retransmitted.

use super::{CongestionControl, RexmitMethod};
use crate::packet::seq::SeqNo;

/// Live mode congestion control.
///
/// Designed for real-time streaming with constant-rate sending.
/// Supports too-late-to-send packet dropping and bandwidth limiting.
pub struct LiveCC {
    /// Packet sending period in microseconds.
    pkt_send_period: f64,
    /// Congestion window size in packets.
    cwnd: f64,
    /// Maximum congestion window.
    max_cwnd: f64,
    /// Maximum bandwidth in bytes/sec (0 = unlimited).
    max_bw: i64,
    /// Estimated input bandwidth in bytes/sec.
    input_bw: i64,
    /// Overhead as percentage (default: 25%).
    overhead_pct: i32,
    /// Average payload size in bytes.
    avg_payload_size: f64,
    /// Estimated link bandwidth in packets/sec.
    bandwidth: i32,
}

impl LiveCC {
    pub fn new() -> Self {
        Self {
            pkt_send_period: 1.0, // 1 microsecond = nearly unlimited
            cwnd: 1000.0,
            max_cwnd: 1000.0,
            max_bw: 0,
            input_bw: 0,
            overhead_pct: 25,
            avg_payload_size: 1316.0,
            bandwidth: 0,
        }
    }

    /// Set the input bandwidth for rate calculation.
    pub fn set_input_bw(&mut self, input_bw: i64) {
        self.input_bw = input_bw;
        self.update_send_period();
    }

    /// Set the overhead percentage.
    pub fn set_overhead_pct(&mut self, pct: i32) {
        self.overhead_pct = pct;
        self.update_send_period();
    }

    /// Update the packet send period based on configured limits.
    fn update_send_period(&mut self) {
        let max_bw = if self.max_bw > 0 {
            self.max_bw
        } else if self.input_bw > 0 {
            // Auto: input_bw * (1 + overhead%)
            self.input_bw * (100 + self.overhead_pct as i64) / 100
        } else if self.bandwidth > 0 {
            // Fallback: use estimated bandwidth
            let bw = (self.bandwidth as f64 * self.avg_payload_size) as i64;
            bw * (100 + self.overhead_pct as i64) / 100
        } else {
            return; // No limit
        };

        if max_bw > 0 && self.avg_payload_size > 0.0 {
            // send_period = payload_size / max_bw * 1e6
            self.pkt_send_period = self.avg_payload_size / max_bw as f64 * 1_000_000.0;
        }
    }
}

impl Default for LiveCC {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionControl for LiveCC {
    fn on_ack(&mut self, _ack_seq: SeqNo, _rtt_us: i32) {
        // Live mode doesn't adjust rate on ACK
    }

    fn on_loss(&mut self, _loss_list: &[(SeqNo, SeqNo)]) {
        // Live mode doesn't reduce rate on loss
        // (packets are dropped by TSBPD instead)
    }

    fn on_timer(&mut self) {
        // No periodic adjustment needed
    }

    fn pkt_send_period_us(&self) -> f64 {
        self.pkt_send_period
    }

    fn congestion_window(&self) -> f64 {
        self.cwnd
    }

    fn max_congestion_window(&self) -> f64 {
        self.max_cwnd
    }

    fn set_bandwidth(&mut self, bandwidth_pkts_per_sec: i32) {
        self.bandwidth = bandwidth_pkts_per_sec;
        self.update_send_period();
    }

    fn set_max_bandwidth(&mut self, max_bw_bytes_per_sec: i64) {
        self.max_bw = max_bw_bytes_per_sec;
        self.update_send_period();
    }

    fn rexmit_method(&self) -> RexmitMethod {
        RexmitMethod::LateRexmit
    }
}
