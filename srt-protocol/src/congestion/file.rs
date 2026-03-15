//! File mode congestion control (AIMD).
//!
//! TCP-like slow-start and congestion avoidance for reliable file transfer.
//! Maximizes throughput while adapting to network capacity.

use super::{CongestionControl, RexmitMethod};
use crate::packet::seq::SeqNo;

/// File mode congestion control (AIMD - Additive Increase Multiplicative Decrease).
///
/// Designed for reliable file transfer. Uses a TCP-like slow-start
/// and congestion avoidance algorithm.
#[allow(dead_code)]
pub struct FileCC {
    /// Packet sending period in microseconds.
    pkt_send_period: f64,
    /// Congestion window size in packets.
    cwnd: f64,
    /// Maximum congestion window.
    max_cwnd: f64,
    /// Slow start threshold.
    ss_thresh: f64,
    /// Whether in slow start phase.
    slow_start: bool,
    /// Estimated bandwidth in packets/sec.
    bandwidth: i32,
    /// Average payload size.
    avg_payload_size: f64,
    /// Maximum bandwidth limit.
    max_bw: i64,
    /// Last ACK sequence (for window increase counting).
    last_ack: Option<SeqNo>,
    /// Loss flag (was there a loss in this RTT?).
    loss_in_rtt: bool,
}

impl FileCC {
    pub fn new() -> Self {
        Self {
            pkt_send_period: 1.0,
            cwnd: 16.0,
            max_cwnd: 8192.0,
            ss_thresh: 8192.0,
            slow_start: true,
            bandwidth: 0,
            avg_payload_size: 1456.0,
            max_bw: 0,
            last_ack: None,
            loss_in_rtt: false,
        }
    }
}

impl Default for FileCC {
    fn default() -> Self {
        Self::new()
    }
}

impl CongestionControl for FileCC {
    fn on_ack(&mut self, ack_seq: SeqNo, _rtt_us: i32) {
        if self.slow_start {
            // Slow start: double CWND per RTT
            self.cwnd += 1.0;
            if self.cwnd >= self.ss_thresh {
                self.slow_start = false;
            }
        } else {
            // Congestion avoidance: increase by 1/cwnd per ACK
            self.cwnd += 1.0 / self.cwnd;
        }

        self.cwnd = self.cwnd.min(self.max_cwnd);

        // Update send period based on bandwidth and CWND
        if self.bandwidth > 0 {
            let b = self.bandwidth as f64;
            self.pkt_send_period = 1_000_000.0 / b;
        }

        self.last_ack = Some(ack_seq);
        self.loss_in_rtt = false;
    }

    fn on_loss(&mut self, _loss_list: &[(SeqNo, SeqNo)]) {
        if !self.loss_in_rtt {
            self.loss_in_rtt = true;
            // Multiplicative decrease: halve CWND
            self.cwnd = (self.cwnd / 2.0).max(2.0);
            self.ss_thresh = self.cwnd;
            self.slow_start = false;
        }
    }

    fn on_timer(&mut self) {
        // No specific timer action for file CC
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
    }

    fn set_max_bandwidth(&mut self, max_bw_bytes_per_sec: i64) {
        self.max_bw = max_bw_bytes_per_sec;
    }

    fn rexmit_method(&self) -> RexmitMethod {
        RexmitMethod::FastRexmit
    }
}
