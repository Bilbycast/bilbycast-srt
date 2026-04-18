// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Rate estimation and payload size tracking utilities.
//!
//! Used by congestion control and flow control to measure incoming
//! data rates and adapt sending behavior.

/// Input rate estimator.
///
/// Tracks the rate of incoming data for bandwidth estimation
/// and congestion control.
pub struct RateEstimator {
    /// Accumulated bytes in the current sample period.
    bytes_in_period: u64,
    /// Number of packets in the current sample period.
    pkts_in_period: u64,
    /// Start time of the current sample period.
    period_start: std::time::Instant,
    /// Sample period duration.
    period_duration: std::time::Duration,
    /// Last computed rate in bytes/sec.
    rate_bps: u64,
    /// Last computed packet rate in pkt/sec.
    rate_pps: u64,
    /// Average payload size in bytes.
    avg_payload_size: usize,
}

impl RateEstimator {
    pub fn new() -> Self {
        Self {
            bytes_in_period: 0,
            pkts_in_period: 0,
            period_start: std::time::Instant::now(),
            period_duration: std::time::Duration::from_secs(1),
            rate_bps: 0,
            rate_pps: 0,
            avg_payload_size: 0,
        }
    }

    /// Record a packet arrival.
    pub fn on_packet(&mut self, payload_size: usize) {
        self.bytes_in_period += payload_size as u64;
        self.pkts_in_period += 1;

        // Update average payload size (EWMA)
        if self.avg_payload_size == 0 {
            self.avg_payload_size = payload_size;
        } else {
            self.avg_payload_size = (self.avg_payload_size * 7 + payload_size) / 8;
        }

        let elapsed = self.period_start.elapsed();
        if elapsed >= self.period_duration {
            let secs = elapsed.as_secs_f64();
            if secs > 0.0 {
                self.rate_bps = (self.bytes_in_period as f64 / secs) as u64;
                self.rate_pps = (self.pkts_in_period as f64 / secs) as u64;
            }
            self.bytes_in_period = 0;
            self.pkts_in_period = 0;
            self.period_start = std::time::Instant::now();
        }
    }

    /// Current rate in bytes per second.
    pub fn rate_bps(&self) -> u64 {
        self.rate_bps
    }

    /// Current rate in packets per second.
    pub fn rate_pps(&self) -> u64 {
        self.rate_pps
    }

    /// Current average payload size.
    pub fn avg_payload_size(&self) -> usize {
        self.avg_payload_size
    }
}

impl Default for RateEstimator {
    fn default() -> Self {
        Self::new()
    }
}
