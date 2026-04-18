// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! ACK window and packet timing measurement.
//!
//! Provides ring-buffer based windows for RTT calculation and bandwidth
//! estimation. Maps to the C++ `CACKWindow` and `CPktTimeWindow`.

use std::time::Instant;

/// ACK window for tracking ACK sequence numbers and their timestamps.
///
/// Maps to C++ `CACKWindow`. Used to calculate RTT when an ACKACK is received
/// by looking up the time the corresponding ACK was sent.
pub struct AckWindow {
    /// Ring buffer of (ack_seq_no, timestamp) pairs.
    records: Vec<(i32, Instant)>,
    /// Write position (next slot to write).
    head: usize,
    /// Capacity.
    capacity: usize,
}

impl AckWindow {
    pub fn new(size: usize) -> Self {
        Self {
            records: vec![(0, Instant::now()); size],
            head: 0,
            capacity: size,
        }
    }

    /// Record a sent ACK with its sequence number.
    pub fn store(&mut self, ack_seq: i32) {
        self.records[self.head] = (ack_seq, Instant::now());
        self.head = (self.head + 1) % self.capacity;
    }

    /// Look up when an ACK with the given sequence number was sent.
    /// Returns the round-trip time if found.
    pub fn acknowledge(&self, ack_seq: i32) -> Option<std::time::Duration> {
        let now = Instant::now();
        for &(seq, time) in &self.records {
            if seq == ack_seq {
                return Some(now.duration_since(time));
            }
        }
        None
    }
}

/// Packet arrival time window for bandwidth estimation.
///
/// Maps to C++ `CPktTimeWindow`. Tracks inter-packet arrival intervals
/// to estimate the receiving rate and link bandwidth.
pub struct PktTimeWindow {
    /// Ring buffer of inter-packet arrival intervals (microseconds).
    intervals: Vec<i64>,
    /// Write position.
    head: usize,
    /// Number of intervals recorded.
    count: usize,
    /// Last packet arrival time.
    last_arrival: Option<Instant>,
    /// Ring buffer of packet pair probe intervals (microseconds).
    probe_intervals: Vec<i64>,
    /// Write position for probes.
    probe_head: usize,
    /// Number of probe intervals recorded.
    probe_count: usize,
    /// Last probe arrival time.
    last_probe: Option<Instant>,
}

impl PktTimeWindow {
    /// Default window sizes (from C++ implementation).
    const PKT_WINDOW_SIZE: usize = 16;
    const PROBE_WINDOW_SIZE: usize = 16;

    pub fn new() -> Self {
        Self {
            intervals: vec![1_000_000; Self::PKT_WINDOW_SIZE], // 1 second default
            head: 0,
            count: 0,
            last_arrival: None,
            probe_intervals: vec![1_000_000; Self::PROBE_WINDOW_SIZE],
            probe_head: 0,
            probe_count: 0,
            last_probe: None,
        }
    }

    /// Record a packet arrival for bandwidth estimation.
    pub fn on_pkt_arrival(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.last_arrival {
            let interval = now.duration_since(last).as_micros() as i64;
            self.intervals[self.head] = interval;
            self.head = (self.head + 1) % Self::PKT_WINDOW_SIZE;
            if self.count < Self::PKT_WINDOW_SIZE {
                self.count += 1;
            }
        }
        self.last_arrival = Some(now);
    }

    /// Record a probe packet arrival for link capacity estimation.
    pub fn on_probe_arrival(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.last_probe {
            let interval = now.duration_since(last).as_micros() as i64;
            self.probe_intervals[self.probe_head] = interval;
            self.probe_head = (self.probe_head + 1) % Self::PROBE_WINDOW_SIZE;
            if self.probe_count < Self::PROBE_WINDOW_SIZE {
                self.probe_count += 1;
            }
        }
        self.last_probe = Some(now);
    }

    /// Estimate the receiving rate in packets per second.
    ///
    /// Uses the median of recorded intervals (outlier-resistant).
    pub fn recv_speed(&self) -> Option<i32> {
        if self.count < 2 {
            return None;
        }

        let mut sorted: Vec<i64> = self.intervals[..self.count].to_vec();
        sorted.sort_unstable();

        // Remove outliers: use the middle 50%
        let lower = self.count / 4;
        let upper = self.count * 3 / 4;
        if lower >= upper {
            return None;
        }

        let sum: i64 = sorted[lower..upper].iter().sum();
        let count = (upper - lower) as i64;
        let avg_interval = sum / count;

        if avg_interval > 0 {
            Some((1_000_000 / avg_interval) as i32)
        } else {
            None
        }
    }

    /// Estimate the link bandwidth in packets per second using probe packets.
    pub fn bandwidth(&self) -> Option<i32> {
        if self.probe_count < 2 {
            return None;
        }

        let mut sorted: Vec<i64> = self.probe_intervals[..self.probe_count].to_vec();
        sorted.sort_unstable();

        let lower = self.probe_count / 4;
        let upper = self.probe_count * 3 / 4;
        if lower >= upper {
            return None;
        }

        let sum: i64 = sorted[lower..upper].iter().sum();
        let count = (upper - lower) as i64;
        let avg_interval = sum / count;

        if avg_interval > 0 {
            Some((1_000_000 / avg_interval) as i32)
        } else {
            None
        }
    }
}

impl Default for PktTimeWindow {
    fn default() -> Self {
        Self::new()
    }
}
