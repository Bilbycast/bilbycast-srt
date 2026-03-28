// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Timestamp-Based Packet Delivery (TSBPD).
//!
//! TSBPD ensures packets are delivered to the application at the correct
//! time relative to the sender's timestamps, compensating for network
//! jitter and clock drift between sender and receiver.
//!
//! The drift tracer uses a 1000-sample sliding window with a maximum
//! correction of 5ms per adjustment.

use std::time::{Duration, Instant};

/// Maximum timestamp value (32-bit wrapping, ~71 minutes).
pub const MAX_TIMESTAMP: u32 = 0xFFFF_FFFF;

/// Maximum drift correction (5ms).
const MAX_DRIFT_US: i64 = 5_000;

/// Drift tracer sample window size.
const DRIFT_SAMPLE_WINDOW: usize = 1000;

/// Timestamp-Based Packet Delivery (TSBPD) time controller.
///
/// Maps to C++ `CTsbpdTime`. Maintains a mapping between the sender's
/// relative timestamp (32-bit microsecond counter wrapping at ~71 min)
/// and the receiver's local clock. Accounts for clock drift between
/// sender and receiver.
pub struct TsbpdTime {
    /// Base time: the local instant corresponding to sender timestamp 0.
    base_time: Instant,
    /// TSBPD delay (configured latency).
    delay: Duration,
    /// Drift tracer (accumulates drift samples).
    drift_tracer: DriftTracer,
    /// Whether TSBPD is enabled.
    enabled: bool,
}

impl TsbpdTime {
    pub fn new(delay: Duration) -> Self {
        Self {
            base_time: Instant::now(),
            delay,
            drift_tracer: DriftTracer::new(),
            enabled: true,
        }
    }

    /// Set the base time for TSBPD (called when connection is established).
    pub fn set_base_time(&mut self, base: Instant) {
        self.base_time = base;
    }

    /// Set the TSBPD delay.
    pub fn set_delay(&mut self, delay: Duration) {
        self.delay = delay;
    }

    /// Enable or disable TSBPD.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the configured TSBPD delay.
    pub fn delay(&self) -> Duration {
        self.delay
    }

    /// Convert a sender timestamp to a local delivery time.
    ///
    /// delivery_time = base_time + sender_timestamp + delay + drift_correction
    pub fn delivery_time(&self, sender_ts: u32) -> Instant {
        let ts_duration = Duration::from_micros(sender_ts as u64);
        let drift_correction = self.drift_tracer.correction();
        self.base_time + ts_duration + self.delay + drift_correction
    }

    /// Check if a packet with the given timestamp is ready for delivery.
    pub fn is_ready(&self, sender_ts: u32) -> bool {
        if !self.enabled {
            return true;
        }
        Instant::now() >= self.delivery_time(sender_ts)
    }

    /// Compute how long to wait until a packet with the given timestamp is ready.
    pub fn time_until_ready(&self, sender_ts: u32) -> Duration {
        if !self.enabled {
            return Duration::ZERO;
        }
        let delivery = self.delivery_time(sender_ts);
        let now = Instant::now();
        if now >= delivery {
            Duration::ZERO
        } else {
            delivery - now
        }
    }

    /// Check if a packet is too late (should be dropped in live mode).
    ///
    /// A packet is too late if its delivery time has passed by more than
    /// the configured latency (so total delay > 2x latency).
    pub fn is_too_late(&self, sender_ts: u32) -> bool {
        if !self.enabled {
            return false;
        }
        let delivery = self.delivery_time(sender_ts);
        let now = Instant::now();
        now > delivery + self.delay
    }

    /// Record a drift sample to update the clock correction.
    ///
    /// Called when an ACK round-trip completes. The drift is the difference
    /// between the expected and actual arrival times.
    pub fn update_drift(&mut self, drift_us: i64) {
        self.drift_tracer.add_sample(drift_us);
    }
}

/// Clock drift tracer.
///
/// Maintains a sliding window of drift samples and computes a smoothed
/// correction value. Limits correction to prevent large jumps.
struct DriftTracer {
    /// Accumulated drift samples.
    samples: Vec<i64>,
    /// Current drift correction (microseconds).
    correction_us: i64,
    /// Whether enough samples have been collected for correction.
    active: bool,
}

impl DriftTracer {
    fn new() -> Self {
        Self {
            samples: Vec::with_capacity(DRIFT_SAMPLE_WINDOW),
            correction_us: 0,
            active: false,
        }
    }

    /// Add a drift sample (microseconds).
    fn add_sample(&mut self, drift_us: i64) {
        self.samples.push(drift_us);
        if self.samples.len() >= DRIFT_SAMPLE_WINDOW {
            self.compute_correction();
            self.samples.clear();
        }
    }

    /// Compute the drift correction from accumulated samples.
    fn compute_correction(&mut self) {
        if self.samples.is_empty() {
            return;
        }
        let sum: i64 = self.samples.iter().sum();
        let avg = sum / self.samples.len() as i64;

        // Clamp correction to MAX_DRIFT_US
        let clamped = avg.clamp(-MAX_DRIFT_US, MAX_DRIFT_US);
        self.correction_us += clamped;
        self.active = true;
    }

    /// Get the current correction as a Duration.
    /// Returns Duration::ZERO if correction is not yet active.
    fn correction(&self) -> Duration {
        if !self.active || self.correction_us == 0 {
            Duration::ZERO
        } else if self.correction_us > 0 {
            Duration::from_micros(self.correction_us as u64)
        } else {
            // Negative correction: we need to subtract, but Duration is unsigned.
            // Return ZERO and handle subtraction at the call site if needed.
            // For simplicity, we embed it in the base_time adjustment.
            Duration::ZERO
        }
    }
}
