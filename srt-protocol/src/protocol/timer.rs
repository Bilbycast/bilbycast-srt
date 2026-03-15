//! SRT protocol timers.
//!
//! Manages periodic events: ACK generation (10ms), NAK retransmission,
//! keepalive (1s), and connection expiration. Maps to the C++ timer
//! management in `CUDT::checkTimers`.

use std::time::{Duration, Instant};

/// SRT protocol timing constants (in microseconds).

/// ACK period (10ms).
pub const COMM_SYN_INTERVAL_US: u64 = 10_000;

/// Keep-alive period (1 second).
pub const COMM_KEEPALIVE_PERIOD_US: u64 = 1_000_000;

/// Initial RTT estimate (100ms).
pub const INITIAL_RTT_US: i32 = 100_000;

/// Initial RTT variance (50ms).
pub const INITIAL_RTTVAR_US: i32 = 50_000;

/// Maximum expiration counter before connection timeout.
pub const COMM_RESPONSE_MAX_EXP: u32 = 16;

/// Minimum TSBPD threshold for packet drop (1000ms).
pub const SRT_TLPKTDROP_MINTHRESHOLD_MS: u32 = 1000;

/// A periodic timer that fires at a configurable interval.
#[derive(Debug)]
pub struct PeriodicTimer {
    interval: Duration,
    next_fire: Instant,
}

impl PeriodicTimer {
    pub fn new(interval: Duration) -> Self {
        let now = Instant::now();
        Self {
            interval,
            next_fire: now + interval,
        }
    }

    /// Check if the timer has fired. If so, advance it and return true.
    pub fn check(&mut self) -> bool {
        let now = Instant::now();
        if now >= self.next_fire {
            self.next_fire = now + self.interval;
            true
        } else {
            false
        }
    }

    /// Reset the timer to fire after one interval from now.
    pub fn reset(&mut self) {
        self.next_fire = Instant::now() + self.interval;
    }

    /// Time remaining until next fire.
    pub fn time_remaining(&self) -> Duration {
        let now = Instant::now();
        if now >= self.next_fire {
            Duration::ZERO
        } else {
            self.next_fire - now
        }
    }

    /// Update the timer interval.
    pub fn set_interval(&mut self, interval: Duration) {
        self.interval = interval;
    }
}

/// Collection of SRT protocol timers.
pub struct SrtTimers {
    /// ACK timer (10ms).
    pub ack: PeriodicTimer,
    /// NAK timer (dynamically adjusted based on RTT).
    pub nak: PeriodicTimer,
    /// Keep-alive timer (1s).
    pub keepalive: PeriodicTimer,
    /// Expiration (connection timeout) counter.
    pub exp_count: u32,
    /// Last response time from peer.
    pub last_response: Instant,
    /// Smoothed RTT (microseconds).
    pub srtt: i32,
    /// RTT variance (microseconds).
    pub rttvar: i32,
}

impl SrtTimers {
    pub fn new() -> Self {
        Self {
            ack: PeriodicTimer::new(Duration::from_micros(COMM_SYN_INTERVAL_US)),
            nak: PeriodicTimer::new(Duration::from_micros(COMM_SYN_INTERVAL_US * 3)),
            keepalive: PeriodicTimer::new(Duration::from_micros(COMM_KEEPALIVE_PERIOD_US)),
            exp_count: 1,
            last_response: Instant::now(),
            srtt: INITIAL_RTT_US,
            rttvar: INITIAL_RTTVAR_US,
        }
    }

    /// Update RTT estimates using the TCP-like EWMA algorithm.
    ///
    /// SRTT = (7/8) * SRTT + (1/8) * sample
    /// RTTVAR = (3/4) * RTTVAR + (1/4) * |SRTT - sample|
    pub fn update_rtt(&mut self, rtt_sample_us: i32) {
        let diff = (self.srtt - rtt_sample_us).abs();
        self.rttvar = (self.rttvar * 3 + diff) / 4;
        self.srtt = (self.srtt * 7 + rtt_sample_us) / 8;

        // Update NAK timer based on new RTT
        let nak_interval = self.nak_interval();
        self.nak.set_interval(nak_interval);
    }

    /// Compute the NAK reporting interval based on RTT.
    /// NAK interval = RTT + 4 * RTTVar, minimum 20ms.
    pub fn nak_interval(&self) -> Duration {
        let interval_us = (self.srtt + 4 * self.rttvar).max(20_000) as u64;
        Duration::from_micros(interval_us)
    }

    /// Compute the EXP (expiration/timeout) interval.
    /// EXP = (SRTT + 4 * RTTVar + SYN) * 2^exp_count
    pub fn exp_interval(&self) -> Duration {
        let base = (self.srtt + 4 * self.rttvar + COMM_SYN_INTERVAL_US as i32) as u64;
        let scaled = base.saturating_mul(1u64 << self.exp_count.min(16));
        Duration::from_micros(scaled.max(COMM_KEEPALIVE_PERIOD_US))
    }

    /// Record that a response was received from the peer.
    pub fn on_response_received(&mut self) {
        self.last_response = Instant::now();
        self.exp_count = 1;
    }

    /// Check if the connection has timed out.
    pub fn is_expired(&self) -> bool {
        self.exp_count > COMM_RESPONSE_MAX_EXP
    }
}

impl Default for SrtTimers {
    fn default() -> Self {
        Self::new()
    }
}
