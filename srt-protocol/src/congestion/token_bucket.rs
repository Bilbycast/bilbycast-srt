// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Token Bucket rate limiter for retransmission bandwidth control.
//!
//! Implements `SRTO_MAXREXMITBW` — limits the bandwidth consumed by
//! retransmitted packets so they don't starve new data on lossy links.
//! Uses a classic token bucket algorithm: tokens accumulate at the
//! configured rate, and each retransmitted packet consumes tokens
//! equal to its wire size.

use std::time::Instant;

/// Token bucket rate limiter for retransmission bandwidth.
///
/// Tokens are measured in bytes. The bucket fills at `rate_bytes_per_sec`
/// and holds up to `burst_bytes` tokens. A retransmission is allowed
/// only if enough tokens are available.
#[derive(Debug)]
pub struct TokenBucket {
    /// Maximum retransmission rate in bytes per second. 0 = unlimited.
    rate_bytes_per_sec: i64,
    /// Maximum burst size in bytes (bucket capacity).
    burst_bytes: f64,
    /// Current token count.
    tokens: f64,
    /// Last time tokens were replenished.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    ///
    /// - `rate_bytes_per_sec`: Maximum retransmission bandwidth. Use -1 or 0 for unlimited.
    /// - `mss`: Maximum segment size, used to size the burst bucket.
    pub fn new(rate_bytes_per_sec: i64, mss: u32) -> Self {
        // Burst capacity: at least 2 MSS worth, or 10ms of bandwidth, whichever is larger.
        // This avoids micro-bursts being unnecessarily throttled.
        let burst = if rate_bytes_per_sec > 0 {
            let time_burst = (rate_bytes_per_sec as f64) * 0.01; // 10ms worth
            let min_burst = (mss as f64) * 2.0;
            time_burst.max(min_burst)
        } else {
            f64::MAX
        };

        Self {
            rate_bytes_per_sec,
            burst_bytes: burst,
            tokens: burst, // start full
            last_refill: Instant::now(),
        }
    }

    /// Check if retransmission of `pkt_size` bytes is allowed, consuming tokens if so.
    ///
    /// Returns `true` if the packet can be sent, `false` if the bucket is empty.
    pub fn try_consume(&mut self, pkt_size: usize) -> bool {
        if self.rate_bytes_per_sec <= 0 {
            return true; // unlimited
        }

        self.refill();

        let cost = pkt_size as f64;
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }

    /// Returns `true` if retransmission bandwidth is unlimited (no shaping).
    pub fn is_unlimited(&self) -> bool {
        self.rate_bytes_per_sec <= 0
    }

    /// Update the rate. Takes effect immediately; current tokens are clamped to new burst.
    pub fn set_rate(&mut self, rate_bytes_per_sec: i64, mss: u32) {
        self.refill(); // settle current tokens first
        self.rate_bytes_per_sec = rate_bytes_per_sec;
        if rate_bytes_per_sec > 0 {
            let time_burst = (rate_bytes_per_sec as f64) * 0.01;
            let min_burst = (mss as f64) * 2.0;
            self.burst_bytes = time_burst.max(min_burst);
            self.tokens = self.tokens.min(self.burst_bytes);
        } else {
            self.burst_bytes = f64::MAX;
            self.tokens = f64::MAX;
        }
    }

    /// Refill tokens based on elapsed time since last refill.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        self.last_refill = now;

        let added = (self.rate_bytes_per_sec as f64) * elapsed.as_secs_f64();
        self.tokens = (self.tokens + added).min(self.burst_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_unlimited_always_allows() {
        let mut tb = TokenBucket::new(0, 1500);
        assert!(tb.is_unlimited());
        assert!(tb.try_consume(10000));
        assert!(tb.try_consume(10000));
    }

    #[test]
    fn test_negative_rate_is_unlimited() {
        let mut tb = TokenBucket::new(-1, 1500);
        assert!(tb.is_unlimited());
        assert!(tb.try_consume(10000));
    }

    #[test]
    fn test_rate_limiting() {
        // 1500 bytes/sec rate, MSS=1500 → burst = max(15, 3000) = 3000 bytes
        let mut tb = TokenBucket::new(1500, 1500);
        assert!(!tb.is_unlimited());

        // Bucket starts full with 3000 tokens
        assert!(tb.try_consume(1500)); // 1500 remaining
        assert!(tb.try_consume(1500)); // 0 remaining
        assert!(!tb.try_consume(1500)); // denied
    }

    #[test]
    fn test_refill_over_time() {
        let mut tb = TokenBucket::new(100_000, 1500);
        // Drain the bucket
        while tb.try_consume(1500) {}

        // Manually advance by replacing last_refill
        tb.last_refill = Instant::now() - Duration::from_millis(100);
        // After 100ms at 100KB/s = 10,000 bytes added
        assert!(tb.try_consume(1500));
    }

    #[test]
    fn test_set_rate() {
        let mut tb = TokenBucket::new(0, 1500);
        assert!(tb.is_unlimited());

        tb.set_rate(1000, 1500);
        assert!(!tb.is_unlimited());
    }
}
