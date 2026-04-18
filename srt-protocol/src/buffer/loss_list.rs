// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Send and receive loss lists for ARQ (Automatic Repeat reQuest).
//!
//! Loss lists track which packets have been reported lost and need
//! retransmission. The send-side list is populated from NAK reports,
//! while the receive-side list tracks gaps detected during reception.

use crate::packet::seq::SeqNo;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Send-side loss list.
///
/// Tracks packets reported as lost by the receiver (via NAK).
/// Packets in this list need to be retransmitted.
pub struct SendLossList {
    /// Map from sequence number to the time the loss was reported.
    losses: BTreeMap<i32, Instant>,
}

impl SendLossList {
    pub fn new() -> Self {
        Self {
            losses: BTreeMap::new(),
        }
    }

    /// Insert a single lost sequence number.
    pub fn insert(&mut self, seq: SeqNo) {
        self.losses.insert(seq.value(), Instant::now());
    }

    /// Insert a range of lost sequence numbers.
    pub fn insert_range(&mut self, first: SeqNo, last: SeqNo) {
        let count = SeqNo::offset(first, last);
        for i in 0..=count {
            let seq = first.add(i);
            self.losses.insert(seq.value(), Instant::now());
        }
    }

    /// Remove a sequence number (after retransmission or ACK).
    pub fn remove(&mut self, seq: SeqNo) {
        self.losses.remove(&seq.value());
    }

    /// Remove all sequence numbers up to the given ACK.
    pub fn acknowledge(&mut self, ack_seq: SeqNo) {
        // Remove all entries with seq < ack_seq (considering wrapping)
        let to_remove: Vec<i32> = self
            .losses
            .keys()
            .copied()
            .filter(|&s| SeqNo::new(s).is_before(ack_seq))
            .collect();
        for seq in to_remove {
            self.losses.remove(&seq);
        }
    }

    /// Pop the next loss to retransmit (oldest first).
    pub fn pop_front(&mut self) -> Option<SeqNo> {
        let (&seq, _) = self.losses.iter().next()?;
        self.losses.remove(&seq);
        Some(SeqNo::new(seq))
    }

    /// Peek at the next loss without removing it.
    pub fn peek_front(&self) -> Option<SeqNo> {
        self.losses.keys().next().map(|&s| SeqNo::new(s))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.losses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.losses.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.losses.clear();
    }
}

impl Default for SendLossList {
    fn default() -> Self {
        Self::new()
    }
}

/// Receive-side loss list.
///
/// Tracks gaps in received packet sequences. Used to generate
/// NAK (loss) reports to the sender.
pub struct ReceiveLossList {
    /// Map from sequence number to the time the gap was detected.
    losses: BTreeMap<i32, LossEntry>,
}

struct LossEntry {
    /// When the loss was first detected.
    #[allow(dead_code)]
    detected: Instant,
    /// When the last NAK was sent for this loss.
    last_nak: Instant,
    /// Number of NAKs sent for this loss.
    nak_count: u32,
}

impl ReceiveLossList {
    pub fn new() -> Self {
        Self {
            losses: BTreeMap::new(),
        }
    }

    /// Insert a range of lost sequence numbers.
    pub fn insert_range(&mut self, first: SeqNo, last: SeqNo) {
        let now = Instant::now();
        let count = SeqNo::offset(first, last);
        for i in 0..=count {
            let seq = first.add(i);
            self.losses.entry(seq.value()).or_insert(LossEntry {
                detected: now,
                last_nak: now,
                nak_count: 0,
            });
        }
    }

    /// Remove a sequence number (packet received).
    pub fn remove(&mut self, seq: SeqNo) {
        self.losses.remove(&seq.value());
    }

    /// Remove all entries up to the ACK point.
    pub fn acknowledge(&mut self, ack_seq: SeqNo) {
        let to_remove: Vec<i32> = self
            .losses
            .keys()
            .copied()
            .filter(|&s| SeqNo::new(s).is_before(ack_seq))
            .collect();
        for seq in to_remove {
            self.losses.remove(&seq);
        }
    }

    /// Get loss ranges for NAK reporting, suppressing recently-NAK'd losses.
    ///
    /// Only includes losses whose last NAK was sent more than
    /// `min_nak_interval` ago (or that have never been NAK'd). This
    /// prevents the receiver from flooding the sender with redundant NAKs
    /// for the same packet losses every timer cycle.
    ///
    /// Updates `last_nak` and `nak_count` for all returned entries.
    pub fn get_loss_ranges(&mut self, min_nak_interval: Duration) -> Vec<(SeqNo, SeqNo)> {
        if self.losses.is_empty() {
            return Vec::new();
        }

        let now = Instant::now();

        // Collect sequence numbers eligible for NAK (not recently NAK'd)
        let eligible: Vec<i32> = self
            .losses
            .iter()
            .filter(|(_, entry)| {
                // Include if never NAK'd (nak_count == 0) or enough time has passed
                entry.nak_count == 0 || now.duration_since(entry.last_nak) >= min_nak_interval
            })
            .map(|(&seq, _)| seq)
            .collect();

        if eligible.is_empty() {
            return Vec::new();
        }

        // Mark all eligible entries as NAK'd
        for &seq in &eligible {
            if let Some(entry) = self.losses.get_mut(&seq) {
                entry.last_nak = now;
                entry.nak_count += 1;
            }
        }

        // Coalesce into contiguous ranges
        let mut ranges = Vec::new();
        let mut iter = eligible.iter().copied();
        if let Some(first) = iter.next() {
            let mut range_start = SeqNo::new(first);
            let mut range_end = range_start;

            for seq_val in iter {
                let seq = SeqNo::new(seq_val);
                if SeqNo::offset(range_end, seq) == 1 {
                    range_end = seq;
                } else {
                    ranges.push((range_start, range_end));
                    range_start = seq;
                    range_end = seq;
                }
            }
            ranges.push((range_start, range_end));
        }

        ranges
    }

    /// Number of lost packets tracked.
    pub fn len(&self) -> usize {
        self.losses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.losses.is_empty()
    }

    pub fn clear(&mut self) {
        self.losses.clear();
    }
}

impl Default for ReceiveLossList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_losses_always_eligible() {
        let mut list = ReceiveLossList::new();
        list.insert_range(SeqNo::new(10), SeqNo::new(14));

        // First call: all 5 losses should be eligible (nak_count == 0)
        let ranges = list.get_loss_ranges(Duration::from_secs(999));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (SeqNo::new(10), SeqNo::new(14)));
    }

    #[test]
    fn test_suppression_within_interval() {
        let mut list = ReceiveLossList::new();
        list.insert_range(SeqNo::new(10), SeqNo::new(12));

        // First NAK: eligible
        let ranges = list.get_loss_ranges(Duration::from_secs(10));
        assert_eq!(ranges.len(), 1);

        // Immediately after: suppressed (nak_count > 0, interval not elapsed)
        let ranges = list.get_loss_ranges(Duration::from_secs(10));
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_re_eligible_after_interval() {
        let mut list = ReceiveLossList::new();
        list.insert_range(SeqNo::new(10), SeqNo::new(10));

        // First NAK
        let ranges = list.get_loss_ranges(Duration::from_millis(1));
        assert_eq!(ranges.len(), 1);

        // Wait longer than suppression interval
        std::thread::sleep(Duration::from_millis(5));

        // Should be eligible again
        let ranges = list.get_loss_ranges(Duration::from_millis(1));
        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn test_removed_losses_not_reported() {
        let mut list = ReceiveLossList::new();
        list.insert_range(SeqNo::new(10), SeqNo::new(14));

        // Remove one entry
        list.remove(SeqNo::new(12));
        assert_eq!(list.len(), 4);

        let ranges = list.get_loss_ranges(Duration::from_secs(0));
        // Should get two ranges: 10-11 and 13-14
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], (SeqNo::new(10), SeqNo::new(11)));
        assert_eq!(ranges[1], (SeqNo::new(13), SeqNo::new(14)));
    }

    #[test]
    fn test_acknowledge_clears_old_entries() {
        let mut list = ReceiveLossList::new();
        list.insert_range(SeqNo::new(10), SeqNo::new(20));

        list.acknowledge(SeqNo::new(15));
        // Entries 10-14 should be removed
        assert_eq!(list.len(), 6); // 15-20

        let ranges = list.get_loss_ranges(Duration::from_secs(0));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (SeqNo::new(15), SeqNo::new(20)));
    }

    #[test]
    fn test_insert_preserves_existing_entries() {
        let mut list = ReceiveLossList::new();
        list.insert_range(SeqNo::new(10), SeqNo::new(12));

        // NAK them (sets nak_count=1)
        let _ = list.get_loss_ranges(Duration::from_secs(0));

        // Re-insert overlapping range — existing entries should keep nak_count=1
        list.insert_range(SeqNo::new(11), SeqNo::new(14));

        // With a very long suppression, only the NEW entries (13-14) should be eligible
        let ranges = list.get_loss_ranges(Duration::from_secs(999));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], (SeqNo::new(13), SeqNo::new(14)));
    }
}
