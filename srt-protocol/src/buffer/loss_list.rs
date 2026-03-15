//! Send and receive loss lists for ARQ (Automatic Repeat reQuest).
//!
//! Loss lists track which packets have been reported lost and need
//! retransmission. The send-side list is populated from NAK reports,
//! while the receive-side list tracks gaps detected during reception.

use crate::packet::seq::SeqNo;
use std::collections::BTreeMap;
use std::time::Instant;

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

#[allow(dead_code)]
struct LossEntry {
    /// When the loss was first detected.
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

    /// Get all loss ranges for NAK reporting.
    pub fn get_loss_ranges(&self) -> Vec<(SeqNo, SeqNo)> {
        if self.losses.is_empty() {
            return Vec::new();
        }

        let mut ranges = Vec::new();
        let mut iter = self.losses.keys().copied();
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
