//! Receive buffer with TSBPD delivery and packet reordering.
//!
//! Incoming packets are inserted by sequence number into a circular buffer.
//! Packets are delivered to the application in order, respecting the TSBPD
//! delivery time calculated from the packet timestamp and configured latency.

use bytes::{Bytes, BytesMut};
use std::time::Instant;

use crate::packet::header::PacketBoundary;
use crate::packet::msg::MsgNo;
use crate::packet::seq::SeqNo;
use crate::protocol::tsbpd::TsbpdTime;

/// State of a slot in the receive buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotState {
    /// Slot is empty (packet not yet received).
    Empty,
    /// Slot contains a valid packet.
    Valid,
    /// Slot was read by the application.
    Read,
    /// Slot was dropped (too late).
    Dropped,
}

/// An entry in the receive buffer.
#[derive(Debug, Clone)]
pub struct ReceiveEntry {
    /// Packet payload.
    pub data: Bytes,
    /// Sequence number.
    pub seq_no: SeqNo,
    /// Message number.
    pub msg_no: MsgNo,
    /// Packet boundary.
    pub boundary: PacketBoundary,
    /// Sender timestamp.
    pub timestamp: u32,
    /// Whether in-order delivery is required.
    pub in_order: bool,
    /// Slot state.
    pub state: SlotState,
    /// Local arrival time.
    pub arrival_time: Instant,
}

/// Receive buffer with circular storage and TSBPD delivery.
///
/// Maps to C++ `CRcvBuffer`. Stores received packets in a circular
/// buffer indexed by sequence number. Delivers packets to the
/// application in order, respecting TSBPD timing.
pub struct ReceiveBuffer {
    /// Circular buffer of receive entries.
    entries: Vec<Option<ReceiveEntry>>,
    /// Buffer capacity in packets.
    capacity: usize,
    /// Start position (index of the first unread packet).
    start_pos: usize,
    /// Start sequence number (maps to start_pos).
    start_seq: SeqNo,
    /// Number of valid (unread) packets.
    valid_count: usize,
}

impl ReceiveBuffer {
    pub fn new(capacity: usize, initial_seq: SeqNo) -> Self {
        let mut entries = Vec::with_capacity(capacity);
        entries.resize_with(capacity, || None);
        Self {
            entries,
            capacity,
            start_pos: 0,
            start_seq: initial_seq,
            valid_count: 0,
        }
    }

    /// Insert a received packet into the buffer.
    ///
    /// Returns true if the packet was successfully inserted (not a duplicate).
    pub fn insert(
        &mut self,
        seq_no: SeqNo,
        msg_no: MsgNo,
        boundary: PacketBoundary,
        timestamp: u32,
        in_order: bool,
        data: Bytes,
    ) -> bool {
        let offset = SeqNo::offset(self.start_seq, seq_no);
        if offset < 0 || offset as usize >= self.capacity {
            return false; // Out of buffer range
        }

        let pos = (self.start_pos + offset as usize) % self.capacity;

        // Check for duplicate
        if self.entries[pos].is_some() {
            return false;
        }

        self.entries[pos] = Some(ReceiveEntry {
            data,
            seq_no,
            msg_no,
            boundary,
            timestamp,
            in_order,
            state: SlotState::Valid,
            arrival_time: Instant::now(),
        });
        self.valid_count += 1;
        true
    }

    /// Read the next available message from the buffer.
    ///
    /// In message mode, returns a complete message (all packets from First to Last
    /// or a Solo packet). In stream mode, returns whatever contiguous data is available.
    ///
    /// If `tsbpd` is provided, only returns data whose delivery time has arrived.
    pub fn read_message(&mut self, tsbpd: Option<&TsbpdTime>) -> Option<Bytes> {
        // Find the first valid entry
        let first = self.entries[self.start_pos].as_ref()?;

        // Check TSBPD readiness
        if let Some(tsbpd) = tsbpd {
            if !tsbpd.is_ready(first.timestamp) {
                return None;
            }
        }

        match first.boundary {
            PacketBoundary::Solo => {
                let entry = self.entries[self.start_pos].take()?;
                self.advance_start(1);
                self.valid_count -= 1;
                Some(entry.data)
            }
            PacketBoundary::First => {
                // Look for all packets until Last
                let mut msg = BytesMut::new();
                let mut count = 0;
                let msg_no = first.msg_no;

                loop {
                    let pos = (self.start_pos + count) % self.capacity;
                    match &self.entries[pos] {
                        Some(entry) if entry.msg_no == msg_no => {
                            msg.extend_from_slice(&entry.data);
                            count += 1;
                            if entry.boundary == PacketBoundary::Last
                                || entry.boundary == PacketBoundary::Solo
                            {
                                break;
                            }
                        }
                        _ => return None, // Message incomplete
                    }
                }

                // Remove all packets of this message
                for i in 0..count {
                    let pos = (self.start_pos + i) % self.capacity;
                    self.entries[pos] = None;
                    self.valid_count -= 1;
                }
                self.advance_start(count);
                Some(msg.freeze())
            }
            _ => {
                // Subsequent or Last without First: skip/drop
                self.entries[self.start_pos] = None;
                self.valid_count -= 1;
                self.advance_start(1);
                None
            }
        }
    }

    /// Read available data in stream mode (returns contiguous bytes).
    pub fn read_stream(&mut self, max_len: usize) -> Bytes {
        let mut result = BytesMut::new();
        let mut count = 0;

        while result.len() < max_len {
            let pos = (self.start_pos + count) % self.capacity;
            match &self.entries[pos] {
                Some(entry) if entry.state == SlotState::Valid => {
                    let remaining = max_len - result.len();
                    let to_copy = entry.data.len().min(remaining);
                    result.extend_from_slice(&entry.data[..to_copy]);
                    count += 1;
                }
                _ => break,
            }
        }

        // Mark read entries
        for i in 0..count {
            let pos = (self.start_pos + i) % self.capacity;
            self.entries[pos] = None;
            self.valid_count -= 1;
        }
        if count > 0 {
            self.advance_start(count);
        }

        result.freeze()
    }

    /// Drop packets that are too late for delivery.
    /// Returns the number of packets dropped.
    pub fn drop_too_late(&mut self, tsbpd: &TsbpdTime) -> usize {
        let mut dropped = 0;
        loop {
            let pos = self.start_pos;
            match &self.entries[pos] {
                Some(entry) if tsbpd.is_too_late(entry.timestamp) => {
                    self.entries[pos] = None;
                    self.valid_count -= 1;
                    self.advance_start(1);
                    dropped += 1;
                }
                None => {
                    // Gap - check if the next valid entry is too late
                    // and skip the gap
                    let mut found_late = false;
                    for offset in 1..self.capacity {
                        let check_pos = (self.start_pos + offset) % self.capacity;
                        if let Some(entry) = &self.entries[check_pos] {
                            if tsbpd.is_too_late(entry.timestamp) {
                                found_late = true;
                            }
                            break;
                        }
                    }
                    if found_late {
                        self.advance_start(1);
                        dropped += 1;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
        dropped
    }

    fn advance_start(&mut self, count: usize) {
        self.start_pos = (self.start_pos + count) % self.capacity;
        self.start_seq = self.start_seq.add(count as i32);
    }

    /// Get the ACK sequence number (first unacknowledged gap).
    pub fn ack_seq(&self) -> SeqNo {
        let mut offset = 0;
        while offset < self.capacity {
            let pos = (self.start_pos + offset) % self.capacity;
            if self.entries[pos].is_none() {
                break;
            }
            offset += 1;
        }
        self.start_seq.add(offset as i32)
    }

    /// Get the list of missing sequence numbers (for NAK generation).
    pub fn get_loss_list(&self) -> Vec<(SeqNo, SeqNo)> {
        let mut losses = Vec::new();
        let mut i = 0;
        while i < self.capacity {
            let pos = (self.start_pos + i) % self.capacity;
            if self.entries[pos].is_none() {
                let range_start = self.start_seq.add(i as i32);
                let mut range_end = range_start;
                i += 1;
                while i < self.capacity {
                    let pos = (self.start_pos + i) % self.capacity;
                    if self.entries[pos].is_some() {
                        break;
                    }
                    range_end = self.start_seq.add(i as i32);
                    i += 1;
                }
                losses.push((range_start, range_end));
            } else {
                i += 1;
            }
        }
        losses
    }

    /// Number of valid packets in the buffer.
    pub fn len(&self) -> usize {
        self.valid_count
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.valid_count == 0
    }

    /// Available space in the buffer.
    pub fn available(&self) -> usize {
        self.capacity - self.valid_count
    }
}
