// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

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
    /// Slot holds an FEC packet placeholder — counted as received for ACK
    /// continuity but not deliverable to the application. This matches libsrt
    /// behavior where FEC packets occupy receive buffer slots for ACK tracking
    /// but are processed by the FEC decoder, not the application.
    FecPlaceholder,
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
    /// Highest sequence number received from the network (data or FEC).
    /// Used to cap `ack_seq()` so it never exceeds what the sender actually sent.
    /// FEC recovery can fill in gaps and make the contiguous range appear to
    /// extend beyond the sender's current position — the cap prevents this.
    highest_recv_seq: Option<SeqNo>,
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
            highest_recv_seq: None,
        }
    }

    /// Reset the starting sequence number (used after handshake to set peer's ISN).
    pub fn set_start_seq(&mut self, seq: SeqNo) {
        self.start_seq = seq;
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

    /// Insert an FEC placeholder at the given sequence number.
    ///
    /// FEC packets occupy sequence number slots but are not deliverable to the
    /// application. The placeholder ensures `ack_seq()` counts the slot as
    /// received (no gap in the contiguous sequence) and `get_loss_list()` does
    /// not report it as missing. `read_message()` skips over placeholders.
    pub fn insert_fec_placeholder(&mut self, seq_no: SeqNo, timestamp: u32) -> bool {
        let offset = SeqNo::offset(self.start_seq, seq_no);
        if offset < 0 || offset as usize >= self.capacity {
            return false;
        }
        let pos = (self.start_pos + offset as usize) % self.capacity;
        if self.entries[pos].is_some() {
            return false; // Already occupied
        }
        self.entries[pos] = Some(ReceiveEntry {
            data: Bytes::new(),
            seq_no,
            msg_no: MsgNo::new(0),
            boundary: PacketBoundary::Solo,
            timestamp,
            in_order: false,
            state: SlotState::FecPlaceholder,
            arrival_time: Instant::now(),
        });
        // Don't increment valid_count — FEC placeholders are not deliverable data
        true
    }

    /// Read the next available message from the buffer.
    ///
    /// In message mode, returns a complete message (all packets from First to Last
    /// or a Solo packet). In stream mode, returns whatever contiguous data is available.
    ///
    /// If `tsbpd` is provided, only returns data whose delivery time has arrived.
    pub fn read_message(&mut self, tsbpd: Option<&TsbpdTime>) -> Option<Bytes> {
        // Skip FEC placeholders at the head of the buffer — they occupy sequence
        // slots for ACK tracking but are not deliverable data.
        while let Some(entry) = &self.entries[self.start_pos] {
            if entry.state == SlotState::FecPlaceholder {
                self.entries[self.start_pos] = None;
                self.advance_start(1);
            } else {
                break;
            }
        }

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
        // Skip FEC placeholders at the head
        while let Some(entry) = &self.entries[self.start_pos] {
            if entry.state == SlotState::FecPlaceholder {
                self.entries[self.start_pos] = None;
                self.advance_start(1);
            } else {
                break;
            }
        }

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
                    let is_fec = entry.state == SlotState::FecPlaceholder;
                    self.entries[pos] = None;
                    if !is_fec {
                        self.valid_count -= 1;
                    }
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

    /// Drop a range of packets by sequence number (used for DropReq from sender).
    /// Returns the number of packets actually dropped.
    pub fn drop_range(&mut self, first: SeqNo, last: SeqNo) -> usize {
        let mut dropped = 0;
        let count = SeqNo::offset(first, last) + 1;
        for i in 0..count {
            let seq = first.add(i);
            let offset = SeqNo::offset(self.start_seq, seq);
            if offset >= 0 && (offset as usize) < self.capacity {
                let pos = (self.start_pos + offset as usize) % self.capacity;
                if let Some(entry) = &self.entries[pos] {
                    let is_fec = entry.state == SlotState::FecPlaceholder;
                    self.entries[pos] = None;
                    if !is_fec {
                        self.valid_count -= 1;
                    }
                    dropped += 1;
                }
            }
        }
        dropped
    }

    fn advance_start(&mut self, count: usize) {
        self.start_pos = (self.start_pos + count) % self.capacity;
        self.start_seq = self.start_seq.add(count as i32);
    }

    /// Update the highest sequence number received from the network.
    /// Call this for every data packet and FEC packet received from the peer
    /// (but NOT for FEC-recovered packets, which fill in earlier gaps).
    pub fn update_highest_recv(&mut self, seq: SeqNo) {
        match self.highest_recv_seq {
            Some(h) if seq.is_after(h) => self.highest_recv_seq = Some(seq),
            None => self.highest_recv_seq = Some(seq),
            _ => {}
        }
    }

    /// Get the ACK sequence number (first unacknowledged gap).
    ///
    /// The result is capped at `highest_recv_seq + 1` to prevent FEC recovery
    /// from inflating the ACK beyond what the sender actually sent. Without
    /// this cap, FEC-recovered packets can make the contiguous range appear
    /// to extend past the sender's current sequence, triggering libsrt's
    /// "ATTACK/IPE: incoming ack seq exceeds current" error.
    pub fn ack_seq(&self) -> SeqNo {
        let mut offset = 0;
        while offset < self.capacity {
            let pos = (self.start_pos + offset) % self.capacity;
            if self.entries[pos].is_none() {
                break;
            }
            offset += 1;
        }
        let raw_ack = self.start_seq.add(offset as i32);

        // Cap at highest_recv_seq + 1 so we never ACK beyond what was sent
        if let Some(highest) = self.highest_recv_seq {
            let max_ack = highest.increment();
            if raw_ack.is_after(max_ack) {
                return max_ack;
            }
        }
        raw_ack
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

    /// Check if a packet with the given sequence number is in the buffer.
    pub fn has_packet(&self, seq: SeqNo) -> bool {
        let offset = SeqNo::offset(self.start_seq, seq);
        if offset < 0 || offset as usize >= self.capacity {
            return false;
        }
        let pos = (self.start_pos + offset as usize) % self.capacity;
        self.entries[pos].is_some()
    }
}
