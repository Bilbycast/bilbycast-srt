// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Send buffer with message segmentation and retransmission.
//!
//! Messages submitted by the application are segmented into MTU-sized packets,
//! stored with their sequence numbers, and held until acknowledged by the receiver.
//! Lost packets (reported via NAK) are retransmitted from this buffer.

use bytes::Bytes;
use std::collections::VecDeque;
use std::time::Instant;

use crate::packet::header::PacketBoundary;
use crate::packet::msg::MsgNo;
use crate::packet::seq::SeqNo;

/// An entry in the send buffer representing one packet.
#[derive(Debug, Clone)]
pub struct SendBufferEntry {
    /// Packet payload data.
    pub data: Bytes,
    /// Sequence number assigned to this packet.
    pub seq_no: SeqNo,
    /// Message number this packet belongs to.
    pub msg_no: MsgNo,
    /// Packet boundary (Solo, First, Subsequent, Last).
    pub boundary: PacketBoundary,
    /// Wall-clock instant at which this packet was queued in the send
    /// buffer. Used for the time-to-live (TTL) drop check and for
    /// initialising [`origin_time`] before the packet is first sent.
    pub queue_time: Instant,
    /// Wall-clock instant at which this packet was first handed to
    /// `mux.send_to`. Set on the first call to [`SendBuffer::next_packet`]
    /// and re-used for retransmissions, so the SRT data packet timestamp
    /// (`origin_time - conn.start_time`) reflects the actual moment the
    /// packet hit the wire — matching what libsrt's TSBPD drift tracer
    /// expects (Bug B in the 2026-04-09 test report).
    ///
    /// Before the first send this field equals `queue_time`. After the
    /// first send it never changes (so retransmissions of the same
    /// `seq_no` carry the same wire timestamp as the original send,
    /// per the SRT live-mode spec).
    pub origin_time: Instant,
    /// Whether in-order delivery is required.
    pub in_order: bool,
    /// Time-to-live for the message (ms), -1 for unlimited.
    pub msg_ttl: i32,
    /// Number of times this packet has been sent.
    pub send_count: u32,
    /// Whether this packet has been acknowledged.
    pub acked: bool,
}

/// Send buffer for managing outgoing data.
///
/// Maps to C++ `CSndBuffer`. Handles message-to-packet segmentation
/// and maintains the retransmission queue. Packets remain in the buffer
/// until acknowledged — a send cursor tracks the next unsent position.
pub struct SendBuffer {
    /// Ring buffer of packet entries.
    entries: VecDeque<SendBufferEntry>,
    /// Maximum buffer size in packets.
    max_packets: usize,
    /// Maximum payload size per packet.
    max_payload_size: usize,
    /// Next sequence number to assign.
    next_seq: SeqNo,
    /// Next message number to assign.
    next_msg: MsgNo,
    /// First unacknowledged sequence number.
    first_unacked: SeqNo,
    /// Cursor into entries: index of next packet to send for the first time.
    /// Packets before this index have already been sent (but remain for retransmission).
    send_cursor: usize,
}

impl SendBuffer {
    pub fn new(max_packets: usize, max_payload_size: usize, initial_seq: SeqNo) -> Self {
        Self {
            entries: VecDeque::with_capacity(max_packets),
            max_packets,
            max_payload_size,
            next_seq: initial_seq,
            next_msg: MsgNo::new(1),
            first_unacked: initial_seq,
            send_cursor: 0,
        }
    }

    /// Add a message to the send buffer, segmenting into packets.
    ///
    /// Returns the number of packets created, or None if the buffer is full.
    pub fn add_message(&mut self, data: &[u8], ttl: i32, in_order: bool) -> Option<usize> {
        let payload_size = if self.max_payload_size > 0 {
            self.max_payload_size
        } else {
            data.len()
        };

        let num_packets = if data.is_empty() {
            1
        } else {
            (data.len() + payload_size - 1) / payload_size
        };

        if self.entries.len() + num_packets > self.max_packets {
            return None;
        }

        let msg_no = self.next_msg;
        self.next_msg = msg_no.increment();
        let now = Instant::now();

        if data.is_empty() {
            // Empty solo message
            self.entries.push_back(SendBufferEntry {
                data: Bytes::new(),
                seq_no: self.next_seq,
                msg_no,
                boundary: PacketBoundary::Solo,
                queue_time: now,
                origin_time: now,
                in_order,
                msg_ttl: ttl,
                send_count: 0,
                acked: false,
            });
            self.next_seq = self.next_seq.increment();
        } else {
            let chunks: Vec<Bytes> = data
                .chunks(payload_size)
                .map(|c| Bytes::copy_from_slice(c))
                .collect();
            let last_idx = chunks.len() - 1;

            for (i, chunk) in chunks.into_iter().enumerate() {
                let boundary = if last_idx == 0 {
                    PacketBoundary::Solo
                } else if i == 0 {
                    PacketBoundary::First
                } else if i == last_idx {
                    PacketBoundary::Last
                } else {
                    PacketBoundary::Subsequent
                };

                self.entries.push_back(SendBufferEntry {
                    data: chunk,
                    seq_no: self.next_seq,
                    msg_no,
                    boundary,
                    queue_time: now,
                    origin_time: now,
                    in_order,
                    msg_ttl: ttl,
                    send_count: 0,
                    acked: false,
                });
                self.next_seq = self.next_seq.increment();
            }
        }

        Some(num_packets)
    }

    /// Get the next unsent packet and advance the cursor.
    /// The packet remains in the buffer for potential retransmission.
    /// Returns a clone of the entry (with `send_count` incremented and
    /// `origin_time` stamped at the moment of first dispatch — see the
    /// `origin_time` field doc for the rationale). Retransmissions
    /// reuse this same `origin_time` so the SRT data packet timestamp
    /// is identical on every wire copy of the same `seq_no`.
    pub fn next_packet(&mut self) -> Option<SendBufferEntry> {
        if self.send_cursor >= self.entries.len() {
            return None;
        }
        let entry = &mut self.entries[self.send_cursor];
        entry.send_count += 1;
        entry.origin_time = Instant::now();
        let result = entry.clone();
        self.send_cursor += 1;
        Some(result)
    }

    /// Whether there are unsent packets ready to send.
    pub fn has_unsent(&self) -> bool {
        self.send_cursor < self.entries.len()
    }

    /// Get a packet by sequence number for retransmission.
    /// Increments send_count and returns a clone.
    pub fn get_packet_for_retransmit(&mut self, seq: SeqNo) -> Option<SendBufferEntry> {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.seq_no == seq) {
            entry.send_count += 1;
            Some(entry.clone())
        } else {
            None
        }
    }

    /// Get a mutable reference to a packet by sequence number.
    pub fn get_packet(&mut self, seq: SeqNo) -> Option<&mut SendBufferEntry> {
        self.entries.iter_mut().find(|e| e.seq_no == seq)
    }

    /// Acknowledge all packets up to (but not including) the given sequence number.
    /// Returns the number of packets removed.
    pub fn acknowledge(&mut self, ack_seq: SeqNo) -> usize {
        let mut removed = 0;
        while let Some(front) = self.entries.front() {
            if front.seq_no.is_before(ack_seq) {
                self.entries.pop_front();
                removed += 1;
            } else {
                break;
            }
        }
        // Adjust send_cursor since we removed entries from the front
        self.send_cursor = self.send_cursor.saturating_sub(removed);
        if ack_seq.is_after(self.first_unacked) {
            self.first_unacked = ack_seq;
        }
        removed
    }

    /// Get packets that need retransmission (from loss list).
    pub fn get_retransmit_packets(&self, loss_list: &[SeqNo]) -> Vec<&SendBufferEntry> {
        loss_list
            .iter()
            .filter_map(|seq| self.entries.iter().find(|e| e.seq_no == *seq))
            .collect()
    }

    /// Number of packets currently in the buffer (sent + unsent, awaiting ACK).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer has no packets at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the buffer is full.
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.max_packets
    }

    /// Maximum buffer capacity in packets.
    pub fn max_packets(&self) -> usize {
        self.max_packets
    }

    /// Next sequence number that will be assigned.
    pub fn next_seq_no(&self) -> SeqNo {
        self.next_seq
    }

    /// First unacknowledged sequence number.
    pub fn first_unacked(&self) -> SeqNo {
        self.first_unacked
    }

    /// Number of packets in flight (sent but unacknowledged).
    pub fn in_flight(&self) -> usize {
        self.entries.iter().filter(|e| !e.acked && e.send_count > 0).count()
    }

    /// Peek at the data of the next unsent packet.
    /// Returns the serialized payload data, or None if no unsent packets.
    pub fn peek_next_data(&self) -> Option<Vec<u8>> {
        if self.send_cursor < self.entries.len() {
            Some(self.entries[self.send_cursor].data.to_vec())
        } else {
            None
        }
    }

    /// Drop messages that have expired (TTL exceeded).
    /// Returns the number of packets dropped.
    pub fn drop_expired(&mut self) -> usize {
        let now = Instant::now();
        let before = self.entries.len();

        // Count how many entries before send_cursor will be removed
        let cursor_adjust: usize = self.entries.iter().take(self.send_cursor).filter(|e| {
            if e.msg_ttl < 0 {
                return false; // kept, no adjustment
            }
            let elapsed = now.duration_since(e.queue_time);
            elapsed.as_millis() > e.msg_ttl as u128
        }).count();

        self.entries.retain(|e| {
            if e.msg_ttl < 0 {
                return true; // No TTL
            }
            let elapsed = now.duration_since(e.queue_time);
            elapsed.as_millis() <= e.msg_ttl as u128
        });

        self.send_cursor = self.send_cursor.saturating_sub(cursor_adjust);
        before - self.entries.len()
    }

    /// Drop expired messages and return info for DropReq packets.
    /// Each returned tuple is (msg_no as i32, first_seq, last_seq).
    pub fn drop_expired_with_info(&mut self) -> Vec<(i32, SeqNo, SeqNo)> {
        let now = Instant::now();
        let mut dropped_msgs: Vec<(i32, SeqNo, SeqNo)> = Vec::new();

        // Identify expired entries and group by message number
        let mut expired_seqs: Vec<(MsgNo, SeqNo)> = Vec::new();
        for e in &self.entries {
            if e.msg_ttl >= 0 {
                let elapsed = now.duration_since(e.queue_time);
                if elapsed.as_millis() > e.msg_ttl as u128 {
                    expired_seqs.push((e.msg_no, e.seq_no));
                }
            }
        }

        // Group by message number to build DropReq ranges
        if !expired_seqs.is_empty() {
            let mut current_msg = expired_seqs[0].0;
            let mut first_seq = expired_seqs[0].1;
            let mut last_seq = expired_seqs[0].1;

            for &(msg, seq) in &expired_seqs[1..] {
                if msg == current_msg {
                    last_seq = seq;
                } else {
                    dropped_msgs.push((current_msg.value() as i32, first_seq, last_seq));
                    current_msg = msg;
                    first_seq = seq;
                    last_seq = seq;
                }
            }
            dropped_msgs.push((current_msg.value() as i32, first_seq, last_seq));
        }

        // Now actually remove them
        if !expired_seqs.is_empty() {
            let cursor_adjust: usize = self.entries.iter().take(self.send_cursor).filter(|e| {
                if e.msg_ttl < 0 { return false; }
                now.duration_since(e.queue_time).as_millis() > e.msg_ttl as u128
            }).count();

            self.entries.retain(|e| {
                if e.msg_ttl < 0 { return true; }
                now.duration_since(e.queue_time).as_millis() <= e.msg_ttl as u128
            });
            self.send_cursor = self.send_cursor.saturating_sub(cursor_adjust);
        }

        dropped_msgs
    }
}
