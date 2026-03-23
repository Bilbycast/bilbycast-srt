// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
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
    /// Timestamp when this packet was first sent.
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
/// and maintains the retransmission queue.
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

    /// Get a packet by sequence number for sending or retransmission.
    pub fn get_packet(&mut self, seq: SeqNo) -> Option<&mut SendBufferEntry> {
        self.entries.iter_mut().find(|e| e.seq_no == seq)
    }

    /// Acknowledge all packets up to (but not including) the given sequence number.
    /// Returns the number of packets removed.
    pub fn acknowledge(&mut self, ack_seq: SeqNo) -> usize {
        let mut removed = 0;
        while let Some(front) = self.entries.front() {
            if front.seq_no.is_before(ack_seq) || front.seq_no == ack_seq {
                self.entries.pop_front();
                removed += 1;
            } else {
                break;
            }
        }
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

    /// Number of packets currently in the buffer.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether the buffer is full.
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.max_packets
    }

    /// Next sequence number that will be assigned.
    pub fn next_seq_no(&self) -> SeqNo {
        self.next_seq
    }

    /// First unacknowledged sequence number.
    pub fn first_unacked(&self) -> SeqNo {
        self.first_unacked
    }

    /// Number of packets in flight (unacknowledged).
    pub fn in_flight(&self) -> usize {
        self.entries.iter().filter(|e| !e.acked).count()
    }

    /// Peek at the data of the next unsent packet (front of the buffer).
    /// Returns the serialized payload data, or None if empty.
    pub fn peek_next_data(&self) -> Option<Vec<u8>> {
        self.entries.front().map(|e| e.data.to_vec())
    }

    /// Take the next unsent entry from the front of the buffer.
    ///
    /// Removes and returns the front entry, incrementing its send_count.
    /// Unlike `peek_next_data`, this actually dequeues the entry so it
    /// won't be sent again (unless re-inserted for retransmission).
    pub fn take_next_entry(&mut self) -> Option<SendBufferEntry> {
        self.entries.pop_front().map(|mut e| {
            e.send_count += 1;
            e
        })
    }

    /// Drop messages that have expired (TTL exceeded).
    /// Returns the number of packets dropped.
    pub fn drop_expired(&mut self) -> usize {
        let now = Instant::now();
        let before = self.entries.len();
        self.entries.retain(|e| {
            if e.msg_ttl < 0 {
                return true; // No TTL
            }
            let elapsed = now.duration_since(e.origin_time);
            elapsed.as_millis() <= e.msg_ttl as u128
        });
        before - self.entries.len()
    }
}
