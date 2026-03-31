// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT control packet types and payloads.
//!
//! Control packets handle connection management (handshake, keepalive, shutdown),
//! reliability (ACK, NAK, ACKACK), and flow control (drop request).

use super::header::*;
use super::seq::SeqNo;
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// UDT/SRT control message types.
///
/// These match the C++ `UDTMessageType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ControlType {
    Handshake = 0,
    Keepalive = 1,
    Ack = 2,
    Nak = 3,
    CongestionWarning = 4,
    Shutdown = 5,
    AckAck = 6,
    DropReq = 7,
    PeerError = 8,
    /// User-defined extension type.
    UserDefined = 0x7FFF,
}

impl ControlType {
    pub fn from_value(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::Handshake),
            1 => Some(Self::Keepalive),
            2 => Some(Self::Ack),
            3 => Some(Self::Nak),
            4 => Some(Self::CongestionWarning),
            5 => Some(Self::Shutdown),
            6 => Some(Self::AckAck),
            7 => Some(Self::DropReq),
            8 => Some(Self::PeerError),
            0x7FFF => Some(Self::UserDefined),
            _ => None,
        }
    }
}

/// SRT handshake extension command types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SrtExtType {
    Reject = 0,
    HsReq = 1,
    HsRsp = 2,
    KmReq = 3,
    KmRsp = 4,
    Sid = 5,
    Congestion = 6,
    Filter = 7,
    Group = 8,
}

impl SrtExtType {
    pub fn from_value(val: u16) -> Option<Self> {
        match val {
            0 => Some(Self::Reject),
            1 => Some(Self::HsReq),
            2 => Some(Self::HsRsp),
            3 => Some(Self::KmReq),
            4 => Some(Self::KmRsp),
            5 => Some(Self::Sid),
            6 => Some(Self::Congestion),
            7 => Some(Self::Filter),
            8 => Some(Self::Group),
            _ => None,
        }
    }
}

/// Acknowledgement packet data.
///
/// Sent periodically from receiver to sender to indicate successful reception.
/// Field order matches SRT spec (ACKD_* indices in libsrt):
///   0: Last ACK Seq No, 1: RTT, 2: RTT Var, 3: Available Buffer Size (packets),
///   4: Packets Receiving Rate, 5: Estimated Link Capacity, 6: Receiving Rate (bytes/s)
#[derive(Debug, Clone)]
pub struct AckData {
    /// The sequence number up to which all packets have been received.
    pub ack_seq: SeqNo,
    /// Round-trip time in microseconds.
    pub rtt: Option<i32>,
    /// RTT variance in microseconds.
    pub rtt_var: Option<i32>,
    /// ACKD_BUFFERLEFT: Available receiver buffer size in packets.
    /// This is the peer's advertised flow window — used by the sender
    /// to gate how many packets can be in flight.
    pub available_buf_size: Option<i32>,
    /// ACKD_RCVSPEED: Packets receiving rate (packets per second).
    pub recv_speed_pkts: Option<i32>,
    /// ACKD_BANDWIDTH: Estimated link bandwidth in packets per second.
    pub bandwidth: Option<i32>,
    /// ACKD_RCVRATE: Receiving rate in bytes per second.
    pub recv_rate: Option<i32>,
}

impl AckData {
    /// Size of the full ACK data in bytes (7 x 4 = 28 bytes for full ACK).
    pub const FULL_SIZE: usize = 28;
    /// Minimum size: just the ACK sequence number (4 bytes).
    pub const MIN_SIZE: usize = 4;

    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_i32(self.ack_seq.value());
        if let Some(rtt) = self.rtt {
            buf.put_i32(rtt);
            buf.put_i32(self.rtt_var.unwrap_or(0));
            buf.put_i32(self.available_buf_size.unwrap_or(0)); // ACKD_BUFFERLEFT
            buf.put_i32(self.recv_speed_pkts.unwrap_or(0));    // ACKD_RCVSPEED
            buf.put_i32(self.bandwidth.unwrap_or(0));           // ACKD_BANDWIDTH
            if let Some(recv_rate) = self.recv_rate {
                buf.put_i32(recv_rate);                         // ACKD_RCVRATE
            }
        }
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < Self::MIN_SIZE {
            return None;
        }
        let mut buf = &data[..];
        let ack_seq = SeqNo::new(buf.get_i32());
        let (rtt, rtt_var, available_buf, recv_speed, bandwidth, recv_rate) = if buf.remaining() >= 8 {
            let rtt = buf.get_i32();
            let rtt_var = buf.get_i32();
            let avail = if buf.remaining() >= 4 { Some(buf.get_i32()) } else { None };  // ACKD_BUFFERLEFT
            let speed = if buf.remaining() >= 4 { Some(buf.get_i32()) } else { None };  // ACKD_RCVSPEED
            let bw = if buf.remaining() >= 4 { Some(buf.get_i32()) } else { None };     // ACKD_BANDWIDTH
            let rr = if buf.remaining() >= 4 { Some(buf.get_i32()) } else { None };     // ACKD_RCVRATE
            (Some(rtt), Some(rtt_var), avail, speed, bw, rr)
        } else {
            (None, None, None, None, None, None)
        };

        Some(Self {
            ack_seq,
            rtt,
            rtt_var,
            available_buf_size: available_buf,
            recv_speed_pkts: recv_speed,
            bandwidth,
            recv_rate,
        })
    }
}

/// Loss report (NAK) data containing lost sequence number ranges.
#[derive(Debug, Clone)]
pub struct LossReport {
    /// List of lost sequence numbers or ranges.
    /// Single loss: (seq, seq). Range: (first, last).
    pub losses: Vec<(SeqNo, SeqNo)>,
}

impl LossReport {
    /// Serialize loss list into wire format.
    ///
    /// Encoding: For a range of consecutive losses, the first sequence number
    /// has bit 31 set (LOSSDATA_RANGE_FIRST). Single losses use the raw
    /// sequence number.
    pub fn serialize(&self, buf: &mut BytesMut) {
        for &(first, last) in &self.losses {
            if first == last {
                // Single loss
                buf.put_i32(first.value());
            } else {
                // Range: first with bit 31 set, then last
                buf.put_i32(first.value() | LOSSDATA_RANGE_FIRST);
                buf.put_i32(last.value());
            }
        }
    }

    /// Deserialize loss list from wire format.
    pub fn deserialize(data: &[u8]) -> Self {
        let mut losses = Vec::new();
        let mut buf = &data[..];
        while buf.remaining() >= 4 {
            let val = buf.get_i32();
            if val & LOSSDATA_RANGE_FIRST != 0 {
                // Range: this is the first, next word is the last
                let first = SeqNo::new(val & !LOSSDATA_RANGE_FIRST);
                if buf.remaining() >= 4 {
                    let last = SeqNo::new(buf.get_i32());
                    losses.push((first, last));
                }
            } else {
                // Single loss
                let seq = SeqNo::new(val);
                losses.push((seq, seq));
            }
        }
        Self { losses }
    }

    /// Total number of lost packets described by this report.
    pub fn total_losses(&self) -> i32 {
        self.losses
            .iter()
            .map(|&(first, last)| SeqNo::offset(first, last) + 1)
            .sum()
    }
}

/// Drop request message data.
#[derive(Debug, Clone)]
pub struct DropReqData {
    /// Message ID of the message to drop.
    pub msg_id: i32,
    /// First sequence number of the message.
    pub first_seq: SeqNo,
    /// Last sequence number of the message.
    pub last_seq: SeqNo,
}

impl DropReqData {
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_i32(self.first_seq.value());
        buf.put_i32(self.last_seq.value());
    }

    pub fn deserialize(msg_id: i32, data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let mut buf = &data[..];
        let first_seq = SeqNo::new(buf.get_i32());
        let last_seq = SeqNo::new(buf.get_i32());
        Some(Self {
            msg_id,
            first_seq,
            last_seq,
        })
    }
}

/// Parsed control packet body.
#[derive(Debug, Clone)]
pub enum ControlBody {
    Handshake(Bytes),
    Keepalive,
    Ack(AckData),
    Nak(LossReport),
    CongestionWarning,
    Shutdown,
    AckAck,
    DropReq(DropReqData),
    PeerError(i32),
    /// Extension control packet with subtype.
    Extension {
        ext_type: u16,
        data: Bytes,
    },
}
