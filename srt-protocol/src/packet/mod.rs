// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT packet wire format.
//!
//! SRT packets consist of a 128-bit (16-byte) header followed by a variable-length
//! payload. The header format depends on the packet type:
//!
//! - **Data packets** (bit 0 = 0): carry sequence number, message number,
//!   encryption flags, and user payload.
//! - **Control packets** (bit 0 = 1): carry control type, subtype, and
//!   protocol-specific payloads (ACK data, handshake info, etc.).
//!
//! # Submodules
//!
//! - [`header`] - Bit-field constants and enums for header manipulation
//! - [`control`] - Control packet types (ACK, NAK, Handshake, etc.)
//! - [`seq`] - 31-bit circular sequence number arithmetic
//! - [`msg`] - 26-bit message number with boundary/retransmission flags

pub mod control;
pub mod header;
pub mod msg;
pub mod seq;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use self::control::ControlType;
use self::header::*;
use self::msg::MsgNo;
use self::seq::SeqNo;

/// An SRT packet (data or control).
///
/// Maps to C++ `CPacket`. The header is 128 bits (4 x u32), followed by a
/// variable-length payload.
///
/// Data packets:
/// ```text
/// Word 0: [0][    31-bit Sequence Number   ]
/// Word 1: [BB][O][KK][R][  26-bit Message Number  ]
/// Word 2: [         32-bit Timestamp              ]
/// Word 3: [      Destination Socket ID            ]
/// ```
///
/// Control packets:
/// ```text
/// Word 0: [1][  15-bit Type  ][  16-bit ExtType  ]
/// Word 1: [      Additional Info (e.g. ACK SeqNo) ]
/// Word 2: [         32-bit Timestamp              ]
/// Word 3: [      Destination Socket ID            ]
/// ```
#[derive(Debug, Clone)]
pub struct SrtPacket {
    /// The 128-bit header as 4 x u32 (host byte order).
    header: [u32; 4],
    /// The payload (data or control info).
    payload: Bytes,
}

impl SrtPacket {
    /// Create a data packet.
    pub fn new_data(
        seq: SeqNo,
        msg_no: MsgNo,
        boundary: PacketBoundary,
        in_order: bool,
        enc_key: EncryptionKeySpec,
        rexmit: bool,
        timestamp: u32,
        dest_socket_id: u32,
        payload: Bytes,
    ) -> Self {
        let mut msgno_field: u32 = msg_no.value();
        msgno_field |= (boundary as u32) << MSGNO_BOUNDARY_SHIFT;
        if in_order {
            msgno_field |= MSGNO_INORDER_MASK;
        }
        msgno_field |= (enc_key as u32) << MSGNO_ENCKEYSPEC_SHIFT;
        if rexmit {
            msgno_field |= MSGNO_REXMIT_MASK;
        }

        Self {
            header: [
                seq.value() as u32, // bit 31 = 0 (data packet)
                msgno_field,
                timestamp,
                dest_socket_id,
            ],
            payload,
        }
    }

    /// Create a control packet.
    pub fn new_control(
        ctrl_type: ControlType,
        ext_type: u16,
        additional_info: u32,
        timestamp: u32,
        dest_socket_id: u32,
        payload: Bytes,
    ) -> Self {
        let seqno_field = SEQNO_CONTROL_MASK
            | ((ctrl_type as u32) << SEQNO_MSGTYPE_SHIFT)
            | (ext_type as u32);

        Self {
            header: [seqno_field, additional_info, timestamp, dest_socket_id],
            payload,
        }
    }

    // ── Header accessors ──

    /// True if this is a control packet.
    #[inline]
    pub fn is_control(&self) -> bool {
        self.header[PH_SEQNO] & SEQNO_CONTROL_MASK != 0
    }

    /// True if this is a data packet.
    #[inline]
    pub fn is_data(&self) -> bool {
        !self.is_control()
    }

    // ── Data packet accessors ──

    /// Get the 31-bit sequence number (data packets only).
    #[inline]
    pub fn sequence_number(&self) -> SeqNo {
        SeqNo::new(self.header[PH_SEQNO] as i32)
    }

    /// Get the packet boundary type.
    #[inline]
    pub fn boundary(&self) -> PacketBoundary {
        PacketBoundary::from_bits(self.header[PH_MSGNO] >> MSGNO_BOUNDARY_SHIFT)
    }

    /// Get the in-order delivery flag.
    #[inline]
    pub fn in_order(&self) -> bool {
        self.header[PH_MSGNO] & MSGNO_INORDER_MASK != 0
    }

    /// Get the encryption key specification.
    #[inline]
    pub fn encryption_key(&self) -> EncryptionKeySpec {
        EncryptionKeySpec::from_bits(self.header[PH_MSGNO] >> MSGNO_ENCKEYSPEC_SHIFT)
    }

    /// Get the retransmission flag.
    #[inline]
    pub fn rexmit_flag(&self) -> bool {
        self.header[PH_MSGNO] & MSGNO_REXMIT_MASK != 0
    }

    /// Set the retransmission flag.
    #[inline]
    pub fn set_rexmit_flag(&mut self, rexmit: bool) {
        if rexmit {
            self.header[PH_MSGNO] |= MSGNO_REXMIT_MASK;
        } else {
            self.header[PH_MSGNO] &= !MSGNO_REXMIT_MASK;
        }
    }

    /// Get the 26-bit message number.
    #[inline]
    pub fn message_number(&self) -> MsgNo {
        MsgNo::new(self.header[PH_MSGNO] & MSGNO_SEQ_MASK)
    }

    /// Get the message number without rexmit flag (legacy 27-bit).
    #[inline]
    pub fn message_number_old(&self) -> u32 {
        self.header[PH_MSGNO] & MSGNO_SEQ_OLD_MASK
    }

    /// Set the encryption key spec bits.
    pub fn set_encryption_key(&mut self, spec: EncryptionKeySpec) {
        self.header[PH_MSGNO] = (self.header[PH_MSGNO] & !MSGNO_ENCKEYSPEC_MASK)
            | ((spec as u32) << MSGNO_ENCKEYSPEC_SHIFT);
    }

    // ── Control packet accessors ──

    /// Get the control message type (control packets only).
    #[inline]
    pub fn control_type(&self) -> Option<ControlType> {
        if !self.is_control() {
            return None;
        }
        let msg_type = ((self.header[PH_SEQNO] & SEQNO_MSGTYPE_MASK) >> SEQNO_MSGTYPE_SHIFT) as u16;
        ControlType::from_value(msg_type)
    }

    /// Get the extended type field (for UMSG_EXT control packets).
    #[inline]
    pub fn extended_type(&self) -> u16 {
        (self.header[PH_SEQNO] & SEQNO_EXTTYPE_MASK) as u16
    }

    /// Get the additional info field (Word 1, used by ACK/ACKACK for ack seq no, etc).
    #[inline]
    pub fn additional_info(&self) -> u32 {
        self.header[PH_MSGNO]
    }

    // ── Common accessors ──

    /// Get the 32-bit timestamp (microseconds since connection start).
    #[inline]
    pub fn timestamp(&self) -> u32 {
        self.header[PH_TIMESTAMP]
    }

    /// Set the timestamp.
    #[inline]
    pub fn set_timestamp(&mut self, ts: u32) {
        self.header[PH_TIMESTAMP] = ts;
    }

    /// Get the destination socket ID.
    #[inline]
    pub fn dest_socket_id(&self) -> u32 {
        self.header[PH_ID]
    }

    /// Set the destination socket ID.
    #[inline]
    pub fn set_dest_socket_id(&mut self, id: u32) {
        self.header[PH_ID] = id;
    }

    /// Get a reference to the payload data.
    #[inline]
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Get a mutable reference to the payload data.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut Bytes {
        &mut self.payload
    }

    /// Get the payload length in bytes.
    #[inline]
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Total wire size (header + payload).
    #[inline]
    pub fn wire_size(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }

    /// Get the raw header words.
    #[inline]
    pub fn raw_header(&self) -> &[u32; 4] {
        &self.header
    }

    /// Get the raw MSGNO word (Word 1) without any field extraction.
    ///
    /// This is needed for FEC packet detection, where msgno=0 is a sentinel
    /// value that `MsgNo::new()` would clamp to 1.
    #[inline]
    pub fn raw_msgno_word(&self) -> u32 {
        self.header[PH_MSGNO]
    }

    /// Check if this is an FEC packet.
    ///
    /// FEC packets are data packets (not control) with message number = 0
    /// and boundary = Solo. The raw MSGNO word is `0xC000_0000 | (kflg << 27)`.
    #[inline]
    pub fn is_fec_packet(&self) -> bool {
        if self.is_control() {
            return false;
        }
        let msgno_word = self.header[PH_MSGNO];
        // Check: boundary == Solo (bits 31-30 = 11) AND msgno == 0 (bits 25-0 = 0)
        let boundary = (msgno_word >> MSGNO_BOUNDARY_SHIFT) & 0x3;
        let msgno = msgno_word & MSGNO_SEQ_MASK;
        boundary == PacketBoundary::Solo as u32 && msgno == 0
    }

    /// Create an FEC data packet.
    ///
    /// FEC packets are sent as regular SRT data packets with a special MSGNO word:
    /// `0xC000_0000` (PB_SOLO + msgno=0). The payload contains the 4-byte FEC header
    /// followed by XOR parity data.
    ///
    /// FEC packets are NOT encrypted themselves — they carry XOR'd encrypted payloads.
    /// The encryption key spec is set to NoEnc (0).
    pub fn new_fec_data(
        seq: SeqNo,
        timestamp: u32,
        dest_socket_id: u32,
        payload: Bytes,
    ) -> Self {
        // PB_SOLO (11 << 30) + msgno=0 = 0xC000_0000
        let msgno_field: u32 = (PacketBoundary::Solo as u32) << MSGNO_BOUNDARY_SHIFT;
        // No encryption, no rexmit, no in-order flag, msgno=0

        Self {
            header: [
                seq.value() as u32, // bit 31 = 0 (data packet)
                msgno_field,
                timestamp,
                dest_socket_id,
            ],
            payload,
        }
    }

    // ── Serialization ──

    /// Serialize the packet to network byte order into a buffer.
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.reserve(HEADER_SIZE + self.payload.len());
        // Header words in network byte order (big-endian)
        for &word in &self.header {
            buf.put_u32(word);
        }
        // Payload: control packets have their 32-bit words in network byte order,
        // data packet payloads are opaque bytes.
        buf.extend_from_slice(&self.payload);
    }

    /// Serialize to a new BytesMut.
    pub fn to_bytes(&self) -> BytesMut {
        let mut buf = BytesMut::with_capacity(self.wire_size());
        self.serialize(&mut buf);
        buf
    }

    /// Deserialize a packet from a byte buffer (network byte order).
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < HEADER_SIZE {
            return None;
        }
        let mut buf = &data[..];
        let header = [
            buf.get_u32(),
            buf.get_u32(),
            buf.get_u32(),
            buf.get_u32(),
        ];
        let payload = Bytes::copy_from_slice(&data[HEADER_SIZE..]);

        Some(Self { header, payload })
    }
}

impl std::fmt::Display for SrtPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_control() {
            write!(
                f,
                "CTRL type={:?} ext={} ts={} dst={} len={}",
                self.control_type(),
                self.extended_type(),
                self.timestamp(),
                self.dest_socket_id(),
                self.payload_len(),
            )
        } else {
            write!(
                f,
                "DATA seq={} msg={} {:?} enc={:?} rexmit={} ts={} dst={} len={}",
                self.sequence_number(),
                self.message_number(),
                self.boundary(),
                self.encryption_key(),
                self.rexmit_flag(),
                self.timestamp(),
                self.dest_socket_id(),
                self.payload_len(),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_packet_roundtrip() {
        let pkt = SrtPacket::new_data(
            SeqNo::new(42),
            MsgNo::new(7),
            PacketBoundary::Solo,
            true,
            EncryptionKeySpec::NoEnc,
            false,
            123456,
            999,
            Bytes::from_static(b"hello"),
        );

        assert!(pkt.is_data());
        assert!(!pkt.is_control());
        assert_eq!(pkt.sequence_number(), SeqNo::new(42));
        assert_eq!(pkt.message_number(), MsgNo::new(7));
        assert_eq!(pkt.boundary(), PacketBoundary::Solo);
        assert!(pkt.in_order());
        assert_eq!(pkt.encryption_key(), EncryptionKeySpec::NoEnc);
        assert!(!pkt.rexmit_flag());
        assert_eq!(pkt.timestamp(), 123456);
        assert_eq!(pkt.dest_socket_id(), 999);
        assert_eq!(pkt.payload().as_ref(), b"hello");

        // Serialize and deserialize
        let bytes = pkt.to_bytes();
        let pkt2 = SrtPacket::deserialize(&bytes).unwrap();
        assert_eq!(pkt2.sequence_number(), SeqNo::new(42));
        assert_eq!(pkt2.message_number(), MsgNo::new(7));
        assert_eq!(pkt2.boundary(), PacketBoundary::Solo);
        assert_eq!(pkt2.payload().as_ref(), b"hello");
    }

    #[test]
    fn test_control_packet_roundtrip() {
        let pkt = SrtPacket::new_control(
            ControlType::Ack,
            0,
            55, // ACK seq no
            789,
            111,
            Bytes::new(),
        );

        assert!(pkt.is_control());
        assert_eq!(pkt.control_type(), Some(ControlType::Ack));
        assert_eq!(pkt.additional_info(), 55);
        assert_eq!(pkt.timestamp(), 789);
        assert_eq!(pkt.dest_socket_id(), 111);

        let bytes = pkt.to_bytes();
        let pkt2 = SrtPacket::deserialize(&bytes).unwrap();
        assert!(pkt2.is_control());
        assert_eq!(pkt2.control_type(), Some(ControlType::Ack));
        assert_eq!(pkt2.additional_info(), 55);
    }

    #[test]
    fn test_encryption_key_spec() {
        let mut pkt = SrtPacket::new_data(
            SeqNo::new(1),
            MsgNo::new(1),
            PacketBoundary::Solo,
            false,
            EncryptionKeySpec::Even,
            false,
            0,
            0,
            Bytes::new(),
        );

        assert_eq!(pkt.encryption_key(), EncryptionKeySpec::Even);

        pkt.set_encryption_key(EncryptionKeySpec::Odd);
        assert_eq!(pkt.encryption_key(), EncryptionKeySpec::Odd);

        pkt.set_encryption_key(EncryptionKeySpec::NoEnc);
        assert_eq!(pkt.encryption_key(), EncryptionKeySpec::NoEnc);
    }

    #[test]
    fn test_fec_packet() {
        let fec_pkt = SrtPacket::new_fec_data(
            SeqNo::new(99),
            12345,
            42,
            Bytes::from_static(b"\xFF\x00\x05\x1Cparity_data"),
        );

        assert!(fec_pkt.is_data());
        assert!(!fec_pkt.is_control());
        assert!(fec_pkt.is_fec_packet());
        assert_eq!(fec_pkt.sequence_number(), SeqNo::new(99));
        assert_eq!(fec_pkt.timestamp(), 12345);
        assert_eq!(fec_pkt.boundary(), PacketBoundary::Solo);
        assert_eq!(fec_pkt.encryption_key(), EncryptionKeySpec::NoEnc);
        // Raw MSGNO should be 0xC0000000
        assert_eq!(fec_pkt.raw_msgno_word(), 0xC000_0000);

        // Roundtrip
        let bytes = fec_pkt.to_bytes();
        let pkt2 = SrtPacket::deserialize(&bytes).unwrap();
        assert!(pkt2.is_fec_packet());
        assert_eq!(pkt2.sequence_number(), SeqNo::new(99));
    }

    #[test]
    fn test_regular_data_not_fec() {
        let pkt = SrtPacket::new_data(
            SeqNo::new(1),
            MsgNo::new(1),
            PacketBoundary::Solo,
            false,
            EncryptionKeySpec::NoEnc,
            false,
            0,
            0,
            Bytes::from_static(b"hello"),
        );
        assert!(!pkt.is_fec_packet());
    }

    #[test]
    fn test_rexmit_flag() {
        let mut pkt = SrtPacket::new_data(
            SeqNo::new(1),
            MsgNo::new(1),
            PacketBoundary::Solo,
            false,
            EncryptionKeySpec::NoEnc,
            true,
            0,
            0,
            Bytes::new(),
        );

        assert!(pkt.rexmit_flag());
        pkt.set_rexmit_flag(false);
        assert!(!pkt.rexmit_flag());
        pkt.set_rexmit_flag(true);
        assert!(pkt.rexmit_flag());
    }
}
