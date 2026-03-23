// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT packet header bit-field manipulation.
//!
//! An SRT packet header is 128 bits (4 x 32-bit words):
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |C|           Sequence Number / Type + ExtType                  |  Word 0: SRT_PH_SEQNO
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |ff|o|kf|r|           Message Number / Additional Info          |  Word 1: SRT_PH_MSGNO
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Timestamp                            |  Word 2: SRT_PH_TIMESTAMP
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Destination Socket ID                     |  Word 3: SRT_PH_ID
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

/// Size of the SRT packet header in bytes.
pub const HEADER_SIZE: usize = 16; // 4 x u32

/// Size of the UDP header (IPv4 + UDP).
pub const UDP_HEADER_SIZE: usize = 28; // 20 bytes IPv4 + 8 bytes UDP

/// Standard Ethernet MTU.
pub const ETH_MAX_MTU: usize = 1500;

/// Maximum SRT payload size (MTU - UDP header - SRT header).
pub const SRT_MAX_PAYLOAD_SIZE: usize = ETH_MAX_MTU - UDP_HEADER_SIZE - HEADER_SIZE;

/// Indices for the 4-word header array.
pub const PH_SEQNO: usize = 0;
pub const PH_MSGNO: usize = 1;
pub const PH_TIMESTAMP: usize = 2;
pub const PH_ID: usize = 3;

// ── Word 0 (SEQNO) bit masks ──

/// Bit 31: control packet flag (1 = control, 0 = data).
pub const SEQNO_CONTROL_MASK: u32 = 1 << 31;

/// Bits 30-16: message type for control packets.
pub const SEQNO_MSGTYPE_SHIFT: u32 = 16;
pub const SEQNO_MSGTYPE_MASK: u32 = 0x7FFF << SEQNO_MSGTYPE_SHIFT;

/// Bits 15-0: extended type for control packets.
pub const SEQNO_EXTTYPE_MASK: u32 = 0xFFFF;

/// Bits 30-0: sequence number for data packets.
pub const SEQNO_VALUE_MASK: u32 = 0x7FFF_FFFF;

// ── Word 1 (MSGNO) bit masks for data packets ──

/// Bits 31-30: packet boundary (SOLO=3, FIRST=2, LAST=1, SUBSEQUENT=0).
pub const MSGNO_BOUNDARY_SHIFT: u32 = 30;
pub const MSGNO_BOUNDARY_MASK: u32 = 0x3 << MSGNO_BOUNDARY_SHIFT;

/// Bit 29: in-order delivery flag.
pub const MSGNO_INORDER_MASK: u32 = 1 << 29;

/// Bits 28-27: encryption key spec (NOENC=0, EVEN=1, ODD=2).
pub const MSGNO_ENCKEYSPEC_SHIFT: u32 = 27;
pub const MSGNO_ENCKEYSPEC_MASK: u32 = 0x3 << MSGNO_ENCKEYSPEC_SHIFT;

/// Bit 26: retransmission flag.
pub const MSGNO_REXMIT_MASK: u32 = 1 << 26;

/// Bits 25-0: message sequence number (26-bit).
pub const MSGNO_SEQ_MASK: u32 = 0x03FF_FFFF;

/// Bits 26-0: legacy message sequence number (no rexmit flag support).
pub const MSGNO_SEQ_OLD_MASK: u32 = 0x07FF_FFFF;

// ── Loss report encoding ──

/// Bit 31 set means this is the FIRST of a range pair.
pub const LOSSDATA_RANGE_FIRST: i32 = i32::MIN; // 0x80000000

/// Packet boundary types for message framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketBoundary {
    /// Middle packet of a message.
    Subsequent = 0,
    /// Last packet of a message.
    Last = 1,
    /// First packet of a message.
    First = 2,
    /// Single-packet message (solo).
    Solo = 3,
}

impl PacketBoundary {
    pub fn from_bits(val: u32) -> Self {
        match val & 0x3 {
            0 => Self::Subsequent,
            1 => Self::Last,
            2 => Self::First,
            3 => Self::Solo,
            _ => unreachable!(),
        }
    }
}

/// Encryption key specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EncryptionKeySpec {
    /// No encryption.
    NoEnc = 0,
    /// Encrypted with even key.
    Even = 1,
    /// Encrypted with odd key.
    Odd = 2,
}

impl EncryptionKeySpec {
    pub fn from_bits(val: u32) -> Self {
        match val & 0x3 {
            0 => Self::NoEnc,
            1 => Self::Even,
            2 => Self::Odd,
            _ => Self::NoEnc,
        }
    }

    pub fn is_encrypted(self) -> bool {
        !matches!(self, Self::NoEnc)
    }
}

/// Encryption status for an SRT connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionStatus {
    Clear,
    Failed,
    NotSupported,
}
