// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT HSv5 handshake protocol.
//!
//! Implements the SRT handshake state machine for connection establishment.
//! The HSv5 handshake uses a two-phase exchange (INDUCTION + CONCLUSION)
//! with SRT extension blocks for feature negotiation, encryption key
//! exchange, and stream ID.

use bytes::{Buf, BufMut, BytesMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::{srt_options::SrtFlags, SRT_VERSION};
use crate::error::RejectReason;

/// Handshake version constants.
pub const HS_VERSION_UDT4: i32 = 4;
pub const HS_VERSION_SRT1: i32 = 5;

/// Size of the serialized base handshake (without extensions).
pub const HANDSHAKE_CONTENT_SIZE: usize = 48;

/// Handshake extension flags.
pub const HS_EXT_HSREQ: i32 = 1 << 0;
pub const HS_EXT_KMREQ: i32 = 1 << 1;
pub const HS_EXT_CONFIG: i32 = 1 << 2;

/// SRT Handshake magic code.
pub const SRT_MAGIC_CODE: u32 = 0x4A17;

/// Handshake request type (stage of the handshake process).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    /// Client→Server: initial contact (HSv4+HSv5 caller-listener).
    Induction,
    /// Peer→Peer: initial rendezvous contact.
    Waveahand,
    /// Second phase of handshake negotiation.
    Conclusion,
    /// Final rendezvous step.
    Agreement,
    /// Internal: nothing to send in response.
    Done,
    /// Failure with rejection reason.
    Failure(RejectReason),
}

impl HandshakeType {
    pub fn from_raw(val: i32) -> Self {
        match val {
            1 => Self::Induction,
            0 => Self::Waveahand,
            -1 => Self::Conclusion,
            -2 => Self::Agreement,
            -3 => Self::Done,
            v if v >= 1000 => Self::Failure(RejectReason::from_code(v - 1000)),
            _ => Self::Failure(RejectReason::Unknown),
        }
    }

    pub fn to_raw(self) -> i32 {
        match self {
            Self::Induction => 1,
            Self::Waveahand => 0,
            Self::Conclusion => -1,
            Self::Agreement => -2,
            Self::Done => -3,
            Self::Failure(reason) => 1000 + reason as i32,
        }
    }
}

/// Rendezvous connection state machine (HSv5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendezvousState {
    Invalid,
    Waving,
    Attention,
    Fine,
    Initiated,
    Connected,
}

/// SRT Handshake packet.
///
/// Serialized size: 48 bytes (base) + variable extensions.
#[derive(Debug, Clone)]
pub struct Handshake {
    /// UDT/SRT version (4 = UDT, 5 = SRT HSv5).
    pub version: i32,
    /// Socket type (UDT4) / extension flags (SRT HSv5).
    pub ext_flags: i32,
    /// Initial Sequence Number.
    pub isn: i32,
    /// Maximum Segment Size.
    pub mss: i32,
    /// Flow control window size (packets).
    pub flight_flag_size: i32,
    /// Request type (handshake stage).
    pub req_type: HandshakeType,
    /// Socket ID of the sender.
    pub socket_id: i32,
    /// Cookie for connection validation.
    pub cookie: i32,
    /// IP address of the peer.
    pub peer_ip: IpAddr,
}

impl Handshake {
    pub fn new() -> Self {
        Self {
            version: HS_VERSION_SRT1,
            ext_flags: 0,
            isn: 0,
            mss: 1500,
            flight_flag_size: 25600,
            req_type: HandshakeType::Induction,
            socket_id: 0,
            cookie: 0,
            peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// True if this is an HSv5 (or higher) handshake.
    pub fn is_v5(&self) -> bool {
        self.version > HS_VERSION_UDT4
    }

    /// Serialize the handshake to a byte buffer (network byte order).
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.reserve(HANDSHAKE_CONTENT_SIZE);
        buf.put_i32(self.version);
        buf.put_i32(self.ext_flags);
        buf.put_i32(self.isn);
        buf.put_i32(self.mss);
        buf.put_i32(self.flight_flag_size);
        buf.put_i32(self.req_type.to_raw());
        buf.put_i32(self.socket_id);
        buf.put_i32(self.cookie);
        // Peer IP: 4 x u32 (IPv4 in first word, IPv6 in all four)
        match self.peer_ip {
            IpAddr::V4(v4) => {
                buf.put_u32(u32::from(v4));
                buf.put_u32(0);
                buf.put_u32(0);
                buf.put_u32(0);
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                for chunk in octets.chunks(4) {
                    buf.put_u32(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                }
            }
        }
    }

    /// Deserialize a handshake from a byte buffer.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < HANDSHAKE_CONTENT_SIZE {
            return None;
        }
        let mut buf = &data[..];
        let version = buf.get_i32();
        let ext_flags = buf.get_i32();
        let isn = buf.get_i32();
        let mss = buf.get_i32();
        let flight_flag_size = buf.get_i32();
        let req_type = HandshakeType::from_raw(buf.get_i32());
        let socket_id = buf.get_i32();
        let cookie = buf.get_i32();
        let ip0 = buf.get_u32();
        let ip1 = buf.get_u32();
        let ip2 = buf.get_u32();
        let ip3 = buf.get_u32();

        let peer_ip = if ip1 == 0 && ip2 == 0 && ip3 == 0 {
            IpAddr::V4(Ipv4Addr::from(ip0))
        } else {
            let mut octets = [0u8; 16];
            octets[0..4].copy_from_slice(&ip0.to_be_bytes());
            octets[4..8].copy_from_slice(&ip1.to_be_bytes());
            octets[8..12].copy_from_slice(&ip2.to_be_bytes());
            octets[12..16].copy_from_slice(&ip3.to_be_bytes());
            IpAddr::V6(Ipv6Addr::from(octets))
        };

        Some(Self {
            version,
            ext_flags,
            isn,
            mss,
            flight_flag_size,
            req_type,
            socket_id,
            cookie,
            peer_ip,
        })
    }
}

impl Default for Handshake {
    fn default() -> Self {
        Self::new()
    }
}

/// SRT Handshake Request extension (HSREQ/HSRSP).
///
/// Carried inside the handshake CONCLUSION phase to negotiate SRT features.
#[derive(Debug, Clone)]
pub struct SrtHsExtension {
    /// SRT version (0xMMNNPP).
    pub srt_version: u32,
    /// SRT option flags.
    pub srt_flags: SrtFlags,
    /// Receiver TSBPD delay (ms) in high 16 bits, sender delay in low 16 bits.
    pub tsbpd_delay: u32,
    /// Reserved field.
    pub reserved: u32,
}

impl SrtHsExtension {
    pub fn new() -> Self {
        Self {
            srt_version: SRT_VERSION,
            srt_flags: SrtFlags::empty(),
            tsbpd_delay: 0,
            reserved: 0,
        }
    }

    /// Set the receiver TSBPD delay (ms).
    pub fn set_recv_tsbpd_delay(&mut self, delay_ms: u16) {
        self.tsbpd_delay = (self.tsbpd_delay & 0x0000_FFFF) | ((delay_ms as u32) << 16);
    }

    /// Set the sender TSBPD delay (ms).
    pub fn set_send_tsbpd_delay(&mut self, delay_ms: u16) {
        self.tsbpd_delay = (self.tsbpd_delay & 0xFFFF_0000) | (delay_ms as u32);
    }

    /// Get the receiver TSBPD delay (ms).
    pub fn recv_tsbpd_delay(&self) -> u16 {
        (self.tsbpd_delay >> 16) as u16
    }

    /// Get the sender TSBPD delay (ms).
    pub fn send_tsbpd_delay(&self) -> u16 {
        (self.tsbpd_delay & 0xFFFF) as u16
    }

    /// Serialize to wire format (4 x u32 = 16 bytes).
    pub fn serialize(&self, buf: &mut BytesMut) {
        buf.put_u32(self.srt_version);
        buf.put_u32(self.srt_flags.bits());
        buf.put_u32(self.tsbpd_delay);
        buf.put_u32(self.reserved);
    }

    /// Deserialize from wire format.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let mut buf = &data[..];
        let srt_version = buf.get_u32();
        let srt_flags = SrtFlags::from_bits_truncate(buf.get_u32());
        let tsbpd_delay = buf.get_u32();
        let reserved = buf.get_u32();
        Some(Self {
            srt_version,
            srt_flags,
            tsbpd_delay,
            reserved,
        })
    }
}

impl Default for SrtHsExtension {
    fn default() -> Self {
        Self::new()
    }
}

/// Handshake extension block (type + content).
#[derive(Debug, Clone)]
pub struct HandshakeExtension {
    /// Extension command type.
    pub ext_type: u16,
    /// Extension data (array of u32 values).
    pub data: Vec<u32>,
}

impl HandshakeExtension {
    /// Parse extension blocks from raw bytes following the base handshake.
    pub fn parse_extensions(data: &[u8]) -> Vec<Self> {
        let mut extensions = Vec::new();
        let mut remaining = data;

        while remaining.len() >= 4 {
            let cmd_spec = (&remaining[..4]).get_u32();
            let ext_type = (cmd_spec >> 16) as u16;
            let size_words = (cmd_spec & 0xFFFF) as usize;
            remaining = &remaining[4..];

            let size_bytes = size_words * 4;
            if remaining.len() < size_bytes {
                break;
            }

            let mut ext_data = Vec::with_capacity(size_words);
            let mut ext_buf = &remaining[..size_bytes];
            for _ in 0..size_words {
                ext_data.push(ext_buf.get_u32());
            }
            remaining = &remaining[size_bytes..];

            extensions.push(HandshakeExtension {
                ext_type,
                data: ext_data,
            });
        }

        extensions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_handshake_roundtrip() {
        let hs = Handshake {
            version: HS_VERSION_SRT1,
            ext_flags: HS_EXT_HSREQ | HS_EXT_KMREQ,
            isn: 12345,
            mss: 1500,
            flight_flag_size: 25600,
            req_type: HandshakeType::Conclusion,
            socket_id: 42,
            cookie: 0xDEADBEEF_u32 as i32,
            peer_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        };

        let mut buf = BytesMut::new();
        hs.serialize(&mut buf);
        assert_eq!(buf.len(), HANDSHAKE_CONTENT_SIZE);

        let hs2 = Handshake::deserialize(&buf).unwrap();
        assert_eq!(hs2.version, HS_VERSION_SRT1);
        assert_eq!(hs2.isn, 12345);
        assert_eq!(hs2.req_type, HandshakeType::Conclusion);
        assert_eq!(hs2.socket_id, 42);
        assert_eq!(hs2.peer_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_handshake_type_roundtrip() {
        assert_eq!(HandshakeType::from_raw(1), HandshakeType::Induction);
        assert_eq!(HandshakeType::from_raw(0), HandshakeType::Waveahand);
        assert_eq!(HandshakeType::from_raw(-1), HandshakeType::Conclusion);
        assert_eq!(HandshakeType::from_raw(-2), HandshakeType::Agreement);
        assert_eq!(HandshakeType::Induction.to_raw(), 1);
        assert_eq!(HandshakeType::Conclusion.to_raw(), -1);
    }

    #[test]
    fn test_srt_hs_extension() {
        let mut ext = SrtHsExtension::new();
        ext.set_recv_tsbpd_delay(120);
        ext.set_send_tsbpd_delay(80);
        assert_eq!(ext.recv_tsbpd_delay(), 120);
        assert_eq!(ext.send_tsbpd_delay(), 80);

        let mut buf = BytesMut::new();
        ext.serialize(&mut buf);
        let ext2 = SrtHsExtension::deserialize(&buf).unwrap();
        assert_eq!(ext2.recv_tsbpd_delay(), 120);
        assert_eq!(ext2.send_tsbpd_delay(), 80);
    }
}
