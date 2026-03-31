// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Key Material (KM) message encoding/decoding for KMREQ/KMRSP exchange.
//!
//! During the SRT handshake, the initiator sends a KMREQ containing
//! the wrapped SEK(s) and crypto parameters. The responder decodes
//! and unwraps the keys, then responds with a KMRSP.

use bytes::{Buf, BufMut, BytesMut};

use crate::config::KeySize;
use super::KeyIndex;

/// Key Material message flags.
const KM_FLAG_EVEN: u8 = 0x01;
const KM_FLAG_ODD: u8 = 0x02;

/// KM message version (V field in Row 0). Spec says value = 1.
const KM_VERSION: u32 = 1;
/// KM message packet type (PT field in Row 0). Value = 2 for Key Material.
const KM_PT: u32 = 2;
/// Haivision signature (Sign field in Row 0). Value = 0x2029.
const KM_SIGN: u32 = 0x2029;

/// SRT Key Material message for key exchange.
///
/// This is the payload of SRT_CMD_KMREQ / SRT_CMD_KMRSP control packets.
/// Contains the wrapped SEK(s) encrypted with the KEK derived from the passphrase.
#[derive(Debug, Clone)]
pub struct KeyMaterialMessage {
    /// Key flags (which keys are included: even, odd, or both).
    pub key_flags: u8,
    /// Key Encryption Key Index (usually 0).
    pub keki: u32,
    /// Cipher type.
    pub cipher: CipherType,
    /// Authentication type.
    pub auth: AuthType,
    /// Stream encapsulation type.
    pub se: StreamEncap,
    /// Salt (16 bytes).
    pub salt: [u8; 16],
    /// Wrapped key(s).
    pub wrapped_keys: Vec<u8>,
    /// Key size.
    pub key_size: KeySize,
}

/// Cipher type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CipherType {
    None = 0,
    AesEcb = 1,
    AesCtr = 2,
    AesGcm = 3,
}

impl CipherType {
    pub fn from_value(v: u8) -> Self {
        match v {
            0 => Self::None,
            1 => Self::AesEcb,
            2 => Self::AesCtr,
            3 => Self::AesGcm,
            _ => Self::None,
        }
    }
}

/// Authentication type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthType {
    None = 0,
}

impl AuthType {
    pub fn from_value(v: u8) -> Self {
        match v {
            0 => Self::None,
            _ => Self::None,
        }
    }
}

/// Stream encapsulation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamEncap {
    Srt = 2,
}

impl StreamEncap {
    pub fn from_value(v: u8) -> Self {
        match v {
            2 => Self::Srt,
            _ => Self::Srt,
        }
    }
}

impl KeyMaterialMessage {
    /// Whether the even key is included.
    pub fn has_even_key(&self) -> bool {
        self.key_flags & KM_FLAG_EVEN != 0
    }

    /// Whether the odd key is included.
    pub fn has_odd_key(&self) -> bool {
        self.key_flags & KM_FLAG_ODD != 0
    }

    /// Number of keys included.
    pub fn key_count(&self) -> usize {
        let mut count = 0;
        if self.has_even_key() { count += 1; }
        if self.has_odd_key() { count += 1; }
        count
    }

    /// Build a KM message with a single wrapped key.
    pub fn new_single(
        index: KeyIndex,
        key_size: KeySize,
        cipher: CipherType,
        salt: [u8; 16],
        wrapped_key: Vec<u8>,
    ) -> Self {
        let key_flags = match index {
            KeyIndex::Even => KM_FLAG_EVEN,
            KeyIndex::Odd => KM_FLAG_ODD,
        };
        Self {
            key_flags,
            keki: 0,
            cipher,
            auth: AuthType::None,
            se: StreamEncap::Srt,
            salt,
            wrapped_keys: wrapped_key,
            key_size,
        }
    }

    /// Build a KM message with both keys.
    pub fn new_both(
        key_size: KeySize,
        cipher: CipherType,
        salt: [u8; 16],
        wrapped_even: &[u8],
        wrapped_odd: &[u8],
    ) -> Self {
        let mut wrapped = Vec::with_capacity(wrapped_even.len() + wrapped_odd.len());
        wrapped.extend_from_slice(wrapped_even);
        wrapped.extend_from_slice(wrapped_odd);
        Self {
            key_flags: KM_FLAG_EVEN | KM_FLAG_ODD,
            keki: 0,
            cipher,
            auth: AuthType::None,
            se: StreamEncap::Srt,
            salt,
            wrapped_keys: wrapped,
            key_size,
        }
    }

    /// Serialize to wire format (SRT spec, draft-sharabayko-srt Figure 11).
    ///
    /// ```text
    /// Row 0: S(1)|V(3)|PT(4)|Sign(16)|Resv(6)|KK(2)
    /// Row 1: KEKI(32)
    /// Row 2: Cipher(8)|Auth(8)|SE(8)|Resv(8)
    /// Row 3: Resv(16)|Slen/4(8)|Klen/4(8)
    /// Salt:  Slen bytes (16)
    /// Wrap:  wrapped key data
    /// ```
    pub fn serialize(&self, buf: &mut BytesMut) {
        // Row 0: S=0, V=1, PT=2 (KM), Sign=0x2029, Resv=0, KK=key_flags
        let row0: u32 = (KM_VERSION << 28)
            | (KM_PT << 24)
            | (KM_SIGN << 8)
            | (self.key_flags as u32 & 0x03);
        buf.put_u32(row0);

        // Row 1: KEKI
        buf.put_u32(self.keki);

        // Row 2: Cipher(8) | Auth(8) | SE(8) | Resv(8)
        let row2: u32 = ((self.cipher as u32) << 24)
            | ((self.auth as u32) << 16)
            | ((self.se as u32) << 8);
        buf.put_u32(row2);

        // Row 3: Resv(16) | Slen/4(8) | Klen/4(8)
        let slen_field = (self.salt.len() / 4) as u32;
        let klen_field = (self.key_size as u32) / 4;
        let row3: u32 = (slen_field << 8) | klen_field;
        buf.put_u32(row3);

        // Salt (Slen bytes)
        buf.extend_from_slice(&self.salt);

        // Wrapped key(s)
        buf.extend_from_slice(&self.wrapped_keys);
    }

    /// Deserialize from wire format (SRT spec, draft-sharabayko-srt Figure 11).
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        // Minimum: 4 rows (16 bytes) + at least some salt
        if data.len() < 16 {
            return None;
        }

        let mut buf = &data[..];

        // Row 0: S(1)|V(3)|PT(4)|Sign(16)|Resv(6)|KK(2)
        let row0 = buf.get_u32();
        let pt = (row0 >> 24) & 0x0F;
        let sign = (row0 >> 8) & 0xFFFF;
        let key_flags = (row0 & 0x03) as u8;

        // Validate PT and Sign
        if pt != KM_PT {
            return None;
        }
        if sign != KM_SIGN {
            return None;
        }

        // Row 1: KEKI
        if buf.remaining() < 4 {
            return None;
        }
        let keki = buf.get_u32();

        // Row 2: Cipher(8)|Auth(8)|SE(8)|Resv(8)
        if buf.remaining() < 4 {
            return None;
        }
        let row2 = buf.get_u32();
        let cipher = CipherType::from_value((row2 >> 24) as u8);
        let auth = AuthType::from_value(((row2 >> 16) & 0xFF) as u8);
        let se = StreamEncap::from_value(((row2 >> 8) & 0xFF) as u8);

        // Row 3: Resv(16)|Slen/4(8)|Klen/4(8)
        if buf.remaining() < 4 {
            return None;
        }
        let row3 = buf.get_u32();
        let slen = ((row3 >> 8) & 0xFF) as usize * 4;
        let klen = (row3 & 0xFF) as usize * 4;
        let key_size = KeySize::from_bytes(klen)?;

        // Salt (Slen bytes, typically 16)
        if buf.remaining() < slen || slen > 16 {
            return None;
        }
        let mut salt = [0u8; 16];
        buf.copy_to_slice(&mut salt[..slen]);

        // Wrapped key(s) — remainder of the message
        let wrap_len = buf.remaining();
        if wrap_len == 0 {
            return None;
        }
        let mut wrapped_keys = vec![0u8; wrap_len];
        buf.copy_to_slice(&mut wrapped_keys);

        Some(Self {
            key_flags,
            keki,
            cipher,
            auth,
            se,
            salt,
            wrapped_keys,
            key_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_roundtrip() {
        let salt = [0x42u8; 16];
        let wrapped = vec![0xAA; 24]; // AES-128 wrapped = 16 + 8 = 24 bytes
        let msg = KeyMaterialMessage::new_single(
            KeyIndex::Even,
            KeySize::AES128,
            CipherType::AesCtr,
            salt,
            wrapped.clone(),
        );

        let mut buf = BytesMut::new();
        msg.serialize(&mut buf);

        let parsed = KeyMaterialMessage::deserialize(&buf).expect("deserialize should succeed");
        assert_eq!(parsed.key_flags, KM_FLAG_EVEN);
        assert_eq!(parsed.keki, 0);
        assert_eq!(parsed.cipher, CipherType::AesCtr);
        assert_eq!(parsed.auth, AuthType::None);
        assert_eq!(parsed.se, StreamEncap::Srt);
        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.wrapped_keys, wrapped);
        assert_eq!(parsed.key_size, KeySize::AES128);
    }

    #[test]
    fn test_serialize_roundtrip_aes256() {
        let salt = [0x13u8; 16];
        let wrapped = vec![0xBB; 40]; // AES-256 wrapped = 32 + 8 = 40 bytes
        let msg = KeyMaterialMessage::new_single(
            KeyIndex::Odd,
            KeySize::AES256,
            CipherType::AesGcm,
            salt,
            wrapped.clone(),
        );

        let mut buf = BytesMut::new();
        msg.serialize(&mut buf);

        let parsed = KeyMaterialMessage::deserialize(&buf).expect("deserialize should succeed");
        assert_eq!(parsed.key_flags, KM_FLAG_ODD);
        assert_eq!(parsed.key_size, KeySize::AES256);
        assert_eq!(parsed.cipher, CipherType::AesGcm);
        assert_eq!(parsed.wrapped_keys, wrapped);
    }

    #[test]
    fn test_wire_format_row0() {
        let msg = KeyMaterialMessage::new_single(
            KeyIndex::Even,
            KeySize::AES128,
            CipherType::AesCtr,
            [0u8; 16],
            vec![0u8; 24],
        );

        let mut buf = BytesMut::new();
        msg.serialize(&mut buf);

        // Row 0: S=0, V=1, PT=2, Sign=0x2029, Resv=0, KK=01
        // Bits: 0_001_0010_0010000000101001_000000_01
        // Byte 0: 0b0_001_0010 = 0x12  (S=0, V=1, PT=2)
        // Byte 1: 0x20  (Sign high byte)
        // Byte 2: 0x29  (Sign low byte)
        // Byte 3: 0x01  (Resv=0, KK=01 for Even)
        assert_eq!(buf[0], 0x12, "byte 0: S=0, V=1, PT=2");
        assert_eq!(buf[1], 0x20, "byte 1: Sign high");
        assert_eq!(buf[2], 0x29, "byte 2: Sign low");
        assert_eq!(buf[3], 0x01, "byte 3: KK=Even");
    }

    #[test]
    fn test_wire_format_row0_both_keys() {
        let msg = KeyMaterialMessage::new_both(
            KeySize::AES128,
            CipherType::AesCtr,
            [0u8; 16],
            &vec![0u8; 24],
            &vec![0u8; 24],
        );

        let mut buf = BytesMut::new();
        msg.serialize(&mut buf);

        // KK=0x03 for both keys
        assert_eq!(buf[3], 0x03, "byte 3: KK=Both");
    }

    #[test]
    fn test_wire_format_row2_cipher() {
        let msg = KeyMaterialMessage::new_single(
            KeyIndex::Even,
            KeySize::AES128,
            CipherType::AesCtr,
            [0u8; 16],
            vec![0u8; 24],
        );

        let mut buf = BytesMut::new();
        msg.serialize(&mut buf);

        // Row 2 at bytes 8-11: Cipher(8)|Auth(8)|SE(8)|Resv(8)
        assert_eq!(buf[8], CipherType::AesCtr as u8, "cipher = AesCtr (2)");
        assert_eq!(buf[9], AuthType::None as u8, "auth = None (0)");
        assert_eq!(buf[10], StreamEncap::Srt as u8, "se = Srt (2)");
        assert_eq!(buf[11], 0, "resv = 0");
    }

    #[test]
    fn test_wire_format_row3_key_size_aes128() {
        let msg = KeyMaterialMessage::new_single(
            KeyIndex::Even,
            KeySize::AES128,
            CipherType::AesCtr,
            [0u8; 16],
            vec![0u8; 24],
        );

        let mut buf = BytesMut::new();
        msg.serialize(&mut buf);

        // Row 3 at bytes 12-15: Resv(16)|Slen/4(8)|Klen/4(8)
        assert_eq!(buf[12], 0, "resv high");
        assert_eq!(buf[13], 0, "resv low");
        assert_eq!(buf[14], 4, "Slen/4 = 16/4 = 4");
        assert_eq!(buf[15], 4, "Klen/4 = 16/4 = 4 (AES-128)");
    }

    #[test]
    fn test_wire_format_row3_key_size_aes256() {
        let msg = KeyMaterialMessage::new_single(
            KeyIndex::Even,
            KeySize::AES256,
            CipherType::AesCtr,
            [0u8; 16],
            vec![0u8; 40],
        );

        let mut buf = BytesMut::new();
        msg.serialize(&mut buf);

        // Klen/4 = 32/4 = 8 for AES-256
        assert_eq!(buf[15], 8, "Klen/4 = 32/4 = 8 (AES-256)");
    }

    #[test]
    fn test_wire_format_salt_position() {
        let salt = [0x42u8; 16];
        let msg = KeyMaterialMessage::new_single(
            KeyIndex::Even,
            KeySize::AES128,
            CipherType::AesCtr,
            salt,
            vec![0xAA; 24],
        );

        let mut buf = BytesMut::new();
        msg.serialize(&mut buf);

        // Salt starts at byte 16 (after 4 rows × 4 bytes)
        assert_eq!(&buf[16..32], &salt, "salt at bytes 16-31");
        // Wrapped keys start at byte 32
        assert_eq!(&buf[32..56], &[0xAA; 24], "wrapped keys at bytes 32+");
    }

    #[test]
    fn test_deserialize_rejects_wrong_pt() {
        let mut buf = BytesMut::new();
        // Row 0 with PT=3 instead of 2
        let row0: u32 = (1 << 28) | (3 << 24) | (0x2029 << 8) | 0x01;
        buf.put_u32(row0);
        buf.put_u32(0); // KEKI
        buf.put_u32(0x02000200); // Cipher/Auth/SE
        buf.put_u32(0x00000404); // Slen/Klen
        buf.extend_from_slice(&[0u8; 16]); // Salt
        buf.extend_from_slice(&[0u8; 24]); // Wrapped

        assert!(KeyMaterialMessage::deserialize(&buf).is_none());
    }

    #[test]
    fn test_deserialize_rejects_wrong_sign() {
        let mut buf = BytesMut::new();
        // Row 0 with Sign=0x1234 instead of 0x2029
        let row0: u32 = (1 << 28) | (2 << 24) | (0x1234 << 8) | 0x01;
        buf.put_u32(row0);
        buf.put_u32(0);
        buf.put_u32(0x02000200);
        buf.put_u32(0x00000404);
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(&[0u8; 24]);

        assert!(KeyMaterialMessage::deserialize(&buf).is_none());
    }

    #[test]
    fn test_interop_libsrt_format() {
        // Hand-construct a spec-compliant KM message as libsrt would produce
        let mut buf = BytesMut::new();

        // Row 0: S=0, V=1, PT=2, Sign=0x2029, Resv=0, KK=01 (Even)
        buf.put_u32(0x12202901);
        // Row 1: KEKI=0
        buf.put_u32(0x00000000);
        // Row 2: Cipher=AesCtr(2), Auth=None(0), SE=Srt(2), Resv=0
        buf.put_u32(0x02000200);
        // Row 3: Resv=0, Slen/4=4, Klen/4=4 (AES-128)
        buf.put_u32(0x00000404);
        // Salt: 16 bytes
        let salt = [0x55u8; 16];
        buf.extend_from_slice(&salt);
        // Wrapped key: 24 bytes (16-byte SEK + 8-byte AES-KW overhead)
        let wrapped = [0xDD; 24];
        buf.extend_from_slice(&wrapped);

        let msg = KeyMaterialMessage::deserialize(&buf).expect("should parse libsrt format");
        assert_eq!(msg.key_flags, KM_FLAG_EVEN);
        assert_eq!(msg.keki, 0);
        assert_eq!(msg.cipher, CipherType::AesCtr);
        assert_eq!(msg.auth, AuthType::None);
        assert_eq!(msg.se, StreamEncap::Srt);
        assert_eq!(msg.salt, salt);
        assert_eq!(msg.wrapped_keys, &wrapped[..]);
        assert_eq!(msg.key_size, KeySize::AES128);
    }

    #[test]
    fn test_total_message_size() {
        // AES-128: 16 header + 16 salt + 24 wrapped = 56 bytes
        let msg = KeyMaterialMessage::new_single(
            KeyIndex::Even,
            KeySize::AES128,
            CipherType::AesCtr,
            [0u8; 16],
            vec![0u8; 24],
        );
        let mut buf = BytesMut::new();
        msg.serialize(&mut buf);
        assert_eq!(buf.len(), 56, "AES-128 KM message = 56 bytes");

        // AES-256: 16 header + 16 salt + 40 wrapped = 72 bytes
        let msg = KeyMaterialMessage::new_single(
            KeyIndex::Even,
            KeySize::AES256,
            CipherType::AesCtr,
            [0u8; 16],
            vec![0u8; 40],
        );
        let mut buf = BytesMut::new();
        msg.serialize(&mut buf);
        assert_eq!(buf.len(), 72, "AES-256 KM message = 72 bytes");
    }
}
