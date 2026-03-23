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

    /// Serialize to wire format.
    pub fn serialize(&self, buf: &mut BytesMut) {
        // Version + PT (4 bytes)
        let version_pt: u32 = 0x00000000 // version 0
            | ((self.key_flags as u32) << 8)
            | 0x02; // packet type = KM
        buf.put_u32(version_pt);

        // Sign (Haivision)
        buf.put_u16(0x2029);

        // Key info
        let key_size_bits = (self.key_size as u32) >> 3; // Convert bytes to 3-bit field
        let key_info: u16 = ((self.cipher as u16) << 8)
            | ((self.auth as u16) << 4)
            | (self.se as u16);
        buf.put_u16(key_info);

        // KEKI
        buf.put_u32(self.keki);

        // Salt
        buf.extend_from_slice(&self.salt);

        // Wrapped key size in 32-bit words
        let wrap_len_words = (self.wrapped_keys.len() / 4) as u16;
        buf.put_u16(wrap_len_words);
        buf.put_u16(key_size_bits as u16);

        // Wrapped key(s)
        buf.extend_from_slice(&self.wrapped_keys);
    }

    /// Deserialize from wire format.
    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 28 {
            return None;
        }

        let mut buf = &data[..];

        let version_pt = buf.get_u32();
        let key_flags = ((version_pt >> 8) & 0xFF) as u8;

        let _sign = buf.get_u16();

        let key_info = buf.get_u16();
        let cipher = CipherType::from_value((key_info >> 8) as u8);
        let auth = AuthType::from_value(((key_info >> 4) & 0xF) as u8);
        let se = StreamEncap::from_value((key_info & 0xF) as u8);

        let keki = buf.get_u32();

        let mut salt = [0u8; 16];
        if buf.remaining() < 16 {
            return None;
        }
        buf.copy_to_slice(&mut salt);

        if buf.remaining() < 4 {
            return None;
        }
        let wrap_len_words = buf.get_u16() as usize;
        let key_size_bits = buf.get_u16();
        let key_size = KeySize::from_bytes(((key_size_bits as usize) << 3).max(16))?;

        let wrap_len_bytes = wrap_len_words * 4;
        if buf.remaining() < wrap_len_bytes {
            return None;
        }
        let mut wrapped_keys = vec![0u8; wrap_len_bytes];
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
