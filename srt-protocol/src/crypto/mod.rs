// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT encryption using pure-Rust cryptography.
//!
//! This module implements the SRT encryption subsystem using [RustCrypto](https://github.com/RustCrypto)
//! crates -- no OpenSSL or system crypto libraries required.
//!
//! # Encryption Flow
//!
//! 1. **Key derivation**: A passphrase is converted to a Key Encrypting Key (KEK) via
//!    PBKDF2-HMAC-SHA1 (2048 iterations, 16-byte random salt).
//! 2. **Key exchange**: Stream Encrypting Keys (SEKs) are wrapped with AES Key Wrap
//!    (RFC 3394) and exchanged via KMREQ/KMRSP control messages during the handshake.
//! 3. **Packet encryption**: Data payloads are encrypted with AES-CTR or AES-GCM
//!    using the active SEK. Key sizes of 128, 192, and 256 bits are supported.
//! 4. **Key rotation**: Keys rotate every ~16 million packets. A new key is
//!    pre-announced 4096 packets before the switch for seamless transitions.
//!
//! # Submodules
//!
//! - [`key_material`] - PBKDF2 key derivation, AES Key Wrap/Unwrap, salt/SEK generation
//! - [`aes_ctr`] - AES-CTR encryption/decryption (128/192/256-bit)
//! - [`aes_gcm`] - AES-GCM authenticated encryption/decryption (128/192/256-bit)
//! - [`km_exchange`] - Key Material message encoding/decoding for KMREQ/KMRSP

pub mod aes_ctr;
pub mod aes_gcm;
pub mod key_material;
pub mod km_exchange;

use crate::config::KeySize;
use crate::packet::header::EncryptionKeySpec;

/// Crypto key index (even or odd).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyIndex {
    Even = 0,
    Odd = 1,
}

impl KeyIndex {
    pub fn toggle(self) -> Self {
        match self {
            Self::Even => Self::Odd,
            Self::Odd => Self::Even,
        }
    }

    pub fn to_enc_key_spec(self) -> EncryptionKeySpec {
        match self {
            Self::Even => EncryptionKeySpec::Even,
            Self::Odd => EncryptionKeySpec::Odd,
        }
    }

    pub fn from_enc_key_spec(spec: EncryptionKeySpec) -> Option<Self> {
        match spec {
            EncryptionKeySpec::Even => Some(Self::Even),
            EncryptionKeySpec::Odd => Some(Self::Odd),
            EncryptionKeySpec::NoEnc => None,
        }
    }
}

/// Crypto mode (cipher algorithm).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoMode {
    /// AES Counter mode.
    AesCtr,
    /// AES Galois/Counter mode (authenticated encryption).
    AesGcm,
}

/// Stream Encrypting Key (SEK) pair.
///
/// SRT maintains two keys (even/odd) for seamless key rotation.
#[derive(Clone)]
pub struct KeyPair {
    /// Even key.
    pub even: Option<Vec<u8>>,
    /// Odd key.
    pub odd: Option<Vec<u8>>,
    /// Key size.
    pub key_size: KeySize,
    /// Currently active key index.
    pub active: KeyIndex,
}

impl KeyPair {
    pub fn new(key_size: KeySize) -> Self {
        Self {
            even: None,
            odd: None,
            key_size,
            active: KeyIndex::Even,
        }
    }

    /// Get the currently active key.
    pub fn active_key(&self) -> Option<&[u8]> {
        match self.active {
            KeyIndex::Even => self.even.as_deref(),
            KeyIndex::Odd => self.odd.as_deref(),
        }
    }

    /// Get a key by index.
    pub fn key(&self, index: KeyIndex) -> Option<&[u8]> {
        match index {
            KeyIndex::Even => self.even.as_deref(),
            KeyIndex::Odd => self.odd.as_deref(),
        }
    }

    /// Set a key by index.
    pub fn set_key(&mut self, index: KeyIndex, key: Vec<u8>) {
        match index {
            KeyIndex::Even => self.even = Some(key),
            KeyIndex::Odd => self.odd = Some(key),
        }
    }

    /// Switch to the other key.
    pub fn toggle_active(&mut self) {
        self.active = self.active.toggle();
    }
}

/// Crypto control state machine.
///
/// Maps to C++ `CCryptoControl`. Manages key material generation,
/// exchange, and rotation for an SRT connection.
pub struct CryptoControl {
    /// Key pair (even/odd SEKs).
    pub keys: KeyPair,
    /// Crypto mode.
    pub mode: CryptoMode,
    /// Key Encrypting Key (derived from passphrase via PBKDF2).
    pub kek: Option<Vec<u8>>,
    /// Salt for PBKDF2.
    pub salt: [u8; 16],
    /// Packet counter for key refresh.
    pub pkt_count: u64,
    /// Key refresh rate (packets).
    pub km_refresh_rate: u32,
    /// Key pre-announce interval (packets before refresh).
    pub km_pre_announce: u32,
    /// Whether we are the key material initiator.
    pub is_initiator: bool,
    /// Whether key material has been exchanged successfully.
    pub km_exchanged: bool,
}

impl CryptoControl {
    pub fn new(key_size: KeySize, mode: CryptoMode) -> Self {
        Self {
            keys: KeyPair::new(key_size),
            mode,
            kek: None,
            salt: [0u8; 16],
            pkt_count: 0,
            km_refresh_rate: 0x0100_0000, // 16M packets
            km_pre_announce: 0x1000,       // 4096 packets
            is_initiator: false,
            km_exchanged: false,
        }
    }

    /// Check if it's time to generate a new key (pre-announce).
    pub fn should_pre_announce(&self) -> bool {
        if self.km_refresh_rate == 0 {
            return false;
        }
        let next_refresh = self.km_refresh_rate as u64;
        let pre_announce = self.km_pre_announce as u64;
        self.pkt_count > 0 && (self.pkt_count % next_refresh) == (next_refresh - pre_announce)
    }

    /// Check if it's time to switch to the new key.
    pub fn should_switch_key(&self) -> bool {
        if self.km_refresh_rate == 0 {
            return false;
        }
        self.pkt_count > 0 && (self.pkt_count % self.km_refresh_rate as u64) == 0
    }

    /// Increment packet counter.
    pub fn on_packet_sent(&mut self) {
        self.pkt_count += 1;
    }
}
