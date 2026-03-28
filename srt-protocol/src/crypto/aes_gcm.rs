// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! AES-GCM (Galois/Counter Mode) authenticated encryption for SRT data packets.
//!
//! GCM mode provides both confidentiality and authentication (AEAD).
//! It appends a 16-byte authentication tag that detects tampering.
//! Supports 128 and 256-bit key sizes.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use crate::config::KeySize;

/// AES-GCM authenticated encryption/decryption.
///
/// GCM (Galois/Counter Mode) provides both confidentiality and
/// authentication. SRT uses 96-bit (12-byte) nonces constructed from
/// the salt and packet index.
pub struct AesGcmCipher {
    key: Vec<u8>,
    key_size: KeySize,
}

impl AesGcmCipher {
    pub fn new(key: &[u8]) -> Option<Self> {
        let key_size = KeySize::from_bytes(key.len())?;
        // AES-GCM supports 128 and 256 bit keys (not 192 in aes-gcm crate)
        match key_size {
            KeySize::AES128 | KeySize::AES256 => {}
            KeySize::AES192 => return None,
        }
        Some(Self {
            key: key.to_vec(),
            key_size,
        })
    }

    /// Build the 12-byte nonce for AES-GCM from salt and packet index.
    ///
    /// Nonce construction (SRT 1.5.4+):
    /// - Upper 64 bits: XOR with salt
    /// - Bits 8-11: Packet index (PKI)
    fn build_nonce(salt: &[u8; 16], pkt_index: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..12].copy_from_slice(&salt[..12]);

        // XOR packet index into bytes 8-11 (matches libsrt v1.5.5 HAICRYPT)
        let pki_bytes = pkt_index.to_be_bytes();
        nonce[8] ^= pki_bytes[0];
        nonce[9] ^= pki_bytes[1];
        nonce[10] ^= pki_bytes[2];
        nonce[11] ^= pki_bytes[3];

        nonce
    }

    /// Encrypt data using AES-GCM.
    /// Returns ciphertext + 16-byte authentication tag appended.
    pub fn encrypt(&self, salt: &[u8; 16], pkt_index: u32, plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let nonce_bytes = Self::build_nonce(salt, pkt_index);
        let nonce = Nonce::from_slice(&nonce_bytes);

        match self.key_size {
            KeySize::AES128 => {
                let cipher = Aes128Gcm::new_from_slice(&self.key)
                    .map_err(|_| "invalid key")?;
                cipher.encrypt(nonce, plaintext)
                    .map_err(|_| "encryption failed")
            }
            KeySize::AES256 => {
                let cipher = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|_| "invalid key")?;
                cipher.encrypt(nonce, plaintext)
                    .map_err(|_| "encryption failed")
            }
            _ => Err("unsupported key size for GCM"),
        }
    }

    /// Decrypt data using AES-GCM.
    /// Input must include the 16-byte authentication tag at the end.
    pub fn decrypt(&self, salt: &[u8; 16], pkt_index: u32, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        let nonce_bytes = Self::build_nonce(salt, pkt_index);
        let nonce = Nonce::from_slice(&nonce_bytes);

        match self.key_size {
            KeySize::AES128 => {
                let cipher = Aes128Gcm::new_from_slice(&self.key)
                    .map_err(|_| "invalid key")?;
                cipher.decrypt(nonce, ciphertext)
                    .map_err(|_| "decryption failed")
            }
            KeySize::AES256 => {
                let cipher = Aes256Gcm::new_from_slice(&self.key)
                    .map_err(|_| "invalid key")?;
                cipher.decrypt(nonce, ciphertext)
                    .map_err(|_| "decryption failed")
            }
            _ => Err("unsupported key size for GCM"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcm_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 16]; // AES-128
        let salt = [0x01u8; 16];
        let pkt_index = 5678u32;

        let cipher = AesGcmCipher::new(&key).unwrap();

        let plaintext = b"Hello, SRT GCM authenticated encryption!";
        let ciphertext = cipher.encrypt(&salt, pkt_index, plaintext).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], &plaintext[..]);

        let decrypted = cipher.decrypt(&salt, pkt_index, &ciphertext).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_gcm_tampered_data_fails() {
        let key = [0x42u8; 16];
        let salt = [0x01u8; 16];
        let pkt_index = 1u32;

        let cipher = AesGcmCipher::new(&key).unwrap();

        let plaintext = b"test data";
        let mut ciphertext = cipher.encrypt(&salt, pkt_index, plaintext).unwrap();

        // Tamper with the ciphertext
        ciphertext[0] ^= 0xFF;

        let result = cipher.decrypt(&salt, pkt_index, &ciphertext);
        assert!(result.is_err());
    }
}
