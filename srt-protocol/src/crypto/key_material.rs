// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Key derivation and key wrapping for SRT encryption.
//!
//! Implements the cryptographic key management operations:
//! - PBKDF2-HMAC-SHA1 derivation of Key Encrypting Keys (KEK) from passphrases
//! - AES Key Wrap (RFC 3394) for secure SEK exchange
//! - Random salt and Stream Encrypting Key (SEK) generation

use pbkdf2::pbkdf2_hmac;
use rand::RngExt;
use sha1::Sha1;

use crate::config::KeySize;

/// PBKDF2 iteration count (matches C++ HAICRYPT_PBKDF2_ITER_CNT).
const PBKDF2_ITERATIONS: u32 = 2048;

/// Salt size in bytes (matches C++ HAICRYPT_SALT_SZ).
pub const SALT_SIZE: usize = 16;

/// PBKDF2 salt length in bytes (matches C++ HAICRYPT_PBKDF2_SALT_LEN).
/// libsrt uses only the last 8 bytes (LSB 64 bits) of the 16-byte KM salt
/// for PBKDF2 key derivation: `PBKDF2(pwd, salt[8..16], 2048, key_len)`.
const PBKDF2_SALT_LEN: usize = 8;

/// Derive a Key Encrypting Key (KEK) from a passphrase using PBKDF2-HMAC-SHA1.
///
/// This is the first step in SRT encryption setup. The KEK is used to
/// wrap/unwrap the Stream Encrypting Keys (SEKs) for exchange.
///
/// Per the HaiCrypt specification, only the last [`PBKDF2_SALT_LEN`] bytes
/// of the KM salt are used as the PBKDF2 salt input (LSB extraction).
pub fn derive_kek(passphrase: &str, salt: &[u8], key_size: KeySize) -> Vec<u8> {
    let key_len = key_size as usize;
    let mut kek = vec![0u8; key_len];
    // Use LSB(64, salt) = last 8 bytes, matching libsrt's HAICRYPT_PBKDF2_SALT_LEN
    let pbkdf2_salt = if salt.len() >= PBKDF2_SALT_LEN {
        &salt[salt.len() - PBKDF2_SALT_LEN..]
    } else {
        salt
    };
    pbkdf2_hmac::<Sha1>(
        passphrase.as_bytes(),
        pbkdf2_salt,
        PBKDF2_ITERATIONS,
        &mut kek,
    );
    kek
}

/// Wrap a Stream Encrypting Key (SEK) using AES Key Wrap (RFC 3394).
///
/// The KEK (Key Encrypting Key) protects the SEK during transport
/// in key material exchange messages.
pub fn wrap_key(kek: &[u8], sek: &[u8]) -> Result<Vec<u8>, &'static str> {
    use aes_kw::cipher::KeyInit;
    use aes_kw::{KwAes128, KwAes256};

    match kek.len() {
        16 => {
            let kw = KwAes128::new_from_slice(kek).map_err(|_| "invalid KEK")?;
            let mut wrapped = vec![0u8; sek.len() + 8]; // AES-KW adds 8 bytes
            kw.wrap_key(sek, &mut wrapped)
                .map_err(|_| "key wrap failed")?;
            Ok(wrapped)
        }
        32 => {
            let kw = KwAes256::new_from_slice(kek).map_err(|_| "invalid KEK")?;
            let mut wrapped = vec![0u8; sek.len() + 8];
            kw.wrap_key(sek, &mut wrapped)
                .map_err(|_| "key wrap failed")?;
            Ok(wrapped)
        }
        _ => Err("unsupported KEK size"),
    }
}

/// Unwrap a Stream Encrypting Key (SEK) using AES Key Unwrap (RFC 3394).
pub fn unwrap_key(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, &'static str> {
    use aes_kw::cipher::KeyInit;
    use aes_kw::{KwAes128, KwAes256};

    if wrapped.len() < 24 {
        return Err("wrapped key too short");
    }

    match kek.len() {
        16 => {
            let kw = KwAes128::new_from_slice(kek).map_err(|_| "invalid KEK")?;
            let mut unwrapped = vec![0u8; wrapped.len() - 8];
            kw.unwrap_key(wrapped, &mut unwrapped)
                .map_err(|_| "key unwrap failed (wrong password?)")?;
            Ok(unwrapped)
        }
        32 => {
            let kw = KwAes256::new_from_slice(kek).map_err(|_| "invalid KEK")?;
            let mut unwrapped = vec![0u8; wrapped.len() - 8];
            kw.unwrap_key(wrapped, &mut unwrapped)
                .map_err(|_| "key unwrap failed (wrong password?)")?;
            Ok(unwrapped)
        }
        _ => Err("unsupported KEK size"),
    }
}

/// Generate a random salt.
pub fn generate_salt() -> [u8; SALT_SIZE] {
    let mut salt = [0u8; SALT_SIZE];
    rand::rng().fill(&mut salt);
    salt
}

/// Generate a random Stream Encrypting Key of the specified size.
pub fn generate_sek(key_size: KeySize) -> Vec<u8> {
    let mut key = vec![0u8; key_size as usize];
    rand::rng().fill(key.as_mut_slice());
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_kek() {
        let salt = [0x42u8; 16];
        let kek = derive_kek("test_passphrase", &salt, KeySize::AES128);
        assert_eq!(kek.len(), 16);
        // KEK should be deterministic
        let kek2 = derive_kek("test_passphrase", &salt, KeySize::AES128);
        assert_eq!(kek, kek2);
        // Different passphrase should produce different KEK
        let kek3 = derive_kek("other_passphrase", &salt, KeySize::AES128);
        assert_ne!(kek, kek3);
    }

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let kek = derive_kek("passphrase", &[0u8; 16], KeySize::AES128);
        let sek = generate_sek(KeySize::AES128);

        let wrapped = wrap_key(&kek, &sek).unwrap();
        assert_eq!(wrapped.len(), sek.len() + 8);

        let unwrapped = unwrap_key(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, sek);
    }

    #[test]
    fn test_wrong_password_fails() {
        let kek1 = derive_kek("correct", &[0u8; 16], KeySize::AES128);
        let kek2 = derive_kek("wrong", &[0u8; 16], KeySize::AES128);
        let sek = generate_sek(KeySize::AES128);

        let wrapped = wrap_key(&kek1, &sek).unwrap();
        let result = unwrap_key(&kek2, &wrapped);
        assert!(result.is_err());
    }

    #[test]
    fn test_pbkdf2_uses_last_8_bytes_of_salt() {
        // libsrt uses LSB(64, Salt) = last 8 bytes of the 16-byte KM salt
        // for PBKDF2. Verify our derive_kek matches this behavior.
        //
        // Python reference (using last 8 bytes of salt):
        //   hashlib.pbkdf2_hmac('sha1', b"bilbycast-arq-test-2026",
        //       bytes.fromhex("548c85fa0de64955"), 2048, dklen=16)
        //   = 65641012fe6730ae6ecdf6f91ac973c3
        let passphrase = "bilbycast-arq-test-2026";
        let full_salt = [0xa8, 0x48, 0x03, 0xa8, 0x5b, 0xe2, 0x1b, 0x7d,
                         0x54, 0x8c, 0x85, 0xfa, 0x0d, 0xe6, 0x49, 0x55];
        let kek = derive_kek(passphrase, &full_salt, KeySize::AES128);
        let kek_hex: String = kek.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(kek_hex, "65641012fe6730ae6ecdf6f91ac973c3",
            "PBKDF2 must use last 8 bytes of salt (libsrt compat)");
    }

    #[test]
    fn test_aes_kw_rfc3394_vector() {
        // RFC 3394 Section 4.1: 128-bit KEK, 128-bit key data
        let kek_bytes: [u8; 16] = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
        let key_data: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                   0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let expected_wrapped: [u8; 24] = [0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
                                           0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
                                           0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5];

        let wrapped = wrap_key(&kek_bytes, &key_data).expect("wrap should succeed");
        assert_eq!(wrapped, expected_wrapped, "AES-KW must match RFC 3394 test vector");

        let unwrapped = unwrap_key(&kek_bytes, &wrapped).expect("unwrap should succeed");
        assert_eq!(unwrapped, key_data, "Unwrapped must match original");
    }
}
