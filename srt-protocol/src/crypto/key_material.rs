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

/// Derive a Key Encrypting Key (KEK) from a passphrase using PBKDF2-HMAC-SHA1.
///
/// This is the first step in SRT encryption setup. The KEK is used to
/// wrap/unwrap the Stream Encrypting Keys (SEKs) for exchange.
pub fn derive_kek(passphrase: &str, salt: &[u8], key_size: KeySize) -> Vec<u8> {
    let key_len = key_size as usize;
    let mut kek = vec![0u8; key_len];
    pbkdf2_hmac::<Sha1>(
        passphrase.as_bytes(),
        salt,
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
    use aes_kw::Kek;
    use aes::Aes128;
    use aes::Aes256;

    match kek.len() {
        16 => {
            let kek_obj = Kek::<Aes128>::try_from(kek).map_err(|_| "invalid KEK")?;
            let mut wrapped = vec![0u8; sek.len() + 8]; // AES-KW adds 8 bytes
            kek_obj
                .wrap(sek, &mut wrapped)
                .map_err(|_| "key wrap failed")?;
            Ok(wrapped)
        }
        32 => {
            let kek_obj = Kek::<Aes256>::try_from(kek).map_err(|_| "invalid KEK")?;
            let mut wrapped = vec![0u8; sek.len() + 8];
            kek_obj
                .wrap(sek, &mut wrapped)
                .map_err(|_| "key wrap failed")?;
            Ok(wrapped)
        }
        _ => Err("unsupported KEK size"),
    }
}

/// Unwrap a Stream Encrypting Key (SEK) using AES Key Unwrap (RFC 3394).
pub fn unwrap_key(kek: &[u8], wrapped: &[u8]) -> Result<Vec<u8>, &'static str> {
    use aes_kw::Kek;
    use aes::Aes128;
    use aes::Aes256;

    if wrapped.len() < 24 {
        return Err("wrapped key too short");
    }

    match kek.len() {
        16 => {
            let kek_obj = Kek::<Aes128>::try_from(kek).map_err(|_| "invalid KEK")?;
            let mut unwrapped = vec![0u8; wrapped.len() - 8];
            kek_obj
                .unwrap(wrapped, &mut unwrapped)
                .map_err(|_| "key unwrap failed (wrong password?)")?;
            Ok(unwrapped)
        }
        32 => {
            let kek_obj = Kek::<Aes256>::try_from(kek).map_err(|_| "invalid KEK")?;
            let mut unwrapped = vec![0u8; wrapped.len() - 8];
            kek_obj
                .unwrap(wrapped, &mut unwrapped)
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
}
