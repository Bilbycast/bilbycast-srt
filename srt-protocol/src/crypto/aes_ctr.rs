//! AES-CTR (Counter mode) encryption for SRT data packets.
//!
//! CTR mode is the default encryption mode for SRT. It provides
//! confidentiality but not authentication (use AES-GCM for authenticated
//! encryption). Supports 128, 192, and 256-bit key sizes.

use aes::cipher::{KeyIvInit, StreamCipher};
use crate::config::KeySize;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
type Aes192Ctr = ctr::Ctr128BE<aes::Aes192>;
type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// AES-CTR encryption/decryption.
///
/// SRT uses AES in Counter (CTR) mode. The IV is constructed from:
/// - Upper 112 bits: XOR with salt nonce
/// - Bits 10-13: Packet index (PKI)
/// - Lower 16 bits: Block counter (managed by CTR mode)
pub struct AesCtrCipher {
    key: Vec<u8>,
    key_size: KeySize,
}

impl AesCtrCipher {
    pub fn new(key: &[u8]) -> Option<Self> {
        let key_size = KeySize::from_bytes(key.len())?;
        Some(Self {
            key: key.to_vec(),
            key_size,
        })
    }

    /// Build the 16-byte IV for AES-CTR from salt and packet index.
    ///
    /// IV construction (from haicrypt):
    /// - Copy salt (first 14 bytes = 112 bits)
    /// - XOR packet index into bytes 10-13
    /// - Bytes 14-15 are the block counter (start at 0)
    fn build_iv(salt: &[u8; 16], pkt_index: u32) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&salt[..14]);

        // XOR packet index (big-endian) into bytes 10-13
        let pki_bytes = pkt_index.to_be_bytes();
        iv[10] ^= pki_bytes[0];
        iv[11] ^= pki_bytes[1];
        iv[12] ^= pki_bytes[2];
        iv[13] ^= pki_bytes[3];

        // Bytes 14-15 = block counter (start at 0, handled by CTR mode)
        iv[14] = 0;
        iv[15] = 0;

        iv
    }

    /// Encrypt data in place using AES-CTR.
    pub fn encrypt(&self, salt: &[u8; 16], pkt_index: u32, data: &mut [u8]) -> Result<(), &'static str> {
        let iv = Self::build_iv(salt, pkt_index);
        self.apply_keystream(&iv, data)
    }

    /// Decrypt data in place using AES-CTR.
    /// (CTR mode encryption and decryption are the same operation.)
    pub fn decrypt(&self, salt: &[u8; 16], pkt_index: u32, data: &mut [u8]) -> Result<(), &'static str> {
        self.encrypt(salt, pkt_index, data)
    }

    fn apply_keystream(&self, iv: &[u8; 16], data: &mut [u8]) -> Result<(), &'static str> {
        match self.key_size {
            KeySize::AES128 => {
                let mut cipher = Aes128Ctr::new(
                    self.key.as_slice().into(),
                    iv.as_slice().into(),
                );
                cipher.apply_keystream(data);
            }
            KeySize::AES192 => {
                let mut cipher = Aes192Ctr::new(
                    self.key.as_slice().into(),
                    iv.as_slice().into(),
                );
                cipher.apply_keystream(data);
            }
            KeySize::AES256 => {
                let mut cipher = Aes256Ctr::new(
                    self.key.as_slice().into(),
                    iv.as_slice().into(),
                );
                cipher.apply_keystream(data);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 16]; // AES-128
        let salt = [0x01u8; 16];
        let pkt_index = 1234u32;

        let cipher = AesCtrCipher::new(&key).unwrap();

        let original = b"Hello, SRT world! This is a test payload.";
        let mut data = original.to_vec();

        cipher.encrypt(&salt, pkt_index, &mut data).unwrap();
        assert_ne!(&data[..], &original[..]);

        cipher.decrypt(&salt, pkt_index, &mut data).unwrap();
        assert_eq!(&data[..], &original[..]);
    }
}
