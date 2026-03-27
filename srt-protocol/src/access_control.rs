// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Access control for SRT listener connections.
//!
//! Provides the [`AccessControl`] trait that lets the listener inspect
//! incoming connection metadata (peer address, Stream ID, encryption state)
//! and decide whether to accept or reject the connection.
//!
//! This maps to libsrt's `srt_listen_callback()` mechanism. The callback
//! receives a [`HandshakeInfo`] struct and returns either `Ok(())` to
//! accept or `Err(RejectReason)` to reject with an SRT-standard rejection
//! code that the caller will see.
//!
//! # Stream ID Access Control Format
//!
//! SRT defines a standardized Stream ID format for access control:
//! `#!::key1=value1,key2=value2,...`
//!
//! Standard keys:
//! - `u` — Username / authorization identity
//! - `r` — Resource name (stream/file)
//! - `h` — Hostname
//! - `s` — Session ID
//! - `t` — Type: `stream` (default), `file`, `auth`
//! - `m` — Mode: `request` (default), `publish`, `bidirectional`

use std::net::SocketAddr;

use crate::error::RejectReason;

/// SRT handshake extension command type for Stream ID.
pub const SRT_CMD_SID: u16 = 5;

/// Information about an incoming connection, provided to the access control callback.
#[derive(Debug, Clone)]
pub struct HandshakeInfo {
    /// Remote peer address.
    pub peer_addr: SocketAddr,
    /// Stream ID sent by the caller (empty if none).
    pub stream_id: String,
    /// Whether the caller is using encryption.
    pub is_encrypted: bool,
    /// The caller's SRT socket ID.
    pub peer_socket_id: u32,
    /// The caller's SRT version (from the handshake).
    pub peer_version: i32,
}

/// Trait for controlling access to an SRT listener.
///
/// Implement this trait to inspect incoming connections and decide
/// whether to accept or reject them based on Stream ID, peer address,
/// encryption state, or any other criteria.
///
/// # Example
///
/// ```ignore
/// use srt_protocol::access_control::{AccessControl, HandshakeInfo};
/// use srt_protocol::error::RejectReason;
///
/// struct MyAccessControl;
///
/// impl AccessControl for MyAccessControl {
///     fn on_accept(&self, info: &HandshakeInfo) -> Result<(), RejectReason> {
///         if info.stream_id.starts_with("#!::r=live/") {
///             Ok(())
///         } else {
///             Err(RejectReason::Peer)
///         }
///     }
/// }
/// ```
pub trait AccessControl: Send + Sync + 'static {
    /// Called when a new connection completes the handshake.
    ///
    /// Return `Ok(())` to accept or `Err(RejectReason)` to reject.
    /// The reject reason is sent back to the caller in the handshake
    /// failure response.
    fn on_accept(&self, info: &HandshakeInfo) -> Result<(), RejectReason>;
}

/// An access control implementation that accepts all connections (default).
pub struct AcceptAll;

impl AccessControl for AcceptAll {
    fn on_accept(&self, _info: &HandshakeInfo) -> Result<(), RejectReason> {
        Ok(())
    }
}

/// Access control via a closure.
///
/// Allows using a closure instead of implementing the trait:
/// ```ignore
/// listener.access_control(|info| {
///     if info.stream_id == "secret" { Ok(()) }
///     else { Err(RejectReason::Peer) }
/// })
/// ```
pub struct AccessControlFn<F>(pub F);

impl<F> AccessControl for AccessControlFn<F>
where
    F: Fn(&HandshakeInfo) -> Result<(), RejectReason> + Send + Sync + 'static,
{
    fn on_accept(&self, info: &HandshakeInfo) -> Result<(), RejectReason> {
        (self.0)(info)
    }
}

/// Parse the Stream ID from a handshake extension block.
///
/// The Stream ID extension (type 5 / `SRT_CMD_SID`) carries UTF-8 text
/// packed into u32 words in network byte order, with optional trailing
/// null padding.
pub fn parse_stream_id(ext_data: &[u32]) -> String {
    let bytes: Vec<u8> = ext_data
        .iter()
        .flat_map(|w| w.to_be_bytes())
        .collect();
    // Trim trailing null bytes (padding)
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stream_id_simple() {
        // "test" = [0x74657374]
        let data = vec![0x7465_7374];
        assert_eq!(parse_stream_id(&data), "test");
    }

    #[test]
    fn test_parse_stream_id_with_padding() {
        // "hi" = [0x68690000]
        let data = vec![0x6869_0000];
        assert_eq!(parse_stream_id(&data), "hi");
    }

    #[test]
    fn test_parse_stream_id_empty() {
        let data: Vec<u32> = vec![];
        assert_eq!(parse_stream_id(&data), "");
    }

    #[test]
    fn test_parse_stream_id_multi_word() {
        // "hello world" = 11 bytes = 3 words with padding
        let s = "hello world";
        let mut bytes = s.as_bytes().to_vec();
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        let data: Vec<u32> = bytes.chunks(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        assert_eq!(parse_stream_id(&data), "hello world");
    }

    #[test]
    fn test_accept_all() {
        let ac = AcceptAll;
        let info = HandshakeInfo {
            peer_addr: "127.0.0.1:1234".parse().unwrap(),
            stream_id: String::new(),
            is_encrypted: false,
            peer_socket_id: 1,
            peer_version: 5,
        };
        assert!(ac.on_accept(&info).is_ok());
    }

    #[test]
    fn test_access_control_fn() {
        let ac = AccessControlFn(|info: &HandshakeInfo| {
            if info.stream_id == "allowed" {
                Ok(())
            } else {
                Err(RejectReason::Peer)
            }
        });

        let mut info = HandshakeInfo {
            peer_addr: "127.0.0.1:1234".parse().unwrap(),
            stream_id: "allowed".into(),
            is_encrypted: false,
            peer_socket_id: 1,
            peer_version: 5,
        };
        assert!(ac.on_accept(&info).is_ok());

        info.stream_id = "denied".into();
        assert_eq!(ac.on_accept(&info), Err(RejectReason::Peer));
    }

    #[test]
    fn test_stream_id_access_control_format() {
        // Test the #!::key=value format parsing
        let ac = AccessControlFn(|info: &HandshakeInfo| {
            let sid = &info.stream_id;
            if sid.starts_with("#!::") {
                // Parse key=value pairs
                let params = &sid[4..];
                for pair in params.split(',') {
                    let mut kv = pair.splitn(2, '=');
                    if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                        if k == "r" && v == "live/cam1" {
                            return Ok(());
                        }
                    }
                }
            }
            Err(RejectReason::Peer)
        });

        let info = HandshakeInfo {
            peer_addr: "127.0.0.1:1234".parse().unwrap(),
            stream_id: "#!::r=live/cam1,m=publish".into(),
            is_encrypted: false,
            peer_socket_id: 1,
            peer_version: 5,
        };
        assert!(ac.on_accept(&info).is_ok());
    }
}
