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

/// Maximum Stream ID length in bytes (per SRT spec).
pub const SRT_MAX_STREAM_ID_LEN: usize = 512;

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

/// Serialize a Stream ID string into u32 words for the SRT_CMD_SID extension.
///
/// The string is encoded as UTF-8 bytes packed into big-endian u32 words,
/// with trailing null-byte padding to the next 4-byte boundary.
/// Returns the extension header word followed by the data words.
pub fn serialize_stream_id(stream_id: &str) -> Vec<u32> {
    if stream_id.is_empty() {
        return Vec::new();
    }
    let mut bytes = stream_id.as_bytes().to_vec();
    // Pad to 4-byte boundary
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    let size_words = bytes.len() / 4;
    let mut words = Vec::with_capacity(1 + size_words);
    // Extension header: type=SID(5), size in words
    words.push((SRT_CMD_SID as u32) << 16 | size_words as u32);
    for chunk in bytes.chunks(4) {
        words.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    words
}

/// Parsed SRT Access Control Stream ID.
///
/// Represents the structured `#!::key=value,...` format defined by the
/// SRT Access Control specification. Standard keys:
/// - `r` — Resource name (stream/file identifier)
/// - `m` — Mode: `request` (pull), `publish` (push), `bidirectional`
/// - `s` — Session ID (one-time verification)
/// - `t` — Type: `stream` (default), `file`, `auth`
/// - `u` — Username / authorization identity
/// - `h` — Hostname
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamIdInfo {
    /// Resource name (`r` key).
    pub resource: Option<String>,
    /// Mode (`m` key): `request`, `publish`, or `bidirectional`.
    pub mode: Option<String>,
    /// Session ID (`s` key).
    pub session_id: Option<String>,
    /// Type (`t` key): `stream`, `file`, or `auth`.
    pub content_type: Option<String>,
    /// Username (`u` key).
    pub user_name: Option<String>,
    /// Hostname (`h` key).
    pub host_name: Option<String>,
    /// Non-standard extra key-value pairs.
    pub extra: Vec<(String, String)>,
    /// The raw Stream ID string.
    pub raw: String,
}

/// SRT Access Control mode values.
pub mod stream_mode {
    pub const REQUEST: &str = "request";
    pub const PUBLISH: &str = "publish";
    pub const BIDIRECTIONAL: &str = "bidirectional";
}

/// SRT Access Control type values.
pub mod stream_type {
    pub const STREAM: &str = "stream";
    pub const FILE: &str = "file";
    pub const AUTH: &str = "auth";
}

impl StreamIdInfo {
    /// Parse a Stream ID string into structured fields.
    ///
    /// If the string uses the SRT Access Control format (`#!::key=value,...`),
    /// the standard keys are extracted into typed fields. Any non-standard
    /// keys are collected in `extra`.
    ///
    /// If the string does not start with `#!::`, it is treated as a plain
    /// resource name (assigned to the `resource` field).
    pub fn parse(stream_id: &str) -> Self {
        let mut info = StreamIdInfo {
            raw: stream_id.to_string(),
            ..Default::default()
        };

        if stream_id.is_empty() {
            return info;
        }

        // Check for structured format: #!::key=value,...
        if let Some(params) = stream_id.strip_prefix("#!::") {
            for pair in params.split(',') {
                let pair = pair.trim();
                if pair.is_empty() {
                    continue;
                }
                if let Some((key, value)) = pair.split_once('=') {
                    match key {
                        "r" => info.resource = Some(value.to_string()),
                        "m" => info.mode = Some(value.to_string()),
                        "s" => info.session_id = Some(value.to_string()),
                        "t" => info.content_type = Some(value.to_string()),
                        "u" => info.user_name = Some(value.to_string()),
                        "h" => info.host_name = Some(value.to_string()),
                        _ => info.extra.push((key.to_string(), value.to_string())),
                    }
                }
            }
        } else {
            // Plain string — treat as resource name
            info.resource = Some(stream_id.to_string());
        }

        info
    }

    /// Format this info back into the SRT Access Control string format.
    pub fn to_stream_id(&self) -> String {
        let mut parts = Vec::new();
        if let Some(ref r) = self.resource {
            parts.push(format!("r={r}"));
        }
        if let Some(ref m) = self.mode {
            parts.push(format!("m={m}"));
        }
        if let Some(ref s) = self.session_id {
            parts.push(format!("s={s}"));
        }
        if let Some(ref t) = self.content_type {
            parts.push(format!("t={t}"));
        }
        if let Some(ref u) = self.user_name {
            parts.push(format!("u={u}"));
        }
        if let Some(ref h) = self.host_name {
            parts.push(format!("h={h}"));
        }
        for (k, v) in &self.extra {
            parts.push(format!("{k}={v}"));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("#!::{}", parts.join(","))
        }
    }
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
        // Test the #!::key=value format parsing via AccessControl callback
        let ac = AccessControlFn(|info: &HandshakeInfo| {
            let parsed = StreamIdInfo::parse(&info.stream_id);
            if parsed.resource.as_deref() == Some("live/cam1") {
                Ok(())
            } else {
                Err(RejectReason::Peer)
            }
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

    #[test]
    fn test_serialize_stream_id_empty() {
        assert!(serialize_stream_id("").is_empty());
    }

    #[test]
    fn test_serialize_stream_id_roundtrip() {
        let original = "#!::r=live/cam1,m=publish,u=user1";
        let words = serialize_stream_id(original);
        // First word is header: type=5, size in words
        assert_eq!(words[0] >> 16, SRT_CMD_SID as u32);
        // Parse back
        let parsed = parse_stream_id(&words[1..]);
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_serialize_stream_id_alignment() {
        // "hi" is 2 bytes, should be padded to 4 bytes (1 word)
        let words = serialize_stream_id("hi");
        assert_eq!(words.len(), 2); // 1 header + 1 data word
        let parsed = parse_stream_id(&words[1..]);
        assert_eq!(parsed, "hi");
    }

    #[test]
    fn test_stream_id_info_parse_structured() {
        let info = StreamIdInfo::parse("#!::r=live/cam1,m=publish,u=admin,t=stream,s=abc123,h=example.com");
        assert_eq!(info.resource.as_deref(), Some("live/cam1"));
        assert_eq!(info.mode.as_deref(), Some("publish"));
        assert_eq!(info.user_name.as_deref(), Some("admin"));
        assert_eq!(info.content_type.as_deref(), Some("stream"));
        assert_eq!(info.session_id.as_deref(), Some("abc123"));
        assert_eq!(info.host_name.as_deref(), Some("example.com"));
        assert!(info.extra.is_empty());
    }

    #[test]
    fn test_stream_id_info_parse_plain() {
        let info = StreamIdInfo::parse("my-stream-name");
        assert_eq!(info.resource.as_deref(), Some("my-stream-name"));
        assert!(info.mode.is_none());
    }

    #[test]
    fn test_stream_id_info_parse_empty() {
        let info = StreamIdInfo::parse("");
        assert!(info.resource.is_none());
        assert!(info.mode.is_none());
    }

    #[test]
    fn test_stream_id_info_parse_extra_keys() {
        let info = StreamIdInfo::parse("#!::r=test,custom=value,x=y");
        assert_eq!(info.resource.as_deref(), Some("test"));
        assert_eq!(info.extra, vec![
            ("custom".to_string(), "value".to_string()),
            ("x".to_string(), "y".to_string()),
        ]);
    }

    #[test]
    fn test_stream_id_info_roundtrip() {
        let original = StreamIdInfo {
            resource: Some("live/cam1".to_string()),
            mode: Some("publish".to_string()),
            user_name: Some("admin".to_string()),
            ..Default::default()
        };
        let stream_id = original.to_stream_id();
        assert_eq!(stream_id, "#!::r=live/cam1,m=publish,u=admin");
        let parsed = StreamIdInfo::parse(&stream_id);
        assert_eq!(parsed.resource, original.resource);
        assert_eq!(parsed.mode, original.mode);
        assert_eq!(parsed.user_name, original.user_name);
    }
}
