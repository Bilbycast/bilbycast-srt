// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT Forward Error Correction (FEC) module.
//!
//! Implements the SRT packet filter FEC as defined in libsrt v1.5.5.
//! FEC adds XOR-based parity packets to the data stream, enabling
//! the receiver to recover lost packets without retransmission.
//!
//! # Configuration
//!
//! FEC is configured via the `SRTO_PACKETFILTER` socket option using a
//! config string format: `"fec,cols:10,rows:5,layout:staircase,arq:onreq"`
//!
//! # Wire Format
//!
//! FEC packets are regular SRT data packets with message number = 0
//! (`SRT_MSGNO_CONTROL`). The MSGNO word is `0xC000_0000` (PB_SOLO + msgno=0).
//! The payload starts with a 4-byte FEC header followed by XOR parity data.

pub mod decoder;
pub mod encoder;

use std::fmt;

use crate::packet::seq::SeqNo;

/// SRT_CMD_FILTER extension type for handshake negotiation.
pub const SRT_CMD_FILTER: u16 = 7;

/// Message number value that identifies FEC control packets.
/// FEC packets use msgno=0 in the SRT data packet header.
pub const SRT_MSGNO_CONTROL: u32 = 0;

/// Size of the FEC payload header in bytes.
/// [group_index: i8][xor_enc_flags: u8][xor_length: u16 BE]
pub const FEC_HEADER_SIZE: usize = 4;

/// Group index value for row FEC packets (signed -1 stored as 0xFF).
pub const FEC_GROUP_ROW: i8 = -1;

// ── FEC Layout ──

/// FEC matrix layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FecLayout {
    /// Simple grid: column groups start at sequential offsets.
    Even,
    /// Staircase: column groups are staggered to spread FEC packets evenly.
    /// This is the default and recommended layout.
    Staircase,
}

impl Default for FecLayout {
    fn default() -> Self {
        Self::Staircase
    }
}

impl fmt::Display for FecLayout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Even => write!(f, "even"),
            Self::Staircase => write!(f, "staircase"),
        }
    }
}

// ── ARQ Mode ──

/// ARQ (Automatic Repeat reQuest) interaction mode with FEC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArqMode {
    /// Normal retransmission + FEC in parallel (default SRT behavior).
    Always,
    /// Suppress NAK until FEC exhausts recovery; then report uncoverable losses.
    /// This is the default for FEC-enabled connections.
    OnReq,
    /// No retransmission at all — FEC-only mode.
    Never,
}

impl Default for ArqMode {
    fn default() -> Self {
        Self::OnReq
    }
}

impl fmt::Display for ArqMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Always => write!(f, "always"),
            Self::OnReq => write!(f, "onreq"),
            Self::Never => write!(f, "never"),
        }
    }
}

// ── FEC Config ──

/// FEC filter configuration.
///
/// Parsed from the libsrt-compatible config string format:
/// `"fec,cols:10,rows:5,layout:staircase,arq:onreq"`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FecConfig {
    /// Number of columns (row group size R). Each row FEC packet protects `cols` data packets.
    pub cols: usize,
    /// Number of rows (column group size C). Each column FEC packet protects `rows` data packets
    /// spaced `cols` apart. Set to 1 for row-only FEC (no column protection).
    pub rows: usize,
    /// Matrix layout: `Even` (simple grid) or `Staircase` (staggered columns).
    pub layout: FecLayout,
    /// ARQ interaction mode.
    pub arq: ArqMode,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            cols: 10,
            rows: 1,
            layout: FecLayout::Staircase,
            arq: ArqMode::OnReq,
        }
    }
}

impl FecConfig {
    /// Parse a libsrt-compatible packet filter config string.
    ///
    /// Format: `"fec,cols:10,rows:5,layout:staircase,arq:onreq"`
    ///
    /// The leading `"fec,"` prefix is required. Parameters are comma-separated
    /// key:value pairs. All parameters are optional and have defaults:
    /// - `cols`: 10 (row group size)
    /// - `rows`: 1 (column group size, 1 = row-only)
    /// - `layout`: `staircase`
    /// - `arq`: `onreq`
    pub fn parse(config_str: &str) -> Result<Self, String> {
        let trimmed = config_str.trim();
        if trimmed.is_empty() {
            return Err("empty config string".to_string());
        }

        // Must start with "fec"
        let parts: Vec<&str> = trimmed.splitn(2, ',').collect();
        if parts[0].trim() != "fec" {
            return Err(format!("config must start with 'fec', got '{}'", parts[0]));
        }

        let mut config = FecConfig::default();

        if parts.len() < 2 {
            return Ok(config);
        }

        // Parse comma-separated key:value pairs
        for param in parts[1].split(',') {
            let param = param.trim();
            if param.is_empty() {
                continue;
            }
            let kv: Vec<&str> = param.splitn(2, ':').collect();
            if kv.len() != 2 {
                return Err(format!("invalid parameter '{}', expected key:value", param));
            }
            let key = kv[0].trim();
            let value = kv[1].trim();

            match key {
                "cols" => {
                    config.cols = value.parse::<usize>()
                        .map_err(|_| format!("invalid cols value: '{}'", value))?;
                    if config.cols == 0 {
                        return Err("cols must be >= 1".to_string());
                    }
                }
                "rows" => {
                    // Negative rows in libsrt means column-only (no row FEC).
                    // We store the absolute value; column-only is indicated by rows > 1 + cols == 0,
                    // but libsrt doesn't actually support cols:0. Negative rows simply means
                    // the value of C (column group size). We parse it as unsigned here.
                    let raw: i64 = value.parse()
                        .map_err(|_| format!("invalid rows value: '{}'", value))?;
                    config.rows = raw.unsigned_abs() as usize;
                    if config.rows == 0 {
                        return Err("rows must be >= 1".to_string());
                    }
                }
                "layout" => {
                    config.layout = match value {
                        "even" => FecLayout::Even,
                        "staircase" => FecLayout::Staircase,
                        _ => return Err(format!("invalid layout: '{}', expected 'even' or 'staircase'", value)),
                    };
                }
                "arq" => {
                    config.arq = match value {
                        "always" => ArqMode::Always,
                        "onreq" => ArqMode::OnReq,
                        "never" => ArqMode::Never,
                        _ => return Err(format!("invalid arq: '{}', expected 'always', 'onreq', or 'never'", value)),
                    };
                }
                _ => {
                    // Unknown parameters are ignored for forward compatibility
                    log::debug!("FEC config: ignoring unknown parameter '{}'", key);
                }
            }
        }

        Ok(config)
    }

    /// Serialize to the libsrt-compatible config string format.
    pub fn to_config_string(&self) -> String {
        format!("fec,cols:{},rows:{},layout:{},arq:{}",
            self.cols, self.rows, self.layout, self.arq)
    }

    /// Whether this is a 2D FEC configuration (both row and column protection).
    pub fn is_2d(&self) -> bool {
        self.rows > 1
    }

    /// Total number of data packets in one complete FEC matrix.
    pub fn matrix_size(&self) -> usize {
        self.cols * self.rows
    }

    /// Calculate the column base offset for a given column index.
    ///
    /// For `Even` layout: column `c` starts at offset `c`.
    /// For `Staircase` layout: column `c` starts at `c * (1 + cols)` mod `matrix_size`.
    pub fn column_base_offset(&self, col_index: usize) -> usize {
        match self.layout {
            FecLayout::Even => col_index,
            FecLayout::Staircase => {
                let matrix = self.matrix_size();
                if matrix == 0 {
                    return 0;
                }
                (col_index * (1 + self.cols)) % matrix
            }
        }
    }
}

impl fmt::Display for FecConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_config_string())
    }
}

// ── Handshake Extension Serialization ──

/// Serialize a packet filter config string for the SRT_CMD_FILTER handshake extension.
///
/// Returns the extension header word followed by data words. The config string is
/// encoded as UTF-8 bytes packed into big-endian u32 words, null-padded to 4-byte alignment.
/// This follows the same pattern as `serialize_stream_id` for SRT_CMD_SID.
pub fn serialize_filter_extension(config: &str) -> Vec<u32> {
    if config.is_empty() {
        return Vec::new();
    }
    let mut bytes = config.as_bytes().to_vec();
    // Pad to 4-byte boundary
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    let size_words = bytes.len() / 4;
    let mut words = Vec::with_capacity(1 + size_words);
    // Extension header: type=Filter(7), size in words
    words.push((SRT_CMD_FILTER as u32) << 16 | size_words as u32);
    // String-based extensions use little-endian u32 packing (HtoILA in libsrt).
    // libsrt applies NtoHLA (ntohl) to the entire control packet payload on
    // receive, then ItoHLA (le32toh) on string extensions to recover the bytes.
    // By packing as LE here, the bytes survive the ntohl → le32toh roundtrip.
    for chunk in bytes.chunks(4) {
        words.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
    }
    words
}

/// Parse a packet filter config string from handshake extension u32 words.
///
/// The input is the data words (NOT including the extension header word).
/// Words are in little-endian string encoding (matching libsrt's HtoILA/ItoHLA).
pub fn parse_filter_extension(ext_data: &[u32]) -> String {
    let bytes: Vec<u8> = ext_data
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
    // Trim trailing null bytes (padding)
    let end = bytes.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Negotiate FEC filter configuration between local and peer configs.
///
/// Both sides must agree on the FEC parameters. If both specify a filter,
/// their parameters are compared. Conflicting values cause rejection.
/// If only one side specifies a filter and the other supports FILTER_CAP,
/// the specified config is used.
///
/// Returns the negotiated config string, or an error if incompatible.
pub fn negotiate_filter(local: &str, peer: &str) -> Result<String, String> {
    let local_empty = local.trim().is_empty();
    let peer_empty = peer.trim().is_empty();

    if local_empty && peer_empty {
        return Ok(String::new());
    }

    if local_empty {
        // Peer wants FEC, we accept it
        let _ = FecConfig::parse(peer)?; // validate
        return Ok(peer.to_string());
    }

    if peer_empty {
        // We want FEC, peer doesn't have a filter config but may support it via FILTER_CAP
        let _ = FecConfig::parse(local)?; // validate
        return Ok(local.to_string());
    }

    // Both sides have a filter config — parameters must match
    let local_cfg = FecConfig::parse(local)?;
    let peer_cfg = FecConfig::parse(peer)?;

    if local_cfg.cols != peer_cfg.cols {
        return Err(format!("FEC cols mismatch: local={} peer={}", local_cfg.cols, peer_cfg.cols));
    }
    if local_cfg.rows != peer_cfg.rows {
        return Err(format!("FEC rows mismatch: local={} peer={}", local_cfg.rows, peer_cfg.rows));
    }
    if local_cfg.layout != peer_cfg.layout {
        return Err(format!("FEC layout mismatch: local={} peer={}", local_cfg.layout, peer_cfg.layout));
    }

    // ARQ mode: use the more restrictive of the two (prefer onreq over always)
    let arq = match (local_cfg.arq, peer_cfg.arq) {
        (ArqMode::Never, _) | (_, ArqMode::Never) => ArqMode::Never,
        (ArqMode::OnReq, _) | (_, ArqMode::OnReq) => ArqMode::OnReq,
        _ => ArqMode::Always,
    };

    let negotiated = FecConfig {
        cols: local_cfg.cols,
        rows: local_cfg.rows,
        layout: local_cfg.layout,
        arq,
    };

    Ok(negotiated.to_config_string())
}

// ── XOR Utilities ──

/// XOR `src` into `dst`, extending `dst` with zeros if necessary.
pub fn xor_into(dst: &mut Vec<u8>, src: &[u8]) {
    if dst.len() < src.len() {
        dst.resize(src.len(), 0);
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// FEC group for recovery (used by the decoder).
#[derive(Debug)]
pub struct FecGroup {
    /// Base sequence number of this group.
    pub base_seq: SeqNo,
    /// Number of packets in the group.
    pub group_size: usize,
    /// Received packet flags (true = received).
    pub received: Vec<bool>,
    /// XOR parity accumulated from received packets.
    pub parity: Vec<u8>,
    /// Whether the FEC packet for this group has been received.
    pub fec_received: bool,
}

impl FecGroup {
    pub fn new(base_seq: SeqNo, group_size: usize) -> Self {
        Self {
            base_seq,
            group_size,
            received: vec![false; group_size],
            parity: Vec::new(),
            fec_received: false,
        }
    }

    /// Record a received data packet and XOR into parity.
    pub fn on_data_packet(&mut self, index: usize, payload: &[u8]) {
        if index >= self.group_size {
            return;
        }
        if self.received[index] {
            return; // duplicate
        }
        self.received[index] = true;
        xor_into(&mut self.parity, payload);
    }

    /// Record the FEC parity packet.
    pub fn on_fec_packet(&mut self, payload: &[u8]) {
        self.fec_received = true;
        xor_into(&mut self.parity, payload);
    }

    /// Check if exactly one packet is missing and can be recovered.
    /// Returns the index of the missing packet if recoverable.
    pub fn can_recover(&self) -> Option<usize> {
        if !self.fec_received {
            return None;
        }
        let mut missing_index = None;
        let mut missing_count = 0;
        for (i, &r) in self.received.iter().enumerate() {
            if !r {
                missing_count += 1;
                missing_index = Some(i);
                if missing_count > 1 {
                    return None;
                }
            }
        }
        if missing_count == 1 {
            missing_index
        } else {
            None
        }
    }

    /// Recover the missing packet (the parity buffer IS the recovered data
    /// after XOR of all other packets + FEC packet).
    pub fn recover(&self) -> Option<Vec<u8>> {
        if self.can_recover().is_some() {
            Some(self.parity.clone())
        } else {
            None
        }
    }

    /// Count how many packets are missing.
    pub fn missing_count(&self) -> usize {
        self.received.iter().filter(|&&r| !r).count()
    }

    /// Whether this group is complete (all packets received).
    pub fn is_complete(&self) -> bool {
        self.received.iter().all(|&r| r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_recovery() {
        let pkt0 = b"Hello, World!!!!";
        let pkt1 = b"SRT FEC testing!";
        let pkt2 = b"Third packet....";

        // Build FEC parity = XOR of all packets
        let mut fec_parity = vec![0u8; pkt0.len()];
        xor_into(&mut fec_parity, pkt0);
        xor_into(&mut fec_parity, pkt1);
        xor_into(&mut fec_parity, pkt2);

        // Simulate losing pkt1
        let mut group = FecGroup::new(SeqNo::new(0), 3);
        group.on_data_packet(0, pkt0);
        // pkt1 is lost
        group.on_data_packet(2, pkt2);
        group.on_fec_packet(&fec_parity);

        assert_eq!(group.can_recover(), Some(1));
        let recovered = group.recover().unwrap();
        assert_eq!(&recovered[..], &pkt1[..]);
    }

    #[test]
    fn test_config_parse_full() {
        let cfg = FecConfig::parse("fec,cols:10,rows:5,layout:staircase,arq:onreq").unwrap();
        assert_eq!(cfg.cols, 10);
        assert_eq!(cfg.rows, 5);
        assert_eq!(cfg.layout, FecLayout::Staircase);
        assert_eq!(cfg.arq, ArqMode::OnReq);
        assert!(cfg.is_2d());
        assert_eq!(cfg.matrix_size(), 50);
    }

    #[test]
    fn test_config_parse_minimal() {
        let cfg = FecConfig::parse("fec").unwrap();
        assert_eq!(cfg.cols, 10);
        assert_eq!(cfg.rows, 1);
        assert_eq!(cfg.layout, FecLayout::Staircase);
        assert_eq!(cfg.arq, ArqMode::OnReq);
        assert!(!cfg.is_2d());
    }

    #[test]
    fn test_config_parse_partial() {
        let cfg = FecConfig::parse("fec,cols:5,arq:never").unwrap();
        assert_eq!(cfg.cols, 5);
        assert_eq!(cfg.rows, 1);
        assert_eq!(cfg.arq, ArqMode::Never);
    }

    #[test]
    fn test_config_roundtrip() {
        let original = FecConfig {
            cols: 8,
            rows: 4,
            layout: FecLayout::Even,
            arq: ArqMode::Always,
        };
        let s = original.to_config_string();
        let parsed = FecConfig::parse(&s).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_config_parse_errors() {
        assert!(FecConfig::parse("").is_err());
        assert!(FecConfig::parse("notfec,cols:5").is_err());
        assert!(FecConfig::parse("fec,cols:0").is_err());
        assert!(FecConfig::parse("fec,rows:0").is_err());
        assert!(FecConfig::parse("fec,layout:invalid").is_err());
        assert!(FecConfig::parse("fec,arq:invalid").is_err());
    }

    #[test]
    fn test_filter_extension_roundtrip() {
        let config = "fec,cols:10,rows:5,layout:staircase,arq:onreq";
        let words = serialize_filter_extension(config);
        assert!(!words.is_empty());
        // First word is the header
        assert_eq!(words[0] >> 16, SRT_CMD_FILTER as u32);
        // Parse back (skip header word)
        let parsed = parse_filter_extension(&words[1..]);
        assert_eq!(parsed, config);
    }

    #[test]
    fn test_negotiate_both_same() {
        let result = negotiate_filter(
            "fec,cols:10,rows:5,layout:staircase,arq:onreq",
            "fec,cols:10,rows:5,layout:staircase,arq:always",
        );
        let negotiated = result.unwrap();
        let cfg = FecConfig::parse(&negotiated).unwrap();
        assert_eq!(cfg.cols, 10);
        assert_eq!(cfg.rows, 5);
        // OnReq is more restrictive than Always
        assert_eq!(cfg.arq, ArqMode::OnReq);
    }

    #[test]
    fn test_negotiate_mismatch() {
        let result = negotiate_filter(
            "fec,cols:10,rows:5",
            "fec,cols:8,rows:5",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_negotiate_one_empty() {
        let result = negotiate_filter("fec,cols:10", "").unwrap();
        assert_eq!(FecConfig::parse(&result).unwrap().cols, 10);
    }

    #[test]
    fn test_staircase_offsets() {
        let cfg = FecConfig {
            cols: 5,
            rows: 4,
            layout: FecLayout::Staircase,
            arq: ArqMode::OnReq,
        };
        // matrix_size = 20
        // col 0: 0 * 6 % 20 = 0
        // col 1: 1 * 6 % 20 = 6
        // col 2: 2 * 6 % 20 = 12
        // col 3: 3 * 6 % 20 = 18
        // col 4: 4 * 6 % 20 = 4
        assert_eq!(cfg.column_base_offset(0), 0);
        assert_eq!(cfg.column_base_offset(1), 6);
        assert_eq!(cfg.column_base_offset(2), 12);
        assert_eq!(cfg.column_base_offset(3), 18);
        assert_eq!(cfg.column_base_offset(4), 4);
    }

    #[test]
    fn test_even_offsets() {
        let cfg = FecConfig {
            cols: 5,
            rows: 4,
            layout: FecLayout::Even,
            arq: ArqMode::OnReq,
        };
        assert_eq!(cfg.column_base_offset(0), 0);
        assert_eq!(cfg.column_base_offset(1), 1);
        assert_eq!(cfg.column_base_offset(4), 4);
    }
}
