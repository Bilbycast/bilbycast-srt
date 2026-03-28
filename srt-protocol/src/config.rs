// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT socket configuration and options.
//!
//! [`SrtConfig`] holds all configurable parameters for an SRT connection,
//! including latency, buffer sizes, encryption settings, and transport mode.
//! It maps to the C++ `CSrtConfig` / `CSrtMuxerConfig` structures.

use std::time::Duration;

/// SRT transmission mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransType {
    /// Live streaming mode: low latency, TSBPD, packet dropping.
    Live,
    /// File transfer mode: reliable delivery, AIMD congestion control.
    File,
}

impl Default for TransType {
    fn default() -> Self {
        Self::Live
    }
}

/// Encryption cipher mode selection.
///
/// Determines whether SRT uses AES-CTR (confidentiality only) or AES-GCM
/// (authenticated encryption with integrity). This enum lives in config
/// (not behind the `encryption` feature gate) so that `SrtConfig` always compiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CryptoModeConfig {
    /// AES Counter mode (default, compatible with all SRT implementations).
    #[default]
    AesCtr,
    /// AES Galois/Counter mode — authenticated encryption. Requires libsrt >= 1.5.2
    /// on the peer. Only supports AES-128 and AES-256 (not AES-192).
    AesGcm,
}

/// Encryption key length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeySize {
    AES128 = 16,
    AES192 = 24,
    AES256 = 32,
}

impl KeySize {
    pub fn from_bytes(len: usize) -> Option<Self> {
        match len {
            16 => Some(Self::AES128),
            24 => Some(Self::AES192),
            32 => Some(Self::AES256),
            _ => None,
        }
    }

    /// Encode key size into the 3-bit field used in handshake (value >> 3).
    pub fn to_hs_bits(self) -> u32 {
        (self as u32) >> 3
    }

    /// Decode from the 3-bit handshake field (value << 3).
    pub fn from_hs_bits(bits: u32) -> Option<Self> {
        Self::from_bytes(((bits & 0x7) << 3) as usize)
    }
}

/// Retransmission algorithm selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetransmitAlgo {
    /// Default retransmission algorithm.
    Default = 0,
    /// Reduced retransmission (avoid unnecessary retransmissions).
    Reduced = 1,
}

/// Key material state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KmState {
    /// No encryption.
    Unsecured = 0,
    /// Encrypted, exchanging key material.
    Securing = 1,
    /// Encrypted, key material exchange complete.
    Secured = 2,
    /// Encrypted but no secret to decrypt.
    NoSecret = 3,
    /// Encrypted but wrong secret.
    BadSecret = 4,
    /// Wrong crypto mode.
    BadCryptoMode = 5,
}

impl KmState {
    pub fn from_value(v: i32) -> Self {
        match v {
            0 => Self::Unsecured,
            1 => Self::Securing,
            2 => Self::Secured,
            3 => Self::NoSecret,
            4 => Self::BadSecret,
            5 => Self::BadCryptoMode,
            _ => Self::Unsecured,
        }
    }
}

/// SRT socket configuration.
///
/// Maps to C++ `CSrtConfig` / `SRT_SOCKOPT`.
#[derive(Debug, Clone)]
pub struct SrtConfig {
    // ── Transport ──

    /// Maximum Segment Size (default: 1500).
    pub mss: u32,
    /// Flow control window size in packets (default: 25600).
    pub flight_flag_size: u32,
    /// Send buffer size in bytes (default: 8192 * SRT_LIVE_DEF_PLSIZE).
    pub send_buffer_size: u32,
    /// Receive buffer size in bytes (default: 8192 * SRT_LIVE_DEF_PLSIZE).
    pub recv_buffer_size: u32,
    /// UDP send buffer size.
    pub udp_send_buffer_size: u32,
    /// UDP receive buffer size.
    pub udp_recv_buffer_size: u32,
    /// Whether sending is blocking.
    pub send_sync: bool,
    /// Whether receiving is blocking.
    pub recv_sync: bool,
    /// Send timeout.
    pub send_timeout: Option<Duration>,
    /// Receive timeout.
    pub recv_timeout: Option<Duration>,
    /// Reuse address.
    pub reuse_addr: bool,
    /// Linger time on close.
    pub linger: Option<Duration>,

    // ── Connection ──

    /// Connection timeout.
    pub connect_timeout: Duration,
    /// Enable rendezvous mode.
    pub rendezvous: bool,
    /// IPv6 only mode.
    pub ipv6_only: bool,
    /// IP Time To Live.
    pub ip_ttl: i32,
    /// IP Type of Service.
    pub ip_tos: i32,
    /// Bind to device.
    pub bind_to_device: Option<String>,
    /// Peer idle timeout.
    pub peer_idle_timeout: Duration,

    // ── Transmission ──

    /// Transmission type (Live or File).
    pub trans_type: TransType,
    /// Use message API (true) or buffer API (false).
    pub message_api: bool,
    /// Maximum payload size (0 = unlimited).
    pub payload_size: u32,
    /// Maximum bandwidth in bytes/sec (0 = unlimited).
    pub max_bw: i64,
    /// Estimated input bandwidth in bytes/sec.
    pub input_bw: i64,
    /// Minimum input bandwidth in bytes/sec.
    pub min_input_bw: i64,
    /// Overhead bandwidth as percentage over input rate.
    pub overhead_bw: i32,
    /// Maximum retransmission bandwidth in bytes/sec (-1 = unlimited, 0 = disable retransmit).
    /// Maps to SRTO_MAXREXMITBW. Uses a token bucket shaper to prevent retransmissions
    /// from starving new data on lossy links.
    pub max_rexmit_bw: i64,

    // ── Live mode ──

    /// Enable TSBPD (Timestamp-Based Packet Delivery).
    pub tsbpd_mode: bool,
    /// Receiver latency in milliseconds.
    pub recv_latency: u32,
    /// Peer (sender-side) latency in milliseconds.
    pub peer_latency: u32,
    /// Enable too-late packet drop.
    pub tlpkt_drop: bool,
    /// Extra delay for sender drop decision (ms, -1 = off).
    pub send_drop_delay: i32,
    /// Enable NAK reports.
    pub nak_report: bool,
    /// Enable drift tracer.
    pub drift_tracer: bool,
    /// Maximum packet reorder tolerance.
    pub loss_max_ttl: i32,

    // ── Encryption ──

    /// Passphrase for encryption (empty = no encryption).
    pub passphrase: String,
    /// Encryption key length.
    pub key_size: KeySize,
    /// Encryption cipher mode (AES-CTR or AES-GCM).
    pub crypto_mode: CryptoModeConfig,
    /// Enforce encryption (reject unencrypted peers).
    pub enforced_encryption: bool,
    /// Key material refresh rate (packets).
    pub km_refresh_rate: u32,
    /// Key material pre-announce (packets before refresh).
    pub km_pre_announce: u32,

    // ── Sender flag ──

    /// Sender mode flag.
    pub sender: bool,

    // ── Stream ID ──

    /// Stream ID string.
    pub stream_id: String,

    // ── Congestion ──

    /// Congestion controller type name.
    pub congestion: String,

    // ── Packet filter ──

    /// Packet filter configuration string.
    pub packet_filter: String,

    // ── Retransmission ──

    /// Retransmission algorithm.
    pub retransmit_algo: RetransmitAlgo,

    // ── Minimum peer version ──

    /// Minimum SRT version required from peer.
    pub min_version: u32,

    // ── Bonding ──

    /// Allow group connections on listener.
    pub group_connect: bool,
    /// Minimum stability timeout for backup groups (ms).
    pub group_min_stable_timeout: Duration,
}

impl Default for SrtConfig {
    fn default() -> Self {
        Self {
            // Transport
            mss: 1500,
            flight_flag_size: 25600,
            send_buffer_size: 8192 * 1316,
            recv_buffer_size: 8192 * 1316,
            udp_send_buffer_size: 65536,
            udp_recv_buffer_size: 65536,
            send_sync: true,
            recv_sync: true,
            send_timeout: None,
            recv_timeout: None,
            reuse_addr: true,
            linger: Some(Duration::from_secs(180)),

            // Connection
            connect_timeout: Duration::from_secs(3),
            rendezvous: false,
            ipv6_only: false,
            ip_ttl: 64,
            ip_tos: 0,
            bind_to_device: None,
            peer_idle_timeout: Duration::from_secs(5),

            // Transmission
            trans_type: TransType::Live,
            message_api: true,
            payload_size: 1316, // 188 * 7, recommended for MPEG-TS
            max_bw: 0,
            input_bw: 0,
            min_input_bw: 0,
            overhead_bw: 25,
            max_rexmit_bw: -1, // unlimited by default

            // Live mode
            tsbpd_mode: true,
            recv_latency: 120,
            peer_latency: 0,
            tlpkt_drop: true,
            send_drop_delay: -1,
            nak_report: true,
            drift_tracer: true,
            loss_max_ttl: 0,

            // Encryption
            passphrase: String::new(),
            key_size: KeySize::AES128,
            crypto_mode: CryptoModeConfig::default(),
            enforced_encryption: true,
            km_refresh_rate: 0x0100_0000, // 16M packets
            km_pre_announce: 0x1000,       // 4096 packets

            // Sender
            sender: false,

            // Stream ID
            stream_id: String::new(),

            // Congestion
            congestion: String::from("live"),

            // Packet filter
            packet_filter: String::new(),

            // Retransmission
            retransmit_algo: RetransmitAlgo::Default,

            // Min version
            min_version: 0,

            // Bonding
            group_connect: false,
            group_min_stable_timeout: Duration::from_millis(60),
        }
    }
}

impl SrtConfig {
    /// Apply `SRTT_LIVE` transmission type defaults.
    pub fn live_defaults(&mut self) {
        self.trans_type = TransType::Live;
        self.message_api = true;
        self.tsbpd_mode = true;
        self.tlpkt_drop = true;
        self.nak_report = true;
        self.payload_size = 1316;
        self.congestion = String::from("live");
    }

    /// Apply `SRTT_FILE` transmission type defaults.
    pub fn file_defaults(&mut self) {
        self.trans_type = TransType::File;
        self.message_api = true;
        self.tsbpd_mode = false;
        self.tlpkt_drop = false;
        self.nak_report = false;
        self.payload_size = 0; // unlimited
        self.congestion = String::from("file");
    }

    /// Maximum payload that fits in a single SRT packet.
    pub fn max_payload_size(&self) -> usize {
        (self.mss as usize).saturating_sub(super::packet::header::UDP_HEADER_SIZE + super::packet::header::HEADER_SIZE)
    }

    /// Whether encryption is enabled.
    pub fn encryption_enabled(&self) -> bool {
        !self.passphrase.is_empty()
    }
}

/// SRT socket status (state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SocketStatus {
    Init = 1,
    Opened = 2,
    Listening = 3,
    Connecting = 4,
    Connected = 5,
    Broken = 6,
    Closing = 7,
    Closed = 8,
    NonExist = 9,
}

/// SRT handshake options (capability flags).
///
/// Sent during HSv5 handshake to negotiate features.
pub mod srt_options {
    use bitflags::bitflags;

    bitflags! {
        /// SRT option flags exchanged during handshake.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct SrtFlags: u32 {
            /// Timestamp-based packet delivery (sender).
            const TSBPD_SND = 1 << 0;
            /// Timestamp-based packet delivery (receiver).
            const TSBPD_RCV = 1 << 1;
            /// HaiCrypt AES encryption capability.
            const HAICRYPT = 1 << 2;
            /// Too-late packet drop.
            const TLPKT_DROP = 1 << 3;
            /// Periodic NAK reports.
            const NAK_REPORT = 1 << 4;
            /// Retransmission flag in message number field.
            const REXMIT_FLG = 1 << 5;
            /// Stream mode (not message mode).
            const STREAM = 1 << 6;
            /// Packet filter capability.
            const FILTER_CAP = 1 << 7;
        }
    }

    /// Capability flags always reported by this implementation.
    pub fn version_capabilities() -> SrtFlags {
        SrtFlags::HAICRYPT | SrtFlags::FILTER_CAP
    }
}

/// Default SRT live payload size (MPEG-TS: 188 * 7).
pub const SRT_LIVE_DEF_PLSIZE: u32 = 1316;

/// Maximum payload for live mode.
pub const SRT_LIVE_MAX_PLSIZE: u32 = 1456;

/// Default live latency in milliseconds.
pub const SRT_LIVE_DEF_LATENCY_MS: u32 = 120;

/// SRT protocol version number.
/// Format: 0xMMNNPP (Major.Minor.Patch) — v1.5.5 = 0x010505.
pub const SRT_VERSION: u32 = 0x01_05_05;
