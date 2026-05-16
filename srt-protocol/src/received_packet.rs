// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Receive-side packet container with sender metadata.
//!
//! Returned from [`SrtSocket::recv`] and friends. Carries the payload
//! bytes alongside the per-packet metadata libsrt surfaces via
//! `SRT_MsgCtrl` — most importantly `srctime`, the sender-set
//! microsecond timestamp that bilbycast's master-clock uses for rate
//! recovery on internet-contribution paths where MPEG-TS PCR sampled
//! from the bytes after a 200 ms+ latency-buffer release is too
//! bursty for the PLL to lock cleanly.
//!
//! ## API surface choice
//!
//! Bundled metadata (this struct), not a parallel `recv_with_meta()`
//! method. Matches the industry pattern — librist's `RistDataBlock`,
//! GStreamer's `GstSample`, FFmpeg's `AVPacket`, libsrt's own C
//! `srt_recvmsg2` — every serious media-transport library returns
//! payload + metadata as one unit. Callers that don't need the
//! metadata pay nothing extra (a single `Option<i64>` in the struct).
//!
//! ## API parity
//!
//! Mirrored byte-for-byte in `bilbycast-libsrt-rs/srt-protocol/src/received_packet.rs`
//! so the two backends remain drop-in swappable per
//! `bilbycast-edge/Cargo.toml`'s `── SRT backend ──` block. Changes
//! here must land in both backends.

use bytes::Bytes;

/// One application-layer packet delivered by SRT, with the sender's
/// per-packet metadata when available.
#[derive(Debug, Clone)]
pub struct ReceivedPacket {
    /// Application payload (post-decryption, post-FEC-recover,
    /// post-loss-recovery — exactly what the sender's `srt_sendmsg`
    /// passed in).
    pub data: Bytes,
    /// Sender-set delivery timestamp in microseconds since the Unix
    /// epoch, when carried on the wire.
    ///
    /// `None` when the pure-Rust protocol implementation doesn't
    /// surface a sender timestamp on the current message — by
    /// default the bilbycast-srt SRT stack does not propagate
    /// `srctime` as libsrt does, since the wire format doesn't carry
    /// it explicitly outside of libsrt's TSBPD bookkeeping. Callers
    /// fall back to MPEG-TS PCR sampled from the bytes when this
    /// field is `None`, matching the libsrt-backed behaviour.
    ///
    /// Reserved for forward compatibility — when the pure-Rust SRT
    /// stack adds a TSBPD-style send-time propagation path in
    /// future, populate this field at TSBPD-output to keep the API
    /// identical to the libsrt backend.
    pub sender_timestamp_us: Option<i64>,
}

impl ReceivedPacket {
    /// Build with no sender timestamp (default for the pure-Rust SRT
    /// backend; consumers fall back to PCR-from-bytes).
    pub fn from_bytes(data: Bytes) -> Self {
        Self {
            data,
            sender_timestamp_us: None,
        }
    }

    /// Build with the sender's microsecond timestamp. Provided for
    /// API parity with the libsrt backend; today no callers in the
    /// pure-Rust stack invoke this.
    pub fn with_srctime(data: Bytes, srctime_us: i64) -> Self {
        let ts = if srctime_us == 0 { None } else { Some(srctime_us) };
        Self {
            data,
            sender_timestamp_us: ts,
        }
    }

    /// Discard metadata, return payload bytes. Legacy-API convenience.
    #[inline]
    pub fn into_bytes(self) -> Bytes {
        self.data
    }
}

impl From<Bytes> for ReceivedPacket {
    fn from(data: Bytes) -> Self {
        Self::from_bytes(data)
    }
}

impl AsRef<[u8]> for ReceivedPacket {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}
