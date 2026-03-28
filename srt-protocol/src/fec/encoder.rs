// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! FEC encoder (sender side).
//!
//! Tracks data packets, accumulates XOR parity per group, and emits FEC
//! packets at the correct intervals. Row FEC is emitted every `cols` packets,
//! column FEC is emitted every `cols * rows` packets (2D mode only).
//!
//! FEC packets are fire-and-forget — they are NOT stored in the send buffer
//! and are NOT retransmitted.

use bytes::Bytes;

use crate::packet::seq::SeqNo;
use super::{FecConfig, FecLayout, FEC_GROUP_ROW, FEC_HEADER_SIZE, xor_into};

/// Data needed to construct and send an FEC packet on the wire.
#[derive(Debug, Clone)]
pub struct FecPacketData {
    /// Sequence number = last data packet's sequence number in the group.
    pub seq_no: SeqNo,
    /// Timestamp = XOR of all data packet timestamps in the group.
    pub timestamp: u32,
    /// Complete FEC payload: 4-byte header + XOR parity data.
    pub payload: Bytes,
}

/// State for a single FEC group (row or column) during encoding.
struct FecGroupState {
    /// XOR-accumulated payload data (zero-padded to max payload size).
    parity_payload: Vec<u8>,
    /// XOR of all timestamps in the group.
    parity_timestamp: u32,
    /// XOR of encryption flag bytes.
    parity_enc_flags: u8,
    /// XOR of payload lengths (16-bit, big-endian in the FEC header).
    parity_length: u16,
    /// Number of data packets accumulated so far.
    count: usize,
    /// Total expected packets for this group.
    expected: usize,
    /// Sequence number of the last data packet fed into this group.
    last_seq: SeqNo,
}

impl FecGroupState {
    fn new(expected: usize) -> Self {
        Self {
            parity_payload: Vec::new(),
            parity_timestamp: 0,
            parity_enc_flags: 0,
            parity_length: 0,
            count: 0,
            expected,
            last_seq: SeqNo::new(0),
        }
    }

    fn reset(&mut self) {
        self.parity_payload.clear();
        self.parity_timestamp = 0;
        self.parity_enc_flags = 0;
        self.parity_length = 0;
        self.count = 0;
    }

    /// Feed a data packet into this group.
    fn feed(&mut self, seq: SeqNo, timestamp: u32, enc_flags: u8, payload: &[u8]) {
        xor_into(&mut self.parity_payload, payload);
        self.parity_timestamp ^= timestamp;
        self.parity_enc_flags ^= enc_flags;
        self.parity_length ^= payload.len() as u16;
        self.count += 1;
        self.last_seq = seq;
    }

    /// Whether this group is complete (all expected packets fed).
    fn is_complete(&self) -> bool {
        self.count >= self.expected
    }

    /// Build the FEC packet payload (4-byte header + parity data).
    fn build_fec_payload(&self, group_index: i8) -> Bytes {
        let mut buf = Vec::with_capacity(FEC_HEADER_SIZE + self.parity_payload.len());
        buf.push(group_index as u8);
        buf.push(self.parity_enc_flags);
        buf.extend_from_slice(&self.parity_length.to_be_bytes());
        buf.extend_from_slice(&self.parity_payload);
        Bytes::from(buf)
    }
}

/// FEC encoder for the sender side.
///
/// Tracks outgoing data packets, accumulates XOR parity per row and column
/// groups, and produces FEC packets when groups complete.
pub struct FecEncoder {
    config: FecConfig,
    /// Current row group being accumulated.
    row_group: FecGroupState,
    /// Current column groups (one per column). Only used in 2D mode.
    col_groups: Vec<FecGroupState>,
    /// Counter of data packets fed (mod matrix_size for column tracking).
    pkt_counter: usize,
}

impl FecEncoder {
    /// Create a new FEC encoder.
    pub fn new(config: FecConfig) -> Self {
        let cols = config.cols;
        let rows = config.rows;
        let col_groups = if config.is_2d() {
            (0..cols).map(|_| FecGroupState::new(rows)).collect()
        } else {
            Vec::new()
        };

        Self {
            row_group: FecGroupState::new(cols),
            col_groups,
            pkt_counter: 0,
            config,
        }
    }

    /// Feed a data packet to the encoder.
    ///
    /// Returns 0, 1, or 2 FEC packets:
    /// - A row FEC packet every `cols` data packets
    /// - A column FEC packet when a column group completes (2D mode only)
    ///
    /// The `enc_flags` should be the encryption key spec bits from the data packet
    /// header (0 = no encryption, 1 = even key, 2 = odd key).
    pub fn on_data_packet(
        &mut self,
        seq: SeqNo,
        timestamp: u32,
        enc_flags: u8,
        payload: &[u8],
    ) -> Vec<FecPacketData> {
        let mut fec_packets = Vec::new();

        // Feed into current row group
        self.row_group.feed(seq, timestamp, enc_flags, payload);

        // Feed into column group (2D mode)
        if self.config.is_2d() {
            let col_index = self.column_index_for_packet(self.pkt_counter);
            if col_index < self.col_groups.len() {
                self.col_groups[col_index].feed(seq, timestamp, enc_flags, payload);
            }
        }

        self.pkt_counter += 1;

        // Check if row group is complete → emit row FEC
        if self.row_group.is_complete() {
            let fec_payload = self.row_group.build_fec_payload(FEC_GROUP_ROW);
            fec_packets.push(FecPacketData {
                seq_no: self.row_group.last_seq,
                timestamp: self.row_group.parity_timestamp,
                payload: fec_payload,
            });
            self.row_group.reset();
            self.row_group.expected = self.config.cols;
        }

        // Check if any column group is complete → emit column FEC
        if self.config.is_2d() {
            for (col_idx, col_group) in self.col_groups.iter_mut().enumerate() {
                if col_group.is_complete() {
                    let fec_payload = col_group.build_fec_payload(col_idx as i8);
                    fec_packets.push(FecPacketData {
                        seq_no: col_group.last_seq,
                        timestamp: col_group.parity_timestamp,
                        payload: fec_payload,
                    });
                    col_group.reset();
                    col_group.expected = self.config.rows;
                }
            }
        }

        fec_packets
    }

    /// Determine which column a packet at position `pkt_pos` (within the matrix) belongs to.
    ///
    /// For `Even` layout: `pkt_pos % cols`
    /// For `Staircase` layout: calculated based on staggered column base offsets.
    fn column_index_for_packet(&self, pkt_pos: usize) -> usize {
        let cols = self.config.cols;
        if cols == 0 {
            return 0;
        }

        // Position within the current matrix cycle
        let pos_in_matrix = pkt_pos % self.config.matrix_size();

        match self.config.layout {
            FecLayout::Even => {
                // In Even layout, packets are laid out row by row:
                // Row 0: [0, 1, 2, ..., cols-1]
                // Row 1: [cols, cols+1, ..., 2*cols-1]
                // Column index = position mod cols
                pos_in_matrix % cols
            }
            FecLayout::Staircase => {
                // In Staircase layout, column base offsets are staggered.
                // We need to find which column this position belongs to.
                // Column c collects packets at: base_offset(c), base_offset(c)+cols, base_offset(c)+2*cols, ...
                let matrix = self.config.matrix_size();
                for c in 0..cols {
                    let base = self.config.column_base_offset(c);
                    // Check if pos_in_matrix matches any slot in column c
                    // Column c slots: base, base+cols, base+2*cols, ... (mod matrix_size)
                    for r in 0..self.config.rows {
                        let slot = (base + r * cols) % matrix;
                        if slot == pos_in_matrix {
                            return c;
                        }
                    }
                }
                // Fallback (should not happen with valid config)
                pos_in_matrix % cols
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fec::FecConfig;

    #[test]
    fn test_row_fec_generation() {
        let config = FecConfig {
            cols: 3,
            rows: 1,
            layout: FecLayout::Even,
            arq: super::super::ArqMode::OnReq,
        };
        let mut encoder = FecEncoder::new(config);

        // Send 3 packets (one row group)
        let pkt0 = b"aaaa";
        let pkt1 = b"bbbb";
        let pkt2 = b"cccc";

        let fec0 = encoder.on_data_packet(SeqNo::new(0), 100, 0, pkt0);
        assert!(fec0.is_empty());

        let fec1 = encoder.on_data_packet(SeqNo::new(1), 200, 0, pkt1);
        assert!(fec1.is_empty());

        let fec2 = encoder.on_data_packet(SeqNo::new(2), 300, 0, pkt2);
        assert_eq!(fec2.len(), 1);

        let fec_pkt = &fec2[0];
        // Seq should be last data packet's seq
        assert_eq!(fec_pkt.seq_no, SeqNo::new(2));
        // Timestamp should be XOR of all timestamps
        assert_eq!(fec_pkt.timestamp, 100 ^ 200 ^ 300);

        // Payload should be 4-byte header + XOR parity
        assert!(fec_pkt.payload.len() >= FEC_HEADER_SIZE);
        // Group index for row = -1 = 0xFF
        assert_eq!(fec_pkt.payload[0], 0xFF);
    }

    #[test]
    fn test_row_fec_recovery() {
        // Encoder produces FEC, decoder can use it to recover
        let config = FecConfig {
            cols: 3,
            rows: 1,
            layout: FecLayout::Even,
            arq: super::super::ArqMode::OnReq,
        };
        let mut encoder = FecEncoder::new(config);

        let pkt0 = b"Hello!!!";
        let pkt1 = b"FEC test";
        let pkt2 = b"Recovery";

        encoder.on_data_packet(SeqNo::new(0), 100, 0, pkt0);
        encoder.on_data_packet(SeqNo::new(1), 200, 0, pkt1);
        let fec_pkts = encoder.on_data_packet(SeqNo::new(2), 300, 0, pkt2);
        assert_eq!(fec_pkts.len(), 1);

        // Extract XOR parity from FEC payload (skip 4-byte header)
        let fec_payload = &fec_pkts[0].payload[FEC_HEADER_SIZE..];

        // Simulate losing pkt1: XOR pkt0, pkt2, and fec_parity should give pkt1
        let mut recovered = fec_payload.to_vec();
        crate::fec::xor_into(&mut recovered, pkt0);
        crate::fec::xor_into(&mut recovered, pkt2);
        assert_eq!(&recovered[..pkt1.len()], &pkt1[..]);
    }

    #[test]
    fn test_2d_fec_generation() {
        let config = FecConfig {
            cols: 3,
            rows: 2,
            layout: FecLayout::Even,
            arq: super::super::ArqMode::OnReq,
        };
        let mut encoder = FecEncoder::new(config);

        let mut total_fec = 0;
        // Send 6 packets (one complete matrix = 3 cols * 2 rows)
        for i in 0..6 {
            let payload = format!("pkt{:04}", i);
            let fec = encoder.on_data_packet(
                SeqNo::new(i),
                (i as u32 + 1) * 100,
                0,
                payload.as_bytes(),
            );
            total_fec += fec.len();
        }

        // Should have: 2 row FEC packets (one per row of 3) + 3 column FEC packets (one per column of 2)
        assert_eq!(total_fec, 5);
    }

    #[test]
    fn test_column_index_even() {
        let config = FecConfig {
            cols: 4,
            rows: 3,
            layout: FecLayout::Even,
            arq: super::super::ArqMode::OnReq,
        };
        let encoder = FecEncoder::new(config);

        assert_eq!(encoder.column_index_for_packet(0), 0);
        assert_eq!(encoder.column_index_for_packet(1), 1);
        assert_eq!(encoder.column_index_for_packet(2), 2);
        assert_eq!(encoder.column_index_for_packet(3), 3);
        assert_eq!(encoder.column_index_for_packet(4), 0); // second row
        assert_eq!(encoder.column_index_for_packet(5), 1);
    }
}
