// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! FEC decoder (receiver side).
//!
//! Tracks received data packets and FEC packets, attempts XOR recovery
//! when exactly one packet is missing from a group. In 2D mode, recovery
//! in one dimension can cascade to enable recovery in the other dimension.

use std::collections::{HashMap, HashSet};

use bytes::Bytes;

use crate::packet::seq::SeqNo;
use super::{FecConfig, FecLayout, FEC_GROUP_ROW, FEC_HEADER_SIZE, xor_into};

/// A recovered data packet.
#[derive(Debug, Clone)]
pub struct RecoveredPacket {
    /// Sequence number of the recovered packet.
    pub seq_no: SeqNo,
    /// Recovered timestamp (from FEC header XOR + other timestamps).
    pub timestamp: u32,
    /// Recovered encryption flags.
    pub enc_flags: u8,
    /// Recovered payload data.
    pub payload: Bytes,
}

/// Result of processing an FEC packet.
#[derive(Debug, Default)]
pub struct FecDecodeResult {
    /// Packets successfully recovered via FEC.
    pub recovered: Vec<RecoveredPacket>,
    /// Sequence numbers that FEC could NOT recover (2+ missing in a complete group).
    /// Used by ARQ `OnReq` mode to trigger retransmission requests.
    pub uncoverable: Vec<SeqNo>,
}

/// State for a single FEC receive group (row or column).
struct FecRecvGroup {
    /// Sequence numbers of all packets in this group (in order).
    member_seqs: Vec<SeqNo>,
    /// Group size (number of data packets expected).
    group_size: usize,
    /// Which members have been received (indexed by position in group).
    received: Vec<bool>,
    /// XOR parity accumulated from received packets + FEC packet.
    parity_payload: Vec<u8>,
    /// XOR of timestamps.
    parity_timestamp: u32,
    /// XOR of encryption flags.
    parity_enc_flags: u8,
    /// XOR of payload lengths.
    parity_length: u16,
    /// Whether the FEC parity packet has been received.
    fec_received: bool,
}

impl FecRecvGroup {
    fn new(member_seqs: Vec<SeqNo>, group_size: usize) -> Self {
        Self {
            member_seqs,
            group_size,
            received: vec![false; group_size],
            parity_payload: Vec::new(),
            parity_timestamp: 0,
            parity_enc_flags: 0,
            parity_length: 0,
            fec_received: false,
        }
    }

    /// Feed a data packet into this group.
    fn on_data_packet(&mut self, index: usize, timestamp: u32, enc_flags: u8, payload: &[u8]) {
        if index >= self.group_size || self.received[index] {
            return;
        }
        self.received[index] = true;
        xor_into(&mut self.parity_payload, payload);
        self.parity_timestamp ^= timestamp;
        self.parity_enc_flags ^= enc_flags;
        self.parity_length ^= payload.len() as u16;
    }

    /// Feed the FEC parity packet.
    fn on_fec_packet(&mut self, parity_payload: &[u8], parity_timestamp: u32, parity_enc_flags: u8, parity_length: u16) {
        if self.fec_received {
            return;
        }
        self.fec_received = true;
        xor_into(&mut self.parity_payload, parity_payload);
        self.parity_timestamp ^= parity_timestamp;
        self.parity_enc_flags ^= parity_enc_flags;
        self.parity_length ^= parity_length;
    }

    /// Count missing packets.
    fn missing_count(&self) -> usize {
        self.received.iter().filter(|&&r| !r).count()
    }

    /// Try to recover a single missing packet.
    /// Returns the recovered packet if exactly one is missing and FEC is received.
    fn try_recover(&self) -> Option<(usize, RecoveredPacket)> {
        if !self.fec_received || self.missing_count() != 1 {
            return None;
        }

        let missing_idx = self.received.iter().position(|&r| !r)?;
        let missing_seq = self.member_seqs.get(missing_idx).copied()?;

        // The parity buffer now contains the XOR of all other packets + FEC = recovered packet
        let recovered_len = self.parity_length as usize;
        let payload = if recovered_len > 0 && recovered_len <= self.parity_payload.len() {
            Bytes::copy_from_slice(&self.parity_payload[..recovered_len])
        } else {
            Bytes::copy_from_slice(&self.parity_payload)
        };

        Some((missing_idx, RecoveredPacket {
            seq_no: missing_seq,
            timestamp: self.parity_timestamp,
            enc_flags: self.parity_enc_flags,
            payload,
        }))
    }

    /// Get sequence numbers of unrecoverable losses.
    /// Called when FEC is received but 2+ packets are missing.
    fn uncoverable_losses(&self) -> Vec<SeqNo> {
        if !self.fec_received || self.missing_count() < 2 {
            return Vec::new();
        }
        self.received.iter().enumerate()
            .filter(|&(_, &r)| !r)
            .filter_map(|(i, _)| self.member_seqs.get(i).copied())
            .collect()
    }

    /// Mark a member as received (used after cascade recovery).
    fn mark_received(&mut self, index: usize, timestamp: u32, enc_flags: u8, payload: &[u8]) {
        self.on_data_packet(index, timestamp, enc_flags, payload);
    }
}

// ── Group Key ──

/// FEC decoder for the receiver side.
pub struct FecDecoder {
    config: FecConfig,
    /// Active row groups.
    row_groups: HashMap<u32, FecRecvGroup>,
    /// Active column groups (key = col_index * 10000 + matrix_cycle).
    col_groups: HashMap<u64, FecRecvGroup>,
    /// Tracks which sequence numbers have been received or recovered.
    received_seqs: HashSet<i32>,
    /// Base sequence number (peer's ISN).
    base_seq: SeqNo,
    /// Highest matrix cycle completed (for cleanup).
    highest_cycle: u64,
}

impl FecDecoder {
    /// Create a new FEC decoder.
    pub fn new(config: FecConfig, base_seq: SeqNo) -> Self {
        Self {
            row_groups: HashMap::new(),
            col_groups: HashMap::new(),
            received_seqs: HashSet::new(),
            base_seq,
            highest_cycle: 0,
            config,
        }
    }

    /// Register a received data packet.
    ///
    /// The packet is fed into its row and column groups. If feeding the packet
    /// completes a group that can now recover a missing packet, the recovered
    /// packet is returned. In 2D mode, cascade recovery is attempted.
    pub fn on_data_packet(
        &mut self,
        seq: SeqNo,
        timestamp: u32,
        enc_flags: u8,
        payload: &[u8],
    ) -> Vec<RecoveredPacket> {
        if self.received_seqs.contains(&seq.value()) {
            return Vec::new(); // duplicate
        }
        self.received_seqs.insert(seq.value());

        let offset = SeqNo::offset(self.base_seq, seq).max(0) as usize;
        let cols = self.config.cols;
        if cols == 0 {
            return Vec::new();
        }

        // Determine row group
        let row_number = (offset / cols) as u32;
        let row_index = offset % cols;
        self.ensure_row_group(row_number);
        if let Some(group) = self.row_groups.get_mut(&row_number) {
            group.on_data_packet(row_index, timestamp, enc_flags, payload);
        }

        // Determine column group (2D mode)
        if self.config.is_2d() {
            let matrix_size = self.config.matrix_size();
            let matrix_cycle = offset / matrix_size;
            let pos_in_matrix = offset % matrix_size;
            let col_index = self.find_column_index(pos_in_matrix);
            let col_row = self.find_column_row(pos_in_matrix, col_index);

            let col_key = col_index as u64 * 100_000 + matrix_cycle as u64;
            self.ensure_col_group(col_key, col_index, matrix_cycle);
            if let Some(group) = self.col_groups.get_mut(&col_key) {
                group.on_data_packet(col_row, timestamp, enc_flags, payload);
            }

            self.highest_cycle = self.highest_cycle.max(matrix_cycle as u64);
        }

        // Try recovery (including cascade)
        self.try_recover_all()
    }

    /// Process a received FEC packet.
    ///
    /// Parses the 4-byte FEC header, determines the group (row or column),
    /// and attempts recovery. Returns recovered packets and uncoverable losses.
    pub fn on_fec_packet(
        &mut self,
        seq: SeqNo,
        fec_payload: &[u8],
    ) -> FecDecodeResult {
        if fec_payload.len() < FEC_HEADER_SIZE {
            log::debug!("FEC packet too short: {} bytes", fec_payload.len());
            return FecDecodeResult::default();
        }

        // Parse FEC header
        let group_index = fec_payload[0] as i8;
        let xor_enc_flags = fec_payload[1];
        let xor_length = u16::from_be_bytes([fec_payload[2], fec_payload[3]]);
        let xor_payload = &fec_payload[FEC_HEADER_SIZE..];

        // Determine the FEC packet's timestamp from the packet header
        // (The FEC packet itself carries the XOR'd timestamp in the SRT header)
        // We pass 0 here; the actual XOR'd timestamp is handled by the caller
        // via the SRT packet header's timestamp field.

        let offset = SeqNo::offset(self.base_seq, seq).max(0) as usize;
        let cols = self.config.cols;
        if cols == 0 {
            return FecDecodeResult::default();
        }

        if group_index == FEC_GROUP_ROW {
            // Row FEC: the seq = last packet in the row
            // The row number = offset / cols (the FEC packet's seq is the last in the row)
            let row_number = (offset / cols) as u32;
            self.ensure_row_group(row_number);
            if let Some(group) = self.row_groups.get_mut(&row_number) {
                group.on_fec_packet(xor_payload, 0, xor_enc_flags, xor_length);
            }
        } else {
            // Column FEC: group_index = column index
            let col_index = group_index as usize;
            if col_index < self.config.cols && self.config.is_2d() {
                let matrix_size = self.config.matrix_size();
                let matrix_cycle: usize = offset / matrix_size;
                let col_key = col_index as u64 * 100_000 + matrix_cycle as u64;
                self.ensure_col_group(col_key, col_index, matrix_cycle);
                if let Some(group) = self.col_groups.get_mut(&col_key) {
                    group.on_fec_packet(xor_payload, 0, xor_enc_flags, xor_length);
                }
            }
        }

        // Try recovery
        let recovered = self.try_recover_all();

        // Collect uncoverable losses
        let mut uncoverable = Vec::new();
        for group in self.row_groups.values() {
            uncoverable.extend(group.uncoverable_losses());
        }
        for group in self.col_groups.values() {
            uncoverable.extend(group.uncoverable_losses());
        }
        // Deduplicate
        uncoverable.sort_by_key(|s| s.value());
        uncoverable.dedup_by_key(|s| s.value());

        FecDecodeResult { recovered, uncoverable }
    }

    /// Try to recover packets from all groups, including cascade recovery.
    fn try_recover_all(&mut self) -> Vec<RecoveredPacket> {
        let mut all_recovered = Vec::new();
        let mut changed = true;

        // Iterate until no more recoveries are possible (cascade)
        while changed {
            changed = false;

            // Try row groups
            let row_keys: Vec<u32> = self.row_groups.keys().copied().collect();
            for row_key in row_keys {
                if let Some(group) = self.row_groups.get(&row_key) {
                    if let Some((_, recovered)) = group.try_recover() {
                        let recovered_seq = recovered.seq_no;
                        let recovered_ts = recovered.timestamp;
                        let recovered_enc = recovered.enc_flags;
                        let recovered_payload = recovered.payload.clone();

                        all_recovered.push(recovered);
                        self.received_seqs.insert(recovered_seq.value());
                        changed = true;

                        // Feed recovered packet into column groups (cascade)
                        if self.config.is_2d() {
                            let offset = SeqNo::offset(self.base_seq, recovered_seq).max(0) as usize;
                            let matrix_size = self.config.matrix_size();
                            let matrix_cycle = offset / matrix_size;
                            let pos_in_matrix = offset % matrix_size;
                            let col_index = self.find_column_index(pos_in_matrix);
                            let col_row = self.find_column_row(pos_in_matrix, col_index);
                            let col_key = col_index as u64 * 100_000 + matrix_cycle as u64;
                            if let Some(col_group) = self.col_groups.get_mut(&col_key) {
                                col_group.mark_received(col_row, recovered_ts, recovered_enc, &recovered_payload);
                            }
                        }

                        // Mark recovered in the row group itself
                        if let Some(group) = self.row_groups.get_mut(&row_key) {
                            let offset = SeqNo::offset(self.base_seq, recovered_seq).max(0) as usize;
                            let row_index = offset % self.config.cols;
                            group.received[row_index] = true;
                        }
                    }
                }
            }

            // Try column groups
            if self.config.is_2d() {
                let col_keys: Vec<u64> = self.col_groups.keys().copied().collect();
                for col_key in col_keys {
                    if let Some(group) = self.col_groups.get(&col_key) {
                        if let Some((_, recovered)) = group.try_recover() {
                            let recovered_seq = recovered.seq_no;
                            let recovered_ts = recovered.timestamp;
                            let recovered_enc = recovered.enc_flags;
                            let recovered_payload = recovered.payload.clone();

                            all_recovered.push(recovered);
                            self.received_seqs.insert(recovered_seq.value());
                            changed = true;

                            // Feed recovered packet into row group (cascade)
                            let offset = SeqNo::offset(self.base_seq, recovered_seq).max(0) as usize;
                            let row_number = (offset / self.config.cols) as u32;
                            let row_index = offset % self.config.cols;
                            if let Some(row_group) = self.row_groups.get_mut(&row_number) {
                                row_group.mark_received(row_index, recovered_ts, recovered_enc, &recovered_payload);
                            }

                            // Mark in column group
                            if let Some(group) = self.col_groups.get_mut(&col_key) {
                                // Find which row was recovered
                                for (i, member_seq) in group.member_seqs.iter().enumerate() {
                                    if *member_seq == recovered_seq {
                                        group.received[i] = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        all_recovered
    }

    /// Clean up old groups that are fully acked.
    pub fn cleanup_old_groups(&mut self, ack_seq: SeqNo) {
        let ack_offset = SeqNo::offset(self.base_seq, ack_seq).max(0) as usize;
        let cols = self.config.cols;
        if cols == 0 {
            return;
        }
        let ack_row = (ack_offset / cols) as u32;

        // Remove row groups older than ack
        self.row_groups.retain(|&row_num, _| row_num >= ack_row.saturating_sub(1));

        // Remove column groups from old matrix cycles
        if self.config.is_2d() {
            let matrix_size = self.config.matrix_size();
            let ack_cycle = (ack_offset / matrix_size) as u64;
            self.col_groups.retain(|&col_key, _| {
                let cycle = col_key % 100_000;
                cycle >= ack_cycle.saturating_sub(1)
            });
        }

        // Clean up received_seqs (keep only recent)
        let cutoff = ack_seq.add(-(self.config.matrix_size() as i32 * 2));
        self.received_seqs.retain(|&seq_val| {
            let seq = SeqNo::new(seq_val);
            seq.is_after(cutoff) || seq == cutoff
        });
    }

    /// Ensure a row group exists for the given row number.
    fn ensure_row_group(&mut self, row_number: u32) {
        if self.row_groups.contains_key(&row_number) {
            return;
        }
        let cols = self.config.cols;
        let base_offset = row_number as usize * cols;
        let member_seqs: Vec<SeqNo> = (0..cols)
            .map(|i| self.base_seq.add((base_offset + i) as i32))
            .collect();
        self.row_groups.insert(row_number, FecRecvGroup::new(member_seqs, cols));
    }

    /// Ensure a column group exists for the given key.
    fn ensure_col_group(&mut self, col_key: u64, col_index: usize, matrix_cycle: usize) {
        if self.col_groups.contains_key(&col_key) {
            return;
        }
        let cols = self.config.cols;
        let rows = self.config.rows;
        let matrix_size = self.config.matrix_size();
        let cycle_base_offset = matrix_cycle * matrix_size;
        let col_base = self.config.column_base_offset(col_index);

        let member_seqs: Vec<SeqNo> = (0..rows)
            .map(|r| {
                let pos = (col_base + r * cols) % matrix_size;
                self.base_seq.add((cycle_base_offset + pos) as i32)
            })
            .collect();
        self.col_groups.insert(col_key, FecRecvGroup::new(member_seqs, rows));
    }

    /// Find which column a position in the matrix belongs to.
    fn find_column_index(&self, pos_in_matrix: usize) -> usize {
        let cols = self.config.cols;
        let matrix = self.config.matrix_size();

        match self.config.layout {
            FecLayout::Even => pos_in_matrix % cols,
            FecLayout::Staircase => {
                for c in 0..cols {
                    let base = self.config.column_base_offset(c);
                    for r in 0..self.config.rows {
                        let slot = (base + r * cols) % matrix;
                        if slot == pos_in_matrix {
                            return c;
                        }
                    }
                }
                pos_in_matrix % cols
            }
        }
    }

    /// Find which row within a column a position corresponds to.
    fn find_column_row(&self, pos_in_matrix: usize, col_index: usize) -> usize {
        let cols = self.config.cols;
        let matrix = self.config.matrix_size();
        let base = self.config.column_base_offset(col_index);

        for r in 0..self.config.rows {
            let slot = (base + r * cols) % matrix;
            if slot == pos_in_matrix {
                return r;
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fec::encoder::FecEncoder;

    #[test]
    fn test_row_recovery() {
        let config = FecConfig {
            cols: 3,
            rows: 1,
            layout: FecLayout::Even,
            arq: super::super::ArqMode::OnReq,
        };

        let mut encoder = FecEncoder::new(config.clone());
        let mut decoder = FecDecoder::new(config, SeqNo::new(0));

        let pkts: Vec<Vec<u8>> = (0..3).map(|i| format!("pkt{:05}", i).into_bytes()).collect();

        // Encode all 3 packets
        encoder.on_data_packet(SeqNo::new(0), 100, 0, &pkts[0]);
        encoder.on_data_packet(SeqNo::new(1), 200, 0, &pkts[1]);
        let fec_packets = encoder.on_data_packet(SeqNo::new(2), 300, 0, &pkts[2]);
        assert_eq!(fec_packets.len(), 1);

        // Decoder receives pkt0 and pkt2, but NOT pkt1
        let r0 = decoder.on_data_packet(SeqNo::new(0), 100, 0, &pkts[0]);
        assert!(r0.is_empty());

        let r2 = decoder.on_data_packet(SeqNo::new(2), 300, 0, &pkts[2]);
        assert!(r2.is_empty());

        // Decoder receives FEC packet → should recover pkt1
        let result = decoder.on_fec_packet(SeqNo::new(2), &fec_packets[0].payload);
        assert_eq!(result.recovered.len(), 1);
        assert_eq!(result.recovered[0].seq_no, SeqNo::new(1));
        assert_eq!(&result.recovered[0].payload[..pkts[1].len()], &pkts[1][..]);
    }

    #[test]
    fn test_2d_cascade_recovery() {
        // 2D FEC with cols=2, rows=2 → matrix of 4 packets
        // Row 0: [pkt0, pkt1] → row FEC 0
        // Row 1: [pkt2, pkt3] → row FEC 1
        // Col 0: [pkt0, pkt2] → col FEC 0
        // Col 1: [pkt1, pkt3] → col FEC 1
        //
        // Lose pkt1 and pkt2.
        // Row FEC 0 can't recover (has pkt0 but not pkt1, and row FEC would need pkt1)
        // Col FEC 0 has pkt0 but not pkt2 → can recover pkt2 if col FEC 0 is received
        // After recovering pkt2, row FEC 1 has pkt2+pkt3 → row FEC 1 can recover... wait, pkt3 is received
        // Actually: Row 0 has [pkt0, ?] → needs pkt1. Row 1 has [?, pkt3] → needs pkt2.
        // Col 0 has [pkt0, ?] → needs pkt2. Col 1 has [?, pkt3] → needs pkt1.
        //
        // If col FEC 0 arrives: it can recover pkt2 (only pkt2 missing in col 0).
        // After pkt2 recovered: Row 1 now has [pkt2, pkt3] → complete, no recovery needed.
        // But now cascade: feed pkt2 into row group 1 → row 1 is now complete.
        // Row 0 still has [pkt0, ?] → if row FEC 0 arrives, can recover pkt1.

        let config = FecConfig {
            cols: 2,
            rows: 2,
            layout: FecLayout::Even,
            arq: super::super::ArqMode::OnReq,
        };

        let mut encoder = FecEncoder::new(config.clone());
        let mut decoder = FecDecoder::new(config, SeqNo::new(0));

        let pkts: Vec<Vec<u8>> = (0..4).map(|i| format!("packet{:03}", i).into_bytes()).collect();

        // Encode all 4 packets, collect FEC
        let mut all_fec = Vec::new();
        for i in 0..4 {
            let fec = encoder.on_data_packet(
                SeqNo::new(i),
                (i as u32 + 1) * 100,
                0,
                &pkts[i as usize],
            );
            all_fec.extend(fec);
        }
        // Should have: 2 row FECs + 2 column FECs = 4 FEC packets
        assert!(all_fec.len() >= 2); // At minimum 2 row FECs

        // Decoder receives pkt0 and pkt3 (lose pkt1 and pkt2)
        decoder.on_data_packet(SeqNo::new(0), 100, 0, &pkts[0]);
        decoder.on_data_packet(SeqNo::new(3), 400, 0, &pkts[3]);

        // Feed all FEC packets and check total recovery
        let mut total_recovered = Vec::new();
        for fec in &all_fec {
            let result = decoder.on_fec_packet(fec.seq_no, &fec.payload);
            total_recovered.extend(result.recovered);
        }

        // Should have recovered both pkt1 and pkt2 via cascade
        let recovered_seqs: HashSet<i32> = total_recovered.iter().map(|r| r.seq_no.value()).collect();
        assert!(recovered_seqs.contains(&1), "pkt1 should be recovered");
        assert!(recovered_seqs.contains(&2), "pkt2 should be recovered");
    }

    #[test]
    fn test_uncoverable_losses() {
        let config = FecConfig {
            cols: 3,
            rows: 1,
            layout: FecLayout::Even,
            arq: super::super::ArqMode::OnReq,
        };

        let mut encoder = FecEncoder::new(config.clone());
        let mut decoder = FecDecoder::new(config, SeqNo::new(0));

        let pkts: Vec<Vec<u8>> = (0..3).map(|i| format!("pkt{:05}", i).into_bytes()).collect();

        // Encode
        encoder.on_data_packet(SeqNo::new(0), 100, 0, &pkts[0]);
        encoder.on_data_packet(SeqNo::new(1), 200, 0, &pkts[1]);
        let fec = encoder.on_data_packet(SeqNo::new(2), 300, 0, &pkts[2]);

        // Decoder only receives pkt0 (lose pkt1 AND pkt2 → 2 missing, uncoverable)
        decoder.on_data_packet(SeqNo::new(0), 100, 0, &pkts[0]);

        // Feed FEC
        let result = decoder.on_fec_packet(SeqNo::new(2), &fec[0].payload);
        assert!(result.recovered.is_empty());
        assert_eq!(result.uncoverable.len(), 2);
    }

    #[test]
    fn test_cleanup() {
        let config = FecConfig {
            cols: 3,
            rows: 1,
            layout: FecLayout::Even,
            arq: super::super::ArqMode::OnReq,
        };
        let mut decoder = FecDecoder::new(config, SeqNo::new(0));

        // Create some groups
        for i in 0..30 {
            decoder.on_data_packet(SeqNo::new(i), i as u32 * 100, 0, b"data");
        }

        assert!(decoder.row_groups.len() > 5);

        // Cleanup with ack at seq 20
        decoder.cleanup_old_groups(SeqNo::new(20));
        // Old groups should be removed
        assert!(decoder.row_groups.len() <= 5);
    }
}
