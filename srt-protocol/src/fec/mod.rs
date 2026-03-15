//! Forward Error Correction (FEC) module.
//!
//! Implements row/column XOR-based packet recovery to reduce
//! retransmission overhead on lossy links.

/// FEC layout configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FecLayout {
    /// Row-only FEC (1D parity).
    Row,
    /// Row + column FEC (2D parity / staircase).
    Staircase,
}

/// FEC filter configuration.
#[derive(Debug, Clone)]
pub struct FecConfig {
    /// Number of columns in the FEC matrix.
    pub cols: usize,
    /// Number of rows in the FEC matrix.
    pub rows: usize,
    /// Layout type.
    pub layout: FecLayout,
    /// Whether to use the FEC filter for sending.
    pub sending: bool,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            cols: 10,
            rows: 5,
            layout: FecLayout::Staircase,
            sending: true,
        }
    }
}

/// FEC group for recovery.
#[derive(Debug)]
pub struct FecGroup {
    /// Base sequence number of this group.
    pub base_seq: u32,
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
    pub fn new(base_seq: u32, group_size: usize) -> Self {
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
        self.received[index] = true;
        xor_into(&mut self.parity, payload);
    }

    /// Record the FEC parity packet.
    pub fn on_fec_packet(&mut self, payload: &[u8]) {
        self.fec_received = true;
        xor_into(&mut self.parity, payload);
    }

    /// Check if exactly one packet is missing and can be recovered.
    pub fn can_recover(&self) -> Option<usize> {
        if !self.fec_received {
            return None;
        }
        let missing: Vec<usize> = self.received.iter()
            .enumerate()
            .filter(|(_, &r)| !r)
            .map(|(i, _)| i)
            .collect();
        if missing.len() == 1 {
            Some(missing[0])
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
}

/// XOR `src` into `dst`, extending `dst` if necessary.
fn xor_into(dst: &mut Vec<u8>, src: &[u8]) {
    if dst.len() < src.len() {
        dst.resize(src.len(), 0);
    }
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
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
        let mut group = FecGroup::new(0, 3);
        group.on_data_packet(0, pkt0);
        // pkt1 is lost
        group.on_data_packet(2, pkt2);
        group.on_fec_packet(&fec_parity);

        assert_eq!(group.can_recover(), Some(1));
        let recovered = group.recover().unwrap();
        assert_eq!(&recovered[..], &pkt1[..]);
    }
}
