//! Pluggable congestion control for SRT.
//!
//! SRT supports two congestion control modes:
//!
//! - **LIVE mode** ([`LiveCC`](live::LiveCC)): Constant-rate sending optimized for
//!   real-time streaming. Drops packets that arrive too late rather than
//!   retransmitting them.
//! - **FILE mode** ([`FileCC`](file::FileCC)): TCP-like AIMD (Additive Increase,
//!   Multiplicative Decrease) with slow start, optimized for reliable file transfer.
//!
//! Custom congestion control algorithms can be implemented via the
//! [`CongestionControl`] trait.

pub mod live;
pub mod file;

use crate::packet::seq::SeqNo;

/// Pluggable congestion control interface.
///
/// Maps to C++ `SrtCongestionControlBase`. Implementors control
/// the packet sending rate and congestion window size.
pub trait CongestionControl: Send {
    /// Called when an ACK is received.
    fn on_ack(&mut self, ack_seq: SeqNo, rtt_us: i32);

    /// Called when a loss (NAK) is reported.
    fn on_loss(&mut self, loss_list: &[(SeqNo, SeqNo)]);

    /// Called periodically (on timer) for rate adjustments.
    fn on_timer(&mut self);

    /// Get the packet sending period in microseconds.
    /// 0 means send as fast as possible.
    fn pkt_send_period_us(&self) -> f64;

    /// Get the congestion window size in packets.
    fn congestion_window(&self) -> f64;

    /// Get the maximum congestion window size.
    fn max_congestion_window(&self) -> f64;

    /// Update bandwidth estimate.
    fn set_bandwidth(&mut self, bandwidth_pkts_per_sec: i32);

    /// Update the maximum send bandwidth.
    fn set_max_bandwidth(&mut self, max_bw_bytes_per_sec: i64);

    /// Get the retransmission mode.
    fn rexmit_method(&self) -> RexmitMethod {
        RexmitMethod::LateRexmit
    }
}

/// Retransmission method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RexmitMethod {
    /// Schedule retransmit at next send opportunity.
    LateRexmit,
    /// Retransmit immediately upon NAK reception.
    FastRexmit,
}
