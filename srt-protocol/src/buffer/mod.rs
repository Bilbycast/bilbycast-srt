//! Send and receive buffers for SRT data transfer.
//!
//! SRT uses application-level buffers to handle reliable delivery, message
//! segmentation, packet reordering, and Timestamp-Based Packet Delivery (TSBPD).
//!
//! # Submodules
//!
//! - [`send`] - Send buffer: message-to-packet segmentation and retransmission queue
//! - [`receive`] - Receive buffer: circular buffer with TSBPD delivery scheduling
//! - [`loss_list`] - Send/receive loss lists for Automatic Repeat reQuest (ARQ)
//! - [`tools`] - Rate estimation and average payload size tracking

pub mod send;
pub mod receive;
pub mod loss_list;
pub mod tools;
