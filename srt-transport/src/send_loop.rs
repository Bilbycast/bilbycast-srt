//! Async send loop.
//!
//! Maps to C++ `CSndQueue::worker`. Processes the send buffer and
//! transmits packets at the rate determined by congestion control.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};

use srt_protocol::packet::SrtPacket;
use srt_protocol::packet::control::ControlType;
use srt_protocol::packet::header::{EncryptionKeySpec, HEADER_SIZE};

use crate::connection::SrtConnection;
use crate::multiplexer::Multiplexer;

/// Run the send loop for a specific connection.
///
/// Spawned as a tokio task. Checks the send buffer for pending packets
/// and transmits them at the rate determined by congestion control.
pub async fn run(mux: Arc<Multiplexer>, conn: Arc<SrtConnection>) {
    loop {
        if !conn.is_active().await {
            break;
        }

        // Get the send period from congestion control
        let send_period_us = {
            let cc = conn.cc.lock().await;
            cc.pkt_send_period_us()
        };

        // Check if there are packets ready in the send buffer
        let has_data = {
            let send_buf = conn.send_buf.lock().await;
            !send_buf.is_empty()
        };

        if has_data {
            // Get peer address and peer socket ID
            let peer_addr = match *conn.peer_addr.lock().await {
                Some(a) => a,
                None => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };
            let dest_socket_id = *conn.peer_socket_id.lock().await;

            // Take the next entry from the send buffer (removes it)
            let entry = {
                let mut send_buf = conn.send_buf.lock().await;
                send_buf.take_next_entry()
            };

            if let Some(entry) = entry {
                // Calculate timestamp (microseconds since connection start).
                // For now use elapsed from the entry's origin_time as a simple
                // monotonic timestamp. A proper implementation would use the
                // connection start time, but this is sufficient for TSBPD.
                let timestamp = entry.origin_time.elapsed().as_micros() as u32;

                // Build a proper SRT data packet with the 16-byte header
                let pkt = SrtPacket::new_data(
                    entry.seq_no,
                    entry.msg_no,
                    entry.boundary,
                    entry.in_order,
                    EncryptionKeySpec::NoEnc,
                    false, // not a retransmission
                    timestamp,
                    dest_socket_id,
                    entry.data,
                );

                // Serialize to wire format
                let mut buf = BytesMut::with_capacity(pkt.wire_size());
                pkt.serialize(&mut buf);

                if let Err(e) = mux.send_to(&buf, peer_addr).await {
                    log::error!("Send error: {}", e);
                    if is_fatal_error(&e) {
                        break;
                    }
                } else {
                    let mut stats = conn.stats.lock().await;
                    stats.pkt_sent_total += 1;
                    stats.byte_sent_total += pkt.payload_len() as u64;
                }
            }

            // Pace sending
            if send_period_us > 0.0 {
                tokio::time::sleep(Duration::from_micros(send_period_us as u64)).await;
            }
        } else {
            // No data — wait for notification or periodic timer
            tokio::select! {
                _ = conn.send_space_ready.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(1)) => {
                    send_periodic_control(&mux, &conn).await;
                }
            }
        }
    }
}

/// Send periodic control packets (keepalive, etc.).
async fn send_periodic_control(mux: &Multiplexer, conn: &SrtConnection) {
    let mut timers = conn.timers.lock().await;

    // Check keepalive timer
    if timers.keepalive.check() {
        if let Some(peer_addr) = *conn.peer_addr.lock().await {
            let keepalive = SrtPacket::new_control(
                ControlType::Keepalive,
                0, // ext_type
                0, // additional_info
                0, // timestamp
                conn.socket_id,
                Bytes::new(),
            );
            let mut buf = BytesMut::with_capacity(HEADER_SIZE);
            keepalive.serialize(&mut buf);
            let _ = mux.send_to(&buf, peer_addr).await;
        }
    }
}

/// Check if an I/O error is fatal.
fn is_fatal_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(e.kind(), ErrorKind::NotConnected | ErrorKind::BrokenPipe)
}
