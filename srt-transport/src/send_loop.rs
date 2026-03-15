//! Async send loop.
//!
//! Maps to C++ `CSndQueue::worker`. Processes the send buffer and
//! transmits packets at the rate determined by congestion control.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};

use srt_protocol::packet::SrtPacket;
use srt_protocol::packet::control::ControlType;
use srt_protocol::packet::header::HEADER_SIZE;

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
            // Get peer address
            let peer_addr = match *conn.peer_addr.lock().await {
                Some(a) => a,
                None => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }
            };

            // Get next packet data from the send buffer
            let entry_data = {
                let send_buf = conn.send_buf.lock().await;
                send_buf.peek_next_data()
            };

            if let Some(data) = entry_data {
                // Send it
                if let Err(e) = mux.send_to(&data, peer_addr).await {
                    log::error!("Send error: {}", e);
                    if is_fatal_error(&e) {
                        break;
                    }
                } else {
                    let mut stats = conn.stats.lock().await;
                    stats.pkt_sent_total += 1;
                    stats.byte_sent_total += data.len() as u64;
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
