// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Async send loop.
//!
//! Maps to C++ `CSndQueue::worker`. Processes the send buffer and
//! transmits packets at the rate determined by congestion control.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};

use srt_protocol::packet::SrtPacket;
use srt_protocol::packet::control::{AckData, ControlType};
use srt_protocol::packet::header::{EncryptionKeySpec, HEADER_SIZE};
use srt_protocol::protocol::connection::ConnectionState;

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

            // Also send periodic control (ACK/keepalive) while sending data
            send_periodic_control(&mux, &conn).await;
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

/// Send periodic control packets (keepalive) and check for connection timeout.
async fn send_periodic_control(mux: &Multiplexer, conn: &SrtConnection) {
    let mut timers = conn.timers.lock().await;

    // Check keepalive timer
    if timers.keepalive.check() {
        if let Some(peer_addr) = *conn.peer_addr.lock().await {
            let dest_socket_id = *conn.peer_socket_id.lock().await;
            let keepalive = SrtPacket::new_control(
                ControlType::Keepalive,
                0, // ext_type
                0, // additional_info
                0, // timestamp
                dest_socket_id,
                Bytes::new(),
            );
            let mut buf = BytesMut::with_capacity(HEADER_SIZE);
            keepalive.serialize(&mut buf);
            let _ = mux.send_to(&buf, peer_addr).await;
        }
    }

    // Update stats with current RTT and uptime from timers
    {
        let mut stats = conn.stats.lock().await;
        stats.ms_rtt = timers.srtt as f64 / 1000.0; // srtt is in microseconds, convert to ms
        stats.ms_timestamp = timers.connection_start.elapsed().as_millis() as i64;
    }

    // Check ACK timer — send periodic ACK to peer so it knows we received data.
    // Without ACKs the sender's congestion control won't open the send window,
    // which breaks interop with the C++ SRT library.
    if timers.ack.check() {
        if let Some(peer_addr) = *conn.peer_addr.lock().await {
            let dest_socket_id = *conn.peer_socket_id.lock().await;

            // Get the last contiguous received sequence and ACK sequence number.
            let ack_seq = conn.recv_buf.lock().await.ack_seq();
            let mut ack_state = conn.ack_state.lock().await;
            let ack_number = ack_state.next_ack_seq_no();
            ack_state.update_ack(ack_seq);
            ack_state.update_data_ack(ack_seq);
            ack_state.ack_sent();
            drop(ack_state);

            let ack_data = AckData {
                ack_seq,
                rtt: Some(timers.srtt),
                rtt_var: Some(timers.rttvar),
                recv_buf_size: Some(conn.config.recv_buffer_size as i32),
                flow_window: Some(conn.config.flight_flag_size as i32),
                bandwidth: None,
                recv_rate: None,
            };
            let mut payload = BytesMut::with_capacity(AckData::FULL_SIZE);
            ack_data.serialize(&mut payload);

            let ack_pkt = SrtPacket::new_control(
                ControlType::Ack,
                0,
                ack_number as u32,
                0,
                dest_socket_id,
                payload.freeze(),
            );
            let mut buf = BytesMut::with_capacity(HEADER_SIZE + AckData::FULL_SIZE);
            ack_pkt.serialize(&mut buf);
            let _ = mux.send_to(&buf, peer_addr).await;
        }
    }

    // Check expiration timer (exponential backoff, matching C SRT's EXP event).
    // If no response from peer within the current exp_interval, increment exp_count.
    // After COMM_RESPONSE_MAX_EXP (16) consecutive expirations, the connection is broken.
    let exp_interval = timers.exp_interval();
    if timers.last_response.elapsed() >= exp_interval {
        timers.exp_count += 1;

        if timers.is_expired() {
            log::warn!("Connection {} timed out (exp_count={})", conn.socket_id, timers.exp_count);
            drop(timers); // release lock before state change
            send_shutdown_and_break(mux, conn).await;
            return;
        }
    }

    // Check configurable peer_idle_timeout (maps to SRTO_PEERIDLETIMEO).
    // This is a hard timeout: if no packet arrives within this duration, break immediately.
    let idle_timeout = conn.config.peer_idle_timeout;
    if !idle_timeout.is_zero() && timers.last_response.elapsed() >= idle_timeout {
        log::warn!("Connection {} peer idle timeout ({:?})", conn.socket_id, idle_timeout);
        drop(timers); // release lock before state change
        send_shutdown_and_break(mux, conn).await;
    }
}

/// Send a best-effort Shutdown control packet to the peer and mark the connection as Broken.
async fn send_shutdown_and_break(mux: &Multiplexer, conn: &SrtConnection) {
    if let Some(peer_addr) = *conn.peer_addr.lock().await {
        let peer_socket_id = *conn.peer_socket_id.lock().await;
        let shutdown = SrtPacket::new_control(
            ControlType::Shutdown,
            0,
            0,
            0,
            peer_socket_id,
            Bytes::new(),
        );
        let mut buf = BytesMut::with_capacity(HEADER_SIZE);
        shutdown.serialize(&mut buf);
        let _ = mux.send_to(&buf, peer_addr).await;
    }
    conn.set_state(ConnectionState::Broken).await;
}

/// Check if an I/O error is fatal.
fn is_fatal_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(e.kind(), ErrorKind::NotConnected | ErrorKind::BrokenPipe)
}
