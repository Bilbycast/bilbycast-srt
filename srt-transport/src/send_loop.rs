// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Async send loop.
//!
//! Maps to C++ `CSndQueue::worker`. Processes the send buffer and
//! transmits packets at the rate determined by congestion control.
//! Also handles retransmission of lost packets and periodic control.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};

use srt_protocol::crypto::{CryptoControl, CryptoMode};
use srt_protocol::packet::SrtPacket;
use srt_protocol::packet::control::{AckData, ControlType, DropReqData, LossReport};
use srt_protocol::packet::header::{EncryptionKeySpec, HEADER_SIZE};
use srt_protocol::packet::seq::SeqNo;
use srt_protocol::protocol::connection::ConnectionState;

use crate::connection::SrtConnection;
use crate::multiplexer::Multiplexer;

/// Run the send loop for a specific connection.
///
/// Spawned as a tokio task. Checks the send buffer for pending packets
/// and transmits them at the rate determined by congestion control.
/// Retransmissions from the loss list take priority over new data.
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

        // Priority 1: Retransmit lost packets from send loss list
        let retransmitted = send_retransmissions(&mux, &conn).await;

        // Priority 2: Send new data (gated by congestion and flow windows)
        let (has_data, window_ok) = {
            let send_buf = conn.send_buf.lock().await;
            if !send_buf.has_unsent() {
                (false, false)
            } else {
                let in_flight = send_buf.in_flight();
                let cwnd = conn.cc.lock().await.congestion_window() as usize;
                let flow_window = *conn.peer_flow_window.lock().await as usize;
                let effective_window = cwnd.min(flow_window);
                (true, in_flight < effective_window)
            }
        };

        if retransmitted || (has_data && window_ok) {
            if has_data && window_ok {
                // Get peer address and peer socket ID
                let peer_addr = match *conn.peer_addr.lock().await {
                    Some(a) => a,
                    None => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let dest_socket_id = *conn.peer_socket_id.lock().await;

                // Get the next unsent entry (stays in buffer for retransmission)
                let entry = {
                    let mut send_buf = conn.send_buf.lock().await;
                    send_buf.next_packet()
                };

                if let Some(entry) = entry {
                    let timestamp = entry.origin_time.elapsed().as_micros() as u32;

                    // Encrypt payload if crypto is configured
                    let (payload, enc_key) = encrypt_payload(
                        &conn.crypto, entry.data, entry.seq_no.value() as u32
                    ).await;

                    let pkt = SrtPacket::new_data(
                        entry.seq_no,
                        entry.msg_no,
                        entry.boundary,
                        entry.in_order,
                        enc_key,
                        false, // not a retransmission
                        timestamp,
                        dest_socket_id,
                        payload,
                    );

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
            }

            // Pace sending
            if send_period_us > 0.0 {
                tokio::time::sleep(Duration::from_micros(send_period_us as u64)).await;
            }

            // Also send periodic control (ACK/NAK/keepalive) while sending data
            send_periodic_control(&mux, &conn).await;
        } else if has_data && !window_ok {
            // Window full — wait for ACK to free space, but keep running control
            tokio::select! {
                _ = conn.send_space_ready.notified() => {}
                _ = tokio::time::sleep(Duration::from_millis(1)) => {
                    send_periodic_control(&mux, &conn).await;
                }
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

/// Retransmit packets from the send loss list. Returns true if any were sent.
///
/// Retransmissions are rate-limited by the token bucket shaper when
/// `max_rexmit_bw` is configured (SRTO_MAXREXMITBW). Packets that
/// cannot be sent due to the rate limit are pushed back to the loss
/// list for the next cycle.
async fn send_retransmissions(mux: &Multiplexer, conn: &SrtConnection) -> bool {
    // Collect sequence numbers to retransmit (drain up to a batch)
    let mut seqs_to_retransmit: Vec<SeqNo> = Vec::new();
    {
        let mut loss_list = conn.send_loss_list.lock().await;
        // Retransmit up to 16 packets per cycle to avoid starving new data
        for _ in 0..16 {
            if let Some(seq) = loss_list.pop_front() {
                seqs_to_retransmit.push(seq);
            } else {
                break;
            }
        }
    }

    if seqs_to_retransmit.is_empty() {
        return false;
    }

    let peer_addr = match *conn.peer_addr.lock().await {
        Some(a) => a,
        None => return false,
    };
    let dest_socket_id = *conn.peer_socket_id.lock().await;

    let mut sent_any = false;
    let mut deferred: Vec<SeqNo> = Vec::new();

    for seq in seqs_to_retransmit {
        // Look up packet in send buffer and get a clone for retransmission
        let entry = {
            let mut send_buf = conn.send_buf.lock().await;
            send_buf.get_packet_for_retransmit(seq)
        };

        if let Some(entry) = entry {
            // Check token bucket before sending
            let wire_size = entry.data.len() + HEADER_SIZE;
            let allowed = conn.rexmit_shaper.lock().await.try_consume(wire_size);
            if !allowed {
                // Rate limited — push back for next cycle
                deferred.push(seq);
                continue;
            }

            let timestamp = entry.origin_time.elapsed().as_micros() as u32;

            // Encrypt payload if crypto is configured
            let (payload, enc_key) = encrypt_payload(
                &conn.crypto, entry.data, entry.seq_no.value() as u32
            ).await;

            let pkt = SrtPacket::new_data(
                entry.seq_no,
                entry.msg_no,
                entry.boundary,
                entry.in_order,
                enc_key,
                true, // retransmission flag set
                timestamp,
                dest_socket_id,
                payload,
            );

            let mut buf = BytesMut::with_capacity(pkt.wire_size());
            pkt.serialize(&mut buf);

            if let Err(e) = mux.send_to(&buf, peer_addr).await {
                log::error!("Retransmit send error: {}", e);
            } else {
                let mut stats = conn.stats.lock().await;
                stats.pkt_retrans += 1;
                stats.pkt_retrans_total += 1;
                stats.pkt_sent_total += 1;
                stats.byte_retrans_total += pkt.payload_len() as u64;
                stats.byte_sent_total += pkt.payload_len() as u64;
                sent_any = true;
            }
        } else {
            log::trace!("Retransmit: seq {} not in send buffer (already ACK'd?)", seq.value());
        }
    }

    // Re-insert deferred packets into the loss list for the next cycle
    if !deferred.is_empty() {
        let mut loss_list = conn.send_loss_list.lock().await;
        for seq in deferred {
            loss_list.insert(seq);
        }
    }

    sent_any
}

/// Send periodic control packets (keepalive, ACK, NAK) and check for connection timeout.
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

            // Store in ACK window for RTT measurement when ACKACK arrives
            conn.ack_window.lock().await.store(ack_number);

            // Get bandwidth estimates from packet arrival time window
            let ptw = conn.pkt_time_window.lock().await;
            let bandwidth = ptw.bandwidth();
            let recv_rate = ptw.recv_speed();
            drop(ptw);

            let ack_data = AckData {
                ack_seq,
                rtt: Some(timers.srtt),
                rtt_var: Some(timers.rttvar),
                recv_buf_size: Some(conn.config.recv_buffer_size as i32),
                flow_window: Some(conn.config.flight_flag_size as i32),
                bandwidth,
                recv_rate,
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

            let mut stats = conn.stats.lock().await;
            stats.pkt_sent_ack += 1;
            stats.pkt_sent_ack_total += 1;
        }
    }

    // Check NAK timer — send loss reports to the peer
    if timers.nak.check() {
        let loss_ranges = conn.recv_loss_list.lock().await.get_loss_ranges();
        if !loss_ranges.is_empty() {
            if let Some(peer_addr) = *conn.peer_addr.lock().await {
                let dest_socket_id = *conn.peer_socket_id.lock().await;

                let loss_report = LossReport { losses: loss_ranges };
                let mut payload = BytesMut::with_capacity(loss_report.losses.len() * 8);
                loss_report.serialize(&mut payload);

                let nak_pkt = SrtPacket::new_control(
                    ControlType::Nak,
                    0,
                    0,
                    0,
                    dest_socket_id,
                    payload.freeze(),
                );
                let mut buf = BytesMut::with_capacity(HEADER_SIZE + nak_pkt.payload_len());
                nak_pkt.serialize(&mut buf);
                let _ = mux.send_to(&buf, peer_addr).await;

                let mut stats = conn.stats.lock().await;
                stats.pkt_sent_nak += 1;
                stats.pkt_sent_nak_total += 1;
            }
        }
    }

    // Sender-side too-late-to-send drop: drop expired messages and notify peer via DropReq
    {
        let dropped_msgs = conn.send_buf.lock().await.drop_expired_with_info();
        if !dropped_msgs.is_empty() {
            let total_dropped: usize = dropped_msgs.len();
            if let Some(peer_addr) = *conn.peer_addr.lock().await {
                let dest_socket_id = *conn.peer_socket_id.lock().await;
                for (msg_id, first_seq, last_seq) in &dropped_msgs {
                    let drop_req = DropReqData {
                        msg_id: *msg_id,
                        first_seq: *first_seq,
                        last_seq: *last_seq,
                    };
                    let mut payload = BytesMut::with_capacity(8);
                    drop_req.serialize(&mut payload);

                    let drop_pkt = SrtPacket::new_control(
                        ControlType::DropReq,
                        0,
                        *msg_id as u32,
                        0,
                        dest_socket_id,
                        payload.freeze(),
                    );
                    let mut buf = BytesMut::with_capacity(HEADER_SIZE + 8);
                    drop_pkt.serialize(&mut buf);
                    let _ = mux.send_to(&buf, peer_addr).await;
                }
            }
            let mut stats = conn.stats.lock().await;
            stats.pkt_snd_drop += total_dropped as i32;
            stats.pkt_snd_drop_total += total_dropped as i32;
            log::trace!("Sender dropped {} expired messages, sent DropReq", total_dropped);
        }
    }

    // Too-late-to-play drop: periodically drop packets that missed their TSBPD deadline
    {
        let tsbpd = conn.tsbpd.lock().await;
        let dropped = conn.recv_buf.lock().await.drop_too_late(&tsbpd);
        if dropped > 0 {
            // Clear dropped entries from receive loss list
            conn.recv_loss_list.lock().await.acknowledge(
                conn.recv_buf.lock().await.ack_seq()
            );
            let mut stats = conn.stats.lock().await;
            stats.pkt_rcv_drop += dropped as i32;
            stats.pkt_rcv_drop_total += dropped as i32;
            log::trace!("Dropped {} too-late packets", dropped);
        }
    }

    // Check expiration timer (exponential backoff, matching C SRT's EXP event).
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

/// Encrypt a data payload using the connection's crypto control.
/// Returns (possibly encrypted payload, encryption key spec).
/// If no crypto is configured, returns the original payload unchanged.
async fn encrypt_payload(
    crypto_mutex: &tokio::sync::Mutex<Option<CryptoControl>>,
    payload: Bytes,
    pkt_index: u32,
) -> (Bytes, EncryptionKeySpec) {
    let mut crypto_guard = crypto_mutex.lock().await;
    let crypto = match crypto_guard.as_mut() {
        Some(c) => c,
        None => return (payload, EncryptionKeySpec::NoEnc),
    };

    let key = match crypto.keys.active_key() {
        Some(k) => k.to_vec(),
        None => return (payload, EncryptionKeySpec::NoEnc),
    };

    let enc_spec = crypto.keys.active.to_enc_key_spec();
    let salt = crypto.salt;
    crypto.on_packet_sent();

    match crypto.mode {
        CryptoMode::AesCtr => {
            use srt_protocol::crypto::aes_ctr::AesCtrCipher;
            if let Some(cipher) = AesCtrCipher::new(&key) {
                let mut data = payload.to_vec();
                if cipher.encrypt(&salt, pkt_index, &mut data).is_ok() {
                    return (Bytes::from(data), enc_spec);
                }
            }
            (payload, EncryptionKeySpec::NoEnc)
        }
        CryptoMode::AesGcm => {
            use srt_protocol::crypto::aes_gcm::AesGcmCipher;
            if let Some(cipher) = AesGcmCipher::new(&key) {
                if let Ok(ciphertext) = cipher.encrypt(&salt, pkt_index, &payload) {
                    return (Bytes::from(ciphertext), enc_spec);
                }
            }
            (payload, EncryptionKeySpec::NoEnc)
        }
    }
}

/// Check if an I/O error is fatal.
fn is_fatal_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(e.kind(), ErrorKind::NotConnected | ErrorKind::BrokenPipe)
}
