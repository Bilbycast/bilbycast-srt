// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Async receive loop.
//!
//! Maps to C++ `CRcvQueue::worker`. Continuously receives UDP packets
//! from the channel and routes them to the correct SRT connection.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};

use srt_protocol::crypto::{CryptoMode, KeyIndex};
use srt_protocol::packet::SrtPacket;
use srt_protocol::packet::control::{AckData, ControlType, DropReqData, LossReport};
use srt_protocol::packet::header::{EncryptionKeySpec, HEADER_SIZE};
use srt_protocol::packet::seq::SeqNo;
use srt_protocol::protocol::connection::ConnectionState;
use srt_protocol::protocol::handshake::Handshake;

use crate::connection::SrtConnection;
use crate::multiplexer::Multiplexer;

/// Maximum UDP packet size.
const MAX_UDP_SIZE: usize = 1500;

/// Run the receive loop for a multiplexer.
///
/// This is spawned as a tokio task. It reads packets from the UDP channel
/// and dispatches them to the appropriate SRT connection based on the
/// destination socket ID in the SRT header.
pub async fn run(mux: Arc<Multiplexer>) {
    let mut buf = vec![0u8; MAX_UDP_SIZE];

    loop {
        match mux.channel.recv_from(&mut buf).await {
            Ok((len, src_addr)) => {
                if len < HEADER_SIZE {
                    continue;
                }

                let data = &buf[..len];
                if let Some(packet) = SrtPacket::deserialize(data) {
                    let dest_id = packet.dest_socket_id();
                    log::trace!(
                        "recv_loop: packet from {} dest_id={} ctrl={} type={:?} len={}",
                        src_addr, dest_id, packet.is_control(),
                        packet.control_type(), len
                    );

                    if let Some(conn) = mux.route(dest_id).await {
                        process_packet(conn, packet, src_addr, &mux).await;
                    } else {
                        log::debug!(
                            "recv_loop: no route for dest_id={} from {} (ctrl={}, type={:?})",
                            dest_id, src_addr, packet.is_control(), packet.control_type()
                        );
                    }
                } else {
                    log::debug!("recv_loop: failed to deserialize packet ({} bytes) from {}", len, src_addr);
                }
            }
            Err(e) => {
                if is_fatal_error(&e) {
                    log::error!("Fatal receive error: {}", e);
                    break;
                }
                log::debug!("Transient receive error: {}", e);
            }
        }
    }
}

/// Process a received SRT packet.
async fn process_packet(
    conn: Arc<SrtConnection>,
    packet: SrtPacket,
    src_addr: SocketAddr,
    mux: &Multiplexer,
) {
    // Reset the idle/expiration timer on any packet from the peer.
    // This is how SRT detects that the peer is still alive.
    conn.timers.lock().await.on_response_received();

    if packet.is_control() {
        process_control_packet(&conn, &packet, src_addr, mux).await;
    } else {
        process_data_packet(&conn, &packet).await;
    }
}

/// Process a control packet (ACK, NAK, handshake, keepalive, etc.).
async fn process_control_packet(
    conn: &SrtConnection,
    packet: &SrtPacket,
    src_addr: SocketAddr,
    mux: &Multiplexer,
) {
    match packet.control_type() {
        Some(ControlType::Handshake) => {
            // Parse the handshake from the control packet payload
            if let Some(hs) = Handshake::deserialize(packet.payload()) {
                log::debug!(
                    "Received {:?} handshake from {} (version={}, socket_id={}, cookie={:#x})",
                    hs.req_type,
                    src_addr,
                    hs.version,
                    hs.socket_id,
                    hs.cookie
                );
                // Extract extension bytes (everything after 48-byte handshake header)
                let ext_bytes = if packet.payload().len() > 48 {
                    Bytes::copy_from_slice(&packet.payload()[48..])
                } else {
                    Bytes::new()
                };
                // Deliver the handshake + extensions to the connection's handshake channel.
                if let Err(e) = conn.handshake_tx.try_send((hs, src_addr, ext_bytes)) {
                    log::error!("Failed to deliver handshake to connection: {} (channel full or closed)", e);
                }
            } else {
                log::warn!("Failed to parse handshake from {}", src_addr);
            }
        }
        Some(ControlType::Ack) => {
            process_ack(conn, packet, mux).await;
        }
        Some(ControlType::Nak) => {
            process_nak(conn, packet).await;
        }
        Some(ControlType::AckAck) => {
            process_ackack(conn, packet).await;
        }
        Some(ControlType::DropReq) => {
            process_dropreq(conn, packet).await;
        }
        Some(ControlType::Keepalive) => {
            log::trace!("Keepalive from {}", src_addr);
        }
        Some(ControlType::Shutdown) => {
            conn.set_state(ConnectionState::Closing).await;
        }
        _ => {
            log::trace!("Unhandled control type: {:?}", packet.control_type());
        }
    }
}

/// Process an ACK from the receiver: free send buffer, clear loss list, send ACKACK.
async fn process_ack(conn: &SrtConnection, packet: &SrtPacket, mux: &Multiplexer) {
    let ack_seq_no = packet.additional_info(); // ACK sequence number (for ACKACK)

    // Parse ACK data
    let ack_data = match AckData::deserialize(packet.payload()) {
        Some(d) => d,
        None => {
            log::debug!("Failed to parse ACK data");
            return;
        }
    };

    // Free acknowledged packets from send buffer
    let removed = conn.send_buf.lock().await.acknowledge(ack_data.ack_seq);
    if removed > 0 {
        conn.send_space_ready.notify_one();
    }

    // Clear obsolete entries from send loss list
    conn.send_loss_list.lock().await.acknowledge(ack_data.ack_seq);

    // Update peer's flow window from ACK
    if let Some(fw) = ack_data.flow_window {
        *conn.peer_flow_window.lock().await = fw as u32;
    }

    // Notify congestion control of the ACK
    {
        let rtt_us = ack_data.rtt.unwrap_or(conn.timers.lock().await.srtt);
        conn.cc.lock().await.on_ack(ack_data.ack_seq, rtt_us);
    }

    // Update bandwidth estimate on CC if peer reported it
    if let Some(bw) = ack_data.bandwidth {
        conn.cc.lock().await.set_bandwidth(bw);
    }

    // Update stats
    {
        let mut stats = conn.stats.lock().await;
        stats.pkt_recv_ack += 1;
        stats.pkt_recv_ack_total += 1;
    }

    // Send ACKACK back (for RTT measurement by the peer)
    if let Some(peer_addr) = *conn.peer_addr.lock().await {
        let dest_socket_id = *conn.peer_socket_id.lock().await;
        let ackack = SrtPacket::new_control(
            ControlType::AckAck,
            0,
            ack_seq_no,
            0,
            dest_socket_id,
            Bytes::new(),
        );
        let mut buf = BytesMut::with_capacity(HEADER_SIZE);
        ackack.serialize(&mut buf);
        let _ = mux.send_to(&buf, peer_addr).await;
    }
}

/// Process a NAK from the receiver: populate send-side loss list for retransmission.
async fn process_nak(conn: &SrtConnection, packet: &SrtPacket) {
    let loss_report = LossReport::deserialize(packet.payload());
    let total_losses = loss_report.total_losses();

    {
        let mut send_loss = conn.send_loss_list.lock().await;
        for (first, last) in &loss_report.losses {
            if first == last {
                send_loss.insert(*first);
            } else {
                send_loss.insert_range(*first, *last);
            }
        }
    }

    // Notify congestion control of the loss
    conn.cc.lock().await.on_loss(&loss_report.losses);

    // Update stats
    {
        let mut stats = conn.stats.lock().await;
        stats.pkt_recv_nak += 1;
        stats.pkt_recv_nak_total += 1;
        stats.pkt_snd_loss += total_losses;
        stats.pkt_snd_loss_total += total_losses;
    }

    log::trace!("NAK received: {} lost packets reported", total_losses);
}

/// Process an ACKACK: measure RTT from the ACK round-trip.
async fn process_ackack(conn: &SrtConnection, packet: &SrtPacket) {
    let ack_seq = packet.additional_info() as i32;

    // Look up when we sent the corresponding ACK
    let rtt = conn.ack_window.lock().await.acknowledge(ack_seq);

    if let Some(rtt_duration) = rtt {
        let rtt_us = rtt_duration.as_micros() as i32;
        conn.timers.lock().await.update_rtt(rtt_us);
        log::trace!("ACKACK: RTT sample = {}us", rtt_us);
    }
}

/// Process a DropReq from the sender: drop the specified message range from receive buffer.
async fn process_dropreq(conn: &SrtConnection, packet: &SrtPacket) {
    let msg_id = packet.additional_info() as i32;
    if let Some(drop_req) = DropReqData::deserialize(msg_id, packet.payload()) {
        let dropped = conn.recv_buf.lock().await.drop_range(drop_req.first_seq, drop_req.last_seq);
        // Clear these from loss list since sender says they're gone
        let count = SeqNo::offset(drop_req.first_seq, drop_req.last_seq) + 1;
        {
            let mut recv_loss = conn.recv_loss_list.lock().await;
            for i in 0..count {
                recv_loss.remove(drop_req.first_seq.add(i));
            }
        }
        if dropped > 0 {
            let mut stats = conn.stats.lock().await;
            stats.pkt_rcv_drop += dropped as i32;
            stats.pkt_rcv_drop_total += dropped as i32;
        }
        log::trace!("DropReq: msg_id={}, seq {}..{}, dropped {} packets",
            msg_id, drop_req.first_seq.value(), drop_req.last_seq.value(), dropped);
    }
}

/// Process a data packet.
async fn process_data_packet(
    conn: &SrtConnection,
    packet: &SrtPacket,
) {
    let seq = packet.sequence_number();
    let msg_no = packet.message_number();
    let boundary = packet.boundary();
    let timestamp = packet.timestamp();
    let in_order = packet.in_order();
    let retransmitted = packet.rexmit_flag();
    let enc_key = packet.encryption_key();
    let raw_payload = packet.payload();
    let payload_len = packet.payload_len() as u64;

    // Decrypt payload if encrypted
    let data = decrypt_payload(conn, enc_key, raw_payload, seq.value() as u32).await;

    // Detect gaps and update loss list
    {
        let mut highest = conn.highest_recv_seq.lock().await;
        if seq.is_after(*highest) {
            // Check for gap: if seq > highest + 1, packets in between are missing
            let expected = highest.increment();
            if seq.is_after(expected) {
                let gap_end = seq.add(-1); // last missing seq = seq - 1
                let gap_count = SeqNo::offset(expected, gap_end) + 1;
                conn.recv_loss_list.lock().await.insert_range(expected, gap_end);
                let mut stats = conn.stats.lock().await;
                stats.pkt_rcv_loss += gap_count;
                stats.pkt_rcv_loss_total += gap_count;
                log::trace!(
                    "Gap detected: expected={}, got={}, missing {} packets",
                    expected.value(), seq.value(), gap_count
                );
            }
            *highest = seq;
        } else {
            // Out-of-order or retransmitted — remove from loss list if present
            conn.recv_loss_list.lock().await.remove(seq);
        }
    }

    // Record packet arrival for bandwidth estimation
    conn.pkt_time_window.lock().await.on_pkt_arrival();

    // Insert into receive buffer
    {
        let mut recv_buf = conn.recv_buf.lock().await;
        recv_buf.insert(seq, msg_no, boundary, timestamp, in_order, data);
    }

    // Update statistics
    {
        let mut stats = conn.stats.lock().await;
        stats.pkt_recv_total += 1;
        stats.byte_recv_total += payload_len;
        if retransmitted {
            stats.pkt_rcv_retrans += 1;
        }
    }

    // Notify any waiting receivers
    conn.recv_data_ready.notify_one();
}

/// Decrypt a received payload using the connection's crypto control.
/// If the packet is not encrypted or no crypto is configured, returns the data as-is.
async fn decrypt_payload(
    conn: &SrtConnection,
    enc_key: EncryptionKeySpec,
    raw_payload: &Bytes,
    pkt_index: u32,
) -> Bytes {
    if enc_key == EncryptionKeySpec::NoEnc {
        return Bytes::copy_from_slice(raw_payload);
    }

    let key_index = match KeyIndex::from_enc_key_spec(enc_key) {
        Some(ki) => ki,
        None => return Bytes::copy_from_slice(raw_payload),
    };

    let crypto_guard = conn.crypto.lock().await;
    let crypto = match crypto_guard.as_ref() {
        Some(c) => c,
        None => {
            // Encrypted packet but no crypto configured — count as undecrypted
            let mut stats = conn.stats.lock().await;
            stats.pkt_rcv_undecrypt += 1;
            stats.pkt_rcv_undecrypt_total += 1;
            return Bytes::copy_from_slice(raw_payload);
        }
    };

    let key = match crypto.keys.key(key_index) {
        Some(k) => k.to_vec(),
        None => {
            let mut stats = conn.stats.lock().await;
            stats.pkt_rcv_undecrypt += 1;
            stats.pkt_rcv_undecrypt_total += 1;
            return Bytes::copy_from_slice(raw_payload);
        }
    };
    let salt = crypto.salt;
    let mode = crypto.mode;
    drop(crypto_guard);

    match mode {
        CryptoMode::AesCtr => {
            use srt_protocol::crypto::aes_ctr::AesCtrCipher;
            if let Some(cipher) = AesCtrCipher::new(&key) {
                let mut data = raw_payload.to_vec();
                if cipher.decrypt(&salt, pkt_index, &mut data).is_ok() {
                    return Bytes::from(data);
                }
            }
        }
        CryptoMode::AesGcm => {
            use srt_protocol::crypto::aes_gcm::AesGcmCipher;
            if let Some(cipher) = AesGcmCipher::new(&key) {
                if let Ok(plaintext) = cipher.decrypt(&salt, pkt_index, raw_payload) {
                    return Bytes::from(plaintext);
                }
            }
            // GCM auth failure — count as undecrypted
            let mut stats = conn.stats.lock().await;
            stats.pkt_rcv_undecrypt += 1;
            stats.pkt_rcv_undecrypt_total += 1;
        }
    }

    Bytes::copy_from_slice(raw_payload)
}

/// Check if an I/O error is fatal (should stop the receive loop).
fn is_fatal_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(e.kind(), ErrorKind::NotConnected | ErrorKind::BrokenPipe)
}
