// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Stateless async receive loop.
//!
//! Receives UDP packets, deserializes them, and forwards parsed events
//! to the appropriate connection via channels. Zero state mutation —
//! all protocol processing happens in [`ConnTask`](crate::conn_task::ConnTask).

use std::sync::Arc;

use bytes::Bytes;

use srt_protocol::packet::SrtPacket;
use srt_protocol::packet::control::{AckData, ControlType, DropReqData, LossReport};
use srt_protocol::packet::header::HEADER_SIZE;
use srt_protocol::protocol::handshake::Handshake;

use crate::conn_task::NetEvent;
use crate::multiplexer::Multiplexer;

/// Maximum UDP packet size.
const MAX_UDP_SIZE: usize = 1500;

/// Run the receive loop for a multiplexer.
///
/// Stateless: parses incoming UDP packets and routes them as
/// [`NetEvent`] variants to the connection task via channels.
/// Handshake packets are routed separately to the handshake channel
/// so connectors/listeners can process them during setup.
pub async fn run(mux: Arc<Multiplexer>) {
    let mut buf = vec![0u8; MAX_UDP_SIZE];

    loop {
        if mux.is_shutdown() {
            log::debug!("recv_loop: shutdown signalled, exiting");
            break;
        }

        let recv_result = tokio::select! {
            r = mux.channel.recv_from(&mut buf) => Some(r),
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => None,
        };

        let (len, src_addr) = match recv_result {
            Some(Ok((len, src_addr))) => (len, src_addr),
            Some(Err(e)) => {
                if is_fatal_error(&e) {
                    log::error!("Fatal receive error: {}", e);
                    break;
                }
                log::debug!("Transient receive error: {}", e);
                continue;
            }
            None => continue,
        };

        if len < HEADER_SIZE {
            continue;
        }

        let data = &buf[..len];
        let packet = match SrtPacket::deserialize(data) {
            Some(p) => p,
            None => {
                log::debug!("recv_loop: failed to deserialize packet ({} bytes) from {}", len, src_addr);
                continue;
            }
        };

        let dest_id = packet.dest_socket_id();
        log::trace!(
            "recv_loop: packet from {} dest_id={} ctrl={} type={:?} len={}",
            src_addr, dest_id, packet.is_control(),
            packet.control_type(), len
        );

        let conn = match mux.route(dest_id).await {
            Some(c) => c,
            None => {
                log::debug!(
                    "recv_loop: no route for dest_id={} from {} (ctrl={}, type={:?})",
                    dest_id, src_addr, packet.is_control(), packet.control_type()
                );
                continue;
            }
        };

        // Route handshake packets to the handshake channel (for connector/listener)
        if packet.is_control() && packet.control_type() == Some(ControlType::Handshake) {
            if let Some(hs) = Handshake::deserialize(packet.payload()) {
                log::debug!(
                    "Received {:?} handshake from {} (version={}, socket_id={}, cookie={:#x})",
                    hs.req_type, src_addr, hs.version, hs.socket_id, hs.cookie
                );
                let ext_bytes = if packet.payload().len() > 48 {
                    Bytes::copy_from_slice(&packet.payload()[48..])
                } else {
                    Bytes::new()
                };
                if let Err(e) = conn.handshake_tx.try_send((hs, src_addr, ext_bytes)) {
                    log::error!("Failed to deliver handshake: {} (channel full or closed)", e);
                }
            } else {
                log::warn!("Failed to parse handshake from {}", src_addr);
            }
            continue;
        }

        // Convert all other packets to NetEvent and send to ConnTask
        if let Some(event) = build_net_event(&packet) {
            let _ = conn.net_tx.send(event);
        }
    }
}

/// Convert a parsed SRT packet into a NetEvent.
fn build_net_event(packet: &SrtPacket) -> Option<NetEvent> {
    if packet.is_control() {
        match packet.control_type() {
            Some(ControlType::Ack) => {
                let ack_seq_no = packet.additional_info();
                let data = AckData::deserialize(packet.payload())?;
                Some(NetEvent::Ack { ack_seq_no, data })
            }
            Some(ControlType::Nak) => {
                let report = LossReport::deserialize(packet.payload());
                Some(NetEvent::Nak { report })
            }
            Some(ControlType::AckAck) => {
                let ack_seq = packet.additional_info() as i32;
                Some(NetEvent::AckAck { ack_seq })
            }
            Some(ControlType::DropReq) => {
                let msg_id = packet.additional_info() as i32;
                let drop_data = DropReqData::deserialize(msg_id, packet.payload())?;
                Some(NetEvent::DropReq {
                    msg_id,
                    first_seq: drop_data.first_seq,
                    last_seq: drop_data.last_seq,
                })
            }
            Some(ControlType::Keepalive) => {
                Some(NetEvent::Keepalive)
            }
            Some(ControlType::Shutdown) => {
                Some(NetEvent::Shutdown)
            }
            _ => {
                log::trace!("Unhandled control type: {:?}", packet.control_type());
                None
            }
        }
    } else {
        // Data packet (including FEC)
        Some(NetEvent::Data {
            seq: packet.sequence_number(),
            msg_no: packet.message_number(),
            boundary: packet.boundary(),
            timestamp: packet.timestamp(),
            in_order: packet.in_order(),
            retransmitted: packet.rexmit_flag(),
            enc_key: packet.encryption_key(),
            payload: Bytes::copy_from_slice(packet.payload()),
            is_fec: packet.is_fec_packet(),
        })
    }
}

fn is_fatal_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(e.kind(), ErrorKind::NotConnected | ErrorKind::BrokenPipe)
}
