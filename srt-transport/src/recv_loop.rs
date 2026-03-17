//! Async receive loop.
//!
//! Maps to C++ `CRcvQueue::worker`. Continuously receives UDP packets
//! from the channel and routes them to the correct SRT connection.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;

use srt_protocol::packet::SrtPacket;
use srt_protocol::packet::control::ControlType;
use srt_protocol::packet::header::HEADER_SIZE;
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
                        process_packet(conn, packet, src_addr).await;
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
) {
    // Reset the idle/expiration timer on any packet from the peer.
    // This is how SRT detects that the peer is still alive.
    conn.timers.lock().await.on_response_received();

    if packet.is_control() {
        process_control_packet(&conn, &packet, src_addr).await;
    } else {
        process_data_packet(&conn, &packet).await;
    }
}

/// Process a control packet (ACK, NAK, handshake, keepalive, etc.).
async fn process_control_packet(
    conn: &SrtConnection,
    packet: &SrtPacket,
    src_addr: SocketAddr,
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
                // Deliver the handshake to the connection's handshake channel.
                // The connector (caller-side) or listener awaits on this channel.
                if let Err(e) = conn.handshake_tx.try_send((hs, src_addr)) {
                    log::error!("Failed to deliver handshake to connection: {} (channel full or closed)", e);
                }
            } else {
                log::warn!("Failed to parse handshake from {}", src_addr);
            }
        }
        Some(ControlType::Ack) => {
            let mut stats = conn.stats.lock().await;
            stats.pkt_recv_ack += 1;
        }
        Some(ControlType::Nak) => {
            let mut stats = conn.stats.lock().await;
            stats.pkt_recv_nak += 1;
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
    let data = Bytes::copy_from_slice(packet.payload());

    // Insert into receive buffer
    {
        let mut recv_buf = conn.recv_buf.lock().await;
        recv_buf.insert(seq, msg_no, boundary, timestamp, in_order, data);
    }

    // Update statistics
    {
        let mut stats = conn.stats.lock().await;
        stats.pkt_recv_total += 1;
        stats.byte_recv_total += packet.payload_len() as u64;
    }

    // Notify any waiting receivers
    conn.recv_data_ready.notify_one();
}

/// Check if an I/O error is fatal (should stop the receive loop).
fn is_fatal_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(e.kind(), ErrorKind::NotConnected | ErrorKind::BrokenPipe)
}
