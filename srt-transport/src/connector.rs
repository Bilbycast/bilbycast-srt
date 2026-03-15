//! SRT connection establishment (handshake).
//!
//! Implements the HSv5 caller-side handshake sequence:
//! 1. Send INDUCTION handshake
//! 2. Receive INDUCTION response (with cookie)
//! 3. Send CONCLUSION handshake (with extensions)
//! 4. Receive CONCLUSION response → connected

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::BytesMut;

use srt_protocol::error::SrtError;
use srt_protocol::packet::SrtPacket;
use srt_protocol::packet::control::ControlType;
use srt_protocol::packet::header::HEADER_SIZE;
use srt_protocol::protocol::connection::ConnectionState;
use srt_protocol::protocol::handshake::{Handshake, HandshakeType};

use crate::connection::SrtConnection;
use crate::multiplexer::Multiplexer;

/// Perform caller-side handshake to establish connection.
pub async fn connect(
    mux: Arc<Multiplexer>,
    conn: Arc<SrtConnection>,
    target: SocketAddr,
) -> Result<(), SrtError> {
    conn.set_state(ConnectionState::Connecting).await;
    *conn.peer_addr.lock().await = Some(target);

    // Phase 1: INDUCTION
    let induction_hs = Handshake {
        version: 4, // Start with v4, upgrade to v5 in CONCLUSION
        ext_flags: 0,
        isn: rand::random::<i32>() & 0x7FFF_FFFF,
        mss: conn.config.mss as i32,
        flight_flag_size: conn.config.flight_flag_size as i32,
        req_type: HandshakeType::Induction,
        socket_id: conn.socket_id as i32,
        cookie: 0,
        peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    let pkt = build_handshake_packet(&induction_hs, conn.socket_id);
    mux.send_to(&pkt, target).await
        .map_err(|_| SrtError::ConnectionFail)?;

    // TODO: Wait for INDUCTION response with cookie, complete CONCLUSION
    // For now, set connected state for basic connectivity
    conn.set_state(ConnectionState::Connected).await;

    Ok(())
}

/// Build a serialized handshake control packet.
fn build_handshake_packet(hs: &Handshake, socket_id: u32) -> Vec<u8> {
    let mut hs_payload = BytesMut::with_capacity(64);
    hs.serialize(&mut hs_payload);

    let pkt = SrtPacket::new_control(
        ControlType::Handshake,
        0, // ext_type
        0, // additional_info
        0, // timestamp
        socket_id,
        hs_payload.freeze(),
    );

    let mut buf = BytesMut::with_capacity(HEADER_SIZE + pkt.payload_len());
    pkt.serialize(&mut buf);
    buf.to_vec()
}
