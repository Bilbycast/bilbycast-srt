//! SRT connection establishment (handshake).
//!
//! Implements the HSv5 caller-side handshake sequence:
//! 1. Send INDUCTION handshake (version=4)
//! 2. Receive INDUCTION response (version=5, with cookie)
//! 3. Send CONCLUSION handshake (version=5, echoed cookie, SRT extensions)
//! 4. Receive CONCLUSION response → connected

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::BytesMut;

use srt_protocol::config::srt_options::SrtFlags;
use srt_protocol::config::SRT_VERSION;
use srt_protocol::error::SrtError;
use srt_protocol::packet::SrtPacket;
use srt_protocol::packet::control::ControlType;
use srt_protocol::packet::header::HEADER_SIZE;
use srt_protocol::protocol::connection::ConnectionState;
use srt_protocol::protocol::handshake::{
    HS_EXT_HSREQ, HS_VERSION_SRT1, HS_VERSION_UDT4, Handshake, HandshakeType, SrtHsExtension,
};

use crate::connection::SrtConnection;
use crate::multiplexer::Multiplexer;

/// Perform caller-side HSv5 handshake to establish connection.
///
/// Implements the full two-phase handshake:
/// 1. INDUCTION: send v4 request, receive v5 response with cookie
/// 2. CONCLUSION: send v5 request with cookie + SRT extensions, receive v5 response
pub async fn connect(
    mux: Arc<Multiplexer>,
    conn: Arc<SrtConnection>,
    target: SocketAddr,
) -> Result<(), SrtError> {
    conn.set_state(ConnectionState::Connecting).await;
    *conn.peer_addr.lock().await = Some(target);

    let timeout = conn.config.connect_timeout;

    // Phase 1: INDUCTION
    let induction_hs = Handshake {
        version: HS_VERSION_UDT4, // Start with v4
        ext_flags: 0,
        isn: rand::random::<i32>() & 0x7FFF_FFFF,
        mss: conn.config.mss as i32,
        flight_flag_size: conn.config.flight_flag_size as i32,
        req_type: HandshakeType::Induction,
        socket_id: conn.socket_id as i32,
        cookie: 0,
        peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    let pkt = build_handshake_packet(&induction_hs, 0); // dest_socket_id=0 for listener
    mux.send_to(&pkt, target)
        .await
        .map_err(|_| SrtError::ConnectionFail)?;

    log::debug!("HSv5 caller: sent INDUCTION to {}", target);

    // Wait for INDUCTION response
    let induction_response = {
        let mut rx = conn.handshake_rx.lock().await;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some((hs, _addr))) => hs,
            Ok(None) => {
                log::error!("HSv5 caller: handshake channel closed");
                conn.set_state(ConnectionState::Broken).await;
                return Err(SrtError::ConnectionFail);
            }
            Err(_) => {
                log::error!("HSv5 caller: INDUCTION response timeout");
                conn.set_state(ConnectionState::Broken).await;
                return Err(SrtError::ConnectionFail);
            }
        }
    };

    if induction_response.req_type != HandshakeType::Induction {
        log::error!(
            "HSv5 caller: expected INDUCTION response, got {:?}",
            induction_response.req_type
        );
        conn.set_state(ConnectionState::Broken).await;
        return Err(SrtError::ConnectionFail);
    }

    let cookie = induction_response.cookie;
    let peer_socket_id = induction_response.socket_id;
    log::debug!(
        "HSv5 caller: received INDUCTION response, cookie={:#x}, peer_id={}",
        cookie,
        peer_socket_id
    );

    // Phase 2: CONCLUSION
    // Build SRT HSREQ extension
    let mut srt_ext = SrtHsExtension::new();
    srt_ext.srt_version = SRT_VERSION;
    srt_ext.srt_flags = SrtFlags::TSBPD_SND
        | SrtFlags::TSBPD_RCV
        | SrtFlags::TLPKT_DROP
        | SrtFlags::NAK_REPORT
        | SrtFlags::REXMIT_FLG;
    srt_ext.set_recv_tsbpd_delay(conn.config.recv_latency as u16);
    srt_ext.set_send_tsbpd_delay(conn.config.peer_latency as u16);

    // Serialize HSREQ extension block
    let mut ext_buf = BytesMut::new();
    // Extension header: type=HSREQ(1), size=4 words (16 bytes)
    ext_buf.extend_from_slice(&((1u32 << 16) | 4u32).to_be_bytes());
    srt_ext.serialize(&mut ext_buf);

    let conclusion_hs = Handshake {
        version: HS_VERSION_SRT1,
        ext_flags: HS_EXT_HSREQ,
        isn: induction_hs.isn,
        mss: conn.config.mss as i32,
        flight_flag_size: conn.config.flight_flag_size as i32,
        req_type: HandshakeType::Conclusion,
        socket_id: conn.socket_id as i32,
        cookie,
        peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    let pkt = build_handshake_packet_with_extensions(&conclusion_hs, peer_socket_id as u32, &ext_buf);
    mux.send_to(&pkt, target)
        .await
        .map_err(|_| SrtError::ConnectionFail)?;

    log::debug!("HSv5 caller: sent CONCLUSION to {}", target);

    // Wait for CONCLUSION response
    let conclusion_response = {
        let mut rx = conn.handshake_rx.lock().await;
        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some((hs, _addr))) => hs,
            Ok(None) => {
                log::error!("HSv5 caller: handshake channel closed during CONCLUSION");
                conn.set_state(ConnectionState::Broken).await;
                return Err(SrtError::ConnectionFail);
            }
            Err(_) => {
                log::error!("HSv5 caller: CONCLUSION response timeout");
                conn.set_state(ConnectionState::Broken).await;
                return Err(SrtError::ConnectionFail);
            }
        }
    };

    if conclusion_response.req_type != HandshakeType::Conclusion {
        if let HandshakeType::Failure(reason) = conclusion_response.req_type {
            log::error!("HSv5 caller: connection rejected: {:?}", reason);
            conn.set_state(ConnectionState::Broken).await;
            return Err(SrtError::ConnectionRejected);
        }
        log::error!(
            "HSv5 caller: expected CONCLUSION response, got {:?}",
            conclusion_response.req_type
        );
        conn.set_state(ConnectionState::Broken).await;
        return Err(SrtError::ConnectionFail);
    }

    // Store peer socket ID
    *conn.peer_socket_id.lock().await = conclusion_response.socket_id as u32;

    // Connected!
    conn.set_state(ConnectionState::Connected).await;
    log::info!("HSv5 caller: connected to {}", target);

    Ok(())
}

/// Build a serialized handshake control packet (base handshake only, no extensions).
fn build_handshake_packet(hs: &Handshake, dest_socket_id: u32) -> Vec<u8> {
    let mut hs_payload = BytesMut::with_capacity(64);
    hs.serialize(&mut hs_payload);

    let pkt = SrtPacket::new_control(
        ControlType::Handshake,
        0,
        0,
        0,
        dest_socket_id,
        hs_payload.freeze(),
    );

    let mut buf = BytesMut::with_capacity(HEADER_SIZE + pkt.payload_len());
    pkt.serialize(&mut buf);
    buf.to_vec()
}

/// Build a serialized handshake control packet with SRT extension data appended.
pub fn build_handshake_packet_with_extensions(
    hs: &Handshake,
    dest_socket_id: u32,
    extensions: &[u8],
) -> Vec<u8> {
    let mut hs_payload = BytesMut::with_capacity(64 + extensions.len());
    hs.serialize(&mut hs_payload);
    hs_payload.extend_from_slice(extensions);

    let pkt = SrtPacket::new_control(
        ControlType::Handshake,
        0,
        0,
        0,
        dest_socket_id,
        hs_payload.freeze(),
    );

    let mut buf = BytesMut::with_capacity(HEADER_SIZE + pkt.payload_len());
    pkt.serialize(&mut buf);
    buf.to_vec()
}
