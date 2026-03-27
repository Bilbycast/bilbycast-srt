// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT rendezvous connection establishment (HSv5).
//!
//! Implements the peer-to-peer handshake where both sides simultaneously
//! initiate a connection. Neither side is a caller or listener — both send
//! WAVEAHAND packets, determine roles based on socket IDs, then exchange
//! CONCLUSION/AGREEMENT packets to establish the connection.
//!
//! This is essential for NAT traversal scenarios where neither peer can
//! act as a listener.
//!
//! ## Handshake Flow
//!
//! 1. **Waving**: Both sides send WAVEAHAND (version=5) to each other at dest_socket_id=0
//! 2. **Attention**: Each side receives the peer's WAVEAHAND and records peer_socket_id
//! 3. **Role determination**: Higher socket_id becomes Initiator (HSREQ), lower becomes Responder (HSRSP)
//! 4. **Conclusion**: Both sides exchange CONCLUSION packets with their respective extensions
//! 5. **Agreement**: Both sides send AGREEMENT to confirm — connection established

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;

use srt_protocol::config::srt_options::SrtFlags;
use srt_protocol::config::SRT_VERSION;
use srt_protocol::error::SrtError;
use srt_protocol::protocol::connection::ConnectionState;
use srt_protocol::protocol::handshake::{
    HS_EXT_HSREQ, HS_VERSION_SRT1, Handshake, HandshakeType, SrtHsExtension,
};

use crate::connection::SrtConnection;
use crate::connector::{build_handshake_packet, build_handshake_packet_with_extensions};
use crate::multiplexer::Multiplexer;

/// Retransmit WAVEAHAND every 250ms (matching C SRT library behavior).
const WAVEAHAND_RETRANSMIT_MS: u64 = 250;

/// Perform rendezvous HSv5 handshake to establish a peer-to-peer connection.
///
/// Both sides call this function simultaneously. The function sends WAVEAHAND
/// packets until the peer responds, determines roles, exchanges CONCLUSION,
/// and finalizes with AGREEMENT.
pub async fn connect_rendezvous(
    mux: Arc<Multiplexer>,
    conn: Arc<SrtConnection>,
    remote_addr: SocketAddr,
) -> Result<(), SrtError> {
    conn.set_state(ConnectionState::Connecting).await;
    *conn.peer_addr.lock().await = Some(remote_addr);

    let timeout = conn.config.connect_timeout;
    let isn = rand::random::<i32>() & 0x7FFF_FFFF;

    // Build the WAVEAHAND packet (sent repeatedly until peer responds)
    let waveahand_hs = Handshake {
        version: HS_VERSION_SRT1,
        ext_flags: 0,
        isn,
        mss: conn.config.mss as i32,
        flight_flag_size: conn.config.flight_flag_size as i32,
        req_type: HandshakeType::Waveahand,
        socket_id: conn.socket_id as i32,
        cookie: 0,
        peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let waveahand_pkt = build_handshake_packet(&waveahand_hs, 0);

    // ── Phase 1+2: Waving → Attention ──
    // Send WAVEAHAND periodically and wait for the peer's WAVEAHAND.
    // (RendezvousState: Invalid → Waving → Attention)
    let peer_hs = {

        // Send initial WAVEAHAND
        mux.send_to(&waveahand_pkt, remote_addr)
            .await
            .map_err(|_| SrtError::ConnectionFail)?;
        log::debug!(
            "HSv5 rendezvous: sent WAVEAHAND to {} (socket_id={})",
            remote_addr,
            conn.socket_id
        );

        let mut rx = conn.handshake_rx.lock().await;
        let mut retransmit = tokio::time::interval(Duration::from_millis(WAVEAHAND_RETRANSMIT_MS));
        retransmit.tick().await; // consume the immediate first tick

        let deadline = tokio::time::Instant::now() + timeout;
        #[allow(unused_assignments)]
        let mut peer_handshake: Option<Handshake> = None;

        loop {
            tokio::select! {
                _ = retransmit.tick() => {
                    // Retransmit WAVEAHAND
                    let _ = mux.send_to(&waveahand_pkt, remote_addr).await;
                }
                result = rx.recv() => {
                    match result {
                        Some((hs, _addr, _ext)) => {
                            match hs.req_type {
                                HandshakeType::Waveahand => {
                                    log::debug!(
                                        "HSv5 rendezvous: received WAVEAHAND from peer (socket_id={})",
                                        hs.socket_id
                                    );
                                    peer_handshake = Some(hs);
                                    break;
                                }
                                HandshakeType::Conclusion => {
                                    // Peer already advanced past WAVEAHAND — treat as implicit WAVEAHAND + CONCLUSION
                                    log::debug!(
                                        "HSv5 rendezvous: received early CONCLUSION from peer (socket_id={})",
                                        hs.socket_id
                                    );
                                    peer_handshake = Some(hs);
                                    break;
                                }
                                _ => continue,
                            }
                        }
                        None => {
                            log::error!("HSv5 rendezvous: handshake channel closed");
                            conn.set_state(ConnectionState::Broken).await;
                            return Err(SrtError::ConnectionFail);
                        }
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    log::error!("HSv5 rendezvous: timeout waiting for peer WAVEAHAND");
                    conn.set_state(ConnectionState::Broken).await;
                    return Err(SrtError::NoServer);
                }
            }
        }

        peer_handshake.unwrap()
    };

    // RendezvousState: Attention
    let peer_socket_id = peer_hs.socket_id as u32;

    // ── Phase 3: Role Determination ──
    // Higher socket_id = Initiator (sends HSREQ), lower = Responder (sends HSRSP)
    let is_initiator = if conn.socket_id > peer_socket_id {
        true
    } else if conn.socket_id < peer_socket_id {
        false
    } else {
        // Extremely unlikely with random 30-bit IDs, but handle gracefully
        log::error!(
            "HSv5 rendezvous: socket_id collision ({} == {})",
            conn.socket_id,
            peer_socket_id
        );
        conn.set_state(ConnectionState::Broken).await;
        return Err(SrtError::ConnectionFail);
    };

    log::debug!(
        "HSv5 rendezvous: role={} (local_id={}, peer_id={})",
        if is_initiator { "Initiator" } else { "Responder" },
        conn.socket_id,
        peer_socket_id
    );

    // RendezvousState: Fine

    // ── Phase 4: Conclusion Exchange ──
    // Build SRT extension based on role
    let mut srt_ext = SrtHsExtension::new();
    srt_ext.srt_version = SRT_VERSION;
    srt_ext.srt_flags = SrtFlags::TSBPD_SND
        | SrtFlags::TSBPD_RCV
        | SrtFlags::TLPKT_DROP
        | SrtFlags::NAK_REPORT
        | SrtFlags::REXMIT_FLG;
    srt_ext.set_recv_tsbpd_delay(conn.config.recv_latency as u16);
    srt_ext.set_send_tsbpd_delay(conn.config.peer_latency as u16);

    // Extension type: 1 = HSREQ (initiator), 2 = HSRSP (responder)
    let ext_type: u32 = if is_initiator { 1 } else { 2 };

    let mut ext_buf = BytesMut::new();
    ext_buf.extend_from_slice(&((ext_type << 16) | 4u32).to_be_bytes());
    srt_ext.serialize(&mut ext_buf);

    let conclusion_hs = Handshake {
        version: HS_VERSION_SRT1,
        ext_flags: HS_EXT_HSREQ,
        isn,
        mss: conn.config.mss as i32,
        flight_flag_size: conn.config.flight_flag_size as i32,
        req_type: HandshakeType::Conclusion,
        socket_id: conn.socket_id as i32,
        cookie: 0, // no cookie in rendezvous mode
        peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    let conclusion_pkt =
        build_handshake_packet_with_extensions(&conclusion_hs, peer_socket_id, &ext_buf);

    // If the peer already sent a CONCLUSION (early arrival), skip waiting
    let already_have_conclusion = peer_hs.req_type == HandshakeType::Conclusion;

    // Send our CONCLUSION
    mux.send_to(&conclusion_pkt, remote_addr)
        .await
        .map_err(|_| SrtError::ConnectionFail)?;
    log::debug!("HSv5 rendezvous: sent CONCLUSION to {}", remote_addr);

    // Wait for peer's CONCLUSION (unless we already received it)
    if !already_have_conclusion {
        let remaining = timeout.saturating_sub(Duration::from_millis(WAVEAHAND_RETRANSMIT_MS));
        let mut rx = conn.handshake_rx.lock().await;

        // Retransmit CONCLUSION while waiting for peer's response
        let mut retransmit =
            tokio::time::interval(Duration::from_millis(WAVEAHAND_RETRANSMIT_MS));
        retransmit.tick().await;

        let deadline = tokio::time::Instant::now() + remaining;

        loop {
            tokio::select! {
                _ = retransmit.tick() => {
                    let _ = mux.send_to(&conclusion_pkt, remote_addr).await;
                }
                result = rx.recv() => {
                    match result {
                        Some((hs, _addr, _ext)) => {
                            match hs.req_type {
                                HandshakeType::Conclusion => {
                                    log::debug!("HSv5 rendezvous: received CONCLUSION from peer");
                                    break;
                                }
                                HandshakeType::Agreement => {
                                    // Peer already advanced — we're done
                                    log::debug!("HSv5 rendezvous: received early AGREEMENT from peer");
                                    break;
                                }
                                HandshakeType::Waveahand => {
                                    // Peer is still waving — retransmit our CONCLUSION
                                    let _ = mux.send_to(&conclusion_pkt, remote_addr).await;
                                    continue;
                                }
                                _ => continue,
                            }
                        }
                        None => {
                            conn.set_state(ConnectionState::Broken).await;
                            return Err(SrtError::ConnectionFail);
                        }
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    log::error!("HSv5 rendezvous: timeout waiting for peer CONCLUSION");
                    conn.set_state(ConnectionState::Broken).await;
                    return Err(SrtError::NoServer);
                }
            }
        }
    }

    // RendezvousState: Initiated

    // ── Phase 5: Agreement ──
    let agreement_hs = Handshake {
        version: HS_VERSION_SRT1,
        ext_flags: 0,
        isn,
        mss: conn.config.mss as i32,
        flight_flag_size: conn.config.flight_flag_size as i32,
        req_type: HandshakeType::Agreement,
        socket_id: conn.socket_id as i32,
        cookie: 0,
        peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    let agreement_pkt = build_handshake_packet(&agreement_hs, peer_socket_id);
    let _ = mux.send_to(&agreement_pkt, remote_addr).await;
    log::debug!("HSv5 rendezvous: sent AGREEMENT to {}", remote_addr);

    // Store peer socket ID and mark connected
    *conn.peer_socket_id.lock().await = peer_socket_id;
    conn.set_state(ConnectionState::Connected).await;
    log::info!(
        "HSv5 rendezvous: connected to {} (local_id={}, peer_id={})",
        remote_addr,
        conn.socket_id,
        peer_socket_id
    );

    Ok(())
}
