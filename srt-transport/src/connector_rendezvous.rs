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
//!
//! ## Extension Negotiation (libsrt v1.5.5 compatible)
//!
//! - **Initiator** (higher socket_id) acts like Caller: sends HSREQ + KMREQ + SID + FILTER
//! - **Responder** (lower socket_id) acts like Listener: sends HSRSP initially, then
//!   re-sends CONCLUSION with HSRSP + KMRSP + FILTER after processing Initiator's extensions

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};

use srt_protocol::access_control::{SRT_CMD_SID, parse_stream_id, serialize_stream_id};
use srt_protocol::config::srt_options::SrtFlags;
use srt_protocol::config::SRT_VERSION;
use srt_protocol::crypto::KeyIndex;
use srt_protocol::crypto::key_material;
use srt_protocol::crypto::km_exchange::{CipherType, KeyMaterialMessage};
use srt_protocol::error::SrtError;
use srt_protocol::fec;
use srt_protocol::protocol::connection::ConnectionState;
use srt_protocol::protocol::handshake::{
    HS_EXT_HSREQ, HS_EXT_KMREQ, HS_EXT_SID, HS_VERSION_SRT1, Handshake, HandshakeExtension,
    HandshakeType, SrtHsExtension,
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
///
/// Supports all HSv5 extensions: encryption (KMREQ/KMRSP), Stream ID,
/// and FEC packet filter negotiation — fully compatible with libsrt v1.5.5.
pub async fn connect_rendezvous(
    mux: Arc<Multiplexer>,
    conn: Arc<SrtConnection>,
    remote_addr: SocketAddr,
) -> Result<(), SrtError> {
    conn.set_state(ConnectionState::Connecting).await;
    *conn.peer_addr.lock().await = Some(remote_addr);

    let timeout = conn.config.connect_timeout;
    let isn: i32 = 0; // Must match send buffer starting sequence (SeqNo(0))

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
    let (peer_hs, early_ext) = {

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
        let peer_handshake: Option<Handshake>;
        let mut peer_ext_bytes = Bytes::new();

        loop {
            tokio::select! {
                _ = retransmit.tick() => {
                    // Retransmit WAVEAHAND
                    let _ = mux.send_to(&waveahand_pkt, remote_addr).await;
                }
                result = rx.recv() => {
                    match result {
                        Some((hs, _addr, ext)) => {
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
                                    peer_ext_bytes = ext;
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

        (peer_handshake.unwrap(), peer_ext_bytes)
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
        | SrtFlags::REXMIT_FLG
        | SrtFlags::FILTER_CAP;
    srt_ext.set_recv_tsbpd_delay(conn.config.recv_latency as u16);
    srt_ext.set_send_tsbpd_delay(conn.config.peer_latency as u16);

    // Extension type: 1 = HSREQ (initiator), 2 = HSRSP (responder)
    let ext_type: u32 = if is_initiator { 1 } else { 2 };

    let mut ext_buf = BytesMut::new();
    ext_buf.extend_from_slice(&((ext_type << 16) | 4u32).to_be_bytes());
    srt_ext.serialize(&mut ext_buf);

    // Build additional extensions for Initiator (acts like Caller)
    let mut ext_flags = HS_EXT_HSREQ;
    if is_initiator {
        // KMREQ extension if encryption is enabled
        {
            let crypto_guard = conn.crypto.lock().await;
            if let Some(crypto) = crypto_guard.as_ref() {
                if let Some(sek) = crypto.keys.active_key() {
                    if let Some(kek) = crypto.kek.as_ref() {
                        if let Ok(wrapped) = key_material::wrap_key(kek, sek) {
                            let cipher = match crypto.mode {
                                srt_protocol::crypto::CryptoMode::AesCtr => CipherType::AesCtr,
                                srt_protocol::crypto::CryptoMode::AesGcm => CipherType::AesGcm,
                            };
                            let km_msg = KeyMaterialMessage::new_single(
                                KeyIndex::Even,
                                crypto.keys.key_size,
                                cipher,
                                crypto.salt,
                                wrapped,
                            );
                            let mut km_buf = BytesMut::new();
                            km_msg.serialize(&mut km_buf);

                            // Extension header: type=KmReq(3), size in words
                            let size_words = (km_buf.len() + 3) / 4;
                            ext_buf.put_u32((3u32 << 16) | size_words as u32);
                            ext_buf.extend_from_slice(&km_buf);
                            // Pad to 4-byte boundary
                            while ext_buf.len() % 4 != 0 {
                                ext_buf.put_u8(0);
                            }
                            ext_flags |= HS_EXT_KMREQ;
                        }
                    }
                }
            }
        }

        // Stream ID extension (SRT_CMD_SID) if set
        if !conn.config.stream_id.is_empty() {
            let sid_words = serialize_stream_id(&conn.config.stream_id);
            for word in &sid_words {
                ext_buf.put_u32(*word);
            }
            ext_flags |= HS_EXT_SID;
        }

        // Filter extension (SRT_CMD_FILTER) if packet_filter is set
        if !conn.config.packet_filter.is_empty() {
            let filter_words = fec::serialize_filter_extension(&conn.config.packet_filter);
            for word in &filter_words {
                ext_buf.put_u32(*word);
            }
            ext_flags |= HS_EXT_SID; // Filter uses HS_EXT_CONFIG which equals HS_EXT_SID
        }
    }

    let conclusion_hs = Handshake {
        version: HS_VERSION_SRT1,
        ext_flags,
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
    let (peer_conclusion_hs, peer_conclusion_ext) = if already_have_conclusion {
        (peer_hs.clone(), early_ext)
    } else {
        let remaining = timeout.saturating_sub(Duration::from_millis(WAVEAHAND_RETRANSMIT_MS));
        let mut rx = conn.handshake_rx.lock().await;

        // Retransmit CONCLUSION while waiting for peer's response
        let mut retransmit =
            tokio::time::interval(Duration::from_millis(WAVEAHAND_RETRANSMIT_MS));
        retransmit.tick().await;

        let deadline = tokio::time::Instant::now() + remaining;
        let result_hs: Option<Handshake>;
        let result_ext: Bytes;

        loop {
            tokio::select! {
                _ = retransmit.tick() => {
                    let _ = mux.send_to(&conclusion_pkt, remote_addr).await;
                }
                result = rx.recv() => {
                    match result {
                        Some((hs, _addr, ext)) => {
                            match hs.req_type {
                                HandshakeType::Conclusion => {
                                    log::debug!("HSv5 rendezvous: received CONCLUSION from peer");
                                    result_hs = Some(hs);
                                    result_ext = ext;
                                    break;
                                }
                                HandshakeType::Agreement => {
                                    // Peer already advanced — use the CONCLUSION we may have missed
                                    log::debug!("HSv5 rendezvous: received early AGREEMENT from peer");
                                    result_hs = Some(hs);
                                    result_ext = ext;
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

        (result_hs.unwrap(), result_ext)
    };

    // ── Parse peer's CONCLUSION extensions ──
    let mut negotiated_filter = String::new();

    if !peer_conclusion_ext.is_empty() {
        let extensions = HandshakeExtension::parse_extensions(&peer_conclusion_ext);

        if is_initiator {
            // Initiator receives Responder's extensions: HSRSP(2), KMRSP(4), FILTER(7)
            let mut got_kmrsp = false;
            for ext in &extensions {
                match ext.ext_type {
                    4 => {
                        // KMRSP — confirm key exchange
                        {
                            let km_bytes: Vec<u8> =
                                ext.data.iter().flat_map(|w| w.to_be_bytes()).collect();
                            if let Some(km_msg) = KeyMaterialMessage::deserialize(&km_bytes) {
                                let mut crypto_guard = conn.crypto.lock().await;
                                if let Some(crypto) = crypto_guard.as_mut() {
                                    crypto.salt = km_msg.salt;
                                    crypto.km_exchanged = true;
                                    got_kmrsp = true;
                                    log::debug!(
                                        "HSv5 rendezvous: KMRSP received, encryption active"
                                    );
                                }
                            }
                        }
                    }
                    7 => {
                        // SRT_CMD_FILTER — negotiated filter config
                        negotiated_filter = fec::parse_filter_extension(&ext.data);
                        log::debug!(
                            "HSv5 rendezvous: received Filter config: {}",
                            negotiated_filter
                        );
                    }
                    _ => {}
                }
            }

            // If encryption is configured but the Responder's first CONCLUSION didn't
            // include KMRSP, wait for the Responder to re-send CONCLUSION with KMRSP.
            // This ensures the Responder has set up the shared SEK before we start
            // sending encrypted data.
            if conn.config.encryption_enabled() && !got_kmrsp {
                log::debug!(
                    "HSv5 rendezvous: Initiator waiting for Responder's CONCLUSION with KMRSP"
                );
                let remaining = timeout.saturating_sub(Duration::from_secs(1));
                let mut rx = conn.handshake_rx.lock().await;
                let deadline = tokio::time::Instant::now() + remaining;

                loop {
                    tokio::select! {
                        result = rx.recv() => {
                            match result {
                                Some((hs, _addr, ext)) => {
                                    if hs.req_type == HandshakeType::Conclusion && !ext.is_empty() {
                                        let exts = HandshakeExtension::parse_extensions(&ext);
                                        for e in &exts {
                                            if e.ext_type == 4 {
                                                let km_bytes: Vec<u8> = e.data.iter().flat_map(|w| w.to_be_bytes()).collect();
                                                if let Some(km_msg) = KeyMaterialMessage::deserialize(&km_bytes) {
                                                    let mut crypto_guard = conn.crypto.lock().await;
                                                    if let Some(crypto) = crypto_guard.as_mut() {
                                                        crypto.salt = km_msg.salt;
                                                        crypto.km_exchanged = true;
                                                        log::debug!("HSv5 rendezvous: KMRSP received (second CONCLUSION)");
                                                    }
                                                }
                                                got_kmrsp = true;
                                            } else if e.ext_type == 7 {
                                                negotiated_filter = fec::parse_filter_extension(&e.data);
                                            }
                                        }
                                        if got_kmrsp {
                                            break;
                                        }
                                    }
                                    // Ignore other handshake types, keep waiting
                                }
                                None => {
                                    conn.set_state(ConnectionState::Broken).await;
                                    return Err(SrtError::ConnectionFail);
                                }
                            }
                        }
                        _ = tokio::time::sleep_until(deadline) => {
                            log::error!("HSv5 rendezvous: timeout waiting for KMRSP");
                            conn.set_state(ConnectionState::Broken).await;
                            return Err(SrtError::ConnectionFail);
                        }
                    }
                }
            }
        } else {
            // Responder receives Initiator's extensions: HSREQ(1), KMREQ(3), SID(5), FILTER(7)
            let mut km_response: Option<KeyMaterialMessage> = None;
            let mut peer_filter_config = String::new();

            for ext in &extensions {
                match ext.ext_type {
                    3 => {
                        // KMREQ — unwrap caller's SEK and set on our crypto
                        if conn.config.encryption_enabled() {
                            let km_bytes: Vec<u8> =
                                ext.data.iter().flat_map(|w| w.to_be_bytes()).collect();
                            if let Some(km_msg) = KeyMaterialMessage::deserialize(&km_bytes) {
                                let kek = key_material::derive_kek(
                                    &conn.config.passphrase,
                                    &km_msg.salt,
                                    km_msg.key_size,
                                );
                                if let Ok(sek) = key_material::unwrap_key(&kek, &km_msg.wrapped_keys)
                                {
                                    log::debug!(
                                        "HSv5 rendezvous: KMREQ received, SEK unwrapped successfully"
                                    );
                                    let cipher = match km_msg.cipher {
                                        CipherType::AesGcm => CipherType::AesGcm,
                                        _ => CipherType::AesCtr,
                                    };
                                    // Build KMRSP to echo back
                                    if let Ok(wrapped) = key_material::wrap_key(&kek, &sek) {
                                        km_response = Some(KeyMaterialMessage::new_single(
                                            KeyIndex::Even,
                                            km_msg.key_size,
                                            cipher,
                                            km_msg.salt,
                                            wrapped,
                                        ));
                                    }
                                    // Set the shared SEK on our crypto
                                    let mut crypto_guard = conn.crypto.lock().await;
                                    if let Some(crypto) = crypto_guard.as_mut() {
                                        crypto.keys.set_key(KeyIndex::Even, sek);
                                        crypto.salt = km_msg.salt;
                                        crypto.km_exchanged = true;
                                        log::debug!(
                                            "HSv5 rendezvous: set shared SEK on connection"
                                        );
                                    }
                                } else {
                                    log::warn!(
                                        "HSv5 rendezvous: KMREQ key unwrap failed (wrong passphrase?)"
                                    );
                                }
                            }
                        }
                    }
                    SRT_CMD_SID => {
                        // Stream ID from Initiator
                        let peer_stream_id = parse_stream_id(&ext.data);
                        log::debug!(
                            "HSv5 rendezvous: received Stream ID: {:?}",
                            peer_stream_id
                        );
                    }
                    7 => {
                        // SRT_CMD_FILTER — Initiator's filter config
                        peer_filter_config = fec::parse_filter_extension(&ext.data);
                        log::debug!(
                            "HSv5 rendezvous: received Filter config: {}",
                            peer_filter_config
                        );
                    }
                    _ => {}
                }
            }

            // Negotiate FEC filter
            if !peer_filter_config.is_empty() || !conn.config.packet_filter.is_empty() {
                match fec::negotiate_filter(&conn.config.packet_filter, &peer_filter_config) {
                    Ok(f) => negotiated_filter = f,
                    Err(e) => {
                        log::warn!("HSv5 rendezvous: FEC filter negotiation failed: {}", e);
                        conn.set_state(ConnectionState::Broken).await;
                        return Err(SrtError::ConnectionFail);
                    }
                }
            }

            // Responder re-sends CONCLUSION with HSRSP + KMRSP + FILTER
            // This matches libsrt behavior where the Responder's second CONCLUSION
            // carries the full response extensions after processing the Initiator's.
            let mut resp_ext_buf = BytesMut::new();
            // HSRSP (type 2, size 4 words)
            resp_ext_buf.extend_from_slice(&((2u32 << 16) | 4u32).to_be_bytes());
            srt_ext.serialize(&mut resp_ext_buf);

            let mut resp_ext_flags = HS_EXT_HSREQ;

            // KMRSP extension
            if let Some(km_msg) = &km_response {
                let mut km_buf = BytesMut::new();
                km_msg.serialize(&mut km_buf);
                let size_words = (km_buf.len() + 3) / 4;
                resp_ext_buf.put_u32((4u32 << 16) | size_words as u32);
                resp_ext_buf.extend_from_slice(&km_buf);
                while resp_ext_buf.len() % 4 != 0 {
                    resp_ext_buf.put_u8(0);
                }
                resp_ext_flags |= HS_EXT_KMREQ;
            }

            // Filter extension in response
            if !negotiated_filter.is_empty() {
                let filter_words = fec::serialize_filter_extension(&negotiated_filter);
                for word in &filter_words {
                    resp_ext_buf.put_u32(*word);
                }
                log::debug!(
                    "HSv5 rendezvous: echoing negotiated FEC filter: {}",
                    negotiated_filter
                );
            }

            // Re-send CONCLUSION with full response extensions
            let resp_conclusion_hs = Handshake {
                version: HS_VERSION_SRT1,
                ext_flags: resp_ext_flags,
                isn,
                mss: conn.config.mss as i32,
                flight_flag_size: conn.config.flight_flag_size as i32,
                req_type: HandshakeType::Conclusion,
                socket_id: conn.socket_id as i32,
                cookie: 0,
                peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            };
            let resp_pkt = build_handshake_packet_with_extensions(
                &resp_conclusion_hs,
                peer_socket_id,
                &resp_ext_buf,
            );
            let _ = mux.send_to(&resp_pkt, remote_addr).await;
            log::debug!(
                "HSv5 rendezvous: Responder re-sent CONCLUSION with KMRSP/FILTER to {}",
                remote_addr
            );
        }
    }

    // RendezvousState: Initiated

    // Set peer ISN from CONCLUSION handshake
    conn.set_peer_isn(srt_protocol::packet::seq::SeqNo::new(peer_conclusion_hs.isn))
        .await;

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

    // Initialize FEC if negotiated
    let filter_to_use = if !negotiated_filter.is_empty() {
        negotiated_filter
    } else {
        conn.config.packet_filter.clone()
    };
    if !filter_to_use.is_empty() {
        if let Ok(fec_config) = fec::FecConfig::parse(&filter_to_use) {
            conn.init_fec(fec_config).await;
            log::info!(
                "HSv5 rendezvous: FEC initialized with config: {}",
                filter_to_use
            );
        }
    }

    // Reset TSBPD base time to now (connection establishment time).
    // The base_time was originally set at SrtConnection::new() before the
    // handshake started. Resetting it here ensures sender timestamps
    // (relative to origin_time) align with the receiver's TSBPD schedule.
    conn.tsbpd.lock().await.set_base_time(std::time::Instant::now());

    // Store peer socket ID and mark connected
    *conn.peer_socket_id.lock().await = peer_socket_id;
    conn.set_state(ConnectionState::Connected).await;
    log::info!(
        "HSv5 rendezvous: connected to {} (local_id={}, peer_id={}, role={})",
        remote_addr,
        conn.socket_id,
        peer_socket_id,
        if is_initiator { "Initiator" } else { "Responder" }
    );

    Ok(())
}
