// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT rendezvous connection establishment (HSv5).
//!
//! Implements the peer-to-peer handshake where both sides simultaneously
//! initiate a connection. Neither side is a caller or listener — both send
//! WAVEAHAND packets, determine roles based on socket IDs, then exchange
//! CONCLUSION/AGREEMENT packets to establish the connection.
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
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::{mpsc, watch};

use srt_protocol::access_control::{SRT_CMD_SID, parse_stream_id, serialize_stream_id};
use srt_protocol::config::srt_options::SrtFlags;
use srt_protocol::config::{SrtConfig, SocketStatus, SRT_VERSION};
use srt_protocol::crypto::{CryptoControl, KeyIndex};
use srt_protocol::crypto::key_material;
use srt_protocol::crypto::km_exchange::{CipherType, KeyMaterialMessage};
use srt_protocol::error::SrtError;
use srt_protocol::fec::{self, FecConfig};
use srt_protocol::packet::seq::SeqNo;
use srt_protocol::protocol::handshake::{
    HS_EXT_HSREQ, HS_EXT_KMREQ, HS_EXT_SID, HS_VERSION_SRT1, Handshake, HandshakeExtension,
    HandshakeType, SrtHsExtension,
};

use crate::connector::{HandshakeResult, build_handshake_packet, build_handshake_packet_with_extensions};
use crate::multiplexer::Multiplexer;

/// Retransmit WAVEAHAND every 250ms (matching C SRT library behavior).
const WAVEAHAND_RETRANSMIT_MS: u64 = 250;

/// Perform rendezvous HSv5 handshake.
///
/// Takes individual parameters instead of `Arc<SrtConnection>`.
/// Returns negotiated values as a [`HandshakeResult`].
pub async fn connect_rendezvous(
    mux: &Multiplexer,
    config: &SrtConfig,
    socket_id: u32,
    state_tx: &watch::Sender<SocketStatus>,
    mut crypto: Option<CryptoControl>,
    hs_rx: &mut mpsc::Receiver<(Handshake, SocketAddr, Bytes)>,
    remote_addr: SocketAddr,
) -> Result<HandshakeResult, SrtError> {
    let _ = state_tx.send(SocketStatus::Connecting);

    let timeout = config.connect_timeout;
    let isn: i32 = 0;

    // Build the WAVEAHAND packet
    let waveahand_hs = Handshake {
        version: HS_VERSION_SRT1,
        ext_flags: 0,
        isn,
        mss: config.mss as i32,
        flight_flag_size: config.flight_flag_size as i32,
        req_type: HandshakeType::Waveahand,
        socket_id: socket_id as i32,
        cookie: 0,
        peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let waveahand_pkt = build_handshake_packet(&waveahand_hs, 0);

    // ── Phase 1+2: Waving → Attention ──
    mux.send_to(&waveahand_pkt, remote_addr)
        .await
        .map_err(|_| SrtError::ConnectionFail)?;
    log::debug!(
        "HSv5 rendezvous: sent WAVEAHAND to {} (socket_id={})",
        remote_addr, socket_id
    );

    let mut retransmit = tokio::time::interval(Duration::from_millis(WAVEAHAND_RETRANSMIT_MS));
    retransmit.tick().await;

    let deadline = tokio::time::Instant::now() + timeout;
    let peer_hs: Option<Handshake>;
    let mut early_ext = Bytes::new();

    loop {
        tokio::select! {
            _ = retransmit.tick() => {
                let _ = mux.send_to(&waveahand_pkt, remote_addr).await;
            }
            result = hs_rx.recv() => {
                match result {
                    Some((hs, _addr, ext)) => {
                        match hs.req_type {
                            HandshakeType::Waveahand => {
                                log::debug!("HSv5 rendezvous: received WAVEAHAND from peer (socket_id={})", hs.socket_id);
                                peer_hs = Some(hs);
                                break;
                            }
                            HandshakeType::Conclusion => {
                                log::debug!("HSv5 rendezvous: received early CONCLUSION from peer (socket_id={})", hs.socket_id);
                                early_ext = ext;
                                peer_hs = Some(hs);
                                break;
                            }
                            _ => continue,
                        }
                    }
                    None => {
                        log::error!("HSv5 rendezvous: handshake channel closed");
                        let _ = state_tx.send(SocketStatus::Broken);
                        return Err(SrtError::ConnectionFail);
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                log::error!("HSv5 rendezvous: timeout waiting for peer WAVEAHAND");
                let _ = state_tx.send(SocketStatus::Broken);
                return Err(SrtError::NoServer);
            }
        }
    }

    let peer_hs = peer_hs.unwrap();
    let peer_socket_id = peer_hs.socket_id as u32;

    // ── Phase 3: Role Determination ──
    let is_initiator = if socket_id > peer_socket_id {
        true
    } else if socket_id < peer_socket_id {
        false
    } else {
        log::error!("HSv5 rendezvous: socket_id collision ({} == {})", socket_id, peer_socket_id);
        let _ = state_tx.send(SocketStatus::Broken);
        return Err(SrtError::ConnectionFail);
    };

    log::debug!(
        "HSv5 rendezvous: role={} (local_id={}, peer_id={})",
        if is_initiator { "Initiator" } else { "Responder" },
        socket_id, peer_socket_id
    );

    // ── Phase 4: Conclusion Exchange ──
    let mut srt_ext = SrtHsExtension::new();
    srt_ext.srt_version = SRT_VERSION;
    srt_ext.srt_flags = SrtFlags::TSBPD_SND
        | SrtFlags::TSBPD_RCV
        | SrtFlags::TLPKT_DROP
        | SrtFlags::NAK_REPORT
        | SrtFlags::REXMIT_FLG
        | SrtFlags::FILTER_CAP;
    srt_ext.set_recv_tsbpd_delay(config.recv_latency as u16);
    srt_ext.set_send_tsbpd_delay(config.peer_latency as u16);

    let ext_type: u32 = if is_initiator { 1 } else { 2 };
    let mut ext_buf = BytesMut::new();
    ext_buf.extend_from_slice(&((ext_type << 16) | 4u32).to_be_bytes());
    srt_ext.serialize(&mut ext_buf);

    let mut ext_flags = HS_EXT_HSREQ;
    if is_initiator {
        // KMREQ
        if let Some(ref crypto_state) = crypto {
            if let Some(sek) = crypto_state.keys.active_key() {
                if let Some(kek) = crypto_state.kek.as_ref() {
                    if let Ok(wrapped) = key_material::wrap_key(kek, sek) {
                        let cipher = match crypto_state.mode {
                            srt_protocol::crypto::CryptoMode::AesCtr => CipherType::AesCtr,
                            srt_protocol::crypto::CryptoMode::AesGcm => CipherType::AesGcm,
                        };
                        let km_msg = KeyMaterialMessage::new_single(
                            KeyIndex::Even, crypto_state.keys.key_size,
                            cipher, crypto_state.salt, wrapped,
                        );
                        let mut km_buf = BytesMut::new();
                        km_msg.serialize(&mut km_buf);
                        let size_words = (km_buf.len() + 3) / 4;
                        ext_buf.put_u32((3u32 << 16) | size_words as u32);
                        ext_buf.extend_from_slice(&km_buf);
                        while ext_buf.len() % 4 != 0 { ext_buf.put_u8(0); }
                        ext_flags |= HS_EXT_KMREQ;
                    }
                }
            }
        }

        // Stream ID
        if !config.stream_id.is_empty() {
            let sid_words = serialize_stream_id(&config.stream_id);
            for word in &sid_words { ext_buf.put_u32(*word); }
            ext_flags |= HS_EXT_SID;
        }

        // Filter
        if !config.packet_filter.is_empty() {
            let filter_words = fec::serialize_filter_extension(&config.packet_filter);
            for word in &filter_words { ext_buf.put_u32(*word); }
            ext_flags |= HS_EXT_SID;
        }
    }

    let conclusion_hs = Handshake {
        version: HS_VERSION_SRT1,
        ext_flags,
        isn,
        mss: config.mss as i32,
        flight_flag_size: config.flight_flag_size as i32,
        req_type: HandshakeType::Conclusion,
        socket_id: socket_id as i32,
        cookie: 0,
        peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    let conclusion_pkt = build_handshake_packet_with_extensions(&conclusion_hs, peer_socket_id, &ext_buf);

    let already_have_conclusion = peer_hs.req_type == HandshakeType::Conclusion;

    mux.send_to(&conclusion_pkt, remote_addr)
        .await
        .map_err(|_| SrtError::ConnectionFail)?;
    log::debug!("HSv5 rendezvous: sent CONCLUSION to {}", remote_addr);

    // Wait for peer's CONCLUSION
    let (peer_conclusion_hs, peer_conclusion_ext) = if already_have_conclusion {
        (peer_hs.clone(), early_ext)
    } else {
        let remaining = timeout.saturating_sub(Duration::from_millis(WAVEAHAND_RETRANSMIT_MS));
        let mut retransmit = tokio::time::interval(Duration::from_millis(WAVEAHAND_RETRANSMIT_MS));
        retransmit.tick().await;

        let deadline = tokio::time::Instant::now() + remaining;
        let result_hs: Option<Handshake>;
        let result_ext: Bytes;

        loop {
            tokio::select! {
                _ = retransmit.tick() => {
                    let _ = mux.send_to(&conclusion_pkt, remote_addr).await;
                }
                result = hs_rx.recv() => {
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
                                    log::debug!("HSv5 rendezvous: received early AGREEMENT from peer");
                                    result_hs = Some(hs);
                                    result_ext = ext;
                                    break;
                                }
                                HandshakeType::Waveahand => {
                                    let _ = mux.send_to(&conclusion_pkt, remote_addr).await;
                                    continue;
                                }
                                _ => continue,
                            }
                        }
                        None => {
                            let _ = state_tx.send(SocketStatus::Broken);
                            return Err(SrtError::ConnectionFail);
                        }
                    }
                }
                _ = tokio::time::sleep_until(deadline) => {
                    log::error!("HSv5 rendezvous: timeout waiting for peer CONCLUSION");
                    let _ = state_tx.send(SocketStatus::Broken);
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
            let mut got_kmrsp = false;
            for ext in &extensions {
                match ext.ext_type {
                    4 => {
                        let km_bytes: Vec<u8> = ext.data.iter().flat_map(|w| w.to_be_bytes()).collect();
                        if let Some(km_msg) = KeyMaterialMessage::deserialize(&km_bytes) {
                            if let Some(ref mut c) = crypto {
                                c.salt = km_msg.salt;
                                c.km_exchanged = true;
                                got_kmrsp = true;
                                log::debug!("HSv5 rendezvous: KMRSP received, encryption active");
                            }
                        }
                    }
                    7 => {
                        negotiated_filter = fec::parse_filter_extension(&ext.data);
                        log::debug!("HSv5 rendezvous: received Filter config: {}", negotiated_filter);
                    }
                    _ => {}
                }
            }

            // Wait for KMRSP if encryption configured but not yet received
            if config.encryption_enabled() && !got_kmrsp {
                log::debug!("HSv5 rendezvous: Initiator waiting for Responder's CONCLUSION with KMRSP");
                let remaining = timeout.saturating_sub(Duration::from_secs(1));
                let deadline = tokio::time::Instant::now() + remaining;

                loop {
                    tokio::select! {
                        result = hs_rx.recv() => {
                            match result {
                                Some((hs, _addr, ext)) => {
                                    if hs.req_type == HandshakeType::Conclusion && !ext.is_empty() {
                                        let exts = HandshakeExtension::parse_extensions(&ext);
                                        for e in &exts {
                                            if e.ext_type == 4 {
                                                let km_bytes: Vec<u8> = e.data.iter().flat_map(|w| w.to_be_bytes()).collect();
                                                if let Some(km_msg) = KeyMaterialMessage::deserialize(&km_bytes) {
                                                    if let Some(ref mut c) = crypto {
                                                        c.salt = km_msg.salt;
                                                        c.km_exchanged = true;
                                                        log::debug!("HSv5 rendezvous: KMRSP received (second CONCLUSION)");
                                                    }
                                                }
                                                got_kmrsp = true;
                                            } else if e.ext_type == 7 {
                                                negotiated_filter = fec::parse_filter_extension(&e.data);
                                            }
                                        }
                                        if got_kmrsp { break; }
                                    }
                                }
                                None => {
                                    let _ = state_tx.send(SocketStatus::Broken);
                                    return Err(SrtError::ConnectionFail);
                                }
                            }
                        }
                        _ = tokio::time::sleep_until(deadline) => {
                            log::error!("HSv5 rendezvous: timeout waiting for KMRSP");
                            let _ = state_tx.send(SocketStatus::Broken);
                            return Err(SrtError::ConnectionFail);
                        }
                    }
                }
            }
        } else {
            // Responder
            let mut km_response: Option<KeyMaterialMessage> = None;
            let mut peer_filter_config = String::new();

            for ext in &extensions {
                match ext.ext_type {
                    3 => {
                        if config.encryption_enabled() {
                            let km_bytes: Vec<u8> = ext.data.iter().flat_map(|w| w.to_be_bytes()).collect();
                            if let Some(km_msg) = KeyMaterialMessage::deserialize(&km_bytes) {
                                let kek = key_material::derive_kek(&config.passphrase, &km_msg.salt, km_msg.key_size);
                                if let Ok(sek) = key_material::unwrap_key(&kek, &km_msg.wrapped_keys) {
                                    log::debug!("HSv5 rendezvous: KMREQ received, SEK unwrapped");
                                    let cipher = match km_msg.cipher {
                                        CipherType::AesGcm => CipherType::AesGcm,
                                        _ => CipherType::AesCtr,
                                    };
                                    if let Ok(wrapped) = key_material::wrap_key(&kek, &sek) {
                                        km_response = Some(KeyMaterialMessage::new_single(
                                            KeyIndex::Even, km_msg.key_size, cipher, km_msg.salt, wrapped,
                                        ));
                                    }
                                    if let Some(ref mut c) = crypto {
                                        c.keys.set_key(KeyIndex::Even, sek);
                                        c.salt = km_msg.salt;
                                        c.km_exchanged = true;
                                    }
                                } else {
                                    log::warn!("HSv5 rendezvous: KMREQ key unwrap failed");
                                }
                            }
                        }
                    }
                    SRT_CMD_SID => {
                        let peer_stream_id = parse_stream_id(&ext.data);
                        log::debug!("HSv5 rendezvous: received Stream ID: {:?}", peer_stream_id);
                    }
                    7 => {
                        peer_filter_config = fec::parse_filter_extension(&ext.data);
                        log::debug!("HSv5 rendezvous: received Filter config: {}", peer_filter_config);
                    }
                    _ => {}
                }
            }

            // Negotiate FEC
            if !peer_filter_config.is_empty() || !config.packet_filter.is_empty() {
                match fec::negotiate_filter(&config.packet_filter, &peer_filter_config) {
                    Ok(f) => negotiated_filter = f,
                    Err(e) => {
                        log::warn!("HSv5 rendezvous: FEC negotiation failed: {}", e);
                        let _ = state_tx.send(SocketStatus::Broken);
                        return Err(SrtError::ConnectionFail);
                    }
                }
            }

            // Re-send CONCLUSION with full response extensions
            let mut resp_ext_buf = BytesMut::new();
            resp_ext_buf.extend_from_slice(&((2u32 << 16) | 4u32).to_be_bytes());
            srt_ext.serialize(&mut resp_ext_buf);

            let mut resp_ext_flags = HS_EXT_HSREQ;
            if let Some(km_msg) = &km_response {
                let mut km_buf = BytesMut::new();
                km_msg.serialize(&mut km_buf);
                let size_words = (km_buf.len() + 3) / 4;
                resp_ext_buf.put_u32((4u32 << 16) | size_words as u32);
                resp_ext_buf.extend_from_slice(&km_buf);
                while resp_ext_buf.len() % 4 != 0 { resp_ext_buf.put_u8(0); }
                resp_ext_flags |= HS_EXT_KMREQ;
            }

            if !negotiated_filter.is_empty() {
                let filter_words = fec::serialize_filter_extension(&negotiated_filter);
                for word in &filter_words { resp_ext_buf.put_u32(*word); }
            }

            let resp_conclusion_hs = Handshake {
                version: HS_VERSION_SRT1,
                ext_flags: resp_ext_flags,
                isn,
                mss: config.mss as i32,
                flight_flag_size: config.flight_flag_size as i32,
                req_type: HandshakeType::Conclusion,
                socket_id: socket_id as i32,
                cookie: 0,
                peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            };
            let resp_pkt = build_handshake_packet_with_extensions(&resp_conclusion_hs, peer_socket_id, &resp_ext_buf);
            let _ = mux.send_to(&resp_pkt, remote_addr).await;
            log::debug!("HSv5 rendezvous: Responder re-sent CONCLUSION with KMRSP/FILTER");
        }
    }

    // ── Phase 5: Agreement ──
    let agreement_hs = Handshake {
        version: HS_VERSION_SRT1,
        ext_flags: 0,
        isn,
        mss: config.mss as i32,
        flight_flag_size: config.flight_flag_size as i32,
        req_type: HandshakeType::Agreement,
        socket_id: socket_id as i32,
        cookie: 0,
        peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };
    let agreement_pkt = build_handshake_packet(&agreement_hs, peer_socket_id);
    let _ = mux.send_to(&agreement_pkt, remote_addr).await;
    log::debug!("HSv5 rendezvous: sent AGREEMENT to {}", remote_addr);

    // Build result
    let peer_isn = SeqNo::new(peer_conclusion_hs.isn);
    let tsbpd_base_time = Instant::now();

    let filter_to_use = if !negotiated_filter.is_empty() {
        negotiated_filter
    } else {
        config.packet_filter.clone()
    };
    let fec_config = if !filter_to_use.is_empty() {
        match FecConfig::parse(&filter_to_use) {
            Ok(fc) => {
                log::info!("HSv5 rendezvous: FEC initialized with config: {}", filter_to_use);
                Some(fc)
            }
            Err(_) => None,
        }
    } else {
        None
    };

    let _ = state_tx.send(SocketStatus::Connected);
    log::info!(
        "HSv5 rendezvous: connected to {} (local_id={}, peer_id={}, role={})",
        remote_addr, socket_id, peer_socket_id,
        if is_initiator { "Initiator" } else { "Responder" }
    );

    Ok(HandshakeResult {
        peer_addr: remote_addr,
        peer_socket_id,
        peer_isn,
        crypto,
        fec_config,
        tsbpd_base_time,
    })
}
