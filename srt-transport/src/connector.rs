// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT connection establishment (handshake).
//!
//! Implements the HSv5 caller-side handshake sequence:
//! 1. Send INDUCTION handshake (version=4)
//! 2. Receive INDUCTION response (version=5, with cookie)
//! 3. Send CONCLUSION handshake (version=5, echoed cookie, SRT extensions)
//! 4. Receive CONCLUSION response → connected

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::{mpsc, watch};

use srt_protocol::access_control::serialize_stream_id;
use srt_protocol::fec::{self, FecConfig};
use srt_protocol::config::srt_options::SrtFlags;
use srt_protocol::config::{SrtConfig, SocketStatus, SRT_VERSION};
use srt_protocol::crypto::{CryptoControl, KeyIndex};
use srt_protocol::crypto::km_exchange::{CipherType, KeyMaterialMessage};
use srt_protocol::crypto::key_material;
use srt_protocol::error::SrtError;
use srt_protocol::packet::SrtPacket;
use srt_protocol::packet::control::ControlType;
use srt_protocol::packet::header::HEADER_SIZE;
use srt_protocol::packet::seq::SeqNo;
use srt_protocol::protocol::handshake::{
    HS_EXT_HSREQ, HS_EXT_KMREQ, HS_EXT_SID, HS_VERSION_SRT1, HS_VERSION_UDT4, Handshake,
    HandshakeExtension, HandshakeType, SrtHsExtension,
};

use crate::multiplexer::Multiplexer;

/// Result of a successful handshake — negotiated values needed to
/// construct a [`ConnTask`](crate::conn_task::ConnTask).
pub struct HandshakeResult {
    pub peer_addr: SocketAddr,
    pub peer_socket_id: u32,
    pub peer_isn: SeqNo,
    pub crypto: Option<CryptoControl>,
    pub fec_config: Option<FecConfig>,
    pub tsbpd_base_time: Instant,
}

/// Perform caller-side HSv5 handshake.
///
/// Takes individual parameters instead of an `Arc<SrtConnection>`.
/// Returns negotiated values as a [`HandshakeResult`].
pub async fn connect(
    mux: &Multiplexer,
    config: &SrtConfig,
    socket_id: u32,
    state_tx: &watch::Sender<SocketStatus>,
    mut crypto: Option<CryptoControl>,
    hs_rx: &mut mpsc::Receiver<(Handshake, SocketAddr, Bytes)>,
    target: SocketAddr,
) -> Result<HandshakeResult, SrtError> {
    let _ = state_tx.send(SocketStatus::Connecting);

    let timeout = config.connect_timeout;

    // Phase 1: INDUCTION
    let induction_hs = Handshake {
        version: HS_VERSION_UDT4,
        ext_flags: 2,
        isn: 0,
        mss: config.mss as i32,
        flight_flag_size: config.flight_flag_size as i32,
        req_type: HandshakeType::Induction,
        socket_id: socket_id as i32,
        cookie: 0,
        peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    let pkt = build_handshake_packet(&induction_hs, 0);
    mux.send_to(&pkt, target)
        .await
        .map_err(|_| SrtError::ConnectionFail)?;

    log::debug!("HSv5 caller: sent INDUCTION to {}", target);

    // Wait for INDUCTION response
    let induction_response = match tokio::time::timeout(timeout, hs_rx.recv()).await {
        Ok(Some((hs, _addr, _ext))) => hs,
        Ok(None) => {
            log::error!("HSv5 caller: handshake channel closed");
            let _ = state_tx.send(SocketStatus::Broken);
            return Err(SrtError::ConnectionFail);
        }
        Err(_) => {
            log::error!("HSv5 caller: INDUCTION response timeout");
            let _ = state_tx.send(SocketStatus::Broken);
            return Err(SrtError::ConnectionFail);
        }
    };

    if induction_response.req_type != HandshakeType::Induction {
        log::error!(
            "HSv5 caller: expected INDUCTION response, got {:?}",
            induction_response.req_type
        );
        let _ = state_tx.send(SocketStatus::Broken);
        return Err(SrtError::ConnectionFail);
    }

    let cookie = induction_response.cookie;
    let peer_socket_id = induction_response.socket_id;
    log::debug!(
        "HSv5 caller: received INDUCTION response, cookie={:#x}, peer_id={}",
        cookie, peer_socket_id
    );

    // Phase 2: CONCLUSION
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

    let mut ext_buf = BytesMut::new();
    ext_buf.extend_from_slice(&((1u32 << 16) | 4u32).to_be_bytes());
    srt_ext.serialize(&mut ext_buf);

    let mut ext_flags = HS_EXT_HSREQ;
    if let Some(ref crypto_state) = crypto {
        if let Some(sek) = crypto_state.keys.active_key() {
            if let Some(kek) = crypto_state.kek.as_ref() {
                if let Ok(wrapped) = key_material::wrap_key(kek, sek) {
                    let cipher = match crypto_state.mode {
                        srt_protocol::crypto::CryptoMode::AesCtr => CipherType::AesCtr,
                        srt_protocol::crypto::CryptoMode::AesGcm => CipherType::AesGcm,
                    };
                    let km_msg = KeyMaterialMessage::new_single(
                        KeyIndex::Even,
                        crypto_state.keys.key_size,
                        cipher,
                        crypto_state.salt,
                        wrapped,
                    );
                    let mut km_buf = BytesMut::new();
                    km_msg.serialize(&mut km_buf);
                    let size_words = (km_buf.len() + 3) / 4;
                    ext_buf.put_u32((3u32 << 16) | size_words as u32);
                    ext_buf.extend_from_slice(&km_buf);
                    while ext_buf.len() % 4 != 0 {
                        ext_buf.put_u8(0);
                    }
                    ext_flags |= HS_EXT_KMREQ;
                }
            }
        }
    }

    if !config.stream_id.is_empty() {
        let sid_words = serialize_stream_id(&config.stream_id);
        for word in &sid_words {
            ext_buf.put_u32(*word);
        }
        ext_flags |= HS_EXT_SID;
    }

    if !config.packet_filter.is_empty() {
        let filter_words = fec::serialize_filter_extension(&config.packet_filter);
        for word in &filter_words {
            ext_buf.put_u32(*word);
        }
        ext_flags |= HS_EXT_SID;
    }

    let conclusion_hs = Handshake {
        version: HS_VERSION_SRT1,
        ext_flags,
        isn: 0,
        mss: config.mss as i32,
        flight_flag_size: config.flight_flag_size as i32,
        req_type: HandshakeType::Conclusion,
        socket_id: socket_id as i32,
        cookie,
        peer_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    };

    let pkt = build_handshake_packet_with_extensions(&conclusion_hs, 0, &ext_buf);
    mux.send_to(&pkt, target)
        .await
        .map_err(|_| SrtError::ConnectionFail)?;

    log::debug!("HSv5 caller: sent CONCLUSION to {}", target);

    // Wait for CONCLUSION response
    let (conclusion_response, conclusion_ext_bytes) = match tokio::time::timeout(timeout, hs_rx.recv()).await {
        Ok(Some((hs, _addr, ext))) => (hs, ext),
        Ok(None) => {
            log::error!("HSv5 caller: handshake channel closed during CONCLUSION");
            let _ = state_tx.send(SocketStatus::Broken);
            return Err(SrtError::ConnectionFail);
        }
        Err(_) => {
            log::error!("HSv5 caller: CONCLUSION response timeout");
            let _ = state_tx.send(SocketStatus::Broken);
            return Err(SrtError::ConnectionFail);
        }
    };

    if conclusion_response.req_type != HandshakeType::Conclusion {
        if let HandshakeType::Failure(reason) = conclusion_response.req_type {
            log::error!("HSv5 caller: connection rejected: {:?}", reason);
            let _ = state_tx.send(SocketStatus::Broken);
            return Err(SrtError::ConnectionRejected);
        }
        log::error!(
            "HSv5 caller: expected CONCLUSION response, got {:?}",
            conclusion_response.req_type
        );
        let _ = state_tx.send(SocketStatus::Broken);
        return Err(SrtError::ConnectionFail);
    }

    // Parse extensions
    let mut negotiated_filter = String::new();
    if !conclusion_ext_bytes.is_empty() {
        let extensions = HandshakeExtension::parse_extensions(&conclusion_ext_bytes);
        for ext in &extensions {
            if ext.ext_type == 7 {
                negotiated_filter = fec::parse_filter_extension(&ext.data);
                log::debug!("HSv5 caller: received Filter config: {}", negotiated_filter);
            } else if ext.ext_type == 4 {
                let km_bytes: Vec<u8> = ext.data.iter().flat_map(|w| w.to_be_bytes()).collect();
                if let Some(km_msg) = KeyMaterialMessage::deserialize(&km_bytes) {
                    if let Some(ref mut c) = crypto {
                        c.salt = km_msg.salt;
                        c.km_exchanged = true;
                        log::debug!("HSv5 caller: KMRSP received, encryption active");
                    }
                }
            }
        }
    }

    let peer_isn = SeqNo::new(conclusion_response.isn);
    let tsbpd_base_time = Instant::now();

    // Determine FEC config
    let filter_to_use = if !negotiated_filter.is_empty() {
        negotiated_filter
    } else {
        config.packet_filter.clone()
    };
    let fec_config = if !filter_to_use.is_empty() {
        FecConfig::parse(&filter_to_use).ok()
    } else {
        None
    };

    if fec_config.is_some() {
        log::info!("HSv5 caller: FEC initialized with config: {}", filter_to_use);
    }

    let _ = state_tx.send(SocketStatus::Connected);
    log::info!("HSv5 caller: connected to {}", target);

    Ok(HandshakeResult {
        peer_addr: target,
        peer_socket_id: conclusion_response.socket_id as u32,
        peer_isn,
        crypto,
        fec_config,
        tsbpd_base_time,
    })
}

/// Build a serialized handshake control packet (base handshake only, no extensions).
pub fn build_handshake_packet(hs: &Handshake, dest_socket_id: u32) -> Vec<u8> {
    let mut hs_payload = BytesMut::with_capacity(64);
    hs.serialize(&mut hs_payload);

    let pkt = SrtPacket::new_control(
        ControlType::Handshake, 0, 0, 0,
        dest_socket_id, hs_payload.freeze(),
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
        ControlType::Handshake, 0, 0, 0,
        dest_socket_id, hs_payload.freeze(),
    );

    let mut buf = BytesMut::with_capacity(HEADER_SIZE + pkt.payload_len());
    pkt.serialize(&mut buf);
    buf.to_vec()
}
