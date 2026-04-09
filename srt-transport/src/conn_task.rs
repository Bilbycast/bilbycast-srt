// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Single-owner connection task.
//!
//! Replaces the old two-task model (send_loop + recv_loop sharing ~25
//! `Mutex<T>` fields) with a single tokio task that owns all mutable
//! protocol state as plain fields. The recv_loop feeds parsed network
//! events via an unbounded mpsc channel; the app communicates via
//! bounded mpsc channels for send/recv. Zero mutex acquisitions on
//! the data path.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use tokio::sync::{mpsc, watch, Notify};

use srt_protocol::buffer::loss_list::{ReceiveLossList, SendLossList};
use srt_protocol::buffer::receive::ReceiveBuffer;
use srt_protocol::buffer::send::SendBuffer;
use srt_protocol::config::{SrtConfig, SocketStatus};
use srt_protocol::congestion::CongestionControl;
use srt_protocol::congestion::live::LiveCC;
use srt_protocol::congestion::token_bucket::TokenBucket;
use srt_protocol::crypto::{CryptoControl, CryptoMode, KeyIndex};
use srt_protocol::fec::ArqMode;
use srt_protocol::fec::decoder::FecDecoder;
use srt_protocol::fec::encoder::FecEncoder;
use srt_protocol::packet::SrtPacket;
use srt_protocol::packet::control::{AckData, ControlType, DropReqData, LossReport};
use srt_protocol::packet::header::{EncryptionKeySpec, HEADER_SIZE, PacketBoundary};
use srt_protocol::packet::msg::MsgNo;
use srt_protocol::packet::seq::SeqNo;
use srt_protocol::protocol::ack::AckState;
use srt_protocol::protocol::connection::ConnectionState;
use srt_protocol::protocol::timer::SrtTimers;
use srt_protocol::protocol::tsbpd::TsbpdTime;
use srt_protocol::stats::SrtStats;
use srt_protocol::window::{AckWindow, PktTimeWindow};

use crate::multiplexer::Multiplexer;

/// Maximum number of new-data packets per send batch.
const SEND_BATCH_SIZE: usize = 64;

// ───────────────────────────── NetEvent ─────────────────────────────

/// Network event delivered from the recv_loop to the connection task.
pub enum NetEvent {
    /// A data packet (or FEC packet when `is_fec` is true).
    Data {
        seq: SeqNo,
        msg_no: MsgNo,
        boundary: PacketBoundary,
        timestamp: u32,
        in_order: bool,
        retransmitted: bool,
        enc_key: EncryptionKeySpec,
        payload: Bytes,
        is_fec: bool,
    },
    /// ACK from the receiver.
    Ack {
        ack_seq_no: u32,
        data: AckData,
    },
    /// NAK (loss report) from the receiver.
    Nak {
        report: LossReport,
    },
    /// ACKACK — RTT measurement round-trip.
    AckAck {
        ack_seq: i32,
    },
    /// DropReq from the sender.
    DropReq {
        msg_id: i32,
        first_seq: SeqNo,
        last_seq: SeqNo,
    },
    /// Keepalive.
    Keepalive,
    /// Peer sent SHUTDOWN.
    Shutdown,
}

// ───────────────────────────── ConnTask ─────────────────────────────

/// Single-owner connection task. Owns all mutable protocol state and
/// drives the SRT connection via an async event loop.
pub struct ConnTask {
    // ── Read-only config ──
    config: SrtConfig,
    start_time: Instant,
    socket_id: u32,
    peer_addr: SocketAddr,
    peer_socket_id: u32,

    // ── Owned mutable state (no Mutex!) ──
    send_buf: SendBuffer,
    recv_buf: ReceiveBuffer,
    ack_state: AckState,
    timers: SrtTimers,
    cc: Box<dyn CongestionControl + Send>,
    tsbpd: TsbpdTime,
    stats: SrtStats,
    send_loss_list: SendLossList,
    recv_loss_list: ReceiveLossList,
    ack_window: AckWindow,
    highest_recv_seq: SeqNo,
    peer_flow_window: u32,
    pkt_time_window: PktTimeWindow,
    crypto: Option<CryptoControl>,
    rexmit_shaper: TokenBucket,
    fec_encoder: Option<FecEncoder>,
    fec_decoder: Option<FecDecoder>,
    fec_arq_mode: ArqMode,
    fec_uncoverable: Vec<SeqNo>,
    tsbpd_calibrated: bool,

    // ── Network I/O ──
    mux: Arc<Multiplexer>,

    // ── Channels ──
    net_rx: mpsc::UnboundedReceiver<NetEvent>,
    app_data_rx: mpsc::Receiver<Bytes>,
    app_recv_tx: mpsc::Sender<Bytes>,
    state_tx: watch::Sender<SocketStatus>,
    stats_tx: watch::Sender<SrtStats>,
    close_signal: Arc<Notify>,

    // ── Send pacing ──
    next_send_deadline: tokio::time::Instant,

    // ── Buffered app data when send_buf is full ──
    pending_app_data: Option<Bytes>,

    // ── Connection active flag ──
    active: bool,
}

impl ConnTask {
    /// Create a new connection task with initial state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: SrtConfig,
        start_time: Instant,
        socket_id: u32,
        peer_addr: SocketAddr,
        peer_socket_id: u32,
        peer_isn: SeqNo,
        own_isn: SeqNo,
        crypto: Option<CryptoControl>,
        fec_encoder: Option<FecEncoder>,
        fec_decoder: Option<FecDecoder>,
        fec_arq_mode: ArqMode,
        tsbpd_base_time: Instant,
        mux: Arc<Multiplexer>,
        net_rx: mpsc::UnboundedReceiver<NetEvent>,
        app_data_rx: mpsc::Receiver<Bytes>,
        app_recv_tx: mpsc::Sender<Bytes>,
        state_tx: watch::Sender<SocketStatus>,
        stats_tx: watch::Sender<SrtStats>,
        close_signal: Arc<Notify>,
    ) -> Self {
        let max_payload = config.max_payload_size();
        let send_buf_pkts = (config.send_buffer_size as usize) / max_payload.max(1);
        let recv_buf_pkts = (config.recv_buffer_size as usize) / max_payload.max(1);
        let latency_ms = config.recv_latency;
        let flow_window = config.flight_flag_size;
        let max_rexmit_bw = config.max_rexmit_bw;
        let mss = config.mss;

        let mut tsbpd = TsbpdTime::new(Duration::from_millis(latency_ms as u64));
        tsbpd.set_base_time(tsbpd_base_time);

        let recv_buf = ReceiveBuffer::new(recv_buf_pkts, peer_isn);
        // recv_buf ISN is already set via peer_isn

        Self {
            config,
            start_time,
            socket_id,
            peer_addr,
            peer_socket_id,
            send_buf: SendBuffer::new(send_buf_pkts, max_payload, own_isn),
            recv_buf,
            ack_state: AckState::new(peer_isn),
            timers: SrtTimers::new(),
            cc: Box::new(LiveCC::new()),
            tsbpd,
            stats: SrtStats::default(),
            send_loss_list: SendLossList::new(),
            recv_loss_list: ReceiveLossList::new(),
            ack_window: AckWindow::new(1024),
            highest_recv_seq: peer_isn,
            peer_flow_window: flow_window,
            pkt_time_window: PktTimeWindow::new(),
            crypto,
            rexmit_shaper: TokenBucket::new(max_rexmit_bw, mss),
            fec_encoder,
            fec_decoder,
            fec_arq_mode,
            fec_uncoverable: Vec::new(),
            tsbpd_calibrated: false,
            mux,
            net_rx,
            app_data_rx,
            app_recv_tx,
            state_tx,
            stats_tx,
            close_signal,
            next_send_deadline: tokio::time::Instant::now(),
            pending_app_data: None,
            active: true,
        }
    }

    /// Compute the current SRT timestamp (microseconds since connection start).
    ///
    /// All SRT control packets (ACK, ACKACK, NAK, Keepalive, DropReq) must
    /// carry the sender's current timestamp so that the peer's TSBPD drift
    /// tracker can estimate clock offset. Without this, the libsrt receiver's
    /// drift tracker accumulates a large negative drift that pushes TSBPD
    /// delivery times into the future, filling the receiver buffer and
    /// throttling throughput.
    fn current_timestamp(&self) -> u32 {
        Instant::now()
            .saturating_duration_since(self.start_time)
            .as_micros() as u32
    }

    /// Run the connection task event loop.
    pub async fn run(mut self) {
        loop {
            if !self.active {
                break;
            }

            // Drain all pending network events (non-blocking) so CC/buffer
            // state is fresh before we try to send.
            while let Ok(event) = self.net_rx.try_recv() {
                self.handle_net_event(event).await;
                if !self.active {
                    break;
                }
            }
            if !self.active {
                break;
            }

            // Try to flush pending app data into send_buf
            self.try_flush_pending_app_data();

            // Send data packets + retransmissions
            self.try_send_data().await;

            // Periodic control (ACK/NAK/keepalive/stats/expiry)
            self.try_periodic_control().await;

            if !self.active {
                break;
            }

            // Deliver any ready messages to the app
            self.try_deliver_messages();

            // Compute next wakeup time
            let has_send_work = self.send_buf.has_unsent()
                || !self.send_loss_list.is_empty();
            let next_wakeup = if has_send_work {
                self.next_send_deadline
            } else {
                tokio::time::Instant::now() + Duration::from_millis(1)
            };

            // Block until next event
            let can_accept_app_data = self.pending_app_data.is_none();
            tokio::select! {
                event = self.net_rx.recv() => {
                    match event {
                        Some(e) => self.handle_net_event(e).await,
                        None => {
                            self.active = false;
                        }
                    }
                }
                data = self.app_data_rx.recv(), if can_accept_app_data => {
                    match data {
                        Some(d) => self.on_app_send(d),
                        None => {
                            // App dropped the sender — initiate close
                            self.graceful_close().await;
                        }
                    }
                }
                _ = tokio::time::sleep_until(next_wakeup) => {
                    // Timer fired — loop back to send + control
                }
                _ = self.close_signal.notified() => {
                    self.graceful_close().await;
                }
            }
        }

        // Cleanup
        self.mux.remove_connection(self.socket_id).await;
    }

    // ─────────────────────── Net Event Handlers ───────────────────────

    async fn handle_net_event(&mut self, event: NetEvent) {
        // Reset idle/expiration timer on any packet from the peer.
        self.timers.on_response_received();

        match event {
            NetEvent::Data {
                seq, msg_no, boundary, timestamp, in_order,
                retransmitted, enc_key, payload, is_fec,
            } => {
                if is_fec {
                    self.on_fec_packet(seq, timestamp, &payload).await;
                } else {
                    self.on_data_packet(
                        seq, msg_no, boundary, timestamp, in_order,
                        retransmitted, enc_key, payload,
                    ).await;
                }
            }
            NetEvent::Ack { ack_seq_no, data } => {
                self.on_ack(ack_seq_no, data).await;
            }
            NetEvent::Nak { report } => {
                self.on_nak(report);
            }
            NetEvent::AckAck { ack_seq } => {
                self.on_ackack(ack_seq);
            }
            NetEvent::DropReq { msg_id, first_seq, last_seq } => {
                self.on_drop_req(msg_id, first_seq, last_seq);
            }
            NetEvent::Keepalive => {
                log::trace!("Keepalive received");
            }
            NetEvent::Shutdown => {
                self.set_state(ConnectionState::Closing);
            }
        }
    }

    fn on_data_packet(
        &mut self,
        seq: SeqNo,
        msg_no: MsgNo,
        boundary: PacketBoundary,
        timestamp: u32,
        in_order: bool,
        retransmitted: bool,
        enc_key: EncryptionKeySpec,
        raw_payload: Bytes,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            // Calibrate TSBPD base_time on the first data packet.
            if !self.tsbpd_calibrated {
                let ts_duration = Duration::from_micros(timestamp as u64);
                let now = Instant::now();
                let new_base = now.checked_sub(ts_duration).unwrap_or(now);
                self.tsbpd.set_base_time(new_base);
                self.tsbpd_calibrated = true;
                log::debug!("TSBPD calibrated: first packet ts={}us", timestamp);
            }

            // Decrypt payload
            let data = self.decrypt_payload(enc_key, &raw_payload, seq.value() as u32);

            // Gap detection and loss list update
            self.update_loss_tracking(seq);

            // Record packet arrival for bandwidth estimation
            self.pkt_time_window.on_pkt_arrival();

            // Insert into receive buffer
            self.recv_buf.insert(seq, msg_no, boundary, timestamp, in_order, data.clone());
            self.recv_buf.update_highest_recv(seq);

            // Feed CIPHERTEXT to FEC decoder
            if let Some(decoder) = self.fec_decoder.as_mut() {
                let recovered = decoder.on_data_packet(seq, timestamp, enc_key as u8, &raw_payload);
                for pkt in recovered {
                    self.inject_recovered_packet(pkt);
                }
            }

            // Update statistics
            self.stats.pkt_recv_total += 1;
            self.stats.byte_recv_total += raw_payload.len() as u64;
            if retransmitted {
                self.stats.pkt_rcv_retrans += 1;
                self.stats.pkt_rcv_retrans_total += 1;
            }

            // Deliver ready messages
            self.try_deliver_messages();
        })
    }

    async fn on_fec_packet(&mut self, seq: SeqNo, timestamp: u32, fec_payload: &Bytes) {
        // Insert FEC placeholder
        self.recv_buf.insert_fec_placeholder(seq, timestamp);
        self.recv_buf.update_highest_recv(seq);

        // Gap tracking
        let mut gap_loss: i32 = 0;
        if seq.is_after(self.highest_recv_seq) {
            let expected = self.highest_recv_seq.increment();
            if seq.is_after(expected) {
                let gap_end = seq.add(-1);
                gap_loss = SeqNo::offset(expected, gap_end) + 1;
                self.recv_loss_list.insert_range(expected, gap_end);
            }
            self.highest_recv_seq = seq;
        } else {
            self.recv_loss_list.remove(seq);
        }

        // Stats
        self.stats.pkt_rcv_filter_extra += 1;
        self.stats.pkt_rcv_filter_extra_total += 1;
        if gap_loss > 0 {
            self.stats.pkt_rcv_loss += gap_loss;
            self.stats.pkt_rcv_loss_total += gap_loss;
        }

        // Feed to FEC decoder
        if let Some(decoder) = self.fec_decoder.as_mut() {
            let result = decoder.on_fec_packet(seq, fec_payload);

            for pkt in result.recovered {
                self.inject_recovered_packet(pkt);
            }

            if !result.uncoverable.is_empty() {
                self.fec_uncoverable.extend(result.uncoverable);
            }
        }
    }

    fn inject_recovered_packet(&mut self, pkt: srt_protocol::fec::decoder::RecoveredPacket) {
        // Decrypt the recovered payload if needed
        let data = self.decrypt_payload(
            EncryptionKeySpec::from_bits(pkt.enc_flags as u32),
            &Bytes::copy_from_slice(&pkt.payload),
            pkt.seq_no.value() as u32,
        );

        // Insert into receive buffer
        self.recv_buf.insert(
            pkt.seq_no,
            MsgNo::new(1),
            PacketBoundary::Solo,
            pkt.timestamp,
            true,
            data,
        );

        // Remove from loss list
        self.recv_loss_list.remove(pkt.seq_no);

        // Stats
        self.stats.pkt_rcv_filter_supply += 1;
        self.stats.pkt_rcv_filter_supply_total += 1;

        // Deliver ready messages
        self.try_deliver_messages();
    }

    async fn on_ack(&mut self, ack_seq_no: u32, ack_data: AckData) {
        // Free acknowledged packets from send buffer
        let removed = self.send_buf.acknowledge(ack_data.ack_seq);
        if removed > 0 {
            // Try to flush pending app data now that buffer has space
            self.try_flush_pending_app_data();
        }

        // Clear obsolete entries from send loss list
        self.send_loss_list.acknowledge(ack_data.ack_seq);

        // Update peer's flow window
        if let Some(fw) = ack_data.available_buf_size {
            self.peer_flow_window = fw as u32;
        }

        // Notify congestion control
        let rtt_us = ack_data.rtt.unwrap_or(self.timers.srtt);
        self.cc.on_ack(ack_data.ack_seq, rtt_us);

        // Update bandwidth estimate
        if let Some(bw) = ack_data.bandwidth {
            self.cc.set_bandwidth(bw);
        }

        // Stats
        self.stats.pkt_recv_ack += 1;
        self.stats.pkt_recv_ack_total += 1;

        // Send ACKACK
        let ackack = SrtPacket::new_control(
            ControlType::AckAck,
            0,
            ack_seq_no,
            self.current_timestamp(),
            self.peer_socket_id,
            Bytes::new(),
        );
        let mut buf = BytesMut::with_capacity(HEADER_SIZE);
        ackack.serialize(&mut buf);
        let _ = self.mux.send_to(&buf, self.peer_addr).await;
    }

    fn on_nak(&mut self, report: LossReport) {
        let total_losses = report.total_losses();

        // Populate send-side loss list
        for (first, last) in &report.losses {
            if first == last {
                self.send_loss_list.insert(*first);
            } else {
                self.send_loss_list.insert_range(*first, *last);
            }
        }

        // Notify CC
        self.cc.on_loss(&report.losses);

        // Stats
        self.stats.pkt_recv_nak += 1;
        self.stats.pkt_recv_nak_total += 1;
        self.stats.pkt_snd_loss += total_losses;
        self.stats.pkt_snd_loss_total += total_losses;

        log::trace!("NAK received: {} lost packets reported", total_losses);
    }

    fn on_ackack(&mut self, ack_seq: i32) {
        let rtt = self.ack_window.acknowledge(ack_seq);
        if let Some(rtt_duration) = rtt {
            let rtt_us = rtt_duration.as_micros() as i32;
            self.timers.update_rtt(rtt_us);
            log::trace!("ACKACK: RTT sample = {}us", rtt_us);
        }
    }

    fn on_drop_req(&mut self, msg_id: i32, first_seq: SeqNo, last_seq: SeqNo) {
        let dropped = self.recv_buf.drop_range(first_seq, last_seq);

        // Clear from loss list
        let count = SeqNo::offset(first_seq, last_seq) + 1;
        for i in 0..count {
            self.recv_loss_list.remove(first_seq.add(i));
        }

        if dropped > 0 {
            let drop_bytes = dropped as u64 * self.config.max_payload_size() as u64;
            self.stats.pkt_rcv_drop += dropped as i32;
            self.stats.pkt_rcv_drop_total += dropped as i32;
            self.stats.byte_rcv_drop += drop_bytes;
            self.stats.byte_rcv_drop_total += drop_bytes;
        }

        log::trace!(
            "DropReq: msg_id={}, seq {}..{}, dropped {} packets",
            msg_id, first_seq.value(), last_seq.value(), dropped
        );
    }

    // ─────────────────────── Loss Tracking ───────────────────────

    fn update_loss_tracking(&mut self, seq: SeqNo) {
        let reorder_tolerance = self.config.loss_max_ttl;

        if seq.is_after(self.highest_recv_seq) {
            let expected = self.highest_recv_seq.increment();
            if seq.is_after(expected) {
                let gap_end = seq.add(-1);
                let gap_count = SeqNo::offset(expected, gap_end) + 1;

                if reorder_tolerance > 0 {
                    let threshold = seq.add(-(reorder_tolerance as i32));
                    let mut loss_count = 0i32;
                    let count = SeqNo::offset(expected, gap_end);
                    for i in 0..=count {
                        let gap_seq = expected.add(i);
                        if gap_seq.is_before(threshold) || gap_seq == threshold {
                            self.recv_loss_list.insert_range(gap_seq, gap_seq);
                            loss_count += 1;
                        }
                    }
                    if loss_count > 0 {
                        self.stats.pkt_rcv_loss += loss_count;
                        self.stats.pkt_rcv_loss_total += loss_count;
                    }
                } else {
                    self.recv_loss_list.insert_range(expected, gap_end);
                    self.stats.pkt_rcv_loss += gap_count;
                    self.stats.pkt_rcv_loss_total += gap_count;
                }

                log::trace!(
                    "Gap detected: expected={}, got={}, missing {} packets",
                    expected.value(), seq.value(), gap_count
                );
            }

            // Promote deferred gaps
            if reorder_tolerance > 0 {
                let new_threshold = seq.add(-(reorder_tolerance as i32));
                let old_highest = self.highest_recv_seq;
                let old_threshold = old_highest.add(-(reorder_tolerance as i32));
                if new_threshold.is_after(old_threshold) {
                    let promote_count = SeqNo::offset(old_threshold, new_threshold);
                    let mut promoted = 0i32;
                    for i in 1..=promote_count {
                        let check_seq = old_threshold.add(i);
                        if !self.recv_buf.has_packet(check_seq) {
                            self.recv_loss_list.insert_range(check_seq, check_seq);
                            promoted += 1;
                        }
                    }
                    if promoted > 0 {
                        self.stats.pkt_rcv_loss += promoted;
                        self.stats.pkt_rcv_loss_total += promoted;
                    }
                }
            }

            self.highest_recv_seq = seq;
        } else {
            // Out-of-order or retransmitted — remove from loss list
            self.recv_loss_list.remove(seq);
        }
    }

    // ─────────────────────── App Data ───────────────────────

    fn on_app_send(&mut self, data: Bytes) {
        if self.send_buf.add_message(&data, -1, false).is_some() {
            // Added successfully
        } else {
            // Send buffer full — buffer for later
            self.pending_app_data = Some(data);
        }
    }

    fn try_flush_pending_app_data(&mut self) {
        if let Some(data) = self.pending_app_data.take() {
            if self.send_buf.add_message(&data, -1, false).is_none() {
                // Still full
                self.pending_app_data = Some(data);
            }
        }
    }

    fn try_deliver_messages(&mut self) {
        while let Some(data) = self.recv_buf.read_message(None) {
            if self.app_recv_tx.try_send(data).is_err() {
                // App channel full — stop delivering
                break;
            }
        }
    }

    // ─────────────────────── Sending ───────────────────────

    async fn try_send_data(&mut self) {
        let now = tokio::time::Instant::now();
        if now < self.next_send_deadline {
            return;
        }

        let send_period_us = self.cc.pkt_send_period_us();

        // Priority 1: Retransmissions
        let retransmitted = self.send_retransmissions().await;

        // Priority 2: New data
        let has_data = self.send_buf.has_unsent();
        if !has_data && !retransmitted {
            return;
        }

        let mut batch_sent: usize = 0;
        if has_data {
            let in_flight = self.send_buf.in_flight();
            let cwnd = self.cc.congestion_window() as usize;
            let flow_window = self.peer_flow_window as usize;
            let effective_window = cwnd.min(flow_window);

            if in_flight < effective_window {
                let window_budget = effective_window.saturating_sub(in_flight);
                let target_batch = window_budget.min(SEND_BATCH_SIZE).max(1);

                // Drain entries from send buffer
                let mut entries = Vec::with_capacity(target_batch);
                for _ in 0..target_batch {
                    match self.send_buf.next_packet() {
                        Some(e) => entries.push(e),
                        None => break,
                    }
                }

                if !entries.is_empty() {
                    // Encrypt payloads
                    let encrypted = self.encrypt_payloads_batch(&entries);

                    // Serialize packets
                    let start_time = self.start_time;
                    let dest_socket_id = self.peer_socket_id;
                    let mut serialised: Vec<(BytesMut, EncryptionKeySpec, u32, Bytes, usize)> =
                        Vec::with_capacity(entries.len());
                    for (entry, (payload, enc_key)) in entries.iter().zip(encrypted.into_iter()) {
                        let timestamp = entry.origin_time
                            .saturating_duration_since(start_time)
                            .as_micros() as u32;
                        let payload_for_fec = payload.clone();
                        let pkt = SrtPacket::new_data(
                            entry.seq_no, entry.msg_no, entry.boundary,
                            entry.in_order, enc_key, false, timestamp,
                            dest_socket_id, payload,
                        );
                        let payload_len = pkt.payload_len();
                        let mut buf = BytesMut::with_capacity(pkt.wire_size());
                        pkt.serialize(&mut buf);
                        serialised.push((buf, enc_key, timestamp, payload_for_fec, payload_len));
                    }

                    // Send packets
                    let peer_addr = self.peer_addr;
                    let mut sent_bytes: u64 = 0;
                    for (buf, _, _, _, payload_len) in &serialised {
                        match self.mux.send_to(buf, peer_addr).await {
                            Ok(_) => {
                                batch_sent += 1;
                                sent_bytes += *payload_len as u64;
                            }
                            Err(e) => {
                                log::error!("Send error: {}", e);
                                if is_fatal_error(&e) {
                                    self.active = false;
                                    return;
                                }
                                break;
                            }
                        }
                    }

                    // Stats
                    if batch_sent > 0 {
                        self.stats.pkt_sent_total += batch_sent as i64;
                        self.stats.byte_sent_total += sent_bytes;
                    }

                    // FEC
                    if batch_sent > 0 {
                        if let Some(encoder) = self.fec_encoder.as_mut() {
                            let mut fec_extra: Vec<BytesMut> = Vec::new();
                            for (entry, ser) in entries.iter().zip(serialised.iter()).take(batch_sent) {
                                let (_buf, enc_key, timestamp, fec_payload, _len) = ser;
                                let fec_packets = encoder.on_data_packet(
                                    entry.seq_no, *timestamp, *enc_key as u8, fec_payload,
                                );
                                for fec_pkt in fec_packets {
                                    let fec_srt = SrtPacket::new_fec_data(
                                        fec_pkt.seq_no, fec_pkt.timestamp,
                                        dest_socket_id, fec_pkt.payload,
                                    );
                                    let mut fec_buf = BytesMut::with_capacity(fec_srt.wire_size());
                                    fec_srt.serialize(&mut fec_buf);
                                    fec_extra.push(fec_buf);
                                }
                            }
                            for fec_buf in &fec_extra {
                                if let Err(e) = self.mux.send_to(fec_buf, peer_addr).await {
                                    log::error!("FEC send error: {}", e);
                                } else {
                                    self.stats.pkt_snd_filter_extra += 1;
                                    self.stats.pkt_snd_filter_extra_total += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Pacing
        let still_has_losses = !self.send_loss_list.is_empty();
        if !still_has_losses && send_period_us > 0.0 && batch_sent > 0 {
            let now = tokio::time::Instant::now();
            let starvation_floor = now - Duration::from_millis(1);
            if self.next_send_deadline < starvation_floor {
                self.next_send_deadline = now;
            }
            let batch_period_us = (send_period_us * batch_sent as f64) as u64;
            self.next_send_deadline += Duration::from_micros(batch_period_us);
        }
    }

    async fn send_retransmissions(&mut self) -> bool {
        let mut seqs_to_retransmit: Vec<SeqNo> = Vec::new();
        while let Some(seq) = self.send_loss_list.pop_front() {
            seqs_to_retransmit.push(seq);
        }
        if seqs_to_retransmit.is_empty() {
            return false;
        }

        let peer_addr = self.peer_addr;
        let dest_socket_id = self.peer_socket_id;
        let mut sent_any = false;
        let mut deferred: Vec<SeqNo> = Vec::new();

        for seq in seqs_to_retransmit {
            let entry = self.send_buf.get_packet_for_retransmit(seq);
            if let Some(entry) = entry {
                // Token bucket rate limit
                let wire_size = entry.data.len() + HEADER_SIZE;
                if !self.rexmit_shaper.try_consume(wire_size) {
                    deferred.push(seq);
                    continue;
                }

                let timestamp = entry.origin_time
                    .saturating_duration_since(self.start_time)
                    .as_micros() as u32;

                let (payload, enc_key) = self.encrypt_payload(entry.data, entry.seq_no.value() as u32);

                let pkt = SrtPacket::new_data(
                    entry.seq_no, entry.msg_no, entry.boundary,
                    entry.in_order, enc_key, true, timestamp,
                    dest_socket_id, payload,
                );
                let mut buf = BytesMut::with_capacity(pkt.wire_size());
                pkt.serialize(&mut buf);

                if let Err(e) = self.mux.send_to(&buf, peer_addr).await {
                    log::error!("Retransmit send error: {}", e);
                } else {
                    self.stats.pkt_retrans += 1;
                    self.stats.pkt_retrans_total += 1;
                    self.stats.pkt_sent_total += 1;
                    self.stats.byte_retrans_total += pkt.payload_len() as u64;
                    self.stats.byte_sent_total += pkt.payload_len() as u64;
                    sent_any = true;
                }
            } else {
                log::trace!("Retransmit: seq {} not in send buffer", seq.value());
            }
        }

        // Re-insert deferred packets
        for seq in deferred {
            self.send_loss_list.insert(seq);
        }

        sent_any
    }

    // ─────────────────────── Periodic Control ───────────────────────

    async fn try_periodic_control(&mut self) {
        let peer_addr = self.peer_addr;
        let dest_socket_id = self.peer_socket_id;

        // Keepalive
        if self.timers.keepalive.check() {
            let keepalive = SrtPacket::new_control(
                ControlType::Keepalive, 0, 0, self.current_timestamp(),
                dest_socket_id, Bytes::new(),
            );
            let mut buf = BytesMut::with_capacity(HEADER_SIZE);
            keepalive.serialize(&mut buf);
            let _ = self.mux.send_to(&buf, peer_addr).await;
        }

        // Update stats snapshot
        self.update_stats_snapshot();

        // ACK timer
        if self.timers.ack.check() {
            let ack_seq = self.recv_buf.ack_seq();
            let ack_number = self.ack_state.next_ack_seq_no();
            self.ack_state.update_ack(ack_seq);
            self.ack_state.update_data_ack(ack_seq);
            self.ack_state.ack_sent();

            self.ack_window.store(ack_number);

            let bandwidth = self.pkt_time_window.bandwidth();
            let recv_rate = self.pkt_time_window.recv_speed();

            let ack_data = AckData {
                ack_seq,
                rtt: Some(self.timers.srtt),
                rtt_var: Some(self.timers.rttvar),
                available_buf_size: Some(self.recv_buf.available() as i32),
                recv_speed_pkts: None,
                bandwidth,
                recv_rate,
            };
            let mut payload = BytesMut::with_capacity(AckData::FULL_SIZE);
            ack_data.serialize(&mut payload);

            let ack_pkt = SrtPacket::new_control(
                ControlType::Ack, 0, ack_number as u32, self.current_timestamp(),
                dest_socket_id, payload.freeze(),
            );
            let mut buf = BytesMut::with_capacity(HEADER_SIZE + AckData::FULL_SIZE);
            ack_pkt.serialize(&mut buf);
            let _ = self.mux.send_to(&buf, peer_addr).await;

            self.stats.pkt_sent_ack += 1;
            self.stats.pkt_sent_ack_total += 1;
        }

        // NAK timer
        let should_send_nak = !matches!(self.fec_arq_mode, ArqMode::Never);
        if should_send_nak && self.timers.nak.check() {
            let suppression_interval = self.timers.nak_suppression_interval();
            let loss_ranges = self.recv_loss_list.get_loss_ranges(suppression_interval);
            if !loss_ranges.is_empty() {
                let loss_report = LossReport { losses: loss_ranges };
                let mut payload = BytesMut::with_capacity(loss_report.losses.len() * 8);
                loss_report.serialize(&mut payload);

                let nak_pkt = SrtPacket::new_control(
                    ControlType::Nak, 0, 0, self.current_timestamp(),
                    dest_socket_id, payload.freeze(),
                );
                let mut buf = BytesMut::with_capacity(HEADER_SIZE + nak_pkt.payload_len());
                nak_pkt.serialize(&mut buf);
                let _ = self.mux.send_to(&buf, peer_addr).await;

                self.stats.pkt_sent_nak += 1;
                self.stats.pkt_sent_nak_total += 1;
            }
        }

        // Sender-side too-late-to-send drop
        {
            let dropped_msgs = self.send_buf.drop_expired_with_info();
            if !dropped_msgs.is_empty() {
                let total_dropped = dropped_msgs.len();
                for (msg_id, first_seq, last_seq) in &dropped_msgs {
                    let drop_req = DropReqData {
                        msg_id: *msg_id,
                        first_seq: *first_seq,
                        last_seq: *last_seq,
                    };
                    let mut payload = BytesMut::with_capacity(8);
                    drop_req.serialize(&mut payload);
                    let drop_pkt = SrtPacket::new_control(
                        ControlType::DropReq, 0, *msg_id as u32, self.current_timestamp(),
                        dest_socket_id, payload.freeze(),
                    );
                    let mut buf = BytesMut::with_capacity(HEADER_SIZE + 8);
                    drop_pkt.serialize(&mut buf);
                    let _ = self.mux.send_to(&buf, peer_addr).await;
                }
                let drop_bytes = total_dropped as u64 * self.config.max_payload_size() as u64;
                self.stats.pkt_snd_drop += total_dropped as i32;
                self.stats.pkt_snd_drop_total += total_dropped as i32;
                self.stats.byte_snd_drop += drop_bytes;
                self.stats.byte_snd_drop_total += drop_bytes;
                log::trace!("Sender dropped {} expired messages", total_dropped);
            }
        }

        // Receiver-side too-late-to-play drop
        {
            let dropped = self.recv_buf.drop_too_late(&self.tsbpd);
            if dropped > 0 {
                let ack = self.recv_buf.ack_seq();
                self.recv_loss_list.acknowledge(ack);
                let drop_bytes = dropped as u64 * self.config.max_payload_size() as u64;
                self.stats.pkt_rcv_drop += dropped as i32;
                self.stats.pkt_rcv_drop_total += dropped as i32;
                self.stats.byte_rcv_drop += drop_bytes;
                self.stats.byte_rcv_drop_total += drop_bytes;
                log::trace!("Dropped {} too-late packets", dropped);
            }
        }

        // Expiration timer
        let exp_interval = self.timers.exp_interval();
        if self.timers.last_response.elapsed() >= exp_interval {
            self.timers.exp_count += 1;
            if self.timers.is_expired() {
                log::warn!("Connection {} timed out (exp_count={})", self.socket_id, self.timers.exp_count);
                self.send_shutdown_and_break().await;
                return;
            }
        }

        // Peer idle timeout
        let idle_timeout = self.config.peer_idle_timeout;
        if !idle_timeout.is_zero() && self.timers.last_response.elapsed() >= idle_timeout {
            log::warn!("Connection {} peer idle timeout ({:?})", self.socket_id, idle_timeout);
            self.send_shutdown_and_break().await;
        }

        // Publish stats via watch channel
        let _ = self.stats_tx.send(self.stats.clone());
    }

    fn update_stats_snapshot(&mut self) {
        let max_payload = self.config.max_payload_size().max(1);
        let recv_buf_len = self.recv_buf.len();
        let recv_buf_avail = self.recv_buf.available();
        let elapsed_secs = self.timers.connection_start.elapsed().as_secs_f64();

        self.stats.ms_rtt = self.timers.srtt as f64 / 1000.0;
        self.stats.ms_timestamp = self.timers.connection_start.elapsed().as_millis() as i64;
        self.stats.us_pkt_snd_period = self.cc.pkt_send_period_us();
        self.stats.pkt_flow_window = self.peer_flow_window as i32;
        self.stats.pkt_congestion_window = self.cc.congestion_window() as i32;
        self.stats.pkt_flight_size = self.send_buf.in_flight() as i32;

        let bw_pkts = self.cc.bandwidth();
        if bw_pkts > 0 {
            self.stats.mbps_bandwidth = bw_pkts as f64 * max_payload as f64 * 8.0 / 1_000_000.0;
        }

        if elapsed_secs > 0.0 {
            self.stats.mbps_send_rate = self.stats.byte_sent_total as f64 * 8.0 / (elapsed_secs * 1_000_000.0);
            self.stats.mbps_recv_rate = self.stats.byte_recv_total as f64 * 8.0 / (elapsed_secs * 1_000_000.0);
        }

        self.stats.byte_avail_snd_buf = ((self.send_buf.max_packets() - self.send_buf.len()) * max_payload) as i32;
        self.stats.byte_avail_rcv_buf = (recv_buf_avail * max_payload) as i32;
        self.stats.pkt_snd_buf = self.send_buf.len() as i32;
        self.stats.byte_snd_buf = (self.send_buf.len() * max_payload) as i32;
        self.stats.pkt_rcv_buf = recv_buf_len as i32;
        self.stats.byte_rcv_buf = (recv_buf_len * max_payload) as i32;
        self.stats.ms_rcv_tsbpd_delay = self.tsbpd.delay().as_millis() as i32;
        self.stats.ms_snd_tsbpd_delay = self.config.peer_latency as i32;
        self.stats.mbps_max_bw = self.config.max_bw as f64 * 8.0 / 1_000_000.0;
        self.stats.byte_mss = self.config.mss as i32;
    }

    // ─────────────────────── Crypto ───────────────────────

    fn decrypt_payload(&self, enc_key: EncryptionKeySpec, raw_payload: &Bytes, pkt_index: u32) -> Bytes {
        if enc_key == EncryptionKeySpec::NoEnc {
            return Bytes::copy_from_slice(raw_payload);
        }

        let key_index = match KeyIndex::from_enc_key_spec(enc_key) {
            Some(ki) => ki,
            None => return Bytes::copy_from_slice(raw_payload),
        };

        let crypto = match self.crypto.as_ref() {
            Some(c) => c,
            None => return Bytes::copy_from_slice(raw_payload),
        };

        let key = match crypto.keys.key(key_index) {
            Some(k) => k.to_vec(),
            None => return Bytes::copy_from_slice(raw_payload),
        };
        let salt = crypto.salt;
        let mode = crypto.mode;

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
            }
        }

        Bytes::copy_from_slice(raw_payload)
    }

    fn encrypt_payload(&mut self, payload: Bytes, pkt_index: u32) -> (Bytes, EncryptionKeySpec) {
        let crypto = match self.crypto.as_mut() {
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
                    if let Ok(ct) = cipher.encrypt(&salt, pkt_index, &payload) {
                        return (Bytes::from(ct), enc_spec);
                    }
                }
                (payload, EncryptionKeySpec::NoEnc)
            }
        }
    }

    fn encrypt_payloads_batch(
        &mut self,
        entries: &[srt_protocol::buffer::send::SendBufferEntry],
    ) -> Vec<(Bytes, EncryptionKeySpec)> {
        let crypto = match self.crypto.as_mut() {
            Some(c) => c,
            None => {
                return entries.iter()
                    .map(|e| (e.data.clone(), EncryptionKeySpec::NoEnc))
                    .collect();
            }
        };

        let key = match crypto.keys.active_key() {
            Some(k) => k.to_vec(),
            None => {
                return entries.iter()
                    .map(|e| (e.data.clone(), EncryptionKeySpec::NoEnc))
                    .collect();
            }
        };
        let enc_spec = crypto.keys.active.to_enc_key_spec();
        let salt = crypto.salt;

        let mut out = Vec::with_capacity(entries.len());
        match crypto.mode {
            CryptoMode::AesCtr => {
                use srt_protocol::crypto::aes_ctr::AesCtrCipher;
                if let Some(cipher) = AesCtrCipher::new(&key) {
                    for entry in entries {
                        let pkt_index = entry.seq_no.value() as u32;
                        let mut data = entry.data.to_vec();
                        if cipher.encrypt(&salt, pkt_index, &mut data).is_ok() {
                            out.push((Bytes::from(data), enc_spec));
                        } else {
                            out.push((entry.data.clone(), EncryptionKeySpec::NoEnc));
                        }
                        crypto.on_packet_sent();
                    }
                } else {
                    for entry in entries {
                        out.push((entry.data.clone(), EncryptionKeySpec::NoEnc));
                    }
                }
            }
            CryptoMode::AesGcm => {
                use srt_protocol::crypto::aes_gcm::AesGcmCipher;
                if let Some(cipher) = AesGcmCipher::new(&key) {
                    for entry in entries {
                        let pkt_index = entry.seq_no.value() as u32;
                        match cipher.encrypt(&salt, pkt_index, &entry.data) {
                            Ok(ct) => out.push((Bytes::from(ct), enc_spec)),
                            Err(_) => out.push((entry.data.clone(), EncryptionKeySpec::NoEnc)),
                        }
                        crypto.on_packet_sent();
                    }
                } else {
                    for entry in entries {
                        out.push((entry.data.clone(), EncryptionKeySpec::NoEnc));
                    }
                }
            }
        }
        out
    }

    // ─────────────────────── State Management ───────────────────────

    fn set_state(&mut self, state: ConnectionState) {
        let _ = self.state_tx.send(state.to_socket_status());
        if !state.is_active() {
            self.active = false;
        }
    }

    async fn graceful_close(&mut self) {
        self.set_state(ConnectionState::Closing);

        // Send SHUTDOWN
        let shutdown = SrtPacket::new_control(
            ControlType::Shutdown, 0, 0, 0,
            self.peer_socket_id, Bytes::new(),
        );
        let mut buf = BytesMut::with_capacity(HEADER_SIZE);
        shutdown.serialize(&mut buf);
        let _ = self.mux.send_to(&buf, self.peer_addr).await;

        // Brief drain period
        if let Some(linger) = self.config.linger {
            if !linger.is_zero() {
                tokio::time::sleep(linger.min(Duration::from_secs(1))).await;
            }
        }

        self.set_state(ConnectionState::Closed);
    }

    async fn send_shutdown_and_break(&mut self) {
        let shutdown = SrtPacket::new_control(
            ControlType::Shutdown, 0, 0, 0,
            self.peer_socket_id, Bytes::new(),
        );
        let mut buf = BytesMut::with_capacity(HEADER_SIZE);
        shutdown.serialize(&mut buf);
        let _ = self.mux.send_to(&buf, self.peer_addr).await;
        self.set_state(ConnectionState::Broken);
    }
}

fn is_fatal_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(e.kind(), ErrorKind::NotConnected | ErrorKind::BrokenPipe)
}
