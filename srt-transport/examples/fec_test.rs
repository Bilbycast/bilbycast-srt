// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! FEC loopback test — sends video data through SRT+FEC and measures RTT/throughput.
//!
//! Single process: spawns listener and caller, streams real video file through
//! the SRT+FEC path, and verifies RTT stays healthy (no congestion collapse).
//!
//! Usage:
//!   cargo run --release --example fec_test -p srt-transport -- <video_file> [output_file]

use srt_transport::{SrtListener, SrtSocket};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

const PORT: u16 = 4210;
const FEC_CONFIG: &str = "fec,cols:10,rows:5,layout:staircase,arq:onreq";
const PAYLOAD_SIZE: u32 = 1452; // 1456 - 4 bytes FEC overhead

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let video_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: fec_test <video_file> [output_file]");
        std::process::exit(1);
    });
    let output_path = std::env::args().nth(2).unwrap_or_else(|| "/tmp/fec_test_output.ts".to_string());

    let video_data = std::fs::read(&video_path)?;
    println!("Loaded {} ({} bytes)", video_path, video_data.len());

    let done = Arc::new(AtomicBool::new(false));
    let recv_bytes = Arc::new(AtomicU64::new(0));
    let recv_pkts = Arc::new(AtomicU64::new(0));
    let sender_done = Arc::new(Notify::new());

    // Start listener
    let mut listener = SrtListener::builder()
        .latency(Duration::from_millis(120))
        .payload_size(PAYLOAD_SIZE)
        .packet_filter(FEC_CONFIG.to_string())
        .live_mode()
        .bind(format!("127.0.0.1:{PORT}").parse()?)
        .await?;

    println!("SRT+FEC listener on 127.0.0.1:{PORT}");
    println!("FEC config: {FEC_CONFIG}");

    // Spawn receiver task
    let done_r = done.clone();
    let recv_bytes_r = recv_bytes.clone();
    let recv_pkts_r = recv_pkts.clone();
    let sender_done_r = sender_done.clone();
    let output = output_path.clone();
    let recv_handle = tokio::spawn(async move {
        let socket = listener.accept().await.unwrap();
        println!("Receiver: caller connected");

        let mut file = std::fs::File::create(&output).unwrap();
        let start = Instant::now();
        let mut last_stats = Instant::now();
        let mut max_rtt: f64 = 0.0;
        let mut min_cwnd: i32 = i32::MAX;

        loop {
            match tokio::time::timeout(Duration::from_secs(3), socket.recv()).await {
                Ok(Ok(data)) => {
                    recv_bytes_r.fetch_add(data.len() as u64, Ordering::Relaxed);
                    recv_pkts_r.fetch_add(1, Ordering::Relaxed);
                    file.write_all(&data).unwrap();

                    if last_stats.elapsed() >= Duration::from_secs(2) {
                        let stats = socket.stats().await;
                        let elapsed = start.elapsed().as_secs_f64();
                        let total = recv_bytes_r.load(Ordering::Relaxed);
                        let pkts = recv_pkts_r.load(Ordering::Relaxed);
                        let mbps = total as f64 * 8.0 / elapsed / 1_000_000.0;
                        if stats.ms_rtt > max_rtt { max_rtt = stats.ms_rtt; }
                        if stats.pkt_congestion_window < min_cwnd { min_cwnd = stats.pkt_congestion_window; }
                        println!(
                            "  [{:.1}s] pkts={} bytes={} rate={:.2}Mbps RTT={:.1}ms maxRTT={:.1}ms cwnd={} flight={} fec_recv={} drops={}",
                            elapsed, pkts, total, mbps,
                            stats.ms_rtt, max_rtt,
                            stats.pkt_congestion_window, stats.pkt_flight_size,
                            stats.pkt_rcv_filter_supply_total, stats.pkt_rcv_drop_total,
                        );
                        last_stats = Instant::now();
                    }
                }
                Ok(Err(e)) => {
                    println!("Receiver: connection ended: {e:?}");
                    break;
                }
                Err(_) => {
                    if done_r.load(Ordering::Relaxed) {
                        println!("Receiver: timeout after sender done, ending");
                        break;
                    }
                }
            }
        }

        let stats = socket.stats().await;
        let elapsed = start.elapsed().as_secs_f64();
        let total = recv_bytes_r.load(Ordering::Relaxed);
        let pkts = recv_pkts_r.load(Ordering::Relaxed);

        println!("\n=== FINAL RESULTS ===");
        println!("Duration:      {:.1}s", elapsed);
        println!("Packets:       {}", pkts);
        println!("Bytes:         {}", total);
        println!("Avg rate:      {:.2} Mbps", total as f64 * 8.0 / elapsed / 1_000_000.0);
        println!("Final RTT:     {:.1} ms", stats.ms_rtt);
        println!("Max RTT:       {:.1} ms", max_rtt);
        println!("Min Cwnd:      {}", min_cwnd);
        println!("FEC recovered: {}", stats.pkt_rcv_filter_supply_total);
        println!("FEC loss:      {}", stats.pkt_rcv_filter_loss_total);
        println!("Recv drops:    {}", stats.pkt_rcv_drop_total);
        println!("Recv losses:   {}", stats.pkt_rcv_loss_total);
        println!("Output:        {}", output);

        let _ = socket.close().await;
        let _ = listener.close().await;
        sender_done_r.notify_one();

        (max_rtt, min_cwnd)
    });

    // Give listener time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect caller with FEC
    let socket = SrtSocket::builder()
        .latency(Duration::from_millis(120))
        .payload_size(PAYLOAD_SIZE)
        .packet_filter(FEC_CONFIG.to_string())
        .live_mode()
        .connect(format!("127.0.0.1:{PORT}").parse()?)
        .await?;

    println!("Sender: connected");

    // Send video data in MPEG-TS sized chunks (1316 bytes = 7 x 188)
    let chunk_size = 1316;
    let mut sent: u64 = 0;
    let start = Instant::now();

    for chunk in video_data.chunks(chunk_size) {
        socket.send(chunk).await?;
        sent += chunk.len() as u64;

        // Pace at ~6 Mbps (real-time broadcast rate)
        let target_time = Duration::from_secs_f64(sent as f64 * 8.0 / 6_000_000.0);
        let elapsed = start.elapsed();
        if elapsed < target_time {
            tokio::time::sleep(target_time - elapsed).await;
        }
    }

    println!("Sender: finished sending {} bytes in {:.1}s", sent, start.elapsed().as_secs_f64());
    done.store(true, Ordering::Relaxed);

    // Wait for receiver to finish
    let _ = tokio::time::timeout(Duration::from_secs(5), sender_done.notified()).await;
    let _ = socket.close().await;

    let (max_rtt, min_cwnd) = recv_handle.await?;

    // Verify output
    let output_size = std::fs::metadata(&output_path)?.len();
    let recv_total = recv_bytes.load(Ordering::Relaxed);

    println!("\n=== VERIFICATION ===");
    println!("Sent:     {} bytes", sent);
    println!("Received: {} bytes", recv_total);
    println!("Output:   {} bytes", output_size);

    if max_rtt > 100.0 {
        println!("\nFAIL: Max RTT {:.1}ms exceeds 100ms — congestion collapse detected!", max_rtt);
        std::process::exit(1);
    }
    if min_cwnd < 2 {
        println!("\nFAIL: Min cwnd {} — congestion window collapsed!", min_cwnd);
        std::process::exit(1);
    }
    if recv_total == 0 {
        println!("\nFAIL: No data received!");
        std::process::exit(1);
    }

    let loss_pct = (1.0 - recv_total as f64 / sent as f64) * 100.0;
    println!("Loss:     {:.1}%", loss_pct);

    println!("\nPASS: FEC congestion control healthy (max RTT={:.1}ms, min cwnd={})", max_rtt, min_cwnd);

    // Verify video output is playable
    println!("\nTo verify video: ffplay {}", output_path);

    Ok(())
}
