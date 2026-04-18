// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Bidirectional SRT data transfer with statistics.
//!
//! Both the caller and the listener exchange data. Each side sends a batch
//! of packets, then receives the other side's batch. After the exchange,
//! connection statistics are printed to verify the library works correctly
//! in both directions.
//!
//! Run with: cargo run --example bidirectional

use srt_transport::{SrtListener, SrtSocket};
use std::time::Duration;

const PAYLOAD_SIZE: usize = 1316; // standard MPEG-TS payload
const NUM_PACKETS: usize = 50;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // --- Start listener ---
    let mut listener = SrtListener::builder()
        .latency(Duration::from_millis(200))
        .live_mode()
        .bind("127.0.0.1:0".parse()?)
        .await?;

    let listener_addr = listener.local_addr();
    println!("[listener] Listening on {listener_addr}");

    // Listener task: receive from caller, then send back
    let listener_task = tokio::spawn(async move {
        let socket = listener.accept().await.expect("accept failed");
        println!("[listener] Connection accepted");

        // Phase 1: receive all packets from the caller
        let mut received = 0usize;
        let mut total_bytes = 0usize;
        for _ in 0..NUM_PACKETS {
            match socket.recv().await {
                Ok(data) => {
                    assert_eq!(data[0], b'C', "expected caller tag 'C'");
                    let idx = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                    if received % 10 == 0 {
                        println!("[listener] Received packet #{idx} ({} bytes)", data.len());
                    }
                    total_bytes += data.len();
                    received += 1;
                }
                Err(e) => {
                    eprintln!("[listener] recv error: {e:?}");
                    break;
                }
            }
        }
        println!("[listener] Received {received}/{NUM_PACKETS} packets ({total_bytes} bytes)");

        // Phase 2: send packets back tagged with 'L', pacing them slightly
        // so the send loop has time to drain each one
        for i in 0..NUM_PACKETS {
            let mut payload = vec![b'L'; PAYLOAD_SIZE];
            payload[1..5].copy_from_slice(&(i as u32).to_be_bytes());
            socket.send(&payload).await.expect("listener send failed");
            // Small delay to let the send loop transmit
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        println!("[listener] Queued {NUM_PACKETS} packets back to caller");

        // Wait for send loop to drain the buffer
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Print stats
        let stats = socket.stats().await;
        println!("\n=== Listener Stats ===");
        println!("  Packets sent:     {}", stats.pkt_sent_total);
        println!("  Packets received: {}", stats.pkt_recv_total);
        println!("  Bytes sent:       {}", stats.byte_sent_total);
        println!("  Bytes received:   {}", stats.byte_recv_total);
        println!("  Send losses:      {}", stats.pkt_snd_loss_total);
        println!("  Recv losses:      {}", stats.pkt_rcv_loss_total);
        println!("  Retransmits:      {}", stats.pkt_retrans_total);
        println!("  RTT (ms):         {:.2}", stats.ms_rtt);

        socket.close().await.expect("close failed");
        listener.close().await.expect("listener close failed");
        received
    });

    // Give listener time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // --- Caller side ---
    let socket = SrtSocket::builder()
        .latency(Duration::from_millis(200))
        .live_mode()
        .connect(listener_addr)
        .await?;

    println!("[caller] Connected to {listener_addr}");

    // Phase 1: send packets tagged with 'C', pacing slightly
    for i in 0..NUM_PACKETS {
        let mut payload = vec![b'C'; PAYLOAD_SIZE];
        payload[1..5].copy_from_slice(&(i as u32).to_be_bytes());
        socket.send(&payload).await?;
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    println!("[caller] Sent {NUM_PACKETS} packets to listener");

    // Phase 2: receive packets back from listener
    let mut caller_received = 0usize;
    let mut total_bytes = 0usize;
    for _ in 0..NUM_PACKETS {
        match socket.recv().await {
            Ok(data) => {
                assert_eq!(data[0], b'L', "expected listener tag 'L'");
                let idx = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                if caller_received % 10 == 0 {
                    println!("[caller] Received packet #{idx} ({} bytes)", data.len());
                }
                total_bytes += data.len();
                caller_received += 1;
            }
            Err(e) => {
                eprintln!("[caller] recv error: {e:?}");
                break;
            }
        }
    }
    println!("[caller] Received {caller_received}/{NUM_PACKETS} packets ({total_bytes} bytes)");

    // Print stats
    let stats = socket.stats().await;
    println!("\n=== Caller Stats ===");
    println!("  Packets sent:     {}", stats.pkt_sent_total);
    println!("  Packets received: {}", stats.pkt_recv_total);
    println!("  Bytes sent:       {}", stats.byte_sent_total);
    println!("  Bytes received:   {}", stats.byte_recv_total);
    println!("  Send losses:      {}", stats.pkt_snd_loss_total);
    println!("  Recv losses:      {}", stats.pkt_rcv_loss_total);
    println!("  Retransmits:      {}", stats.pkt_retrans_total);
    println!("  RTT (ms):         {:.2}", stats.ms_rtt);

    socket.close().await?;

    let listener_received = listener_task.await?;

    // --- Final verification ---
    println!("\n=== Verification ===");
    let pass = caller_received == NUM_PACKETS && listener_received == NUM_PACKETS;
    if pass {
        println!(
            "  PASS: All {NUM_PACKETS} packets exchanged successfully in both directions."
        );
    } else {
        eprintln!(
            "  FAIL: caller got {caller_received}/{NUM_PACKETS}, \
             listener got {listener_received}/{NUM_PACKETS}"
        );
        std::process::exit(1);
    }

    Ok(())
}
