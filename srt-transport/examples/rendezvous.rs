// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Reza Rahimi. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT Rendezvous mode: peer-to-peer connection without caller/listener roles.
//!
//! Both peers simultaneously connect to each other on the same port.
//! This is essential for NAT traversal scenarios where neither side can
//! act as a listener.
//!
//! This example demonstrates:
//! 1. Basic unencrypted rendezvous with bidirectional data exchange
//! 2. Encrypted rendezvous with AES-128 and Stream ID
//!
//! Run with: cargo run --example rendezvous -p srt-transport

use std::sync::Arc;

use srt_protocol::config::KeySize;
use srt_transport::SrtSocket;
use std::time::Duration;

const NUM_MESSAGES: usize = 50;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // ── Test 1: Basic unencrypted rendezvous ──
    println!("SRT Rendezvous Example");
    println!("======================\n");
    println!("--- Test 1: Unencrypted Rendezvous ---");

    let peer_a_addr: std::net::SocketAddr = "127.0.0.1:5000".parse()?;
    let peer_b_addr: std::net::SocketAddr = "127.0.0.1:5001".parse()?;

    println!("Peer A: {peer_a_addr}");
    println!("Peer B: {peer_b_addr}\n");

    let (a_received, b_received) = run_rendezvous_test(
        peer_a_addr,
        peer_b_addr,
        None,  // no encryption
        None,  // no stream_id
    )
    .await?;

    verify("Test 1 (unencrypted)", a_received, b_received);

    // Brief pause between tests to release ports
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ── Test 2: Encrypted rendezvous with Stream ID ──
    println!("\n--- Test 2: Encrypted Rendezvous (AES-128 + Stream ID) ---");

    let peer_c_addr: std::net::SocketAddr = "127.0.0.1:5002".parse()?;
    let peer_d_addr: std::net::SocketAddr = "127.0.0.1:5003".parse()?;

    println!("Peer C: {peer_c_addr}");
    println!("Peer D: {peer_d_addr}\n");

    let (c_received, d_received) = run_rendezvous_test(
        peer_c_addr,
        peer_d_addr,
        Some("test_passphrase_1234"),
        Some("rendezvous_test_stream"),
    )
    .await?;

    verify("Test 2 (encrypted)", c_received, d_received);

    Ok(())
}

async fn run_rendezvous_test(
    peer_a_addr: std::net::SocketAddr,
    peer_b_addr: std::net::SocketAddr,
    passphrase: Option<&'static str>,
    stream_id: Option<&'static str>,
) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    // Spawn Peer A
    let peer_a_handle = tokio::spawn(async move {
        let mut builder = SrtSocket::builder()
            .latency(Duration::from_millis(120))
            .live_mode()
            .rendezvous(true);

        if let Some(pass) = passphrase {
            builder = builder.encryption(pass, KeySize::AES128);
        }
        if let Some(sid) = stream_id {
            builder = builder.stream_id(sid.to_string());
        }

        let socket = Arc::new(
            builder
                .connect_rendezvous(peer_a_addr, peer_b_addr)
                .await
                .expect("Peer A: rendezvous connect failed"),
        );

        println!("[Peer A] Connected to Peer B!");

        // Send and receive concurrently (like real streaming)
        let sock_send = socket.clone();
        let send_task = tokio::spawn(async move {
            for i in 0..NUM_MESSAGES {
                let msg = format!("Hello from Peer A #{i}");
                sock_send.send(msg.as_bytes()).await.expect("Peer A: send failed");
                if i % 10 == 0 {
                    println!("[Peer A] Sent: {msg}");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        let sock_recv = socket.clone();
        let recv_task = tokio::spawn(async move {
            let mut received = 0;
            for _ in 0..NUM_MESSAGES {
                match sock_recv.recv().await {
                    Ok(data) => {
                        let text = String::from_utf8_lossy(&data);
                        if received % 10 == 0 {
                            println!("[Peer A] Received: {text}");
                        }
                        received += 1;
                    }
                    Err(e) => {
                        eprintln!("[Peer A] recv error: {e:?}");
                        break;
                    }
                }
            }
            received
        });

        send_task.await.unwrap();
        let received = recv_task.await.unwrap();

        // Print stats
        let stats = socket.stats().await;
        println!("\n=== Peer A Stats ===");
        println!("  Packets sent:     {}", stats.pkt_sent_total);
        println!("  Packets received: {}", stats.pkt_recv_total);
        println!("  Bytes sent:       {}", stats.byte_sent_total);
        println!("  Bytes received:   {}", stats.byte_recv_total);
        println!("  Recv drops:       {}", stats.pkt_rcv_drop_total);

        socket.close().await.expect("Peer A: close failed");
        received
    });

    // Spawn Peer B
    let peer_b_handle = tokio::spawn(async move {
        let mut builder = SrtSocket::builder()
            .latency(Duration::from_millis(120))
            .live_mode()
            .rendezvous(true);

        if let Some(pass) = passphrase {
            builder = builder.encryption(pass, KeySize::AES128);
        }
        // Peer B doesn't set stream_id — only the Initiator sends it

        let socket = Arc::new(
            builder
                .connect_rendezvous(peer_b_addr, peer_a_addr)
                .await
                .expect("Peer B: rendezvous connect failed"),
        );

        println!("[Peer B] Connected to Peer A!");

        // Send and receive concurrently
        let sock_send = socket.clone();
        let send_task = tokio::spawn(async move {
            for i in 0..NUM_MESSAGES {
                let msg = format!("Hello from Peer B #{i}");
                sock_send.send(msg.as_bytes()).await.expect("Peer B: send failed");
                if i % 10 == 0 {
                    println!("[Peer B] Sent: {msg}");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        let sock_recv = socket.clone();
        let recv_task = tokio::spawn(async move {
            let mut received = 0;
            for _ in 0..NUM_MESSAGES {
                match sock_recv.recv().await {
                    Ok(data) => {
                        let text = String::from_utf8_lossy(&data);
                        if received % 10 == 0 {
                            println!("[Peer B] Received: {text}");
                        }
                        received += 1;
                    }
                    Err(e) => {
                        eprintln!("[Peer B] recv error: {e:?}");
                        break;
                    }
                }
            }
            received
        });

        send_task.await.unwrap();
        let received = recv_task.await.unwrap();

        // Print stats
        let stats = socket.stats().await;
        println!("\n=== Peer B Stats ===");
        println!("  Packets sent:     {}", stats.pkt_sent_total);
        println!("  Packets received: {}", stats.pkt_recv_total);
        println!("  Bytes sent:       {}", stats.byte_sent_total);
        println!("  Bytes received:   {}", stats.byte_recv_total);
        println!("  Recv drops:       {}", stats.pkt_rcv_drop_total);

        socket.close().await.expect("Peer B: close failed");
        received
    });

    let a_received = peer_a_handle.await?;
    let b_received = peer_b_handle.await?;

    Ok((a_received, b_received))
}

fn verify(test_name: &str, a_received: usize, b_received: usize) {
    println!("\n=== {test_name} Verification ===");
    // Allow a small number of drops due to TSBPD timing at connection close
    let min_expected = NUM_MESSAGES * 95 / 100; // 95% threshold
    if a_received >= min_expected && b_received >= min_expected {
        println!(
            "  PASS: Peer A received {a_received}/{NUM_MESSAGES}, Peer B received {b_received}/{NUM_MESSAGES} (rendezvous mode)."
        );
    } else {
        eprintln!(
            "  FAIL: Peer A received {a_received}/{NUM_MESSAGES}, Peer B received {b_received}/{NUM_MESSAGES}"
        );
        std::process::exit(1);
    }
}
