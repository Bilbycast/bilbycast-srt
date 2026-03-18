//! SRT Rendezvous mode: peer-to-peer connection without caller/listener roles.
//!
//! Both peers simultaneously connect to each other on the same port.
//! This is essential for NAT traversal scenarios where neither side can
//! act as a listener.
//!
//! This example spawns two peers in the same process. Each peer binds to
//! a local port and connects to the other's address. They exchange messages
//! bidirectionally, then print statistics.
//!
//! Run with: cargo run --example rendezvous -p srt-transport

use srt_transport::SrtSocket;
use std::time::Duration;

const NUM_MESSAGES: usize = 20;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // Both peers must know each other's address in advance.
    // In a real NAT traversal scenario, a signalling server (like lsfbackend)
    // would exchange these addresses between the peers.
    let peer_a_addr: std::net::SocketAddr = "127.0.0.1:5000".parse()?;
    let peer_b_addr: std::net::SocketAddr = "127.0.0.1:5001".parse()?;

    println!("SRT Rendezvous Example");
    println!("======================");
    println!("Peer A: {peer_a_addr}");
    println!("Peer B: {peer_b_addr}");
    println!();

    // Spawn Peer A
    let peer_a_handle = tokio::spawn(async move {
        let socket = SrtSocket::builder()
            .latency(Duration::from_millis(120))
            .live_mode()
            .rendezvous(true)
            .connect_rendezvous(peer_a_addr, peer_b_addr)
            .await
            .expect("Peer A: rendezvous connect failed");

        println!("[Peer A] Connected to Peer B!");

        // Send messages
        for i in 0..NUM_MESSAGES {
            let msg = format!("Hello from Peer A #{i}");
            socket.send(msg.as_bytes()).await.expect("Peer A: send failed");
            if i % 5 == 0 {
                println!("[Peer A] Sent: {msg}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Receive messages from Peer B
        let mut received = 0;
        for _ in 0..NUM_MESSAGES {
            match socket.recv().await {
                Ok(data) => {
                    let text = String::from_utf8_lossy(&data);
                    if received % 5 == 0 {
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

        // Print stats
        let stats = socket.stats().await;
        println!("\n=== Peer A Stats ===");
        println!("  Packets sent:     {}", stats.pkt_sent_total);
        println!("  Packets received: {}", stats.pkt_recv_total);
        println!("  Bytes sent:       {}", stats.byte_sent_total);
        println!("  Bytes received:   {}", stats.byte_recv_total);

        socket.close().await.expect("Peer A: close failed");
        received
    });

    // Spawn Peer B
    let peer_b_handle = tokio::spawn(async move {
        let socket = SrtSocket::builder()
            .latency(Duration::from_millis(120))
            .live_mode()
            .rendezvous(true)
            .connect_rendezvous(peer_b_addr, peer_a_addr)
            .await
            .expect("Peer B: rendezvous connect failed");

        println!("[Peer B] Connected to Peer A!");

        // Send messages
        for i in 0..NUM_MESSAGES {
            let msg = format!("Hello from Peer B #{i}");
            socket.send(msg.as_bytes()).await.expect("Peer B: send failed");
            if i % 5 == 0 {
                println!("[Peer B] Sent: {msg}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Receive messages from Peer A
        let mut received = 0;
        for _ in 0..NUM_MESSAGES {
            match socket.recv().await {
                Ok(data) => {
                    let text = String::from_utf8_lossy(&data);
                    if received % 5 == 0 {
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

        // Print stats
        let stats = socket.stats().await;
        println!("\n=== Peer B Stats ===");
        println!("  Packets sent:     {}", stats.pkt_sent_total);
        println!("  Packets received: {}", stats.pkt_recv_total);
        println!("  Bytes sent:       {}", stats.byte_sent_total);
        println!("  Bytes received:   {}", stats.byte_recv_total);

        socket.close().await.expect("Peer B: close failed");
        received
    });

    // Wait for both peers to finish
    let a_received = peer_a_handle.await?;
    let b_received = peer_b_handle.await?;

    // Verification
    println!("\n=== Verification ===");
    let pass = a_received == NUM_MESSAGES && b_received == NUM_MESSAGES;
    if pass {
        println!(
            "  PASS: All {NUM_MESSAGES} messages exchanged successfully in both directions (rendezvous mode)."
        );
    } else {
        eprintln!(
            "  FAIL: Peer A received {a_received}/{NUM_MESSAGES}, Peer B received {b_received}/{NUM_MESSAGES}"
        );
        std::process::exit(1);
    }

    Ok(())
}
