// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! Simple SRT data transfer: listener receives messages from a caller.
//!
//! This example spawns a listener and a caller in the same process.
//! The caller sends several messages, the listener receives and prints them,
//! then both sides close gracefully.
//!
//! Run with: cargo run --example simple_transfer

use srt_transport::{SrtListener, SrtSocket};
use std::time::Duration;

const NUM_MESSAGES: usize = 10;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    // --- Listener side ---
    let mut listener = SrtListener::builder()
        .latency(Duration::from_millis(120))
        .live_mode()
        .bind("127.0.0.1:0".parse()?)
        .await?;

    let listener_addr = listener.local_addr();
    println!("[listener] Bound on {listener_addr}");

    let listener_handle = tokio::spawn(async move {
        let socket = listener.accept().await.expect("accept failed");
        println!(
            "[listener] Accepted connection from {:?}",
            socket.peer_addr().await
        );

        for i in 0..NUM_MESSAGES {
            match socket.recv().await {
                Ok(data) => {
                    let msg = String::from_utf8_lossy(&data);
                    println!("[listener] Message {i}: {msg}");
                }
                Err(e) => {
                    eprintln!("[listener] recv error: {e:?}");
                    break;
                }
            }
        }

        println!("[listener] All messages received, closing.");
        socket.close().await.expect("close failed");
        listener.close().await.expect("listener close failed");
    });

    // --- Caller side ---
    // Small delay to let the listener's accept loop start
    tokio::time::sleep(Duration::from_millis(50)).await;

    let caller = SrtSocket::builder()
        .latency(Duration::from_millis(120))
        .live_mode()
        .connect(listener_addr)
        .await?;

    println!(
        "[caller] Connected to {listener_addr} from {}",
        caller.local_addr()
    );

    for i in 0..NUM_MESSAGES {
        let msg = format!("Hello SRT #{i}");
        caller.send(msg.as_bytes()).await?;
        println!("[caller] Sent: {msg}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    println!("[caller] All messages sent, closing.");
    caller.close().await?;

    // Wait for listener to finish
    listener_handle.await?;

    println!("\nDone! Simple transfer completed successfully.");
    Ok(())
}
