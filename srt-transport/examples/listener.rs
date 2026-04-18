// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Copyright (c) 2026 Softside Tech Pty Ltd. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

//! SRT Listener - run this first in one terminal.
//!
//! Listens on a port and prints any data received from a caller.
//!
//! Usage:
//!   cargo run --example listener -p srt-transport
//!
//! Then in another terminal:
//!   cargo run --example caller -p srt-transport

use srt_transport::SrtListener;
use std::time::Duration;

const PORT: u16 = 4200;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let addr = format!("127.0.0.1:{PORT}").parse()?;

    let mut listener = SrtListener::builder()
        .latency(Duration::from_millis(120))
        .live_mode()
        .bind(addr)
        .await?;

    println!("SRT listener ready on 127.0.0.1:{PORT}");
    println!("Waiting for a caller to connect...");
    println!("(Run `cargo run --example caller -p srt-transport` in another terminal)\n");

    let socket = listener.accept().await?;
    println!("Caller connected from {:?}!\n", socket.peer_addr().await);

    println!("Receiving messages (Ctrl+C to stop):\n");
    loop {
        match socket.recv().await {
            Ok(data) => {
                let text = String::from_utf8_lossy(&data);
                println!("  Received ({} bytes): {text}", data.len());
            }
            Err(e) => {
                println!("\nConnection ended: {e:?}");
                break;
            }
        }
    }

    socket.close().await?;
    listener.close().await?;
    Ok(())
}
