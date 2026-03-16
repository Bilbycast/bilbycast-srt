//! SRT Caller - run this after starting the listener in another terminal.
//!
//! Connects to the listener and sends test messages.
//!
//! Usage:
//!   # First, in terminal 1:
//!   cargo run --example listener -p srt-transport
//!
//!   # Then, in terminal 2:
//!   cargo run --example caller -p srt-transport

use srt_transport::SrtSocket;
use std::time::Duration;

const LISTENER_ADDR: &str = "127.0.0.1:4200";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("Connecting to SRT listener at {LISTENER_ADDR}...");

    let socket = SrtSocket::builder()
        .latency(Duration::from_millis(120))
        .live_mode()
        .connect(LISTENER_ADDR.parse()?)
        .await?;

    println!("Connected!\n");

    // Send 10 test messages
    for i in 1..=10 {
        let msg = format!("Test message #{i} from caller");
        socket.send(msg.as_bytes()).await?;
        println!("  Sent: {msg}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Send a larger payload to test with real-world sized packets
    let payload = vec![0xABu8; 1316]; // 1316 bytes = standard MPEG-TS payload
    socket.send(&payload).await?;
    println!("  Sent: 1316-byte binary payload");

    println!("\nAll messages sent.");

    let stats = socket.stats().await;
    println!("\nConnection stats:");
    println!("  Packets sent:  {}", stats.pkt_sent_total);
    println!("  Bytes sent:    {}", stats.byte_sent_total);
    println!("  Send losses:   {}", stats.pkt_snd_loss_total);

    socket.close().await?;
    Ok(())
}
