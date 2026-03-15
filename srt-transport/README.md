# srt-transport

Async I/O transport layer for the SRT protocol, built on [tokio](https://tokio.rs/).

This crate provides ready-to-use `SrtSocket` and `SrtListener` types with a builder pattern API. It handles all the networking: UDP sockets, packet dispatch, send/receive scheduling, connection multiplexing, and event notification.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
srt-transport = { path = "../srt-transport" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## API Overview

### Connecting to a remote SRT peer

```rust
use srt_transport::SrtSocket;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = SrtSocket::builder()
        .latency(Duration::from_millis(120))
        .connect("127.0.0.1:4200".parse()?)
        .await?;

    // Send data
    socket.send(b"Hello SRT!").await?;

    // Receive data
    let data = socket.recv().await?;
    println!("Received: {} bytes", data.len());

    // Clean shutdown
    socket.close().await?;

    Ok(())
}
```

### Listening for incoming connections

```rust
use srt_transport::SrtListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = SrtListener::builder()
        .bind("0.0.0.0:4200".parse()?)
        .await?;

    println!("Listening on {}", listener.local_addr());

    // Accept a connection
    let client = listener.accept().await?;
    let data = client.recv().await?;
    println!("Received: {:?}", data);

    Ok(())
}
```

### With encryption

```rust
use srt_transport::SrtSocket;
use srt_protocol::config::KeySize;
use std::time::Duration;

let socket = SrtSocket::builder()
    .latency(Duration::from_millis(120))
    .encryption("my_passphrase", KeySize::AES256)
    .live_mode()
    .connect("127.0.0.1:4200".parse()?)
    .await?;
```

### Monitoring socket status

```rust
use srt_transport::SrtSocket;

let socket = SrtSocket::builder()
    .connect("127.0.0.1:4200".parse()?)
    .await?;

// Check connection status
let status = socket.status();
println!("Socket status: {:?}", status);

// Get performance statistics
let stats = socket.stats().await;
println!("Packets sent: {}", stats.pkt_sent_total);
println!("Packets received: {}", stats.pkt_recv_total);
```

### Event-driven multiplexing (Epoll)

```rust
use srt_transport::{SrtEpoll, SrtEpollOpt};
use std::time::Duration;

let mut epoll = SrtEpoll::new();

// Register sockets for read/write readiness
epoll.add(&socket1, SrtEpollOpt::IN | SrtEpollOpt::OUT);
epoll.add(&socket2, SrtEpollOpt::IN);

// Wait for events
let events = epoll.wait(Duration::from_millis(100)).await?;
for event in &events {
    if event.events.contains(SrtEpollOpt::IN) {
        // Socket is ready for reading
    }
}
```

## Module Reference

| Module | Description |
|--------|-------------|
| `socket` | `SrtSocket` and `SrtSocketBuilder` - main client API |
| `listener` | `SrtListener` and `SrtListenerBuilder` - server/accept API |
| `connector` | HSv5 caller-side handshake implementation |
| `channel` | UDP channel wrapper over `tokio::net::UdpSocket` |
| `multiplexer` | Routes packets across multiple SRT connections on one UDP port |
| `connection` | Internal connection state combining protocol + transport |
| `send_loop` | Async send task with congestion-controlled pacing |
| `recv_loop` | Async receive task with packet dispatch |
| `epoll` | Event notification system for socket multiplexing |
| `manager` | Global socket registry and ID generation |

## Architecture

```
                    +-----------------+
                    |   SrtSocket     |  (user-facing API)
                    +--------+--------+
                             |
                    +--------v--------+
                    |  SrtConnection  |  (protocol state: buffers, CC, timers)
                    +--------+--------+
                             |
              +--------------+--------------+
              |                             |
     +--------v--------+          +--------v--------+
     |   send_loop     |          |   recv_loop     |
     | (tokio::spawn)  |          | (tokio::spawn)  |
     +--------+--------+          +--------+--------+
              |                             |
     +--------v-----------------------------v--------+
     |              Multiplexer                      |
     |  (routes packets by destination socket ID)    |
     +-------------------------+---------------------+
                               |
                      +--------v--------+
                      |   UdpChannel    |
                      | (tokio UdpSocket)|
                      +-----------------+
```

## Testing

```bash
cargo test -p srt-transport
```

## License

[Mozilla Public License 2.0](../LICENSE)
