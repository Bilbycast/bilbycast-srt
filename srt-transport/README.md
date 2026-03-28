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

### With asymmetric latency and retransmission bandwidth cap

```rust
use srt_transport::SrtSocket;
use std::time::Duration;

let socket = SrtSocket::builder()
    .latency(Duration::from_millis(120))           // base latency for both sides
    .receiver_latency(Duration::from_millis(200))   // override: receiver buffers 200ms
    .sender_latency(Duration::from_millis(100))     // override: sender requests 100ms min
    .max_rexmit_bw(500_000)                         // cap retransmissions at 500 KB/s
    .live_mode()
    .connect("127.0.0.1:4200".parse()?)
    .await?;
```

Additional builder methods for advanced tuning:

```rust
let socket = SrtSocket::builder()
    .latency(Duration::from_millis(120))
    .live_mode()
    .max_bw(10_000_000)                 // max 10 MB/s total send rate
    .input_bw(5_000_000)                // estimated 5 MB/s input rate
    .overhead_bw(25)                    // 25% overhead for congestion control
    .enforced_encryption(true)          // reject unencrypted peers
    .connect_timeout(Duration::from_secs(5))
    .flight_flag_size(8192)             // flow control window (packets)
    .send_buffer_size(4096 * 1316)      // send buffer (bytes)
    .recv_buffer_size(4096 * 1316)      // receive buffer (bytes)
    .payload_size(1316)                 // MPEG-TS 7×188
    .ip_tos(46 << 2)                    // DSCP EF (Expedited Forwarding)
    .retransmit_algo(RetransmitAlgo::Reduced)  // v1.5.5 efficient retransmit
    .send_drop_delay(-1)                // -1 = off (no extra drop delay)
    .loss_max_ttl(0)                    // 0 = adaptive reorder tolerance
    .km_refresh_rate(0x0100_0000)       // key rotation every ~16M packets
    .km_pre_announce(0x1000)            // pre-announce 4096 packets before
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

// Get performance statistics (80+ counters in SrtStats)
let stats = socket.stats().await;
println!("Packets sent: {}", stats.pkt_sent_total);
println!("Packets received: {}", stats.pkt_recv_total);
println!("RTT: {:.1}ms", stats.ms_rtt);
println!("Send rate: {:.1} Mb/s", stats.mbps_send_rate);
println!("Bandwidth: {:.1} Mb/s", stats.mbps_bandwidth);
println!("Flight size: {} pkts", stats.pkt_flight_size);
println!("Loss (send/recv): {}/{}", stats.pkt_snd_loss_total, stats.pkt_rcv_loss_total);
println!("Retransmits: {}", stats.pkt_retrans_total);
println!("Drops (send/recv): {}/{}", stats.pkt_snd_drop_total, stats.pkt_rcv_drop_total);
println!("ACK/NAK sent: {}/{}", stats.pkt_sent_ack_total, stats.pkt_sent_nak_total);
println!("Buffer avail (send/recv): {}/{} bytes", stats.byte_avail_snd_buf, stats.byte_avail_rcv_buf);
println!("Buffer latency (send/recv): {}ms/{}ms", stats.ms_snd_buf, stats.ms_rcv_buf);
println!("TSBPD delay (send/recv): {}ms/{}ms", stats.ms_snd_tsbpd_delay, stats.ms_rcv_tsbpd_delay);
println!("Undecryptable: {}", stats.pkt_rcv_undecrypt_total);
println!("FEC recovered/lost: {}/{}", stats.pkt_rcv_filter_supply_total, stats.pkt_rcv_filter_loss_total);
println!("Reorder distance/tolerance: {}/{}", stats.pkt_reorder_distance, stats.pkt_reorder_tolerance);
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
