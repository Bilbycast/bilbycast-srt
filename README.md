# srt-native - Pure Rust SRT Protocol Implementation

A complete, pure-Rust implementation of the [SRT (Secure Reliable Transport)](https://github.com/Haivision/srt) protocol. This project provides the same functionality as the original Haivision C++ SRT library but compiles without any external system dependencies (no OpenSSL, no libssl, no libcrypto).

## Features

- **Pure Rust** - No C/C++ dependencies, no system library linking
- **Full SRT Protocol** - Wire-compatible with the original C++ SRT library
- **Async I/O** - Built on [tokio](https://tokio.rs/) for high-performance async networking
- **Encryption** - AES-128/192/256 in CTR and GCM modes using [RustCrypto](https://github.com/RustCrypto) crates
- **Feature-gated crypto** - Encryption can be disabled at compile time for smaller binaries
- **C FFI** - Optional C-compatible API matching the original `srt.h` interface
- **Cross-platform** - Runs on Linux, macOS, Windows, and any platform Rust supports

## Workspace Structure

The project is organized as a Cargo workspace with three crates:

```
srt-native/
  srt-protocol/    # Pure protocol logic (no I/O, no async runtime)
  srt-transport/   # Async I/O layer (tokio-based networking)
  srt-ffi/         # C FFI compatibility layer (optional)
```

| Crate | Description | Use When |
|-------|-------------|----------|
| [`srt-protocol`](srt-protocol/) | Protocol state machines, packet serialization, crypto, buffers | Building a custom transport or embedding SRT logic |
| [`srt-transport`](srt-transport/) | Ready-to-use async SRT sockets and listeners | Building Rust applications that need SRT |
| [`srt-ffi`](srt-ffi/) | C API (`srt_create_socket`, `srt_send`, etc.) | Drop-in replacement for the C++ SRT library |

## Quick Start

### Add the dependency

```toml
[dependencies]
srt-transport = { path = "path/to/srt-native/srt-transport" }
tokio = { version = "1", features = ["rt-multi-thread", "macros", "time"] }
```

### How SRT connections work

SRT uses a **listener/caller** model (similar to TCP server/client):

1. The **listener** binds to a port and waits for incoming connections
2. The **caller** connects to the listener's address
3. They perform a handshake to establish the connection
4. Once connected, **both sides can send and receive data**

### Step 1: Start a listener

The listener must be running before the caller connects.

```rust
use srt_transport::SrtListener;
use std::time::Duration;

// Bind to a port and start listening
let mut listener = SrtListener::builder()
    .latency(Duration::from_millis(120))  // buffering latency
    .live_mode()                           // real-time streaming mode
    .bind("127.0.0.1:4200".parse()?)
    .await?;

println!("Listening on {}", listener.local_addr());

// Wait for a caller to connect (blocks until one arrives)
let socket = listener.accept().await?;
println!("Caller connected!");

// Receive data from the caller
let data = socket.recv().await?;
println!("Got: {}", String::from_utf8_lossy(&data));

// Clean up
socket.close().await?;
listener.close().await?;
```

### Step 2: Connect a caller

The caller connects to the listener and sends data.

```rust
use srt_transport::SrtSocket;
use std::time::Duration;

// Connect to the listener
let socket = SrtSocket::builder()
    .latency(Duration::from_millis(120))
    .live_mode()
    .connect("127.0.0.1:4200".parse()?)
    .await?;

println!("Connected to listener!");

// Send data
socket.send(b"Hello SRT!").await?;

// You can also receive data (SRT is bidirectional)
// let response = socket.recv().await?;

socket.close().await?;
```

### Step 3: Put it together

In a single process, spawn the listener in a background task so both
sides can run concurrently:

```rust
use srt_transport::{SrtSocket, SrtListener};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Start the listener
    let mut listener = SrtListener::builder()
        .latency(Duration::from_millis(120))
        .live_mode()
        .bind("127.0.0.1:0".parse()?)   // port 0 = pick a free port
        .await?;
    let addr = listener.local_addr();

    // Run the listener in a background task
    let listener_task = tokio::spawn(async move {
        let socket = listener.accept().await.unwrap();
        let data = socket.recv().await.unwrap();
        println!("Listener received: {}", String::from_utf8_lossy(&data));
        socket.close().await.unwrap();
        listener.close().await.unwrap();
    });

    // Give the listener a moment to be ready
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect the caller and send data
    let socket = SrtSocket::builder()
        .latency(Duration::from_millis(120))
        .live_mode()
        .connect(addr)
        .await?;

    socket.send(b"Hello SRT!").await?;
    println!("Caller sent message");

    socket.close().await?;
    listener_task.await?;

    println!("Success! Data was sent through SRT.");
    Ok(())
}
```

### With encryption

Both sides must use the same passphrase:

```rust
use srt_transport::{SrtSocket, SrtListener};
use srt_protocol::config::KeySize;
use std::time::Duration;

// Listener with encryption
let mut listener = SrtListener::builder()
    .latency(Duration::from_millis(120))
    .encryption("my_secret_passphrase", KeySize::AES256)
    .bind("127.0.0.1:4200".parse()?)
    .await?;

// Caller with the same passphrase
let socket = SrtSocket::builder()
    .latency(Duration::from_millis(120))
    .encryption("my_secret_passphrase", KeySize::AES256)
    .connect("127.0.0.1:4200".parse()?)
    .await?;
```

### Run the included examples

**Test with two terminals (recommended way to verify the library works):**

```bash
# Terminal 1 — start the listener
cargo run --example listener -p srt-transport

# Terminal 2 — connect the caller and send data
cargo run --example caller -p srt-transport
```

The listener waits for a connection on port 4200. The caller connects,
sends 10 text messages plus a 1316-byte binary payload, and prints
connection stats when done. You'll see each message appear on both sides.

**Single-process examples (run everything in one command):**

```bash
# One-way transfer: caller sends 10 text messages to a listener
cargo run --example simple_transfer -p srt-transport

# Bidirectional transfer: both sides exchange 50 × 1316-byte packets,
# then print connection statistics (packets, bytes, losses, RTT)
cargo run --example bidirectional -p srt-transport
```

**Enable verbose logging** to see handshake and connection details:

```bash
RUST_LOG=info cargo run --example listener -p srt-transport
```

All example source code is in `srt-transport/examples/`.

## Building

```bash
# Build all crates
cargo build

# Build in release mode
cargo build --release

# Build without encryption support (smaller binary)
cargo build --no-default-features -p srt-protocol

# Verify no system library dependencies (macOS)
otool -L target/release/libsrt_ffi.dylib

# Verify no system library dependencies (Linux)
ldd target/release/libsrt_ffi.so
```

## Testing

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p srt-protocol
cargo test -p srt-transport

# Run tests with output
cargo test -- --nocapture

# Run a specific test
cargo test -p srt-protocol test_handshake_roundtrip
```

### Interoperability Testing

To verify wire compatibility with the original C++ SRT library:

```bash
# Or use srt-live-transmit against a Rust listener bound to port 4200
srt-live-transmit udp://:1234 srt://127.0.0.1:4200
```

## Architecture

### Protocol Layer (`srt-protocol`)

The protocol crate contains all SRT logic with no I/O dependencies:

- **Packet serialization** - 128-bit SRT headers, control packets (ACK, NAK, handshake, etc.)
- **Sequence numbers** - 31-bit circular arithmetic with wrap-around handling
- **Handshake** - HSv5 INDUCTION/CONCLUSION state machine, rendezvous mode
- **Congestion control** - Pluggable trait with LIVE mode (constant-rate) and FILE mode (AIMD)
- **Buffers** - Send buffer with message segmentation, receive buffer with reordering
- **TSBPD** - Timestamp-Based Packet Delivery with clock drift tracking
- **Encryption** - AES-CTR/GCM with PBKDF2 key derivation and key rotation
- **FEC** - Forward Error Correction with XOR-based recovery

### Transport Layer (`srt-transport`)

The transport crate provides the async networking:

- **SrtSocket / SrtListener** - High-level API with builder pattern
- **Multiplexer** - Multiple SRT connections over a single UDP port
- **Send/Receive loops** - tokio tasks for packet scheduling and dispatch
- **Epoll** - Event-driven multiplexing for multiple sockets

### FFI Layer (`srt-ffi`)

The FFI crate provides C function exports matching `srt.h`:

- `srt_startup()` / `srt_cleanup()`
- `srt_create_socket()` / `srt_close()`
- `srt_bind()` / `srt_listen()` / `srt_accept()` / `srt_connect()`
- `srt_send()` / `srt_recv()`
- `srt_setsockopt()` / `srt_getsockopt()`
- `srt_epoll_create()` / `srt_epoll_wait()`

## Using in Other Projects

### As a Rust crate

Reference the crates via path or publish to a registry:

```toml
# Via local path
[dependencies]
srt-transport = { path = "../srt-native/srt-transport" }

# Or just the protocol layer (no tokio dependency)
[dependencies]
srt-protocol = { path = "../srt-native/srt-protocol" }
```

### As a C library

Build the FFI crate as a shared library:

```bash
cargo build --release -p srt-ffi

# The output is at:
# macOS:  target/release/libsrt_ffi.dylib
# Linux:  target/release/libsrt_ffi.so
# Windows: target/release/srt_ffi.dll
```

Link against it from C/C++:

```c
#include <stdio.h>

// Declare SRT functions (or use a generated header)
extern int srt_startup(void);
extern int srt_cleanup(void);
extern int srt_create_socket(void);
extern int srt_getversion(void);

int main() {
    srt_startup();
    printf("SRT version: 0x%x\n", srt_getversion());
    srt_cleanup();
    return 0;
}
```

### As a static library

Add `crate-type = ["staticlib"]` to `srt-ffi/Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib", "staticlib"]
```

Then build and link:

```bash
cargo build --release -p srt-ffi
# Output: target/release/libsrt_ffi.a
```

## Dependencies

All dependencies are pure Rust crates:

| Dependency | Version | Purpose |
|-----------|---------|---------|
| `bytes` | `1.11.1` | Efficient byte buffer management |
| `bitflags` | `2.11.0` | Type-safe bitflag definitions |
| `log` | `0.4.29` | Logging facade |
| `rand` | `0.10.0` | Random number generation |
| `tokio` | `1.50.0` | Async runtime (transport only) |
| `socket2` | `0.6.3` | Low-level socket configuration |
| `aes` | `0.8.4` | AES block cipher (optional) |
| `ctr` | `0.9.2` | CTR mode (optional) |
| `aes-gcm` | `0.10.3` | AES-GCM AEAD (optional) |
| `pbkdf2` | `0.12.2` | Key derivation (optional) |
| `sha1` | `0.10` | SHA-1 hash (optional) |
| `hmac` | `0.12` | HMAC (optional) |
| `aes-kw` | `0.2` | AES Key Wrap RFC 3394 (optional) |

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE), the same license as the [original Haivision SRT library](https://github.com/Haivision/srt).

## Acknowledgments

This is a clean-room Rust implementation based on the [SRT protocol specification](https://datatracker.ietf.org/doc/html/draft-sharabayko-srt) and the [Haivision SRT](https://github.com/Haivision/srt) open-source project.
