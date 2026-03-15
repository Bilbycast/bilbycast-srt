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

### As a Rust dependency

Add `srt-transport` to your `Cargo.toml`:

```toml
[dependencies]
srt-transport = { path = "path/to/srt-native/srt-transport" }
```

Then use the async API:

```rust
use srt_transport::{SrtSocket, SrtListener};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Sender side
    let socket = SrtSocket::builder()
        .latency(Duration::from_millis(120))
        .connect("127.0.0.1:4200".parse()?)
        .await?;

    socket.send(b"Hello SRT!").await?;

    // Receiver side (in another task/process)
    let listener = SrtListener::builder()
        .bind("0.0.0.0:4200".parse()?)
        .await?;

    let client = listener.accept().await?;
    let data = client.recv().await?;

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
    .connect("127.0.0.1:4200".parse()?)
    .await?;
```

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
# Start a Rust SRT listener
cargo run --example listener -- --bind 0.0.0.0:4200

# Connect with the C++ srt-live-transmit tool
srt-live-transmit udp://:1234 srt://127.0.0.1:4200

# Or vice versa - connect Rust to a C++ SRT server
cargo run --example sender -- --connect 127.0.0.1:4200
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
| `bytes` | 1 | Efficient byte buffer management |
| `bitflags` | 2 | Type-safe bitflag definitions |
| `log` | 0.4 | Logging facade |
| `rand` | 0.10 | Random number generation |
| `tokio` | 1 | Async runtime (transport only) |
| `socket2` | 0.6 | Low-level socket configuration |
| `aes` | 0.8 | AES block cipher (optional) |
| `ctr` | 0.9 | CTR mode (optional) |
| `aes-gcm` | 0.10 | AES-GCM AEAD (optional) |
| `pbkdf2` | 0.12 | Key derivation (optional) |
| `sha1` | 0.10 | SHA-1 hash (optional) |
| `hmac` | 0.12 | HMAC (optional) |
| `aes-kw` | 0.2 | AES Key Wrap RFC 3394 (optional) |

## License

This project is licensed under the [Mozilla Public License 2.0](LICENSE), the same license as the [original Haivision SRT library](https://github.com/Haivision/srt).

## Acknowledgments

This is a clean-room Rust implementation based on the [SRT protocol specification](https://datatracker.ietf.org/doc/html/draft-sharabayko-srt) and the [Haivision SRT](https://github.com/Haivision/srt) open-source project.
