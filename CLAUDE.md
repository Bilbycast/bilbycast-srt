# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

bilbycast-srt is a pure Rust, wire-compatible implementation of the SRT (Secure Reliable Transport) protocol. Zero C/C++ dependencies. Licensed under MPL 2.0.

## Build & Test Commands

```bash
# Build all crates
cargo build

# Build without encryption support
cargo build --no-default-features -p srt-protocol

# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p srt-protocol
cargo test -p srt-transport

# Run a single test
cargo test -p srt-protocol test_name

# Build FFI shared/static library
cargo build --release -p srt-ffi

# Run examples (two-terminal: listener + caller)
cargo run --example listener -p srt-transport
cargo run --example caller -p srt-transport

# Single-process examples
cargo run --example simple_transfer -p srt-transport
cargo run --example bidirectional -p srt-transport
cargo run --example rendezvous -p srt-transport

# Enable logging
RUST_LOG=info cargo run --example listener -p srt-transport
```

## Architecture

Three-crate Cargo workspace, layered bottom-up:

### srt-protocol (core, no I/O)
Pure protocol logic with zero async/networking dependencies. Can be used standalone for custom transports or embedded scenarios.
- `packet/` — SRT packet serialization: 128-bit headers, `SeqNo` (31-bit circular), `MsgNo` (26-bit with flags), control packet types (ACK, NAK, Handshake, KM)
- `protocol/` — Connection state machine: HSv5 handshake (Induction→Conclusion→Agreement), ACK/NAK generation, TSBPD (Timestamp-Based Packet Delivery), periodic timers
- `buffer/` — `SendBuffer` (message segmentation, retransmission queue) and `ReceiveBuffer` (reordering, TSBPD scheduling, loss tracking)
- `congestion/` — Pluggable `CongestionControl` trait with `LiveCC` (constant-rate real-time) and `FileCC` (AIMD file transfer) implementations
- `crypto/` — Feature-gated (`encryption` feature, on by default). PBKDF2 key derivation, AES-CTR and AES-GCM modes, AES Key Wrap (RFC 3394), key rotation via even/odd `KeyIndex`. All pure Rust (RustCrypto crates).

### srt-transport (async networking)
Tokio-based async layer on top of srt-protocol.
- `SrtSocket` / `SrtListener` — Main public API with builder pattern (`SrtSocketBuilder`, `SrtListenerBuilder`)
- Each connection spawns two tokio tasks: `send_loop` (paces packets per congestion control) and `recv_loop` (receives/dispatches UDP packets)
- `Multiplexer` — Routes packets on a single UDP port to multiple connections by destination socket ID
- `UdpChannel` — Tokio UDP socket wrapper
- `SrtEpoll` — Event-driven multiplexing

### srt-ffi (C bindings, WIP)
Exports `#[no_mangle] extern "C"` functions matching `srt.h`. Builds as `cdylib` + `staticlib`. Most functions are scaffolding with TODOs — core protocol/transport layers are fully functional.

## Key Design Decisions

- **Protocol/transport separation**: srt-protocol has no I/O deps, making it testable and reusable independently
- **Encryption is feature-gated**: `encryption` feature (default on) controls all crypto dependencies
- **Sequence number arithmetic**: `SeqNo` and `MsgNo` use modular/circular arithmetic with wrap-around — be careful with comparisons and ordering
- **Interop with C++ libsrt**: ISN (Initial Sequence Number) handling is critical for compatibility — recent fixes addressed caller/listener ISN mismatches
