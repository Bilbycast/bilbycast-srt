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
- `crypto/` — Feature-gated (`encryption` feature, on by default). PBKDF2 key derivation, AES-CTR and AES-GCM modes (selectable via `CryptoModeConfig` in `SrtConfig`), AES Key Wrap (RFC 3394), key rotation via even/odd `KeyIndex`. All pure Rust (RustCrypto crates). AES-GCM nonce construction matches libsrt v1.5.5 (12-byte salt + XOR packet index).
- `fec/` — SRT Forward Error Correction (packet filter FEC), wire-compatible with libsrt v1.5.5. `FecConfig` parses the `"fec,cols:10,rows:5,layout:staircase,arq:onreq"` config string. `encoder.rs` generates XOR parity packets (row and column groups, staircase layout). `decoder.rs` recovers lost packets with 2D cascade recovery. FEC packets are SRT data packets with msgno=0 (`SRT_MSGNO_CONTROL`). Handshake negotiation via `SRT_CMD_FILTER` (ext type 7). ARQ modes: `always` (ARQ+FEC parallel), `onreq` (suppress NAK until FEC fails), `never` (FEC only).
- `access_control.rs` — Stream ID and Access Control per libsrt v1.5.5. `AccessControl` trait for listener connection filtering. `HandshakeInfo` provides peer address, Stream ID, encryption state. `StreamIdInfo` parses the structured `#!::key=value,...` format (standard keys: `r`=resource, `m`=mode, `s`=session, `t`=type, `u`=user, `h`=host). `serialize_stream_id()`/`parse_stream_id()` handle the `SRT_CMD_SID` (ext type 5) wire format: UTF-8 packed into big-endian u32 words, max 512 bytes. 18 `RejectReason` codes match libsrt.

### srt-transport (async networking)
Tokio-based async layer on top of srt-protocol.
- `SrtSocket` / `SrtListener` — Main public API with builder pattern (`SrtSocketBuilder`, `SrtListenerBuilder`)
- `SrtSocketBuilder::stream_id(String)` — sets Stream ID sent by the caller during HSv5 CONCLUSION handshake (SRT_CMD_SID extension)
- `SrtSocketBuilder::packet_filter(String)` — sets SRT FEC packet filter config (e.g., `"fec,cols:10,rows:5,layout:staircase,arq:onreq"`). Negotiated via `SRT_CMD_FILTER` (ext type 7) during handshake. Both sides must agree on parameters.
- `SrtListenerBuilder::access_control_fn(|&HandshakeInfo| -> Result<(), RejectReason>)` — register callback to accept/reject connections based on Stream ID, peer address, encryption state
- `SrtListenerBuilder::packet_filter(String)` — same as socket builder, for listener-side FEC config
- `SrtSocket::stream_id()` — read the Stream ID on an accepted connection (caller's ID stored during handshake)
- Advanced builder options (both socket and listener): `.max_bw()`, `.input_bw()`, `.overhead_bw()`, `.enforced_encryption()`, `.connect_timeout()`, `.flight_flag_size()`, `.send_buffer_size()`, `.recv_buffer_size()`, `.payload_size()`, `.ip_tos()`, `.retransmit_algo()`, `.send_drop_delay()`, `.loss_max_ttl()`, `.km_refresh_rate()`, `.km_pre_announce()`
- `SrtSocket::stats()` — returns `SrtStats` with 80+ counters: packet/byte counts, send/recv rates (Mbps), RTT, estimated bandwidth, ACK/NAK, flow/congestion window, flight size, buffer availability and occupancy, TSBPD delays, byte-level drop counts, FEC recovery/loss, reorder metrics. Snapshot fields are populated periodically in `send_periodic_control()`.
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
- **TSBPD base_time calibration**: The receiver's TSBPD base_time is reset after the handshake completes (in both caller and listener paths), and further calibrated on the first data packet arrival to account for network delay. Without this, packets through high-latency links are incorrectly dropped as "too late". The rendezvous path had this fix first; caller/listener paths were added later.
- **Reorder tolerance** (`loss_max_ttl`): When > 0, gap detection in `recv_loop` defers adding losses to the loss list until the gap is more than `loss_max_ttl` packets behind the highest received seq. This prevents jitter-induced packet reordering from triggering unnecessary NAK/retransmit floods. Default is 0 (immediate detection); should be tuned per-link based on expected jitter.
- **Connection expiration**: `COMM_RESPONSE_MAX_EXP` is set to 5 (not 16), so dead connections are detected in ~10 seconds. The EXP timer uses exponential backoff from the initial RTT estimate.
- **Stream ID & Access Control**: Full libsrt v1.5.5 compatibility. Caller sends Stream ID in CONCLUSION via `SRT_CMD_SID` extension. Listener parses it and passes to `AccessControl` callback before accepting. `StreamIdInfo` parses the structured `#!::key=value` format. Wire format: UTF-8 in big-endian u32 words, null-padded to 4-byte boundary, max 512 bytes.
- **FEC (Forward Error Correction)**: Full libsrt v1.5.5 compatible packet filter FEC. Configured via `packet_filter` string (e.g., `"fec,cols:10,rows:5,layout:staircase,arq:onreq"`). Negotiated during handshake via `SRT_CMD_FILTER` (ext type 7). Sender generates XOR parity packets per row/column group. Receiver recovers single lost packets per group; 2D mode enables cascade recovery across row and column groups. ARQ integration: `always` (parallel), `onreq` (FEC-first), `never` (FEC-only). FEC packets are SRT data packets with msgno=0, fire-and-forget (not retransmitted). **C++ FEC interop is not yet working** — see `KNOWN_ISSUES.md` for details and fix plan. Rust ↔ Rust FEC works perfectly. C++ libsrt computes FEC parity from ciphertexts (feedSource after encryption); the Rust receiver matches this by feeding raw_payload (pre-decryption) to the FEC decoder.
