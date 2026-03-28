# bilbycast-srt vs libsrt v1.5.5 — Comparison

**Date:** 2026-03-27
**Last updated:** 2026-03-28 (after SRT FEC, advanced config params, expanded stats — full v1.5.5 feature parity)

**Note:** libsrt v1.5.5 is not yet a stable release — only release candidates (rc.0a, rc.1) exist as of March 2026. bilbycast-srt already advertises wire compatibility with v1.5.5 (`0x010505`).

## Overview

| | **bilbycast-srt** | **libsrt v1.5.5-rc** |
|---|---|---|
| Language | Pure Rust (zero C/C++ deps) | C++ with C API |
| Architecture | 3 crates: `srt-protocol` (no I/O), `srt-transport` (tokio), `srt-ffi` (WIP) | Monolithic C++ library |
| Async model | Tokio async/await | Epoll + threads |
| Crypto deps | RustCrypto (pure Rust) | OpenSSL-EVP (default), mbedTLS, GnuTLS, Botan |
| Version advertised | `0x010505` (1.5.5) | `0x010505` (1.5.5) |

## Feature Parity

| Feature | **bilbycast-srt** | **libsrt v1.5.5** | Notes |
|---|:---:|:---:|---|
| HSv5 Handshake | Yes | Yes | Induction + Conclusion, extension blocks |
| Caller mode | Yes | Yes | |
| Listener mode | Yes | Yes | |
| Rendezvous mode | Yes | Yes | |
| Live mode (TSBPD) | Yes | Yes | Both default 120ms latency |
| File mode (AIMD) | Yes | Yes | |
| AES-CTR encryption | Yes | Yes | |
| **AES-GCM (AEAD)** | **Production** | **Preview** | bilbycast-srt ships GCM as first-class; libsrt still behind `ENABLE_AEAD_API_PREVIEW` build flag, AEAD epic #2336 still open |
| Key sizes 128/192/256 | Yes | Yes | |
| PBKDF2 key derivation | Yes | Yes | HMAC-SHA1, 2048 iterations |
| AES Key Wrap (RFC 3394) | Yes | Yes | |
| Key rotation (even/odd) | Yes | Yes | 16M pkt refresh, 4096 pkt pre-announce |
| Enforced encryption | Yes | Yes | |
| ARQ (NAK retransmit) | Yes | Yes | |
| FEC (row-only) | Yes | Yes | Config: `"fec,cols:10,rows:1"`. Negotiated via `SRT_CMD_FILTER` (ext type 7) in handshake. |
| FEC (staircase/2D) | Yes | Yes | Config: `"fec,cols:10,rows:5,layout:staircase"`. Staircase column offsets match libsrt. 2D cascade recovery. |
| FEC ARQ modes | Yes | Yes | `arq:always` (parallel), `arq:onreq` (FEC-first, default), `arq:never` (FEC-only). NAK suppression matches libsrt. |
| Too-Late Packet Drop | Yes | Yes | |
| Stream ID (send + receive) | Yes | Yes | Up to 512 chars. Caller sends `SRT_CMD_SID` (ext type 5) in CONCLUSION; listener parses and stores. Structured `#!::key=value` format parsed via `StreamIdInfo`. |
| Stream ID on accepted socket | Yes | Yes | bilbycast-srt: `socket.stream_id()` getter; libsrt: `srt_getsockopt(SRTO_STREAMID)` |
| Drift tracking | Yes | Yes | bilbycast-srt: 1000-sample window |
| Statistics (80+ counters) | Yes | Yes | Includes FEC stats (recovered/lost/overhead), ACK/NAK, flow control, buffer state, TSBPD delays, reorder metrics |
| Epoll multiplexing | Yes | Yes | |
| Bidirectional data | Yes | Yes | |
| NAK report | Yes | Yes | |
| Loss max TTL | Yes | Yes | Reorder tolerance |
| Access Control callbacks | Yes | Yes | bilbycast-srt: `AccessControl` trait + `access_control_fn()` closure API with `HandshakeInfo` (peer addr, stream ID, encryption state); libsrt: `srt_listen_callback()` with `SRTSOCKET` handle |
| Retransmit bandwidth cap | Yes | Yes | Both use Token Bucket algorithm; bilbycast-srt: `max_rexmit_bw` config (`SRTO_MAXREXMITBW`); libsrt: `CShaper` class |
| Rejection with reason codes | Yes | Yes | bilbycast-srt sends `HandshakeType::Failure(RejectReason)` on reject; 18 reason codes matching libsrt |
| **Socket Groups / Bonding** | **No** | **Yes** | Broadcast + Main/Backup (Balancing still WIP) |
| **Auto startup/cleanup** | **N/A** | **Yes** | New in v1.5.5 — automatic global init (Rust doesn't need this) |
| **Windows ARM64** | Untested | **Yes** | New in v1.5.5 |
| **HarmonyOS (OHOS)** | No | **Yes** | New in v1.5.5 |
| C FFI | WIP | Native | libsrt's primary interface |

## Access Control — Implementation Comparison

| Aspect | **bilbycast-srt** | **libsrt v1.5.5** |
|---|---|---|
| API style | `AccessControl` trait or closure via `access_control_fn()` | C callback via `srt_listen_callback()` |
| Info provided | `HandshakeInfo { peer_addr, stream_id, is_encrypted, peer_socket_id, peer_version }` | `SRTSOCKET` handle (query any socket option) |
| Rejection | Returns `Err(RejectReason)` — 18 standard codes | Returns `-1` with `srt_setrejectreason()` — same codes |
| Stream ID format | Sends/parses `SRT_CMD_SID` extension (type 5) in CONCLUSION. `StreamIdInfo` parses `#!::key=value` format (keys: r, m, s, t, u, h). | Same wire format |
| Per-connection passphrase | Not yet (callback sees `is_encrypted` but can't override) | Yes — callback can call `srt_setsockopt(SRTO_PASSPHRASE)` |
| Stored on accepted socket | `socket.stream_id()` getter | `srt_getsockopt(SRTO_STREAMID)` |

## Token Bucket Shaper — Implementation Comparison

| Aspect | **bilbycast-srt** | **libsrt v1.5.5** |
|---|---|---|
| Algorithm | Classic Token Bucket | Token Bucket (`CShaper` class) |
| Config | `max_rexmit_bw: i64` in `SrtConfig` | `SRTO_MAXREXMITBW` socket option |
| Rate values | `-1` = unlimited (default), `0` = disable retransmit, `> 0` = bytes/sec | `-1` = unlimited, `0` = disable, `> 0` = bytes/sec |
| Burst sizing | `max(10ms of bandwidth, 2 * MSS)` | Similar heuristic in `CShaper` |
| Integration point | `send_retransmissions()` — checks bucket per packet, defers rate-limited packets | `CSndQueue::worker` — similar per-packet gating |
| Builder API | `.max_rexmit_bw(bytes_per_sec)` on socket and listener builders | `srt_setsockopt(SRTO_MAXREXMITBW)` |

## What Changed from v1.5.4 to v1.5.5

| v1.5.5 Change | Impact on comparison |
|---|---|
| **Token Bucket for MAXREXMITBW** | Parity — bilbycast-srt now has its own `TokenBucket` shaper for `max_rexmit_bw` |
| **Thread safety fixes** (lock-free `m_bListening`, shared mutex, fork safety, strerror reentrancy) | Non-issue for bilbycast-srt — Rust's ownership model prevents these classes of bugs |
| **Cookie contest restored from v1.4.5** | bilbycast-srt should verify its cookie contest logic matches the restored behavior for interop |
| **Blocking srt_connect error codes fixed** | N/A — bilbycast-srt is async, no blocking API |
| **Buffer overflow fix in handshake group data** | N/A — bilbycast-srt doesn't implement groups; Rust would catch this at bounds check anyway |
| **Late-rejection for mismatched packet filter** | Parity — bilbycast-srt rejects with `RejectReason::Filter` when FEC parameters conflict |
| **CMake LIBSRT_ prefix** | N/A — Cargo workspace, no CMake |
| **Windows ARM64 + HarmonyOS** | Platform gap — bilbycast-srt compiles on any Rust target but hasn't been tested on these |

## Where bilbycast-srt Is Ahead

1. **AES-GCM is production-ready** — libsrt v1.5.5 still gates GCM behind a preview build flag with open issues (TSBPD required, listener can't force GCM mode, epic #2336 incomplete).
2. **Memory safety by construction** — Many v1.5.5 fixes (buffer overflow, data races, lock-order inversions, reentrancy bugs, use-after-free patterns) are structurally impossible in Rust.
3. **Clean protocol/transport separation** — `srt-protocol` has zero I/O dependencies, embeddable in any runtime (WASM, no_std, custom event loops). libsrt tightly couples protocol with threading.
4. **Tokio-native async** — Natural fit in Rust async ecosystems. No thread pool management.
5. **Zero system dependencies** — No OpenSSL, no pkg-config, no C toolchain. Single `cargo build`.
6. **Ergonomic access control API** — Rust trait + closure API is more composable than C callback. `HandshakeInfo` struct provides typed fields rather than requiring socket option queries.

## Where libsrt v1.5.5 Is Ahead

1. **Socket Groups / Bonding** — Broadcast and Main/Backup for hitless failover. The only remaining major feature gap. (Balancing mode still WIP even in libsrt.)
2. **Per-connection passphrase override** — libsrt's `srt_listen_callback` can set `SRTO_PASSPHRASE` per connection; bilbycast-srt's access control can accept/reject but not override the passphrase dynamically.
3. **C FFI maturity** — Used by FFmpeg, OBS, GStreamer, VLC. bilbycast-srt's FFI is scaffolding.
4. **Platform breadth** — Now includes Windows ARM64 and HarmonyOS. bilbycast-srt is untested on mobile/embedded.
5. **Ecosystem adoption** — De facto industry standard with broad tooling support.

## Interop Considerations

Since bilbycast-srt advertises version `0x010505`, it should verify:
- **Cookie contest logic** matches the restored v1.4.5 method (changed in v1.5.5)
- ~~**Packet filter late-rejection** handling~~ — **Done:** bilbycast-srt rejects with `RejectReason::Filter` when FEC parameters conflict during negotiation
- **AES-GCM 12-byte IV** (changed in v1.5.4, carried into v1.5.5)
- **Stream ID extension interop** — bilbycast-srt now sends and parses `SRT_CMD_SID` (ext type 5) in CONCLUSION; verify round-trip with libsrt callers and listeners

## Summary

bilbycast-srt now matches libsrt v1.5.5 on **access control**, **retransmission bandwidth shaping** (token bucket), **Stream ID sending and parsing**, **structured Stream ID format** (`#!::key=value`), and **FEC** (row-only, staircase/2D, ARQ integration, handshake negotiation). The only remaining major feature gap is **bonding/socket groups**. bilbycast-srt leads on AES-GCM maturity, memory safety, architectural cleanliness, and API ergonomics.

For bilbycast's use case (media transport gateway with its own relay infrastructure for redundancy), the bonding gap is mitigated by bilbycast-edge's own hitless redundancy and tunnel failover mechanisms.

### Feature coverage: ~95% of libsrt v1.5.5

| Category | Coverage |
|---|---|
| Core protocol (handshake, ARQ, TSBPD, timers) | 100% |
| Encryption (AES-CTR, AES-GCM, key rotation) | 100% (GCM ahead) |
| FEC (row, staircase, ARQ integration) | 100% |
| Congestion control (Live, File) | 100% |
| Access control (Stream ID, accept/reject) | ~90% (missing per-connection passphrase override) |
| Retransmit shaping (Token Bucket) | 100% |
| Connection modes (caller, listener, rendezvous) | 100% |
| Bonding / socket groups | 0% |
| C FFI | ~10% (scaffolding) |
