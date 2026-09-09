# bilbycast-srt vs libsrt — Comparison (baseline v1.5.5)

**Date:** 2026-03-27
**Last updated:** 2026-09-08 (FEC parity claims corrected against `KNOWN_ISSUES.md` #1; upstream baseline note refreshed)

**Note:** the baseline is two releases stale. libsrt v1.5.5 shipped as a stable tag on 2026-04-17 and has since been superseded by v1.5.6 (2026-07-20) and v1.5.7 (2026-08-28) — v1.5.7 is what the sibling `bilbycast-libsrt-rs` vendors and builds (`libsrt-sys/vendor/srt/CMakeLists.txt`, `set (SRT_VERSION 1.5.7)`). Everything below still compares against v1.5.5, which is the version bilbycast-srt advertises on the wire (`0x010505`); see "What Changed from v1.5.5 to v1.5.7" for what that leaves unexamined.

## Overview

| | **bilbycast-srt** | **libsrt v1.5.5** |
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
| FEC (row-only) | **Partial** | Yes | Config: `"fec,cols:10,rows:1"`. Negotiated via `SRT_CMD_FILTER` (ext type 7) in handshake. Recovery is Rust↔Rust-only and only trustworthy at 0 % loss — see the FEC caveat below. |
| FEC (staircase/2D) | **Partial** | Yes | Config: `"fec,cols:10,rows:5,layout:staircase"`. 2D cascade recovery. Same sequence-allocation break as the row-only case. |
| FEC ARQ modes | Yes | Yes | `arq:always` (parallel), `arq:onreq` (FEC-first, default), `arq:never` (FEC-only). NAK suppression matches libsrt — but with FEC recovery itself unsound, `arq:onreq`'s FEC-first ordering inherits the caveat below. |
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

**FEC caveat — open, see [`KNOWN_ISSUES.md`](../KNOWN_ISSUES.md) #1.** The three FEC rows above describe what is *negotiated*, not what interoperates. The Rust encoder gives a parity packet the sequence number of the last data packet in its group (`srt-protocol/src/fec/encoder.rs:161` for rows, `:175` for columns) instead of allocating a dedicated FEC slot the way C++ libsrt does, and the decoder maps a packet to its row/column by naive integer division — `row_number = offset / cols` (`srt-protocol/src/fec/decoder.rs:201`). Against a C++ sender, whose FEC slots consume real sequence numbers, every data packet after the first parity packet lands in the wrong group: ~16 % phantom recoveries at 0 % loss, injecting garbage into the stream. Rust↔Rust is clean only at 0 % loss; under real loss the same `offset / cols` formula mis-bins around the gaps and yields roughly 9x the expected recoveries. `SendBuffer::next_packet()` (`srt-protocol/src/buffer/send.rs:177`) has no FEC-slot skip, and neither `FecSeqMap` nor `allocate_fec_seq` exists in the tree yet — the fix is the three-phase plan in `KNOWN_ISSUES.md`.

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

## What Changed from v1.5.5 to v1.5.7

Two releases have landed on top of the v1.5.5 baseline this document compares against: v1.5.6 (2026-07-20) and v1.5.7 (2026-08-28). Both are dominated by memory-safety hardening of the control plane. The upstream commits are cited rather than CVE identifiers — nothing in the vendored tree names one, and the only reference is an untagged commit subject.

| v1.5.6 / v1.5.7 change | Impact on comparison |
|---|---|
| **KMREQ length bound + KEK rollback** (`c63c311e`, PR #3345) — `processSrtMsg_KMREQ` gained a `bytelen > HCRYPT_MSG_KM_MAX_SZ` check before the `memcpy` into a fixed message buffer, plus a rollback of the KEK when `km_unwrap` fails on a spoofed KMREQ | Structurally non-applicable. `KeyMaterialMessage::deserialize` (`srt-protocol/src/crypto/km_exchange.rs:214`) bounds-checks every field, clamps `slen` to 16, and sizes the wrapped-key `Vec` from the remaining bytes — there is no fixed destination buffer to overrun. There is no persistent KEK to roll back either: the KEK is derived locally per KM message and `peer_sek` / `peer_salt` are assigned only after `unwrap_key` returns `Ok` (`srt-transport/src/listener.rs:416-429`) |
| **`FECFilterBuiltin::ClipData` payload clamp** (`6f817b63`, PR #3359) — `if (payload_size > payloadSize()) payload_size = payloadSize();` before the XOR clip | Already safe, by the opposite mechanism. The Rust clip grows its destination instead of clamping its source: `xor_into` (`srt-protocol/src/fec/mod.rs:362`) resizes `parity_payload` up to an oversized payload's length before XOR-ing, so there is no fixed clip buffer to run past — but where libsrt truncates the rogue packet, Rust widens the group. The bound on the way out is separate: `try_recover` slices `parity_payload[..recovered_len]` only when `recovered_len > 0 && recovered_len <= self.parity_payload.len()`, else it falls back to the whole parity buffer (`srt-protocol/src/fec/decoder.rs:114-119`) |
| **Rogue control-message / OOB-read hardening** (LOSSREPORT range parsing, DROPREQ payload parsing, `CRcvBuffer::dropMessage` range, KMRSP wire length) | Not audited against bilbycast-srt. These are bounds bugs in C parsers; Rust's slicing panics rather than reads out of bounds, but a panic in a control-packet parser is still a denial of service, so the corresponding paths deserve a fuzz pass |
| **Everything else in v1.5.6 / v1.5.7** | Unexamined — the feature-parity tables above have not been re-derived against anything newer than v1.5.5 |

## Where bilbycast-srt Is Ahead

1. **AES-GCM is production-ready** — libsrt v1.5.5 still gates GCM behind a preview build flag with open issues (TSBPD required, listener can't force GCM mode, epic #2336 incomplete).
2. **Memory safety by construction** — Many v1.5.5 fixes (buffer overflow, data races, lock-order inversions, reentrancy bugs, use-after-free patterns) are structurally impossible in Rust.
3. **Clean protocol/transport separation** — `srt-protocol` has zero I/O dependencies, embeddable in any runtime (WASM, no_std, custom event loops). libsrt tightly couples protocol with threading.
4. **Tokio-native async** — Natural fit in Rust async ecosystems. No thread pool management.
5. **Zero system dependencies** — No OpenSSL, no pkg-config, no C toolchain. Single `cargo build`.
6. **Ergonomic access control API** — Rust trait + closure API is more composable than C callback. `HandshakeInfo` struct provides typed fields rather than requiring socket option queries.

## Where libsrt v1.5.5 Is Ahead

1. **Socket Groups / Bonding** — Broadcast and Main/Backup for hitless failover. The only remaining major feature gap. (Balancing mode still WIP even in libsrt.) Note: bilbycast-srt ships bonding *config scaffolding* only — `SrtConfig::group_connect` + `group_min_stable_timeout` exist (`srt-protocol/src/config.rs`) but there is no working group data-plane behind them, so the functional "No" above is accurate.
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

bilbycast-srt now matches libsrt v1.5.5 on **access control**, **retransmission bandwidth shaping** (token bucket), **Stream ID sending and parsing**, and **structured Stream ID format** (`#!::key=value`). **FEC** negotiates and configures at parity but does not interoperate — the sequence-allocation mismatch in `KNOWN_ISSUES.md` #1 makes recovery unsound against a C++ sender at any loss rate, and against a Rust sender above 0 % loss. The remaining major feature gaps are **FEC interop** and **bonding/socket groups**. bilbycast-srt leads on AES-GCM maturity, memory safety, architectural cleanliness, and API ergonomics.

For bilbycast's use case (media transport gateway with its own relay infrastructure for redundancy), the bonding gap is mitigated by bilbycast-edge's own hitless redundancy and tunnel failover mechanisms.

### Feature coverage: ~90% of libsrt v1.5.5

| Category | Coverage |
|---|---|
| Core protocol (handshake, ARQ, TSBPD, timers) | 100% |
| Encryption (AES-CTR, AES-GCM, key rotation) | 100% (GCM ahead) |
| FEC (row, staircase, ARQ integration) | ~60% — negotiation and configuration complete, recovery sound only Rust↔Rust at 0% loss; C++ interop and lossy-link seq mapping open (`KNOWN_ISSUES.md` #1) |
| Congestion control (Live, File) | 100% |
| Access control (Stream ID, accept/reject) | ~90% (missing per-connection passphrase override) |
| Retransmit shaping (Token Bucket) | 100% |
| Connection modes (caller, listener, rendezvous) | 100% |
| Bonding / socket groups | 0% |
| C FFI | ~10% (scaffolding) |
