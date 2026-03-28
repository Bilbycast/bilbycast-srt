# srt-protocol

Pure Rust implementation of the SRT (Secure Reliable Transport) protocol logic.

This crate contains all protocol state machines, packet serialization, cryptography, buffering, and congestion control -- with **no I/O or async runtime dependencies**. It can be used standalone to build custom SRT transports or embedded in other protocol stacks.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
srt-protocol = { path = "../srt-protocol" }
```

### Disable encryption (smaller binary)

```toml
[dependencies]
srt-protocol = { path = "../srt-protocol", default-features = false }
```

## Module Overview

### `packet` - Wire Format

SRT packets use a 128-bit (16-byte) header followed by a payload:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|F|        (depends on packet type)                             |  ← header[0]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        (depends on packet type)                               |  ← header[1]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Timestamp                              |  ← header[2]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Destination Socket ID                         |  ← header[3]
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `F=0`: Data packet (sequence number, message number, in-order flag, encryption key)
- `F=1`: Control packet (type, subtype, additional info)

**Key types:**
- `SrtPacket` - Parsed SRT packet with header and payload
- `SeqNo` - 31-bit circular sequence number with wrapping arithmetic
- `MsgNo` - 26-bit message number with boundary and retransmission flags
- `ControlType` - ACK, NAK, Handshake, Keepalive, Shutdown, DropReq, AckAck

### `protocol` - State Machines

- `handshake` - HSv5 handshake with INDUCTION/CONCLUSION phases, SRT extensions (HSREQ/HSRSP, KMREQ/KMRSP, stream ID)
- `connection` - Connection lifecycle: `Init -> Opened -> Connecting -> Connected -> Broken -> Closed`
- `ack` - ACK/ACKACK/NAK generation, RTT tracking, flow/congestion window management
- `timer` - Periodic timers for ACK (10ms), NAK, keepalive (1s), expiration
- `tsbpd` - Timestamp-Based Packet Delivery with clock drift tracking (1000-sample window, 5ms max drift)

### `buffer` - Send/Receive Buffers

- `send` - Message-to-packet segmentation, retransmission queue
- `receive` - Circular buffer with TSBPD delivery scheduling, packet reordering
- `loss_list` - Send/receive loss tracking for ARQ (Automatic Repeat reQuest)
- `tools` - Rate estimation utilities

### `congestion` - Congestion Control

Pluggable congestion control via the `CongestionControl` trait:

- `LiveCC` - LIVE mode: constant-rate sending with too-late packet drop
- `FileCC` - FILE mode: TCP-like AIMD (Additive Increase, Multiplicative Decrease) with slow start

### `crypto` - Encryption (feature-gated)

All crypto uses pure-Rust [RustCrypto](https://github.com/RustCrypto) crates:

- `key_material` - PBKDF2-HMAC-SHA1 key derivation (2048 iterations), AES Key Wrap (RFC 3394)
- `aes_ctr` - AES-CTR encryption (128/192/256-bit)
- `aes_gcm` - AES-GCM authenticated encryption (128/256-bit; 192-bit not supported)
- `km_exchange` - Key Material message encoding/decoding for KMREQ/KMRSP
- `mod` - CryptoControl state machine with even/odd key rotation

### `fec` - Forward Error Correction

- XOR-based row/column FEC packet recovery
- Configurable FEC group layout (row, staircase)

### `config` - Socket Options

`SrtConfig` contains all configurable parameters:

- **Latency**: `recv_latency` (receiver buffer), `peer_latency` (sender-side minimum)
- **Buffers**: `send_buffer_size`, `recv_buffer_size` (bytes), `flight_flag_size` (flow control window, packets)
- **Bandwidth**: `max_bw` (total send rate cap), `input_bw` (estimated input rate), `overhead_bw` (overhead %), `max_rexmit_bw` (retransmit cap via Token Bucket)
- **Encryption**: `passphrase`, `key_size` (128/192/256), `crypto_mode` (AES-CTR or AES-GCM), `enforced_encryption` (reject unencrypted peers), `km_refresh_rate` / `km_pre_announce` (key rotation timing)
- **Transport**: `trans_type` (Live/File), `payload_size` (default 1316 for MPEG-TS), `mss` (max segment size)
- **Connection**: `connect_timeout`, `peer_idle_timeout`, `rendezvous`
- **Live mode**: `tsbpd_mode`, `tlpkt_drop` (too-late drop), `send_drop_delay`, `nak_report`, `drift_tracer`
- **Tuning**: `retransmit_algo` (Default or Reduced), `loss_max_ttl` (reorder tolerance), `ip_tos` (DSCP)
- **Access control**: `stream_id`, `packet_filter` (FEC config string)
- **Congestion**: `congestion` controller type ("live" or "file")

### `error` - Error Types

`SrtError` enum with 35+ error codes matching the C++ `SRT_ERRNO` values.

## Examples

### Packet serialization round-trip

```rust
use srt_protocol::packet::SrtPacket;
use bytes::{Bytes, BytesMut};

// Create a data packet
let packet = SrtPacket::new_data(
    0,          // sequence number
    0,          // message number (with flags)
    12345,      // timestamp
    42,         // destination socket ID
    Bytes::from_static(b"Hello SRT"),
);

// Serialize
let mut buf = BytesMut::new();
packet.serialize(&mut buf);

// Deserialize
let parsed = SrtPacket::parse(&buf).unwrap();
assert_eq!(parsed.payload(), b"Hello SRT");
```

### Key derivation

```rust
use srt_protocol::crypto::key_material::{derive_kek, wrap_key, unwrap_key, generate_salt, generate_sek};
use srt_protocol::config::KeySize;

let salt = generate_salt();
let kek = derive_kek("my_passphrase", &salt, KeySize::AES256);
let sek = generate_sek(KeySize::AES256);

let wrapped = wrap_key(&kek, &sek).unwrap();
let unwrapped = unwrap_key(&kek, &wrapped).unwrap();
assert_eq!(sek, unwrapped);
```

## Testing

```bash
cargo test -p srt-protocol

# Run with output
cargo test -p srt-protocol -- --nocapture
```

## License

[Mozilla Public License 2.0](../LICENSE)
