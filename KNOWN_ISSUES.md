# Known Issues — bilbycast-srt

## 1. FEC C++ Interop: Sequence Number Allocation Mismatch

**Status:** Open — blocks FEC interop with C++ libsrt (v1.5.x) AND causes phantom recoveries on Rust ↔ Rust under loss  
**Affects:** Any FEC link with actual packet loss. 0% loss works perfectly. ARQ-only works perfectly at all loss rates.  
**Severity:** FEC recovery produces ~9x more recoveries than expected (phantom groups), injecting corrupt data. At severe loss (10%) FEC still helps net (4 errors vs 7 ARQ-only). At mild-moderate loss, ARQ-only is cleaner.

### Symptoms

When a C++ `srt-live-transmit` sends with FEC (`packetfilter=fec,cols:10,rows:5,layout:staircase,arq:onreq`) to a Rust `bilbycast-edge` receiver:

- ~16% phantom FEC recoveries at 0% loss (garbage data injected)
- TS sync loss and H.264 decode errors from injected garbage
- Connection is stable (no timeouts or drops)
- Rust → Rust link in the same chain has 0 phantom recoveries

### Root Cause

The Rust and C++ encoders allocate FEC parity packet sequence numbers differently:

| | Data seqs | FEC parity seqs | Seqs per matrix (cols=10, rows=5) |
|---|---|---|---|
| **Rust encoder** | 0, 1, 2, ..., 49 | Shares seq with last data packet in group (e.g., row FEC at seq 9, col FEC at seq 49) | 50 (no separate FEC slots) |
| **C++ libsrt** | 0-9, 11-20, 22-31, ... (gaps at FEC positions) | Unique seqs: row FEC at 10, 21, 32, ...; col FECs at 55-64 | 65 (50 data + 15 FEC) |

The Rust decoder maps received sequence numbers to row/column positions using simple integer division: `row = offset / cols`, `col = offset % cols`. This works for Rust senders (consecutive data seqs) but fails for C++ senders because the FEC slots at seq 10, 21, etc. shift all subsequent data offsets.

Example: C++ data at seq 11 (first data of row 1) → `offset = 11`, `col = 11 % 10 = 1`. But it should be col 0 (first column of row 1). The row FEC at seq 10 shifted the offset by 1.

### What Needs to Change

**Phase 1: Make the Rust encoder allocate separate FEC sequence numbers (matching C++ libsrt)**

The send buffer (`srt-protocol/src/buffer/send.rs`) needs to:
1. Accept a `FecSeqMap` (or equivalent) that defines which sequence positions are FEC slots
2. Skip FEC slot positions when assigning sequence numbers to data packets via `next_packet()`
3. Provide `allocate_fec_seq()` for the send loop to get the next FEC slot's sequence number

The send loop (`srt-transport/src/send_loop.rs`) needs to:
1. After the encoder returns FEC packets, call `send_buf.allocate_fec_seq()` to get the correct seq (instead of using `fec_pkt.seq_no` from the encoder)
2. The encoder's returned `seq_no` field becomes unused (or removed)

**Phase 2: Update the decoder to handle FEC-aware sequence mapping**

The decoder (`srt-protocol/src/fec/decoder.rs`) `on_data_packet()` needs to:
1. Use a `FecSeqMap` to convert raw seq offsets to data positions (accounting for FEC slots)
2. Replace `row = offset / cols` with `seq_map.seq_offset_to_data_position(offset)`
3. The `DataPosition` struct already exists in `fec/mod.rs` — use its `row_number`, `row_index`, and `col_index` fields

The `FecSeqMap` (`srt-protocol/src/fec/mod.rs`) column assignment must use C++ libsrt's formula:
```
col_index = (seq_offset_within_row) % cols
```
where `seq_offset_within_row` is the sequence-space offset from the current row's start (including any col FEC slots emitted within the row). This naturally produces the staircase pattern because the row base advances by `cols` (not `cols + number_of_FEC_in_row`), leaving a 1-position shift per row.

**Phase 3: Fix the FEC parity XOR basis**

C++ libsrt calls `feedSource()` AFTER encryption in `packData()`, so FEC parity = XOR(ciphertexts). The Rust receiver already feeds ciphertext (`raw_payload`) to the decoder (fixed 2026-04-01). The Rust sender also feeds ciphertext (`payload_for_fec`, which is post-encryption). This is correct and should be preserved.

### Key Files

| File | What to change |
|------|----------------|
| `srt-protocol/src/buffer/send.rs` | Add FEC seq map, skip FEC slots in `next_packet()`, add `allocate_fec_seq()` |
| `srt-protocol/src/fec/mod.rs` | `FecSeqMap::new()` column formula, `DataPosition.col_index` field |
| `srt-protocol/src/fec/decoder.rs` | Use `FecSeqMap` for seq→position mapping instead of `offset/cols` |
| `srt-protocol/src/fec/encoder.rs` | Remove `seq_no` from `FecPacketData` (send loop allocates seqs) |
| `srt-transport/src/send_loop.rs` | Use `send_buf.allocate_fec_seq()` for FEC packet seq numbers |
| `srt-transport/src/connection.rs` | Pass FEC config to send buffer in `init_fec()` |

### Testing

1. `cargo test -p srt-protocol` — all FEC unit tests
2. `cargo run --release --example fec_test` — Rust ↔ Rust: must show 0 drops, 0 phantom recoveries
3. C++ interop: `srt-live-transmit` with FEC → `bilbycast-edge` → verify 0 phantom recoveries, 0 CC errors, 0 decode errors (use `testbed/ARQ_TEST.md` FEC+ARQ procedure)

### Additional Issue: Phantom FEC Recoveries Under Loss

Even Rust ↔ Rust FEC produces ~9x more recoveries than expected when packets are actually lost. At 2% loss with ~25000 packets: expected ~490 recoveries, actual ~4400. The phantom recoveries come from the decoder's simple `offset / cols` formula incorrectly mapping some data packets to wrong row/column groups when gaps exist from lost packets. The phantom-recovered data is garbage (XOR of wrong packet set).

**Fix applied (2026-04-01)**: `receive.rs` `insert()` now allows overwriting FEC placeholders with recovered data. Previously, when a lost packet's seq was shared by the FEC parity, the placeholder blocked the legitimate recovered data from being inserted. This reduced CC errors from ~2400 to ~14-114 depending on profile.

**Remaining**: the phantom recoveries themselves need to be eliminated by fixing the sequence allocation (Phase 1 above).

### Previous Attempts

- A previous session attempted this refactor (changes to encoder.rs, decoder.rs, buffer/send.rs) but introduced a bug that caused complete connection hangs. Those changes were reverted.
- The column assignment formula was also attempted (2026-04-01) but couldn't work without the send buffer FEC seq allocation because the encoder and decoder disagreed on whether FEC slots exist in the sequence space.
- The FEC placeholder overwrite fix (2026-04-01) was successful and should be kept.

---

## 2. ARQ Latency Requirement for Bidirectional Impairment

**Status:** Documented — not a bug, operational guidance  
**Affects:** ARQ performance under loss with impairment proxies

With bidirectional impairment (both data AND control packets face loss), the SRT latency must be ~30× RTT (not the commonly cited 12× RTT). At 2% bidirectional loss with RTT=100ms:

- 1500ms latency: ~298 sender-side DropReq drops, 3 decode errors
- 3000ms latency: 0 drops, 0 decode errors

The extra margin is needed because NAK packets also face loss, delaying retransmission requests. The C++ sender drops packets from its send buffer after `latency + ~10ms` (SNDDROPDELAY), so the receiver must ensure retransmissions complete within this window.

The `testbed/ARQ_TEST.md` impairment profile table has been updated with correct latency values.
