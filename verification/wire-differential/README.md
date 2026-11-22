# wire-differential

Checks `sakuya_wire`, `sakuya_wire_v1` and `sakuya_packet_protection_v1` against other QUIC
implementations and against adversarial input, and fuzzes the handshake
message readers of `kasen_handshake`. This package is not a member of the sakuya
workspace and has its own dependency graph; no package of the workspace
depends on it.

The references are quinn-proto 0.11.19, s2n-quic-core 0.91.0 and the QUIC
keys of rustls. The frame sets and transport parameters are read with version
1, DATAGRAM and RESET_STREAM_AT together, and with version 1 alone.

quinn-proto keeps its frame, packet and range set modules private, so
`vendor.sh` builds a copy under `vendor/quinn-proto` from the crates.io
package, checked against its SHA-256, that changes visibility only. The
changes are listed in `vendor/quinn-proto.visibility.diff`.

`tests/data/suites.txt` holds packet protection vectors for every AEAD from an
independent implementation, OpenSSL through the Python `cryptography` package;
`tools/gen_suite_vectors.py` regenerates them.

## Running

Run these from this directory, after creating the vendored copy. rustup
selects the toolchain of the repository root.

```sh
./vendor.sh
cargo test --release --tests
WIRE_CASES=2000000 cargo test --release --tests
cargo test --release --tests -- --test-threads=1 --nocapture
```

`WIRE_CASES` sets the proptest case count. `WIRE_EXPLORE=1` counts divergences
without failing, for looking at new categories. Each suite ends with a test
that prints the counts of every category and its first sample; run with one
thread and `--nocapture` to see them after the other tests.

The fuzz targets are `frames`, `parameters`, `headers`, `protection` and
`handshake_messages`, built with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz).
The seeds of `handshake_messages` are the RFC 8448 messages that the tests of
`kasen_handshake` hold, so `seed_corpus` also takes a checkout of
[nitori](https://github.com/opengensokyonet/nitori) at the commit that
`Cargo.toml` pins:

```sh
cargo run --release --example seed_corpus -- fuzz/corpus <nitori checkout>
cargo fuzz run --fuzz-dir fuzz -O frames fuzz/corpus/frames -- -max_total_time=600 -max_len=4096
```

`examples/explain.rs` prints what each implementation reads from a frame
payload, `examples/explore_s2n.rs` groups frame divergences by the error
s2n-quic-core reports, and `examples/measure.rs` times the readers on inputs
built to make them work.

## Reading the results

A comparison ends in agreement, in a named category of divergence, or in
failure. Every named category states which side RFC 8999, RFC 9000, RFC 9001,
RFC 9221 or the reliable stream reset draft supports; a divergence without a
category fails the test or the fuzz target.

Besides the comparisons, the tests check properties of sakuya alone: a frame
read and written again gives the bytes it was read from; transport parameters
written and read again give the same parameters; truncated input fails as
incomplete; every failure reports the transport error code or TLS alert the
RFCs name; a buffer with exactly the room a write takes receives the bytes a
growing buffer gets; a source that hands out its bytes in chunks of a few
bytes reads the variable-length integers, frames, transport parameters and
packet headers a contiguous slice reads.

The comparisons cover what the implementations read from a packet payload, a
transport parameter list, a datagram or a handshake message, what they write,
and Initial packet protection. Which frame may appear in which packet, stream
state, flow control and the handshake are outside them.
