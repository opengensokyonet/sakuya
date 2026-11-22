# sakuya

QUIC transport implementation for Open Gensokyo Network, administratively supported by Starspun Works.

The repository is at an early stage. It holds a QUIC version 1 implementation: a client and a server connect through endpoints over UDP, complete the handshake, and open streams to send and receive data, and they interoperate with quinn, quiche and quic-go. The APIs are experimental and are not stable production APIs.

## Layout

Each package has its own documentation in its `src/lib.rs`; `cargo doc --workspace --no-deps --open` builds it.

### Wire formats

- `crates/sakuya_wire`: the wire-level value types that every QUIC version shares (RFC 8999: versions, raw connection IDs, version-independent headers) and the composition of parts (`parts`), read and written whole in memory over `Buf` and `BufMut`; it depends on `nitori_io`.
- `crates/sakuya_wire_v1`: the wire-level value types of QUIC version 1 (RFC 9000: variable-length integers, connection IDs, stream IDs, packet numbers, version 1 headers and packets, frames, parameters and transport parameters); it depends on `sakuya_wire`, `nitori_io` and `nitori_call`.

### Packet protection

- `crates/sakuya_packet_protection_v1`: the packet protection primitives of RFC 9001 (Initial secrets, key derivation, header protection, AEAD protection, the Retry integrity tag) behind a cryptographic backend trait; it depends on `sakuya_wire_v1`, `nitori_tls` and `nitori_crypto`.
- `crates/sakuya_packet_protection_ring`: the `ring` implementation of the cryptographic backend trait of `sakuya_packet_protection_v1`; it depends on `sakuya_packet_protection_v1`, `nitori_crypto` and `ring`.
- `crates/sakuya_packet_protection_aws_lc`: the `aws-lc-rs` implementation of the cryptographic backend trait of `sakuya_packet_protection_v1`; it depends on `sakuya_packet_protection_v1`, `nitori_crypto` and `aws-lc-rs`.

### Recovery

- `crates/sakuya_recovery_v1`: loss recovery, congestion control (NewReno, CUBIC, BBRv3) and datagram size probing for a link path, as replaceable traits with implementations; it depends on `sakuya_wire_v1` and `sakuya_link` and reads no clock.

### Streams

- `crates/sakuya_stream_v1`: the send and receive components of a stream, synchronous cores that take the resets of RFC 9000; it depends on `sakuya_wire` and `sakuya_wire_v1`.

### Connections

- `crates/sakuya_connection`: the structure a QUIC connection is composed in, a tree of nodes driven as one future, with QUIC version 1 as its first part; it depends on `sakuya_stream_v1`, `sakuya_recovery_v1`, `sakuya_packet_protection_v1`, `sakuya_datagram_routing_v1`, `sakuya_link`, `sakuya_clock`, `sakuya_wire` and `sakuya_wire_v1`.

### Endpoints

- `crates/sakuya_endpoint_v1`: QUIC endpoints with a server role, a client role or both, their reflow driver, binding drivers, address validation, and incoming and outgoing connections; it depends on `sakuya_connection`, `sakuya_datagram_routing_v1` and `nitori_sync`.
- `crates/sakuya_datagram_routing_v1`: the routing of received UDP datagrams to registered deliverers, and the claim mechanism by which several candidates compete for one datagram; it depends on `sakuya_link`, `sakuya_wire` and `sakuya_wire_v1`.

### Host adapters

- `crates/sakuya_clock`: the `MonotonicClock` trait, the clock and timer that a connection's driver reads and sleeps on.
- `crates/sakuya_clock_tokio`: `TokioClock`, the `MonotonicClock` of a tokio runtime; it depends on `sakuya_clock`.
- `crates/sakuya_link`: the `Link` trait, a channel for whole datagrams between this side and one peer, the link binding traits and the identity of a link; it depends on `nitori_id` and `nitori_io`.
- `crates/sakuya_udp_tokio`: UDP link bindings and links over a tokio runtime, on Linux, with ECN, GSO and GRO; it depends on `sakuya_link` and `sakuya_clock`, and makes its socket calls through `nix` and `rustix`.
- `crates/sakuya_sync_std`: the wrappers and tables for an endpoint's shared state that synchronize with the locks of std, for hosts whose handles, drivers and connections are on several threads; it depends on `sakuya_connection`, `sakuya_datagram_routing_v1`, `sakuya_endpoint_v1` and `nitori_sync`.

### Diagnostics and testing

- `crates/sakuya_qlog_v1`: `QlogWriter`, which writes the events of a connection as a qlog JSON-SEQ file; it depends on `sakuya_connection` and `sakuya_clock`.
- `crates/sakuya_test_support`: what the tests and test programs of the workspace share (test certificates, a verifier for test roots, measuring counters, a network in memory with impairments); not for production use.
- `crates/sakuya_interop`: an hq-interop server and client for the QUIC interop runner, with test cases of their own for the DATAGRAM and reliable stream reset extensions; not for production use.

### Extensions

An extension of QUIC version 1 has one package in each layer it changes, named `sakuya_<layer>_<extension>`, which depends on the package of its layer and on the packages of the same extension in the layers below; the layers are `wire`, `stream`, `connection` and `qlog`, and an extension adds no package to a layer it does not touch (DATAGRAM has none in `stream`).

| | wire | stream | connection | qlog |
| --- | --- | --- | --- | --- |
| DATAGRAM (RFC 9221) | `sakuya_wire_datagram` | — | `sakuya_connection_datagram` | `sakuya_qlog_datagram` |
| RESET_STREAM_AT (reliable stream reset draft) | `sakuya_wire_reset_stream_at` | `sakuya_stream_reset_stream_at` | `sakuya_connection_reset_stream_at` | `sakuya_qlog_reset_stream_at` |

### Verification

None of these is a member of the workspace, and no package of the workspace depends on them; each has a README.

- `verification/wire-differential`: differential, robustness and fuzz tests of `sakuya_wire`, `sakuya_wire_v1` and `sakuya_packet_protection_v1` against quinn-proto, s2n-quic-core and rustls.
- `verification/routing-shuttle`: Shuttle models of `sakuya_datagram_routing_v1` composed with the tables of `sakuya_sync_std`.
- `verification/claim-loom`: loom models of the claim core of `sakuya_datagram_routing_v1`.
- `verification/interop`: runs of the `sakuya_interop` programs against themselves and quic-go in docker containers, by a weekly and on-demand workflow.
- `verification/interop-runner`: runs of the QUIC Interop Runner between sakuya and sixteen other implementations, by a daily and on-demand workflow, with the results published at <https://opengensokyo.net/interop/>.

Byte IO, the call mechanism, process-unique identities, cryptographic capabilities, the families that synchronize shared state and the TLS 1.3 handshake come from [nitori](https://github.com/opengensokyonet/nitori).

## Development

Install [rustup](https://rustup.rs/). The repository pins `nightly-2026-11-03` with rustfmt and Clippy in `rust-toolchain.toml`; run commands from the repository root so rustup selects this toolchain. Nightly language features are required. Packages remain unpublished (`publish = false`).

`nitori_call`, `nitori_crypto`, `nitori_id`, `nitori_io`, `nitori_sync` and `nitori_tls` are Git dependencies on [nitori](https://github.com/opengensokyonet/nitori), and `snafu` is a Git dependency, each pinned to a specific commit in `Cargo.toml`; Cargo fetches them automatically. The workspace takes `nitori_call`, `nitori_io`, `nitori_sync` and `nitori_tls` without their default `std` feature, and the packages and tests that use what needs the standard library turn it on. `sakuya_interop`, `sakuya_test_support` and the tests of `sakuya_connection`, `sakuya_connection_datagram`, `sakuya_connection_reset_stream_at` and `sakuya_endpoint_v1` also use `nitori_crypto_aws_lc`, which builds aws-lc-rs from C sources and needs a C compiler and CMake.

From the repository root:

```sh
cargo fmt --all --check
for package in crates/*/; do cargo clippy --locked -p "$(basename "$package")" --all-targets -- -D warnings; done
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --doc
```

For development against local checkouts of nitori or SNAFU, an ignored `.cargo/config.toml` may patch their Git sources to local paths under `[patch."https://github.com/opengensokyonet/nitori"]` and `[patch."https://github.com/opengensokyonet/snafu"]`. Keep that configuration and the resulting lockfile changes out of commits; the committed lockfile records the public sources.

## License

Software and code examples are licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Explanatory documentation is licensed under [CC BY 4.0](LICENSE-CC-BY). Contributors retain copyright in their contributions. Project names and logos are not licensed as trademarks by these licenses.
