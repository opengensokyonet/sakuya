# sakuya

QUIC transport implementation for Open Gensokyo Network, administratively supported by Starspun Works.

The repository is at an early stage. It holds parts of a QUIC version 1 implementation and does not yet provide a usable connection. The APIs are experimental and are not stable production APIs.

## Layout

- `crates/sakuya_wire`: wire-level value types (variable-length integers and fields that keep the width of their encoding, connection IDs and their lengths, stateless reset tokens, stream IDs, stream counts, packet numbers, versions, error codes), version-independent packet header interpretation, QUIC version 1 frames (with the DATAGRAM frame of RFC 9221 and the RESET_STREAM_AT frame of the reliable stream reset draft as caller-enabled extensions) and transport parameters. Every wire format is read and written as `nitori_call` operations, which also run synchronously on byte slices and `Bytes`; payload fields are chunks of the source, without copying. A frame value states every detail of its encoding (the width of each variable-length integer, which optional fields are present, the raw fields of ACK), so reading a frame and writing it again reproduces its bytes; the Frame Type must use its shortest encoding.
- `crates/sakuya_protection`: packet protection primitives from RFC 9001: Initial secrets, key derivation, header protection, AEAD packet protection, truncation of packet numbers in the Packet Number field and the Retry integrity tag, behind a cryptographic backend trait with a `ring` implementation (the default `ring` feature). It depends on `sakuya_wire` for the connection IDs and packet numbers it takes.
- `crates/sakuya_link`: the identities of link bindings (`BindingId`) and links (`LinkId`), unique within a process, where each link identity also records the identity of the link binding that produced it.
- `crates/sakuya_datagram_routing`: routing of received UDP datagrams to registered deliverers (a shared-bucket index keyed by connection ID or link binding, registrations revoked by RAII handles, frozen candidate groups, non-inline reflow of unclaimed datagrams, re-examination and publication of new Initial receivers, and a hook for stateless reset detection), and the claim mechanism by which several candidates compete for one datagram.
- `crates/sakuya_stream`: per-stream send and receive components. The send direction has connection-level credit reservation and commitment, a send buffer contract with an implementation keyed by stream offset, and a stream sender with its flow-control and termination policies; the receive direction has a receive buffer contract with a fragment-map implementation, connection-level receive accounting, and a stream receiver with reads, local stop requests and policy-driven delivery boundaries. Both directions are synchronous cores; waiting and async adapters are not implemented.

Byte IO, the call mechanism and process-unique identities come from [nitori](https://github.com/opengensokyonet/nitori).

## Development

Install [rustup](https://rustup.rs/) and clone [nitori](https://github.com/opengensokyonet/nitori) next to this repository, so that it is available as `../nitori`. The repository pins `nightly-2026-09-20` with rustfmt and Clippy in `rust-toolchain.toml`; run commands from the repository root so rustup selects this toolchain. Nightly language features are required. Packages remain unpublished (`publish = false`).

During development, `nitori_call`, `nitori_id` and `nitori_io` are path dependencies on that sibling checkout, and `Cargo.lock` records them as path sources. `snafu` is a Git dependency pinned to a specific commit in `Cargo.toml`; Cargo fetches it automatically.

From the repository root:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --doc
```

For development against a local checkout of SNAFU, an ignored `.cargo/config.toml` may patch its Git source to a local path under `[patch."https://github.com/opengensokyonet/snafu"]`. Keep that configuration and the resulting lockfile changes out of commits; the committed lockfile records the public SNAFU source.

## License

Software and code examples are licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Explanatory documentation is licensed under [CC BY 4.0](LICENSE-CC-BY). Contributors retain copyright in their contributions. Project names and logos are not licensed as trademarks by these licenses.
