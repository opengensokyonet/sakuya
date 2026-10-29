# sakuya

QUIC transport implementation for Open Gensokyo Network, administratively supported by Starspun Works.

The repository is at an early stage. It holds the pieces of a QUIC v1 implementation that are fixed by the protocol or already settled in design, built up incrementally; it does not yet provide a usable connection. The APIs are experimental and are not stable production APIs.

## Layout

- `crates/sakuya_wire`: wire-level value types (variable-length integers, connection IDs, stream IDs) and version-independent packet header interpretation.
- `crates/sakuya_protection`: packet protection primitives from RFC 9001: Initial secrets, key derivation, header protection, AEAD packet protection and the Retry integrity tag, behind a cryptographic backend trait.
- `crates/sakuya_datagram_routing`: routing of received UDP datagrams to registered deliverers, and the claim mechanism by which several candidates compete for one datagram.
- `crates/sakuya_stream`: per-stream send and receive components, their buffers, and connection-level flow-control credit accounting.

Byte IO and the call mechanism come from [nitori](https://github.com/opengensokyonet/nitori).

## Development

Install [rustup](https://rustup.rs/). The repository pins `nightly-2026-09-20` with rustfmt and Clippy in `rust-toolchain.toml`; run commands from the repository root so rustup selects this toolchain. Nightly language features are required. Packages remain unpublished (`publish = false`).

`nitori_call`, `nitori_io` and `snafu` are Git dependencies pinned to specific commits in `Cargo.toml`; Cargo fetches them automatically.

From the repository root:

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --doc
```

For development against sibling checkouts of nitori or SNAFU, an ignored `.cargo/config.toml` may patch their Git sources to local paths under `[patch."https://github.com/opengensokyonet/nitori"]` and `[patch."https://github.com/opengensokyonet/snafu"]`. Keep that configuration and the resulting path-source lockfile changes out of commits; the committed lockfile records the public Git sources.

## License

Software and code examples are licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Explanatory documentation is licensed under [CC BY 4.0](LICENSE-CC-BY). Contributors retain copyright in their contributions. Project names and logos are not licensed as trademarks by these licenses.
