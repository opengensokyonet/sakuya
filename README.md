# sakuya

QUIC transport implementation for Open Gensokyo Network, administratively supported by Starspun Works.

The repository is at an early stage. It holds the pieces of a QUIC v1 implementation that are fixed by the protocol or already settled in design, built up incrementally; it does not yet provide a usable connection. The APIs are experimental and are not stable production APIs.

## Layout

- `crates/sakuya_wire`: wire-level value types (variable-length integers, connection IDs, stream IDs) and version-independent packet header interpretation.
- `crates/sakuya_protection`: packet protection primitives from RFC 9001: Initial secrets, key derivation, header protection, AEAD packet protection and the Retry integrity tag, behind a cryptographic backend trait.
- `crates/sakuya_link`: links, link bindings and link drivers; currently the identities of link bindings (`BindingId`) and links (`LinkId`), unique within a process, where each link identity also records the identity of the link binding that produced it.
- `crates/sakuya_datagram_routing`: routing of received UDP datagrams to registered deliverers, and the claim mechanism by which several candidates compete for one datagram.
- `crates/sakuya_stream`: per-stream send and receive components, their buffers, and connection-level flow-control credit accounting.

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
