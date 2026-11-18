# interop

Interoperability runs of sakuya against itself and against
[quic-go](https://github.com/quic-go/quic-go), with both programs of a run in
docker containers on one docker network and no network simulator in between.
The `Interop` workflow runs them weekly and on demand; they do not gate
pushes. Runs through the QUIC interop runner and its network simulator, with
more peers, are in [`../interop-runner`](../interop-runner/README.md).

The programs are the hq-interop server and client of `sakuya_interop` and,
for quic-go, its own interop server and client plus `quic-go-ext-peer`, a
small program in this directory that adds the two test cases the QUIC interop
runner does not have: `datagram` (RFC 9221) and `resetstreamat`
(RESET_STREAM_AT, draft-ietf-quic-reliable-stream-reset).

## Test cases

`handshake`, `transfer`, `multiconnect`, `chacha20` and `retry` are the
interop runner's test cases of the same names; `datagram` and `resetstreamat`
are the extension cases above. `matrix.sh` runs all seven for sakuya against
sakuya, and for each direction between sakuya and quic-go.

## Prerequisites

- docker, with permission to run containers without `sudo`; the image
  `archlinux:latest` (override with `IMAGE`) is pulled on first use
- OpenSSL, for `certs.sh`
- a Rust toolchain (the repository's `rust-toolchain.toml` selects it)
- Go, at the version in `quic-go-ext-peer/go.mod`
- git, to fetch quic-go

## Running

From the repository root:

```sh
export SAKUYA_BIN_DIR=$PWD/target/release
export QUIC_GO_BIN_DIR=$PWD/target/quic-go-bin
export OUT=$PWD/interop-out

# sakuya's programs; the feature enables the datagram and resetstreamat cases
cargo build --locked --release -p sakuya_interop --features extensions

# quic-go's programs, at the commit that quic-go-ext-peer/go.mod is pinned to
git clone https://github.com/quic-go/quic-go.git target/quic-go
git -C target/quic-go checkout ebcbd4bf2bfb0f3814d9969f95fe040ba0a8ff6a
mkdir -p "$QUIC_GO_BIN_DIR"
(cd target/quic-go && go build -o "$QUIC_GO_BIN_DIR/server" ./interop/server \
  && go build -o "$QUIC_GO_BIN_DIR/client" ./interop/client)
(cd verification/interop/quic-go-ext-peer && go build -o "$QUIC_GO_BIN_DIR/ext-peer" .)

# the whole matrix
verification/interop/matrix.sh

# one run: <server> <client> <testcase>
verification/interop/run.sh sakuya quic-go resetstreamat
```

`SAKUYA_BIN_DIR` holds `sakuya-interop-server` and `sakuya-interop-client`;
`QUIC_GO_BIN_DIR` holds `server`, `client` and `ext-peer`. `OUT` is the run
directory (default `./interop-out`). `run.sh` makes the test certificates
there with `certs.sh` when they are missing. The binaries run inside the
container, so they must be built for a Linux host whose libc is not newer than
the image's.

Each run leaves its files in `$OUT/<server>-to-<client>-<testcase>/`: the
served files (`www`), the downloaded files (`downloads`), both programs' output
(`server.out`, `client.out`) and TLS key logs (`keys.log`).

## Verdicts

`run.sh` exits 0 when a run passes and 1 when it fails; `matrix.sh` prints a
summary and exits non-zero when any run failed.

- `handshake`, `transfer`, `multiconnect`, `chacha20`, `retry`: the client
  exits 0 and every requested file is downloaded and identical to the served
  file, byte for byte.
- `datagram`: the client exits 0 and its summary reports every one of its 50
  datagrams (8 to 1130 bytes) echoed back, with none missing, mismatched or
  unexpected.
- `resetstreamat`: the client exits 0 and, for each file, the answer ended
  with a reset with application error code 0x52, and the bytes saved are a
  prefix of the served file at least half its size.
