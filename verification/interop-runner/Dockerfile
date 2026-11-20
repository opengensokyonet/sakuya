# The endpoint image of sakuya for the QUIC interop runner: the hq-interop
# server and client of sakuya_interop, on the runner's endpoint image.
#
# Build from the repository root:
#   docker build -f verification/interop-runner/Dockerfile -t sakuya-interop:runner .
#
# Dependencies come from the public sources that Cargo.lock records; the
# build context leaves out .cargo/ (see Dockerfile.dockerignore), so a local
# .cargo/config.toml that patches them to local paths does not apply here.

# The build stage runs the same Ubuntu release as the endpoint image, so the
# programs need no newer glibc than the endpoint has (2.39).
ARG BUILD_IMAGE=ubuntu:24.04@sha256:73b999393d07f2bf65a40373778a44dc9a6d54ad7718d29247d8ff9413c4d6a8
ARG ENDPOINT_IMAGE=martenseemann/quic-network-simulator-endpoint@sha256:3b2b9e6fa317da238c8140a7b6d2bf8d4d45a8464b873eecac3ff2a32520b71a

FROM ${BUILD_IMAGE} AS build
# aws-lc-rs, which nitori_crypto_aws_lc builds from C sources, needs a C
# compiler and CMake; Cargo fetches the Git dependencies with git.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl build-essential cmake git \
    && rm -rf /var/lib/apt/lists/*
ARG RUSTUP_VERSION=1.28.2
ARG RUSTUP_SHA256=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    CARGO_TERM_COLOR=never \
    CARGO_INCREMENTAL=0
RUN curl --proto '=https' --tlsv1.2 -sSfo /tmp/rustup-init \
        "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
    && echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - \
    && chmod +x /tmp/rustup-init \
    && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain none \
    && rm /tmp/rustup-init
WORKDIR /src
# The toolchain that rust-toolchain.toml pins, in a layer of its own.
COPY rust-toolchain.toml .
RUN rustup toolchain install && rustc --version --verbose
COPY . .
RUN cargo build --locked --release -p sakuya_interop

FROM ${ENDPOINT_IMAGE}
COPY --from=build /src/target/release/sakuya-interop-server /src/target/release/sakuya-interop-client /
COPY verification/interop-runner/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh
ENTRYPOINT ["/run_endpoint.sh"]
