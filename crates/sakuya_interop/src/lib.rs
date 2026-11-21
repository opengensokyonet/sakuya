//! sakuya's programs for interoperability runs with other QUIC
//! implementations, in the form the QUIC interop runner expects: an
//! hq-interop server and client, configured by the runner's environment
//! variables (`TESTCASE`, `REQUESTS`, `SSLKEYLOGFILE`, `QLOGDIR`;
//! [`environment::Environment`]), with the runner's directories and
//! certificates.
//!
//! - [`server::main`] serves `/www` on port 443, with the runner's
//!   certificates from `/certs`.
//! - [`client::main`] fetches the URLs of `REQUESTS` into `/downloads`.
//! - [`key_log::KeyLogFile`] appends the TLS secrets to the file
//!   `SSLKEYLOGFILE` names, in the NSS key log format.
//!
//! Besides the runner's test cases, both programs run two of their own,
//! for the extensions the runner does not test: `datagram` (RFC 9221) and
//! `resetstreamat` (draft-ietf-quic-reliable-stream-reset); see
//! [`environment::ServerTestCase`] and [`environment::ClientTestCase`]. In
//! each of them both programs announce the extension's transport parameter,
//! which they leave out in the runner's test cases. Under `datagram` the
//! server sends every datagram back and the client checks that each of its
//! datagrams comes back; under `resetstreamat` the server ends each answer
//! with RESET_STREAM_AT at half the file, and the client saves what it read
//! and how the answer ended.
//! A test case either program does not support ends it with exit code 127,
//! as the runner requires. Each connection writes its qlog into
//! `QLOGDIR` through `sakuya_qlog_v1`.
//! The client does not verify the server's certificate chain (the
//! private `verify` module): it takes the server's key from the leaf
//! certificate, which the handshake verifies CertificateVerify with;
//! nothing here is for a production composition.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
mod composition;
pub mod environment;
pub mod hq;
pub mod key_log;
pub mod server;
mod verify;

use core::future::Future;
use std::process::ExitCode;

/// `error` with the chain of its sources, for standard error.
fn report(error: &dyn std::error::Error) -> String {
    let mut out = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

/// Holds at compile time that `value` is `Send`, so that the futures of the
/// real compositions could run on a multi-threaded runtime as well; the
/// programs still spawn them locally.
fn assert_send<T: Send>(_value: &T) {}

/// Runs `program` on a tokio runtime of the current thread, where the
/// endpoints' and connections' futures are spawned locally.
fn run_local(program: impl Future<Output = ExitCode>) -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("sakuya: the runtime cannot start: {error}");
            return ExitCode::FAILURE;
        }
    };
    tokio::task::LocalSet::new().block_on(&runtime, program)
}
