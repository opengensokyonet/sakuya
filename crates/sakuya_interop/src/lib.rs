//! sakuya's programs for interoperability runs with other QUIC
//! implementations, in the form the QUIC interop runner expects: an
//! hq-interop server and client, configured by the runner's environment
//! variables, with the runner's directories and certificates.
//!
//! - [`server::main`] serves `/www` on port 443.
//! - [`client::main`] fetches the URLs of `REQUESTS` into `/downloads`.
//! - [`key_log::KeyLogFile`] writes the TLS key log `SSLKEYLOGFILE` names.
//!
//! A test case either program does not support ends it with exit code 127,
//! as the runner requires. `QLOGDIR` is read, but no qlog is written yet.
//! The client trusts the root in `/certs/ca.pem` and skips Certificate
//! Transparency, which the runner's certificates have none of; nothing here
//! is for a production composition.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
mod composition;
pub mod environment;
pub mod hq;
pub mod key_log;
pub mod server;

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
