//! What the interop runner gives a program: the test case, the requests,
//! and where the key log and qlog go (the runner's `docker-compose.yml`).

use std::{env, path::PathBuf};

use snafu::{ResultExt as _, Snafu};

use crate::hq::{Url, UrlError};

/// The exit code that tells the runner a test case is not supported.
pub const UNSUPPORTED: u8 = 127;

/// A test case a server runs, by what it changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerTestCase {
    /// `handshake`, `transfer` and `multiconnect`: serve with the defaults.
    /// The runner also hands `transfer` to the server of `multiplexing`,
    /// `blackhole`, `keyupdate`, `amplificationlimit` and the others that
    /// differ only in the network or the client.
    Serve,
    /// `chacha20`: offer TLS_CHACHA20_POLY1305_SHA256 alone.
    ChaCha20,
    /// `retry`: answer every Initial without a token with a Retry.
    Retry,
}

impl ServerTestCase {
    /// The test case named `name`, or `None` when the server does not
    /// support it.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "handshake" | "transfer" | "multiconnect" => Some(Self::Serve),
            "chacha20" => Some(Self::ChaCha20),
            "retry" => Some(Self::Retry),
            _ => None,
        }
    }
}

/// A test case a client runs, by what it changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientTestCase {
    /// `handshake`, `transfer` and `retry`: every request on one
    /// connection; under `retry` the server answers the first Initial with
    /// a Retry, which the connection follows.
    OneConnection,
    /// `multiconnect`: a connection of its own for each request, one after
    /// the other.
    ConnectionPerRequest,
    /// `chacha20`: as `transfer`, offering TLS_CHACHA20_POLY1305_SHA256
    /// alone.
    ChaCha20,
}

impl ClientTestCase {
    /// The test case named `name`, or `None` when the client does not
    /// support it.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "handshake" | "transfer" | "retry" => Some(Self::OneConnection),
            "multiconnect" => Some(Self::ConnectionPerRequest),
            "chacha20" => Some(Self::ChaCha20),
            _ => None,
        }
    }
}

/// The environment of one run.
#[derive(Debug)]
pub struct Environment {
    /// `TESTCASE`.
    pub test_case: String,
    /// `REQUESTS`, a client's URLs to fetch.
    pub requests: Vec<Url>,
    /// `SSLKEYLOGFILE`, where to write the key log.
    pub key_log: Option<PathBuf>,
    /// `QLOGDIR`. It is read, but no qlog is written yet.
    pub qlog_dir: Option<PathBuf>,
}

/// The environment cannot be read.
#[derive(Debug, Snafu)]
pub enum EnvironmentError {
    /// `REQUESTS` has a URL the client cannot fetch.
    #[snafu(display("REQUESTS has a URL the client cannot fetch"))]
    Requests {
        /// Which URL.
        source: UrlError,
    },
}

fn path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

impl Environment {
    /// Reads the environment of the process.
    ///
    /// # Errors
    ///
    /// [`EnvironmentError`].
    pub fn read() -> Result<Self, EnvironmentError> {
        let requests = env::var("REQUESTS").unwrap_or_default();
        Ok(Self {
            test_case: env::var("TESTCASE").unwrap_or_default(),
            requests: requests
                .split_whitespace()
                .map(Url::parse)
                .collect::<Result<_, _>>()
                .context(RequestsSnafu)?,
            key_log: path("SSLKEYLOGFILE"),
            qlog_dir: path("QLOGDIR"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_test_cases_are_not_supported() {
        assert_eq!(ServerTestCase::from_name("zerortt"), None);
        assert_eq!(ServerTestCase::from_name("x7Kq2"), None);
        assert_eq!(ClientTestCase::from_name("zerortt"), None);
        assert_eq!(ClientTestCase::from_name(""), None);
        assert_eq!(
            ServerTestCase::from_name("transfer"),
            Some(ServerTestCase::Serve)
        );
        assert_eq!(
            ClientTestCase::from_name("multiconnect"),
            Some(ClientTestCase::ConnectionPerRequest)
        );
        assert_eq!(
            ClientTestCase::from_name("retry"),
            Some(ClientTestCase::OneConnection)
        );
    }
}
