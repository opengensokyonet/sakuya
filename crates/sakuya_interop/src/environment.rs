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
    /// `datagram`, not a test case of the runner, with the feature
    /// `extensions` only: announce
    /// `max_datagram_frame_size` and send every datagram received back
    /// as it came.
    Datagram,
    /// `resetstreamat`, not a test case of the runner, with the feature
    /// `extensions` only: announce
    /// `reset_stream_at`, and end each answer, once the whole file is
    /// written, with a reset at a reliable size of half the file
    /// ([`RESET_AT_CODE`]).
    ResetStreamAt,
}

/// The application error code the answers of `resetstreamat` are reset
/// with.
pub const RESET_AT_CODE: u32 = 0x52;

impl ServerTestCase {
    /// The test case named `name`, or `None` when the server does not
    /// support it.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "handshake" | "transfer" | "multiconnect" => Some(Self::Serve),
            "chacha20" => Some(Self::ChaCha20),
            "retry" => Some(Self::Retry),
            #[cfg(feature = "extensions")]
            "datagram" => Some(Self::Datagram),
            #[cfg(feature = "extensions")]
            "resetstreamat" => Some(Self::ResetStreamAt),
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
    /// `datagram`, not a test case of the runner, with the feature
    /// `extensions` only: announce
    /// `max_datagram_frame_size`, send datagrams to the server of the
    /// first URL on one connection and wait for each to come back; the
    /// paths of the URLs are not fetched.
    Datagram,
    /// `resetstreamat`, not a test case of the runner, with the feature
    /// `extensions` only: as `transfer`,
    /// announcing `reset_stream_at`; an answer the server resets is saved
    /// as far as it was read, and how it ended is written next to it.
    ResetStreamAt,
}

impl ClientTestCase {
    /// The test case named `name`, or `None` when the client does not
    /// support it.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "handshake" | "transfer" | "retry" => Some(Self::OneConnection),
            "multiconnect" => Some(Self::ConnectionPerRequest),
            "chacha20" => Some(Self::ChaCha20),
            #[cfg(feature = "extensions")]
            "datagram" => Some(Self::Datagram),
            #[cfg(feature = "extensions")]
            "resetstreamat" => Some(Self::ResetStreamAt),
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

    /// The extensions' test cases are supported only with the feature
    /// `extensions`.
    #[test]
    fn the_extensions_test_cases_need_the_feature() {
        let with = cfg!(feature = "extensions");
        assert_eq!(
            ServerTestCase::from_name("resetstreamat"),
            with.then_some(ServerTestCase::ResetStreamAt)
        );
        assert_eq!(
            ServerTestCase::from_name("datagram"),
            with.then_some(ServerTestCase::Datagram)
        );
        assert_eq!(
            ClientTestCase::from_name("datagram"),
            with.then_some(ClientTestCase::Datagram)
        );
        assert_eq!(
            ClientTestCase::from_name("resetstreamat"),
            with.then_some(ClientTestCase::ResetStreamAt)
        );
    }
}
