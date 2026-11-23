//! How waiting for the Initial of an incoming connection born from 0-RTT
//! fails: the endpoint's reflow driver, which checks the Initial, is gone.

use core::fmt;

use sakuya_connection::v1::first_flight::ReadFirstFlightError;
use snafu::Snafu;

/// The endpoint's reflow driver is gone, so no Initial that arrives for an
/// incoming connection born from 0-RTT is checked, and none completes it.
///
/// The reflow driver ends only once the endpoint is closed and nothing is
/// registered with routing, which an incoming connection waiting for its
/// Initial is; it is gone earlier only when the host drops it.
#[derive(Debug, Snafu)]
#[snafu(display("the reflow driver is gone"))]
pub struct ReflowDriverGoneError;

/// No Initial can arrive for the incoming connection `H`, born from 0-RTT.
/// It is given back, for the application to refuse or drop.
pub struct InitialArrivedError<H> {
    /// The incoming connection, without its Initial.
    pub half: H,
    /// Why no Initial can arrive.
    pub source: ReflowDriverGoneError,
}

impl<H> fmt::Debug for InitialArrivedError<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialArrivedError")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl<H> fmt::Display for InitialArrivedError<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no Initial can arrive for the incoming connection")
    }
}

impl<H> core::error::Error for InitialArrivedError<H> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Why the first ClientHello of an incoming connection could not be read;
/// `C` is the connection's error.
#[derive(Debug, Snafu)]
pub enum FirstClientHelloError<C> {
    /// The incoming connection was born from 0-RTT, and no Initial can
    /// arrive for it.
    #[snafu(display("no Initial can arrive"))]
    InitialCannotArrive {
        /// Why no Initial can arrive.
        source: ReflowDriverGoneError,
    },
    /// Reading the first flight failed.
    #[snafu(display("the first flight could not be read"))]
    FirstFlight {
        /// The failure.
        source: ReadFirstFlightError<C>,
    },
}
