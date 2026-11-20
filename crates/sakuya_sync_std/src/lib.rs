//! Wrappers and tables for sakuya's shared state that synchronize with the
//! locks of std, for hosts whose handles, drivers and connections are on
//! other threads than the state they reach.
//!
//! The crates of the protocol, up to the endpoint, do not name a lock: what
//! a host shares, and with what, is the host's. Their own implementations
//! are for one thread (`Rc<RefCell<…>>`, hash maps in cells); a lock of std
//! cannot be given their traits from outside them, so the implementations
//! here hold one:
//!
//! - [`MutexSharedConnection`]: a connection behind a mutex
//!   ([`SharedConnection`]).
//! - [`endpoint::LockingEndpointSynchronization`]: the family of an endpoint
//!   whose drivers, connections and handles are on several threads, made of
//!   the tables of [`route`] and [`endpoint`], the queue of [`queue`], the
//!   claim lock of [`claim`], and the mutexes of std behind an `Arc` that
//!   `nitori_sync` shares state in.
//!
//! Every lock here takes a lock a panic poisoned as it is: the crates reach
//! their state on the paths that run while a panic unwinds, where a second
//! panic aborts the process. The maps of `dashmap` and the mutex of `tokio`
//! are not poisoned.
#![warn(missing_docs)]

use std::sync::{Arc, Mutex, PoisonError};

use sakuya_connection::shared::SharedConnection;

pub mod claim;
pub mod endpoint;
pub mod queue;
pub mod route;

/// A connection behind a mutex of std (`MutexSharedConnection`), for a
/// host whose handles of the connection are on other threads than the one
/// that drives it.
///
/// A clone is the same connection. Each operation holds the lock while it
/// runs, and so does each poll of the connection. A lock poisoned by a
/// panic of a holder is taken as it is: the connection itself notes that a
/// panic unwound through its own code, and ends as after one.
pub struct MutexSharedConnection<D>(Arc<Mutex<D>>);

impl<D> MutexSharedConnection<D> {
    /// Share `driver`.
    pub fn new(driver: D) -> Self {
        Self(Arc::new(Mutex::new(driver)))
    }
}

/// A clone is the same connection.
impl<D> Clone for MutexSharedConnection<D> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<D> SharedConnection for MutexSharedConnection<D> {
    type Driver = D;
    fn with<R>(&self, op: impl FnOnce(&mut D) -> R) -> R {
        op(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}
