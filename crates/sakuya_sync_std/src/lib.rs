//! Wrappers for sakuya's shared state that synchronize with the locks of
//! std, for hosts whose handles are on other threads than the state they
//! reach.
//!
//! The crates of the protocol, up to the endpoint, do not name a lock: what
//! a host shares, and with what, is the host's ([`SharedConnection`]).
//! Their own wrappers are for one thread (`Rc<RefCell<…>>`); a lock of std
//! cannot be given their traits from outside them, so the wrappers here
//! hold one.
#![warn(missing_docs)]

use std::sync::{Arc, Mutex, PoisonError};

use sakuya_connection::shared::SharedConnection;

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
