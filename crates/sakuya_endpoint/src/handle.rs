//! The connection handle that `accept` and `start` give the application.
//!
//! This is the part of the connection handle that the endpoint can give
//! before the application handles have code of their own: asking the
//! connection to close. Waiting for the close reason, the handshake's
//! result and the established layer come with the application handles.

use core::fmt;

use sakuya_connection::v1::close_request::CloseRequestCell;

/// What the application holds of a connection from the moment it is made:
/// the connection-level operations.
///
/// `A` is the application's own error type for closing, the
/// [`ApplicationError`](sakuya_connection::v1::Choices::ApplicationError) of
/// the connection's choices. Dropping every handle does not close the
/// connection.
pub struct ConnectionHandle<A> {
    close_request: CloseRequestCell<A>,
}

impl<A> ConnectionHandle<A> {
    pub(crate) fn new(close_request: CloseRequestCell<A>) -> Self {
        Self { close_request }
    }

    /// Asks the connection to close with `error`; it does not wait.
    ///
    /// Only the first reason for closing counts, whether the application
    /// gave it or the connection found it; a later request is dropped.
    pub fn close(&self, error: A) {
        self.close_request.request(error);
    }
}

impl<A> fmt::Debug for ConnectionHandle<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionHandle").finish_non_exhaustive()
    }
}
