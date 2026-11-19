//! A connection in a wrapper the host chooses ([`SharedConnection`]), so
//! that the application's handles reach it by borrowing it for one
//! operation at a time, and the future that drives it from there
//! ([`SharedConnectionDriver`]).
//!
//! The connection does not know whether it is shared, nor with what: the
//! wrapper is the host's, `Rc<RefCell<…>>` for a connection that stays on
//! one thread, or a mutex for one whose handles are on other threads (in a
//! crate with `std`, as `sakuya_sync_std`'s). Each operation of a handle
//! borrows the connection once and lends the node it needs
//! ([`ConnectionDriver::lend`](crate::driver::ConnectionDriver::lend)).
//! The host spawns the future on the wrapper, not the connection itself.
use alloc::rc::Rc;
use core::{
    cell::RefCell,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// A connection in a wrapper (`SharedConnection`): whoever holds a clone
/// borrows it `&mut` for one operation at a time.
///
/// A clone is the same connection. An operation must not borrow the same
/// connection again while it runs.
pub trait SharedConnection: Clone {
    /// The connection.
    type Driver;
    /// Run `op` on the connection, borrowed for as long as it runs.
    fn with<R>(&self, op: impl FnOnce(&mut Self::Driver) -> R) -> R;
}

/// A connection that stays on one thread: the borrow is the cell's, and a
/// borrow while another runs panics.
impl<D> SharedConnection for Rc<RefCell<D>> {
    type Driver = D;
    fn with<R>(&self, op: impl FnOnce(&mut D) -> R) -> R {
        op(&mut self.borrow_mut())
    }
}

/// A connection that a future outside it drives (`DrivenFromOutside`):
/// polled as a future, and told when that future is dropped, since the
/// connection itself stays in its wrapper.
pub trait DrivenFromOutside: Future<Output = ()> + Unpin {
    /// The future that drives it is dropped; see
    /// [`ConnectionDriver::driving_dropped`](crate::driver::ConnectionDriver::driving_dropped).
    fn driving_dropped(&mut self);
}

/// The future that drives a connection in a wrapper
/// (`SharedConnectionDriver`): what the host spawns. It ends when the
/// connection ends; dropped before that, the connection ends as when its
/// driver is dropped, or after a panic that unwound through a poll only
/// marks its end, and stays in the wrapper for the handles to see.
pub struct SharedConnectionDriver<S: SharedConnection>
where
    S::Driver: DrivenFromOutside,
{
    connection: S,
    ended: bool,
}

impl<S: SharedConnection> SharedConnectionDriver<S>
where
    S::Driver: DrivenFromOutside,
{
    /// The future that drives `connection`.
    pub fn new(connection: S) -> Self {
        Self {
            connection,
            ended: false,
        }
    }
}

/// Nothing of it is pinned structurally.
impl<S: SharedConnection> Unpin for SharedConnectionDriver<S> where S::Driver: DrivenFromOutside {}

impl<S: SharedConnection> Future for SharedConnectionDriver<S>
where
    S::Driver: DrivenFromOutside,
{
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let this = self.get_mut();
        if this.ended {
            return Poll::Ready(());
        }
        let polled = this.connection.with(|driver| Pin::new(driver).poll(cx));
        if polled.is_ready() {
            this.ended = true;
        }
        polled
    }
}

impl<S: SharedConnection> Drop for SharedConnectionDriver<S>
where
    S::Driver: DrivenFromOutside,
{
    fn drop(&mut self) {
        if !self.ended {
            self.connection.with(DrivenFromOutside::driving_dropped);
        }
    }
}
