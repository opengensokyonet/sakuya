//! The application's request to close a connection: the cell it is put
//! in, and how the connection takes it into the record of why it closed.
//!
//! A [`CloseRequestCell`] is shared by whoever lets the application ask
//! and the connection node, which keeps a clone of the cell the connection
//! was made with ([`ConnectionArgs::close_request`]). The application asks
//! from outside the connection's tree, where the record of why the
//! connection closed is kept. Asking only puts the request in the cell and
//! wakes the connection; whether it becomes the reason is decided where
//! the record is written, by which reason is first.
//!
//! The cell acts before the calls: at the start of every poll of the
//! connection, before any call, it takes the request out, so that no call
//! of that poll goes on as if the connection were not closing. Its waker is
//! the connection's. With a request taken:
//!
//! - when the record is written already, the request is dropped: the first
//!   reason stays;
//! - when this side is the client and the link has accepted no datagram of
//!   the connection yet ([`DatagramAcceptance`]), the peer cannot know of
//!   the connection: the reason, an application close, goes into the record
//!   and the connection ends at once, with nothing sent;
//! - otherwise the reason goes into the record, and the connection closes
//!   as it does for any reason of this endpoint: each link path enters
//!   `Closing` and seals its close packet once the peer's connection ID is
//!   known. A server always closes so: what the client sent before the
//!   server accepted it shows the client knows of the connection.

use core::{
    fmt,
    task::{Context, Poll, Waker},
};
use std::sync::{Arc, Mutex, MutexGuard};

use futures_util::task::AtomicWaker;
use sakuya_stream::connection::CloseReason;
use sakuya_wire::{parts::Selector, v1::role::Role};

use super::{
    Choices, CloseCauseOf, ConnectionArgs, Side,
    close::{CloseReasonRecord, LocalCloseCause},
    sending::DatagramAcceptance,
};
use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, RequestOf},
    error::ConnectionErrorsOf,
    layer,
    others::OtherNodes,
    request::StructureRequest,
    share::{ConnectionArgsOf, LineageLists, LineagePartList},
    take::GetAt,
};

/// The cell an application's request to close a connection is put in,
/// shared by its clones: the application's side puts the request in, the
/// connection takes it out.
///
/// `A` is the application's own error type for closing. The cell holds the
/// first request; a later one is dropped, also once the first was taken.
/// One task at a time waits on it ([`poll_take`](Self::poll_take)), and
/// the cell keeps its waker until the request is taken.
pub struct CloseRequestCell<A> {
    shared: Arc<CloseRequestShared<A>>,
}

struct CloseRequestShared<A> {
    state: Mutex<CloseRequestState<A>>,
    /// The waker of whoever waits to take the request.
    taker: AtomicWaker,
}

enum CloseRequestState<A> {
    /// No request was made.
    Empty,
    /// The first request, not taken yet.
    Requested(A),
    /// The first request was taken.
    Taken,
}

impl<A> CloseRequestCell<A> {
    /// A cell without a request.
    pub fn new() -> Self {
        Self {
            shared: Arc::new(CloseRequestShared {
                state: Mutex::new(CloseRequestState::Empty),
                taker: AtomicWaker::new(),
            }),
        }
    }

    fn state(&self) -> MutexGuard<'_, CloseRequestState<A>> {
        self.shared
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Ask to close the connection with `error`, and wake whoever waits to
    /// take the request. Only the first request counts: a later `error` is
    /// dropped.
    pub fn request(&self, error: A) {
        // a later request is dropped after the lock is released
        let later = {
            let mut state = self.state();
            match *state {
                CloseRequestState::Empty => {
                    *state = CloseRequestState::Requested(error);
                    None
                }
                CloseRequestState::Requested(_) | CloseRequestState::Taken => Some(error),
            }
        };
        if later.is_none() {
            self.shared.taker.wake();
        }
    }

    /// Take the request out, or `Pending` until one is made; the waker of
    /// `cx` is woken when it is. After the request was taken it stays
    /// `Pending`, and the cell keeps no waker.
    pub fn poll_take(&self, cx: &mut Context<'_>) -> Poll<A> {
        // registered before looking, so that a request made in between
        // wakes
        self.shared.taker.register(cx.waker());
        let request = {
            let mut state = self.state();
            match core::mem::replace(&mut *state, CloseRequestState::Taken) {
                CloseRequestState::Requested(error) => Some(error),
                CloseRequestState::Empty => {
                    *state = CloseRequestState::Empty;
                    return Poll::Pending;
                }
                CloseRequestState::Taken => None,
            }
        };
        // the request is out: nothing is left to wake for
        drop(self.shared.taker.take());
        request.map_or(Poll::Pending, Poll::Ready)
    }
}

/// A clone is the same cell.
impl<A> Clone for CloseRequestCell<A> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<A> Default for CloseRequestCell<A> {
    fn default() -> Self {
        Self::new()
    }
}

/// It shows whether a request is in it, not the request.
impl<A> fmt::Debug for CloseRequestCell<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match *self.state() {
            CloseRequestState::Empty => "Empty",
            CloseRequestState::Requested(_) => "Requested",
            CloseRequestState::Taken => "Taken",
        };
        f.debug_tuple("CloseRequestCell").field(&state).finish()
    }
}

/// The connection node keeps a clone of the cell the connection was made
/// with.
impl<T: Choices, L, I> Build<T, L, layer::Connection, (I,)>
    for CloseRequestCell<T::ApplicationError>
where
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        super::own_args::<T, L, I>(args).close_request.clone()
    }
}

/// It acts before the calls: it takes the application's request out and
/// writes it into the record of why the connection closed, as the
/// [module documentation](self) says. It reads nothing and has no
/// deadline; it takes the record mutably only to write it.
impl<T: Choices, L, I, Ic, Ia> DataComponent<T, L, layer::Connection, (I, Ic, Ia)>
    for CloseRequestCell<T::ApplicationError>
where
    L: LineagePartList<T> + ConnectionErrorsOf,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<CloseRequestCell<T::ApplicationError>, I>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<DatagramAcceptance, Ia>,
{
    const ACTS_BEFORE_CALLS: bool = true;

    fn before_calls<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::Connection>,
        _: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
        waker: &Waker,
    ) -> Option<RequestOf<T, L>> {
        let Poll::Ready(error) = lineage
            .get::<CloseRequestCell<T::ApplicationError>, I>()
            .poll_take(&mut Context::from_waker(waker))
        else {
            return None;
        };
        if lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .is_written()
        {
            // the first reason stays
            return None;
        }
        let unknown_to_peer = <T::Side as Side>::ROLE == Role::Client
            && *lineage.get::<DatagramAcceptance, Ia>() == DatagramAcceptance::NoneAccepted;
        lineage
            .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .record(CloseReason::Local(Arc::new(LocalCloseCause::Application(
                error,
            ))));
        // the peer cannot know of a connection whose client handed it no
        // datagram: it ends with nothing sent, with the same reason
        unknown_to_peer.then_some(StructureRequest::EndConnection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::Wake,
    };

    #[derive(Default)]
    struct Wakes(AtomicUsize);
    impl Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn the_first_request_is_taken_once() {
        let mut cx = Context::from_waker(Waker::noop());
        let cell = CloseRequestCell::new();
        assert!(cell.poll_take(&mut cx).is_pending());
        cell.request(1);
        cell.request(2);
        assert_eq!(
            cell.clone().poll_take(&mut cx),
            Poll::Ready(1),
            "a clone is the same cell"
        );
        assert!(cell.poll_take(&mut cx).is_pending());
        cell.request(3);
        assert!(
            cell.poll_take(&mut cx).is_pending(),
            "a request after the first is dropped"
        );
    }

    #[test]
    fn the_waker_is_let_go_once_the_request_is_taken() {
        let cell = CloseRequestCell::new();
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(cell.poll_take(&mut cx).is_pending());
        assert_eq!(Arc::strong_count(&wakes), 3, "the cell holds the waker");
        cell.request(1);
        assert_eq!(cell.poll_take(&mut cx), Poll::Ready(1));
        assert_eq!(Arc::strong_count(&wakes), 2, "only the test's two are left");
        assert!(cell.poll_take(&mut cx).is_pending());
        assert_eq!(Arc::strong_count(&wakes), 2);
    }

    #[test]
    fn a_request_wakes_whoever_waits_to_take_it() {
        let cell = CloseRequestCell::new();
        let wakes = Arc::new(Wakes::default());
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(cell.poll_take(&mut cx).is_pending());
        assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
        // from another thread, as the application asks
        let asking = cell.clone();
        std::thread::spawn(move || asking.request(7))
            .join()
            .expect("the asking thread");
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        assert_eq!(cell.poll_take(&mut cx), Poll::Ready(7));
        cell.request(8);
        assert_eq!(
            wakes.0.load(Ordering::SeqCst),
            1,
            "a later request wakes nobody"
        );
        assert!(cell.poll_take(&mut cx).is_pending());
    }

    #[test]
    fn the_cell_shows_its_state_without_the_request() {
        struct Opaque;
        let cell = CloseRequestCell::new();
        assert_eq!(format!("{cell:?}"), "CloseRequestCell(\"Empty\")");
        cell.request(Opaque);
        assert_eq!(format!("{cell:?}"), "CloseRequestCell(\"Requested\")");
    }
}
