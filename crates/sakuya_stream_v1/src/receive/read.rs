//! The synchronous core of the stream reader: read results and their
//! priorities.
//!
//! Both ways of reading — copying into a `BufMut` with
//! `StreamReceiver::read_into` (of the package `sakuya_stream_sets`) and taking
//! whole blocks with `StreamReceiver::read_chunk`, at most a given number of
//! bytes each — share one read position and one terminal result. A read
//! returns, in this order of priority:
//!
//! 1. [`ReadError::ReaderDropped`] once the reader was dropped;
//! 2. [`ReadError::LayerEnded`], once the connection closed;
//! 3. the committed terminal result (end of stream or a terminal error);
//! 4. [`ReadOutcome::Wait`], while the stream waits for the connection to
//!    close after a frame violated the protocol: the read does not complete,
//!    exactly as if no new data had arrived, and nothing wakes the reader;
//! 5. the result of a buffer destruction that already took effect;
//! 6. no progress, for an empty target (`read_into` only);
//! 7. the contiguous data that can be delivered now, without waiting to fill
//!    the target;
//! 8. end of stream or a terminal error, judged from the final size, the
//!    local limits and the reset facts: a reset is returned once delivery has
//!    reached the end of the prefix the peer still owes;
//! 9. otherwise, [`ReadOutcome::Wait`].
//!
//! A call that delivers data never also reports the end; the next call does.
//! The call that delivers a terminal error destroys the receive buffer, and
//! repeated reads return the same result, unless the connection closes later.
//! An empty target never commits a result, so a read that cannot take a byte
//! does not end a stream that late data could still complete.
use crate::connection::LayerEndedError;
use crate::receive::remote_reset::{RemoteReset, RemoteResetFacts};
use crate::receive::termination::TerminationEvent;
use core::fmt;
use core::ops::Deref;
use snafu::Snafu;
use std::sync::Arc;

/// The successful outcome of one read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadOutcome<T> {
    /// Non-empty data was delivered.
    Data(T),
    /// The target had no room; nothing was consumed and nothing committed.
    NoProgress,
    /// All data of the stream was delivered: the normal end of stream.
    End,
    /// Nothing can be delivered yet; data that is still expected may arrive.
    Wait,
}

/// A shared handle to a reason of the receive termination policy.
///
/// The stream receiver wraps each reason the policy gives once, and every
/// read error that reports it receives a clone of the same handle, so the
/// reason itself needs neither `Clone` nor `Send` and `Sync`. Two handles are
/// equal when their reasons are.
pub struct SharedTerminationReason<R>(Arc<R>);

impl<R> SharedTerminationReason<R> {
    /// The handle of `reason`, which its clones share.
    pub fn new(reason: R) -> Self {
        Self(Arc::new(reason))
    }
}

impl<R> Clone for SharedTerminationReason<R> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<R> Deref for SharedTerminationReason<R> {
    type Target = R;

    fn deref(&self) -> &R {
        &self.0
    }
}

impl<R: fmt::Debug> fmt::Debug for SharedTerminationReason<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

impl<R: PartialEq> PartialEq for SharedTerminationReason<R> {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

impl<R: Eq> Eq for SharedTerminationReason<R> {}

/// A terminal read error.
///
/// `R` is the receive termination policy's reason type, `Lc` the type of the
/// connection's local close cause and `F` the type of the reset facts of the
/// stream. Every variant can be reported repeatedly: a
/// local reason is reported as a [`SharedTerminationReason`], cloned for each
/// report.
#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum ReadError<R, Lc, F: RemoteResetFacts = RemoteReset> {
    /// The stream reader was dropped; the receive direction takes no more
    /// reads.
    #[snafu(display("the stream reader was dropped"))]
    ReaderDropped,
    /// The connection has closed.
    #[snafu(transparent)]
    LayerEnded {
        /// The closed connection.
        source: LayerEndedError<Lc>,
    },
    /// The peer reset the stream.
    ///
    /// `complete` is true when every byte of `[0, final_size)` was delivered
    /// to the application: the receive termination policy chose to report the
    /// reset although nothing is missing. Complete means the stream's bytes,
    /// not that the application's object or business succeeded.
    #[snafu(display("stream reset by the peer with error code {}", reset.code()))]
    Reset {
        /// The reset facts.
        reset: F,
        /// Whether all of `[0, final_size)` was delivered.
        complete: bool,
    },
    /// The receive termination policy destroyed the receive buffer before
    /// the whole stream was delivered.
    #[snafu(display("the receive buffer was destroyed locally"))]
    BufferDestroyed {
        /// The receive termination policy's reason.
        reason: SharedTerminationReason<R>,
        /// The event during which the destruction took effect.
        trigger: TerminationEvent<F::Change>,
        /// The reset facts, if the peer reset the stream too.
        remote: Option<F>,
    },
    /// Delivery reached the fixed delivery limit before the whole stream was
    /// delivered.
    #[snafu(display("delivery of the stream reached the delivery limit"))]
    DeliveryLimitReached {
        /// The receive termination policy's reason.
        reason: SharedTerminationReason<R>,
        /// The event during which the limit took effect.
        trigger: TerminationEvent<F::Change>,
        /// The reset facts, if the peer reset the stream too.
        remote: Option<F>,
    },
    /// The gap at the read position lies beyond the fixed acceptance limit
    /// and can no longer be filled.
    #[snafu(display("the gap at the read position lies beyond the acceptance limit"))]
    AcceptanceLimitReached {
        /// The receive termination policy's reason.
        reason: SharedTerminationReason<R>,
        /// The event during which the limit took effect.
        trigger: TerminationEvent<F::Change>,
        /// The reset facts, if the peer reset the stream too.
        remote: Option<F>,
    },
}

impl<R, Lc, F: RemoteResetFacts> Clone for ReadError<R, Lc, F> {
    fn clone(&self) -> Self {
        match self {
            Self::ReaderDropped => Self::ReaderDropped,
            Self::LayerEnded { source } => Self::LayerEnded {
                source: source.clone(),
            },
            Self::Reset { reset, complete } => Self::Reset {
                reset: *reset,
                complete: *complete,
            },
            Self::BufferDestroyed {
                reason,
                trigger,
                remote,
            } => Self::BufferDestroyed {
                reason: reason.clone(),
                trigger: *trigger,
                remote: *remote,
            },
            Self::DeliveryLimitReached {
                reason,
                trigger,
                remote,
            } => Self::DeliveryLimitReached {
                reason: reason.clone(),
                trigger: *trigger,
                remote: *remote,
            },
            Self::AcceptanceLimitReached {
                reason,
                trigger,
                remote,
            } => Self::AcceptanceLimitReached {
                reason: reason.clone(),
                trigger: *trigger,
                remote: *remote,
            },
        }
    }
}
