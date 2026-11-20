//! Stream send and receive components for sakuya.
//!
//! The send direction is [`connection_send_credit`] (connection-level credit
//! reservation and commitment), [`send_buffer`] (a send buffer contract with
//! an implementation keyed by stream offset) and [`send`] (a stream sender
//! with its flow-control and termination policies), with the options each
//! write carries in [`send_options`]. The receive direction is
//! [`receive_buffer`] (a receive buffer contract with a fragment-map
//! implementation, [`receive_buffer::fragmented`]),
//! [`connection_receive_flow`] (connection-level receive accounting) and
//! [`receive`] (a stream receiver with reads, local stop requests and
//! policy-driven delivery boundaries). Both directions are synchronous cores
//! that do no waiting of their own: an operation that would have to wait
//! reports that, and the asynchronous stream writers and readers are in
//! `sakuya_connection`. Both directions carry application
//! protocol error codes as
//! [`ApplicationErrorCode`](sakuya_wire_v1::application_error::ApplicationErrorCode)
//! and apply the rules of [`stream_end`]. Which streams of a connection are
//! open, and the limits on opening more, are [`stream_id_ledger`]'s.
//!
//! Both directions take the resets of RFC 9000 by default: the stream sender
//! is generic over the reset target it commits ([`send::local_reset`]), and
//! the stream receiver over the reset facts it keeps
//! ([`receive::remote_reset::RemoteResetFacts`]). The package
//! `sakuya_stream_reset_stream_at` adds the reliable stream reset
//! extension to them: a stream sender that also ends a stream with
//! `RESET_STREAM_AT`, and a stream receiver that also takes it.
#![warn(missing_docs)]

/// Declares an item that the tests of other packages use: public with the
/// feature `test-util`, and this crate's own otherwise. The item is written
/// with `pub`.
macro_rules! test_util_pub {
    ($(#[$attribute:meta])* pub $($item:tt)*) => {
        $(#[$attribute])*
        #[cfg(feature = "test-util")]
        pub $($item)*
        $(#[$attribute])*
        #[cfg(not(feature = "test-util"))]
        pub(crate) $($item)*
    };
}

mod blocked_signal;
pub mod connection;
pub mod connection_receive_flow;
pub mod connection_send_credit;
pub mod receive;
pub mod receive_buffer;
pub mod send;
pub mod send_buffer;
pub mod send_options;
pub mod stream_end;
pub mod stream_id_ledger;
