//! Stream send and receive components for sakuya.
//!
//! The send direction: [`connection_send_credit`], [`send_buffer`] and
//! [`send`], with the options each write carries in [`send_options`]. The receive direction: [`connection_receive_flow`],
//! [`receive_buffer`] and [`receive`]. Both directions carry application
//! protocol error codes as
//! [`ApplicationErrorCode`](sakuya_wire::v1::application_error::ApplicationErrorCode)
//! and apply the rules of [`stream_end`]. Which streams of a connection are
//! open, and the limits on opening more, are [`stream_id_ledger`]'s.
//!
//! Both directions take the resets of RFC 9000. The package
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
