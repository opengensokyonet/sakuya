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
//! Both directions take the resets of RFC 9000. With the `reset_stream_at`
//! feature, off by default, the `reset_stream_at` module adds the reliable
//! stream reset extension to them: a stream sender that also ends a stream
//! with `RESET_STREAM_AT`, and a stream receiver that also takes it.
#![warn(missing_docs)]

mod blocked_signal;
pub mod connection;
pub mod connection_receive_flow;
pub mod connection_send_credit;
pub mod receive;
pub mod receive_buffer;
#[cfg(feature = "reset_stream_at")]
pub mod reset_stream_at;
pub mod send;
pub mod send_buffer;
pub mod send_options;
pub mod stream_end;
pub mod stream_id_ledger;
