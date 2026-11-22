//! Stream send and receive components for sakuya: the contracts of a stream's
//! two directions and their simple implementations.
//!
//! The send direction is [`connection_send_credit`] (connection-level credit
//! reservation and commitment), [`send_buffer`] (a send buffer contract with
//! an implementation keyed by stream offset) and [`send`] (the flow-control
//! and termination policies of a stream sender, the reset targets it can
//! commit and the failures of its operations), with the options each write
//! carries in [`send_options`]. The receive direction is [`receive_buffer`]
//! (a receive buffer contract with a fragment-map implementation,
//! [`receive_buffer::fragmented`]), [`connection_receive_flow`]
//! (connection-level receive accounting) and [`receive`] (the policies of a
//! stream receiver, the reset facts it keeps, the read results and the
//! violations of the peer's frames). Both directions apply the rules of
//! [`stream_end`] and carry application protocol error codes as
//! [`ApplicationErrorCode`](sakuya_wire_v1::application_error::ApplicationErrorCode).
//! Which streams of a connection are open, and the limits on opening more,
//! are [`stream_id_ledger`]'s.
//!
//! The stream sender and the stream receiver themselves, with their
//! operations and the resets of RFC 9000 that choose which resets a
//! connection takes, are in the package `sakuya_stream_sets`. They are
//! synchronous cores that do no waiting of their own: an operation that would
//! have to wait reports that, and the asynchronous stream writers and readers
//! are in `sakuya_connection`.
//!
//! Both directions take the resets of RFC 9000 by default: the stream sender
//! is generic over the reset target it commits ([`send::local_reset`]), and
//! the stream receiver over the reset facts it keeps
//! ([`receive::remote_reset::RemoteResetFacts`]). The package
//! `sakuya_stream_reset_stream_at` defines the reliable stream reset
//! extension for them.
#![warn(missing_docs)]

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
