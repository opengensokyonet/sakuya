//! Stream send and receive components for sakuya.
//!
//! The send direction: [`connection_send_credit`], [`send_buffer`] and
//! [`send`]. The receive direction: [`connection_receive_flow`],
//! [`receive_buffer`] and [`receive`]. Both directions carry application
//! protocol error codes as
//! [`ApplicationErrorCode`](sakuya_wire::v1::application_error::ApplicationErrorCode)
//! and apply the rules of [`stream_end`].
#![warn(missing_docs)]

pub mod connection;
pub mod connection_receive_flow;
pub mod connection_send_credit;
pub mod receive;
pub mod receive_buffer;
pub mod send;
pub mod send_buffer;
pub mod stream_end;
