//! Stream send and receive components for sakuya.
//!
//! The send direction: [`connection_send_credit`], [`send_buffer`] and
//! [`send`]. The receive direction: [`connection_receive_flow`],
//! [`receive_buffer`] and [`receive`]. Both directions use the application
//! protocol error codes of [`application_error_code`].
#![warn(missing_docs)]

pub mod application_error_code;
pub mod connection_receive_flow;
pub mod connection_send_credit;
pub mod receive;
pub mod receive_buffer;
pub mod send;
pub mod send_buffer;
