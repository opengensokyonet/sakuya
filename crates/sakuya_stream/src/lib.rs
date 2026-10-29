//! Stream send and receive components for sakuya.
//!
//! The send direction: [`connection_send_credit`], [`send_buffer`] and
//! [`send`]. The receive direction: [`connection_receive_flow`],
//! [`receive_buffer`] and [`receive`]. Each module documents which parts of
//! its contract are settled and which are provisional.
#![warn(missing_docs)]

pub mod connection_receive_flow;
pub mod connection_send_credit;
pub mod receive;
pub mod receive_buffer;
pub mod send;
pub mod send_buffer;
