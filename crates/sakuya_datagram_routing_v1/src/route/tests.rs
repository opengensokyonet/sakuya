//! Behaviour tests of datagram routing
//!
//! The tests' routing domains are on one thread, with the index of one
//! thread; deliverers and providers are still given as `Arc`s, which the
//! routing API takes.
#![allow(
    clippy::arc_with_non_send_sync,
    reason = "the tests' routing domains are on one thread"
)]

mod acceptance;
mod classification;
mod composition;
mod domains;
mod index;
mod model;
mod offer_to_existing;
mod outside_index;
mod reset_tokens;
mod support;
