//! Differential and robustness checks of `sakuya_wire` and
//! `sakuya_packet_protection`.
//!
//! The references are s2n-quic-core 0.91.0, quinn-proto 0.11.19 and the
//! QUIC keys of rustls. Each module holds a neutral model of what it
//! compares, an adapter per implementation, and a classification of the
//! divergences: every divergence the tests see either has a named category
//! with a verdict from the RFCs, or fails the test.
pub mod cases;
pub mod frames;
pub mod generate;
pub mod headers;
pub mod hosts;
pub mod parameters;
pub mod protection;
pub mod tally;
pub mod var_int;
