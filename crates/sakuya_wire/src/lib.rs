//! QUIC wire-level value types and header interpretation for sakuya.
//!
//! The baseline is QUIC version 1 ([RFC 9000]).
//!
//! - [`var_int`]: variable-length integers ([`var_int::VarInt`]), decoded from
//!   and encoded into byte slices, and read and written as `nitori_call`
//!   operations.
//!
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
#![feature(impl_trait_in_assoc_type)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod var_int;
