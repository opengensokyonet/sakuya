//! QUIC wire-level value types and header interpretation for sakuya.
//!
//! The baseline is QUIC version 1 ([RFC 9000]). Header interpretation follows
//! the version-independent rules of [RFC 8999] first and applies the version 1
//! layout only to packets that carry version 1.
//!
//! - [`var_int`]: variable-length integers ([`var_int::VarInt`]), decoded from
//!   and encoded into byte slices, and read and written as `nitori_call`
//!   operations.
//! - [`connection_id`]: connection IDs ([`connection_id::ConnectionId`]) and
//!   their non-empty form ([`connection_id::NonEmptyCid`]).
//! - [`stream_id`]: stream IDs ([`stream_id::StreamId`]).
//! - [`header`]: the facts a packet header states before packet protection is
//!   removed: header form, version, connection IDs, the version 1 packet type,
//!   tokens, packet boundaries and the offset of the packet number field.
//! - [`frame`]: the frames of a packet payload once protection is removed,
//!   decoded from and encoded into byte slices, and read and written as
//!   `nitori_call` operations; with the DATAGRAM and RESET_STREAM_AT
//!   extensions.
//! - [`transport_error`]: transport error codes ([`transport_error::TransportErrorCode`]).
//!
//! Nothing here interprets protected header fields (reserved bits, packet
//! number length, Key Phase) or removes packet protection. The frame decoders
//! check the encoding only; whether a frame is acceptable in the state of a
//! connection is for the connection to decide.
//!
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
//! [RFC 8999]: https://www.rfc-editor.org/rfc/rfc8999.html
#![feature(impl_trait_in_assoc_type)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod connection_id;
pub mod frame;
pub mod header;
pub mod stream_id;
pub mod transport_error;
pub mod var_int;
