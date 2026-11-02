//! QUIC wire-level value types and header interpretation for sakuya.
//!
//! The baseline is QUIC version 1 ([RFC 9000]). Header interpretation follows
//! the version-independent rules of [RFC 8999] first and applies the version 1
//! layout only to packets that carry version 1.
//!
//! - [`var_int`]: variable-length integers ([`var_int::VarInt`]).
//! - [`connection_id`]: connection IDs ([`connection_id::ConnectionId`]), their
//!   lengths ([`connection_id::ConnectionIdLength`]), their non-empty form
//!   ([`connection_id::NonEmptyCid`]), the version-independent
//!   form of long headers ([`connection_id::RawConnectionId`]), and Stateless
//!   Reset Tokens ([`connection_id::StatelessResetToken`]).
//! - [`stream_id`]: stream IDs ([`stream_id::StreamId`]).
//! - [`stream_count`]: cumulative numbers of streams of one type
//!   ([`stream_count::StreamCount`]), as stream limits state them.
//! - [`packet_number`]: packet numbers ([`packet_number::PacketNumber`]).
//! - [`version`]: QUIC versions ([`version::Version`]).
//! - [`header`]: the facts a packet header states before packet protection is
//!   removed: header form, version, connection IDs, the version 1 packet type,
//!   tokens, packet boundaries and the offsets that header protection needs.
//! - [`frame`]: the frames of a packet payload once protection is removed,
//!   with the DATAGRAM and RESET_STREAM_AT extensions.
//! - [`transport_parameters`]: the transport parameters an endpoint sends in
//!   the TLS handshake.
//! - [`transport_error`] and [`application_error`]: transport error codes
//!   ([`transport_error::TransportErrorCode`]) and application protocol error
//!   codes ([`application_error::ApplicationErrorCode`]).
//! - [`role`]: the client and server roles ([`role::Role`]).
//! - [`payload`]: how variable-length payload fields are read.
//!
//! Every wire format is read and written through `nitori_call` operations, in
//! the `codec` module of its type. They run on sources and sinks that may wait
//! between bytes, and synchronously, through their `sync_` host methods, on
//! byte slices, `Bytes` and other memory hosts; there a source that ends early
//! is an incomplete failure. Payload fields are chunks of the source, so a
//! byte slice yields subslices and `Bytes` yields `Bytes` that share its
//! storage. `encoded_len` methods compute lengths without writing.
//!
//! Nothing here interprets protected header fields (reserved bits, packet
//! number length, Key Phase) or removes packet protection. The frame and
//! transport parameter readers check the encoding only; whether a frame or
//! parameter is acceptable in the state of a connection is for the
//! connection to decide.
//!
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
//! [RFC 8999]: https://www.rfc-editor.org/rfc/rfc8999.html
#![feature(impl_trait_in_assoc_type)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod application_error;
pub mod connection_id;
pub mod frame;
pub mod header;
pub mod packet_number;
pub mod payload;
pub mod role;
pub mod stream_count;
pub mod stream_id;
pub mod transport_error;
pub mod transport_parameters;
pub mod var_int;
pub mod version;
