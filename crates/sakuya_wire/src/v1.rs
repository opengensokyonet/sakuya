//! QUIC version 1 ([RFC 9000]): its value types, the version 1 layer of
//! packet headers, the packets of a datagram, frames and transport
//! parameters.
//!
//! Extensions of version 1 build on what this module makes public, and on
//! the encoding mechanisms of the crate root; its internal items are not
//! visible to them.
//!
//! - [`stream_id`]: stream IDs ([`stream_id::StreamId`]).
//! - [`stream_count`]: cumulative numbers of streams of one type
//!   ([`stream_count::StreamCount`]), as stream limits state them.
//! - [`packet_number`]: packet numbers ([`packet_number::PacketNumber`]).
//! - [`encryption_level`]: the four levels a packet is protected at
//!   ([`encryption_level::EncryptionLevel`]).
//! - [`role`]: the client and server roles ([`role::Role`]).
//! - [`transport_error`] and [`application_error`]: transport error codes
//!   ([`transport_error::TransportErrorCode`]) and application protocol error
//!   codes ([`application_error::ApplicationErrorCode`]).
//! - [`header`]: what version 1 adds to the version-independent header: the
//!   long packet types, tokens and packet boundaries, and the headers a
//!   sender writes up to the Packet Number field.
//! - [`protected_packet`]: cutting the packets of a datagram apart
//!   ([`protected_packet::into_packets`]), each a [`protected_packet::Packet`]
//!   with the header read: a packet with the protection still on
//!   ([`protected_packet::ProtectedPacket`]), a Retry packet or a Version
//!   Negotiation packet.
//! - [`transport_parameters`]: the transport parameters an endpoint sends in
//!   the TLS handshake.
//!
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html

pub mod application_error;
pub mod encryption_level;
pub mod header;
pub mod packet_number;
pub mod protected_packet;
pub mod role;
pub mod stream_count;
pub mod stream_id;
pub mod transport_error;
pub mod transport_parameters;
