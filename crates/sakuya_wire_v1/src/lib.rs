//! QUIC version 1 ([RFC 9000]): its encodings (variable-length integers,
//! connection IDs, sets of parameters, what frames share), its value types,
//! the version 1 layer of packet headers, the packets of a datagram, frames
//! and transport parameters.
//!
//! Extensions of version 1 build on what this module makes public, and on
//! the composition of parts of `sakuya_wire`; its internal items are not
//! visible to them.
//!
//! - [`var_int`]: variable-length integers ([`var_int::VarInt`]), the widths
//!   of their encodings ([`var_int::VarIntWidth`]), and wire fields that hold
//!   a value with the width it is encoded in ([`var_int::VarIntField`]).
//!   Variable-length integers can also be read and written by `nitori_call`
//!   operations, for formats on byte streams ([`var_int::call`]).
//! - [`connection_id`]: connection IDs ([`connection_id::ConnectionId`]), their
//!   lengths ([`connection_id::ConnectionIdLength`]), their non-empty form
//!   ([`connection_id::NonEmptyCid`]), and Stateless Reset Tokens
//!   ([`connection_id::StatelessResetToken`]). A connection ID converts
//!   from and into the `sakuya_wire::connection_id::RawConnectionId` of the
//!   version-independent long header.
//! - [`parameters`]: sets of parameters keyed by ID, composed of the
//!   parameter types of parts: a slot for each type, read and written by one
//!   loop under the rules of a parameter space, with the parameters that no
//!   type claims kept as unknown ones ([`parameters::Parameters::unknown`]).
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
//! - [`frame`]: the frames of version 1 ([`frame::Frame`]), the part of a
//!   frame set that [`Part`] names, and what the frames of every part share:
//!   the kinds of Length field ([`frame::LengthKind`]) and the errors of the
//!   limits that tie a payload to its length.
//! - [`transport_parameters`]: the transport parameters an endpoint sends in
//!   the TLS handshake.
//!
//! A frame value states every detail of its encoding (the width of each
//! variable-length integer, which optional fields are present, the raw fields
//! of ACK), so reading a frame and writing it again reproduces its bytes; only
//! the Frame Type is not stored, and must use its shortest encoding. The
//! frame and transport parameter readers check the encoding only; whether a
//! frame or parameter is acceptable in the state of a connection is for the
//! connection to decide. `encoded_len` methods compute lengths without
//! writing.
//!
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html

#![feature(impl_trait_in_assoc_type)]

extern crate alloc;

pub mod application_error;
pub mod connection_id;
pub mod encryption_level;
pub mod frame;
pub mod header;
pub mod packet_number;
pub mod parameters;
pub mod protected_packet;
pub mod role;
pub mod stream_count;
pub mod stream_id;
pub mod transport_error;
pub mod transport_parameters;
pub mod var_int;

/// The frames of version 1 as a part of a frame set
/// ([`FrameSetPart`](frame::set::FrameSetPart)): [`frame::FrameRun`], of the
/// kinds [`frame::FrameType`].
///
/// A frame set of version 1 alone is the list `HList![v1::Part]`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Part;
