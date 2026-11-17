//! QUIC wire-level value types and header interpretation for sakuya.
//!
//! The baseline is QUIC version 1 ([RFC 9000]). Header interpretation follows
//! the version-independent rules of [RFC 8999] first and applies the version 1
//! layout only to packets that carry version 1.
//!
//! The crate root holds what every QUIC version shares ([RFC 8999]) and the
//! encoding mechanisms that the parts below share:
//!
//! - [`version`]: QUIC versions ([`version::Version`]).
//! - [`connection_id`]: connection IDs ([`connection_id::ConnectionId`]), their
//!   lengths ([`connection_id::ConnectionIdLength`]), their non-empty form
//!   ([`connection_id::NonEmptyCid`]), the version-independent
//!   form of long headers ([`connection_id::RawConnectionId`]), and Stateless
//!   Reset Tokens ([`connection_id::StatelessResetToken`]).
//! - [`header`]: the facts a packet header states before packet protection is
//!   removed under the version-independent rules: header form, version,
//!   connection IDs, and Version Negotiation packets.
//! - [`var_int`]: variable-length integers ([`var_int::VarInt`]), the widths
//!   of their encodings ([`var_int::VarIntWidth`]), and wire fields that hold
//!   a value with the width it is encoded in ([`var_int::VarIntField`]).
//! - [`frame`]: what the frames of every part share: the kinds of Length
//!   field, and the errors of the limits that tie a payload to its length.
//! - [`parts`]: the lists of parts that compose a frame set or a set of
//!   parameters, and the sums of what each part gives, types of `frunk_core`.
//! - [`parameters`]: sets of parameters keyed by ID, composed of the
//!   parameter types of parts: a slot for each type, read and written by one
//!   loop under the rules of a parameter space.
//!
//! Everything else that RFC 9000 defines is in [`v1`]. Each extension of
//! version 1 that this crate implements has a module of its own, compiled
//! with the feature of the same name, which no other feature enables:
//!
//! - `reset_stream_at`: the RESET_STREAM_AT frame of the Internet-Draft
//!   [draft-ietf-quic-reliable-stream-reset-11], with the rule that ties its
//!   Reliable Size to its Final Size.
//! - `datagram`: the DATAGRAM frame of [RFC 9221].
//!
//! Every format here is read and written whole in memory, by the functions in
//! the `codec` module of its type: readers take a [`bytes::Buf`], writers a
//! [`bytes::BufMut`]. A source that ends early is an incomplete failure
//! ([`nitori_io::error::IncompleteError`]). Payload fields, such as the data of
//! a STREAM frame, are pieces of the source cut off with
//! [`nitori_io::SplitTo`], so a byte slice yields subslices and `Bytes` yields
//! `Bytes` that share its storage. Writers have no failure: a `Vec` or
//! `BytesMut` grows, and a fixed buffer without room panics, as `BufMut`
//! does. `encoded_len` methods compute lengths without writing. Variable-length
//! integers can also be read and written by `nitori_call` operations, for
//! formats on byte streams ([`var_int::call`]).
//!
//! Nothing here interprets protected header fields (reserved bits, packet
//! number length, Key Phase) or removes packet protection. The frame and
//! transport parameter readers check the encoding only; whether a frame or
//! parameter is acceptable in the state of a connection is for the
//! connection to decide.
//!
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
//! [RFC 8999]: https://www.rfc-editor.org/rfc/rfc8999.html
//! [RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221.html
//! [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html
#![feature(impl_trait_in_assoc_type)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod connection_id;
#[cfg(feature = "datagram")]
pub mod datagram;
pub mod frame;
pub mod header;
pub mod parameters;
pub mod parts;
#[cfg(feature = "reset_stream_at")]
pub mod reset_stream_at;
mod source;
pub mod v1;

pub mod var_int;
pub mod version;
