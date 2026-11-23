//! QUIC wire-level value types and header interpretation that every QUIC
//! version shares, for sakuya.
//!
//! The crate holds what [RFC 8999] defines: QUIC versions, connection IDs as
//! long headers carry them, the version-independent interpretation of packet
//! headers, and Version Negotiation packets. Header interpretation follows
//! the version-independent rules of [RFC 8999] first; the layout of a version
//! applies only to packets that carry it. The crate also holds the
//! composition of parts that the packages of each version build on, and the
//! reading of fields from a source.
//!
//! - [`version`]: QUIC versions ([`version::Version`]).
//! - [`connection_id`]: the connection ID of the version-independent long
//!   header ([`connection_id::RawConnectionId`]), 0 to 255 bytes.
//! - [`header`]: the facts a packet header states before packet protection is
//!   removed under the version-independent rules: header form, version,
//!   connection IDs, and Version Negotiation packets.
//! - [`parts`]: the lists of parts that compose a frame set or a set of
//!   parameters, and the sums of what each part gives, types of `frunk_core`.
//! - [`source`]: reading from a source that holds a whole format in memory.
//!
//! The variable-length integers of [RFC 9000] are in the package
//! `sakuya_var_int`, which HTTP also uses. Everything else that it defines is
//! in the package `sakuya_wire_v1`: the connection IDs
//! of version 1, which are at most 20 bytes, and Stateless Reset Tokens
//! (`sakuya_wire_v1::connection_id`), the sets of parameters keyed by ID
//! (`sakuya_wire_v1::parameters`), what the frames of every part share
//! (`sakuya_wire_v1::frame`), its value types (stream IDs, stream counts,
//! packet numbers and the length of their field, encryption levels, roles,
//! error codes), the version 1 layer of packet headers with the headers a
//! sender writes up to the Packet Number field, the cutting of a datagram
//! into its packets (protected packets, and the Retry and Version Negotiation
//! packets that are not), the encryption levels with the frame types that can
//! appear in each, and the frames and the transport parameters. Each
//! extension of version 1 that sakuya implements has a package of its own,
//! which depends on that one:
//!
//! - `sakuya_wire_reset_stream_at`: the RESET_STREAM_AT frame of the
//!   Internet-Draft [draft-ietf-quic-reliable-stream-reset-11], with the
//!   rule that ties its Reliable Size to its Final Size.
//! - `sakuya_wire_datagram`: the DATAGRAM frame of [RFC 9221].
//!
//! Each has its transport parameter too. A frame set without an extension
//! reads its Frame Types as unknown, and transport parameters composed
//! without it keep its parameter as an unknown one
//! (`sakuya_wire_v1::frame`).
//!
//! Every format here is read and written whole in memory, by the functions in
//! the `codec` module of its type: readers take a [`bytes::Buf`], writers a
//! [`bytes::BufMut`]. A source that ends early is an incomplete failure
//! ([`nitori_io::error::IncompleteError`]). Payload fields are pieces of the
//! source cut off with [`nitori_io::SplitTo`], so a byte slice yields
//! subslices and `Bytes` yields `Bytes` that share its storage. Writers have
//! no failure: a `Vec` or `BytesMut` grows, and a fixed buffer without room
//! panics, as `BufMut` does.
//!
//! Nothing here interprets protected header fields (reserved bits, packet
//! number length, Key Phase) or removes packet protection.
//!
//! [RFC 9000]: https://www.rfc-editor.org/rfc/rfc9000.html
//! [RFC 8999]: https://www.rfc-editor.org/rfc/rfc8999.html
//! [RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221.html
//! [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod connection_id;
pub mod header;
pub mod parts;
pub mod source;
pub mod version;
