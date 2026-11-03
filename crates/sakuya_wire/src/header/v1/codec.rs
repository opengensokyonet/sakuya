//! Reading the version 1 fields of a long header packet as a `nitori_call`
//! operation.
//!
//! [`read_long_packet`] continues after [`read_long_header`] has read the
//! version-independent fields. It is also the operation struct
//! [`ReadLongPacket`], with `ReadLongPacketExt` on receiver accesses inside
//! other operations and `ReadLongPacketHostExt` on call executors, including
//! the `sync_` methods for receivers that never wait.
//!
//! ```
//! use sakuya_wire::header::{
//!     codec::ReadLongHeaderHostExt as _,
//!     v1::{TypeFields, codec::ReadLongPacketHostExt as _},
//! };
//!
//! // A Handshake packet with an empty DCID and a 4-byte SCID, followed by
//! // the first byte of a coalesced short header packet.
//! let datagram = [0xe0, 0, 0, 0, 1, 0, 4, 9, 9, 9, 9, 3, 0xaa, 0xbb, 0xcc, 0x41];
//! let mut input = &datagram[..];
//! let header = input.sync_read_long_header_unpin().unwrap();
//! let packet = input.sync_read_long_packet_unpin(header).unwrap();
//! let TypeFields::Handshake { bounds, protected } = packet.fields() else { panic!() };
//! assert_eq!((bounds.packet_number_offset(), bounds.end()), (12, 15));
//! assert_eq!(*protected, [0xaa, 0xbb, 0xcc]);
//! assert_eq!(input, [0x41]); // The next packet starts here.
//! ```
//!
//! [`read_long_header`]: crate::header::codec::read_long_header
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::{
    LongPacket, LongPacketType, PacketBounds, RETRY_INTEGRITY_TAG_LEN, TypeFields, VERSION,
};
use crate::{
    connection_id::{ConnectionId, ConnectionIdLengthError},
    header::LongHeader,
    payload::{ReadPayloadError, read_payload, read_payload_to_end},
    var_int::{
        VarInt,
        codec::{ReadVarIntError, read_var_int_counted},
    },
    version::Version,
};
use bytes::Buf;
use nitori_call::{ReceiverAccess, call};
use nitori_io::prelude::*;
use snafu::{ResultExt, Snafu};

/// Reads the version 1 fields that follow the version-independent fields of
/// `header`: for Initial, 0-RTT and Handshake packets up to the end of the
/// Length field's range, and for a Retry packet the rest of the source.
///
/// # Errors
///
/// - [`ReadLongPacketError::Version`] if the version is not [`VERSION`], and
///   [`ReadLongPacketError::DcidLength`] or [`ReadLongPacketError::ScidLength`]
///   if a connection ID exceeds [`ConnectionId::MAX_LEN`], without reading;
/// - [`ReadLongPacketError::TokenLength`] or [`ReadLongPacketError::Token`] if
///   the token of an Initial packet cannot be read;
/// - [`ReadLongPacketError::Length`] if the Length field cannot be read, and
///   [`ReadLongPacketError::Protected`] if the source ends before the end of
///   its range;
/// - [`ReadLongPacketError::Retry`] if the rest of a Retry packet cannot be
///   read, and [`ReadLongPacketError::RetryIntegrityTag`] if it is too short
///   for its integrity tag.
///
/// # Panics
///
/// If the receiver returns a chunk longer than requested, which breaks the
/// `ReadChunk` contract of `nitori_io`; see [`payload`](crate::payload).
#[call(sync)]
pub async fn read_long_packet<F, A>(
    io: &mut A,
    header: LongHeader,
) -> Result<LongPacket<F::Chunk>, ReadLongPacketError<F::Error>>
where
    F: ReadChunk<Chunk: Default>,
    A: ReceiverAccess<Family = F>,
{
    if header.version() != VERSION {
        return read_long_packet_error::VersionSnafu {
            version: header.version(),
        }
        .fail();
    }
    let dcid =
        ConnectionId::try_from(*header.dcid()).context(read_long_packet_error::DcidLengthSnafu)?;
    let scid =
        ConnectionId::try_from(*header.scid()).context(read_long_packet_error::ScidLengthSnafu)?;
    let offset = header.version_specific_offset();
    let fields = match LongPacketType::of(header.first_byte()) {
        LongPacketType::Initial => {
            let (token_len, token_len_len) = read_var_int_counted(io)
                .await
                .context(read_long_packet_error::TokenLengthSnafu)?;
            let token_len = saturating_usize(token_len);
            let token = read_payload(io, token_len)
                .await
                .context(read_long_packet_error::TokenSnafu)?;
            let (bounds, protected) = read_bounded(io, offset + token_len_len + token_len).await?;
            TypeFields::Initial {
                token,
                bounds,
                protected,
            }
        }
        LongPacketType::ZeroRtt => {
            let (bounds, protected) = read_bounded(io, offset).await?;
            TypeFields::ZeroRtt { bounds, protected }
        }
        LongPacketType::Handshake => {
            let (bounds, protected) = read_bounded(io, offset).await?;
            TypeFields::Handshake { bounds, protected }
        }
        LongPacketType::Retry => {
            let mut rest = read_payload_to_end(io)
                .await
                .context(read_long_packet_error::RetrySnafu)?;
            let length = rest.remaining();
            let Some(token_len) = length.checked_sub(RETRY_INTEGRITY_TAG_LEN) else {
                return read_long_packet_error::RetryIntegrityTagSnafu { length }.fail();
            };
            // invariant: `rest` holds `token_len` bytes and the tag after them.
            let token = rest.copy_to_bytes(token_len);
            let mut integrity_tag = [0; RETRY_INTEGRITY_TAG_LEN];
            rest.copy_to_slice(&mut integrity_tag);
            TypeFields::Retry {
                token,
                integrity_tag,
                end: offset + length,
            }
        }
    };
    Ok(LongPacket {
        header,
        dcid,
        scid,
        fields,
    })
}

/// Reads the Length field at `offset` and the range it covers.
async fn read_bounded<F, A>(
    io: &mut A,
    offset: usize,
) -> Result<(PacketBounds, F::Chunk), ReadLongPacketError<F::Error>>
where
    F: ReadChunk<Chunk: Default>,
    A: ReceiverAccess<Family = F>,
{
    let (length, length_len) = read_var_int_counted(io)
        .await
        .context(read_long_packet_error::LengthSnafu)?;
    let protected = read_payload(io, saturating_usize(length))
        .await
        .context(read_long_packet_error::ProtectedSnafu { length })?;
    let packet_number_offset = offset + length_len;
    let bounds = PacketBounds {
        length,
        packet_number_offset,
        end: packet_number_offset + protected.remaining(),
    };
    Ok((bounds, protected))
}

/// A variable-length integer as a length in memory, saturating where `usize`
/// is narrower; a saturated length exceeds every source.
fn saturating_usize(value: VarInt) -> usize {
    usize::try_from(value.get()).unwrap_or(usize::MAX)
}

/// Failures that [`read_long_packet`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_long_packet_error), visibility(pub(crate)))]
pub enum ReadLongPacketError<E> {
    /// The version is not QUIC version 1.
    #[snafu(display("version {version} is not QUIC version 1"))]
    Version {
        /// The version field.
        version: Version,
    },
    /// The destination connection ID is longer than version 1 allows.
    #[snafu(display("invalid destination connection ID"))]
    DcidLength {
        /// The rejected length.
        source: ConnectionIdLengthError,
    },
    /// The source connection ID is longer than version 1 allows.
    #[snafu(display("invalid source connection ID"))]
    ScidLength {
        /// The rejected length.
        source: ConnectionIdLengthError,
    },
    /// The Token Length field of an Initial packet could not be read.
    #[snafu(display("the Token Length field read failed"))]
    TokenLength {
        /// The failure of reading the field.
        source: ReadVarIntError<E>,
    },
    /// The token of an Initial packet could not be read.
    #[snafu(display("token read failed"))]
    Token {
        /// The failure of reading the token.
        source: ReadPayloadError<E>,
    },
    /// The Length field could not be read.
    #[snafu(display("the Length field read failed"))]
    Length {
        /// The failure of reading the field.
        source: ReadVarIntError<E>,
    },
    /// The range of the Length field could not be read; when the source
    /// ended within it, the packet's boundary is unknown.
    #[snafu(display("the Length field range of {length} bytes read failed"))]
    Protected {
        /// The value of the Length field.
        length: VarInt,
        /// The failure of reading the range.
        source: ReadPayloadError<E>,
    },
    /// The rest of a Retry packet could not be read.
    #[snafu(display("Retry packet read failed"))]
    Retry {
        /// The failure of reading the rest.
        source: ReadPayloadError<E>,
    },
    /// A Retry packet is too short for its integrity tag.
    #[snafu(display(
        "Retry packet has {length} bytes after its header, fewer than its 16-byte integrity tag"
    ))]
    RetryIntegrityTag {
        /// The bytes after the source connection ID.
        length: usize,
    },
}

impl<E> ReadLongPacketError<E> {
    /// Whether the source ended within the packet.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::TokenLength { source } | Self::Length { source } => source.is_incomplete(),
            Self::Token { source } | Self::Protected { source, .. } | Self::Retry { source } => {
                source.is_incomplete()
            }
            Self::RetryIntegrityTag { .. } => true,
            Self::Version { .. } | Self::DcidLength { .. } | Self::ScidLength { .. } => false,
        }
    }
}
