//! Reading the version-independent header layers, and writing Version
//! Negotiation packets, as `nitori_call` operations.
//!
//! [`read_long_header`] and [`read_short_header`] start at the first byte of
//! a packet; [`read_version_negotiation`] continues after a long header with
//! [`Version::NEGOTIATION`]. [`write_version_negotiation`] writes a whole
//! Version Negotiation packet. Each function is also an operation struct with
//! `{Name}Ext` on receiver accesses inside other operations and
//! `{Name}HostExt` on call executors, including the `sync_` methods for
//! receivers that never wait. A source that ends early is an incomplete
//! failure, which the errors' `is_incomplete` methods recognize.
//!
//! ```
//! use sakuya_wire::{
//!     connection_id::RawConnectionId,
//!     header::codec::{
//!         ReadLongHeaderHostExt as _, ReadVersionNegotiationHostExt as _,
//!         WriteVersionNegotiationHostExt as _,
//!     },
//!     version::Version,
//! };
//!
//! // The client's packet had these connection IDs; the response swaps them.
//! let client_dcid = RawConnectionId::new(&[7; 30]).unwrap();
//! let client_scid = RawConnectionId::new(&[1, 2]).unwrap();
//! let mut packet = Vec::new();
//! packet
//!     .sync_write_version_negotiation_unpin(0x40, &client_scid, &client_dcid, &[Version::V1])
//!     .unwrap();
//! assert_eq!(packet[..6], [0xc0, 0, 0, 0, 0, 2]);
//!
//! let mut input = &packet[..];
//! let header = input.sync_read_long_header_unpin().unwrap();
//! let negotiation = input.sync_read_version_negotiation_unpin(header).unwrap();
//! assert_eq!(negotiation.dcid(), &client_scid);
//! assert_eq!(negotiation.scid(), &client_dcid);
//! assert_eq!(negotiation.supported_versions().collect::<Vec<_>>(), [Version::V1]);
//! ```
// `#[call]` generates constructors, fields and extension traits without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use super::{FORM_BIT, HeaderForm, LongHeader, ShortHeader, VERSION_LEN, VersionNegotiation};
use crate::{
    connection_id::{
        ConnectionIdLength, RawConnectionId,
        codec::{ReadRawConnectionIdError, ReadRawConnectionIdExt as _},
    },
    payload::{ReadPayloadError, read_payload_to_end},
    version::Version,
};
use bytes::Buf;
use nitori_call::{ReceiverAccess, call};
use nitori_io::{
    calls::{ReadArrayError, ReadBeError, ReadExactError, WriteAllError},
    prelude::*,
};
use snafu::{ResultExt, Snafu};

/// Reads the version-independent fields of the long header at the start of
/// the source: the first byte, the version and the two connection IDs with
/// their lengths, and nothing after them.
///
/// # Errors
///
/// [`ReadLongHeaderError::FirstByte`] if the source is empty,
/// [`ReadLongHeaderError::ShortForm`] if the first byte announces a short
/// header, and [`ReadLongHeaderError::Version`],
/// [`ReadLongHeaderError::Dcid`] or [`ReadLongHeaderError::Scid`] if the
/// source ends within those fields.
#[call(sync)]
pub async fn read_long_header<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<LongHeader, ReadLongHeaderError<F::Error>> {
    let [first_byte] = io
        .read_array::<1>()
        .await
        .context(read_long_header_error::FirstByteSnafu)?;
    if HeaderForm::of(first_byte) == HeaderForm::Short {
        return read_long_header_error::ShortFormSnafu.fail();
    }
    let version = io
        .read_be::<u32>()
        .await
        .context(read_long_header_error::VersionSnafu)?;
    let dcid = io
        .read_raw_connection_id()
        .await
        .context(read_long_header_error::DcidSnafu)?;
    let scid = io
        .read_raw_connection_id()
        .await
        .context(read_long_header_error::ScidSnafu)?;
    Ok(LongHeader {
        first_byte,
        version: Version::new(version),
        dcid,
        scid,
    })
}

/// Failures that [`read_long_header`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_long_header_error), visibility(pub(crate)))]
pub enum ReadLongHeaderError<E> {
    /// The first byte could not be read.
    #[snafu(display("first byte read failed"))]
    FirstByte {
        /// The failure of reading the byte.
        source: ReadArrayError<E>,
    },
    /// The first byte announces a short header.
    #[snafu(display("first byte announces a short header"))]
    ShortForm,
    /// The version field could not be read.
    #[snafu(display("version read failed"))]
    Version {
        /// The failure of reading the field.
        source: ReadBeError<E>,
    },
    /// The destination connection ID could not be read.
    #[snafu(display("destination connection ID read failed"))]
    Dcid {
        /// The failure of reading the connection ID.
        source: ReadRawConnectionIdError<E>,
    },
    /// The source connection ID could not be read.
    #[snafu(display("source connection ID read failed"))]
    Scid {
        /// The failure of reading the connection ID.
        source: ReadRawConnectionIdError<E>,
    },
}

impl<E> ReadLongHeaderError<E> {
    /// Whether the source ended within the header.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::FirstByte { source } => matches!(source, ReadArrayError::Incomplete { .. }),
            Self::Version { source } => matches!(source, ReadBeError::Incomplete { .. }),
            Self::Dcid { source } | Self::Scid { source } => source.is_incomplete(),
            Self::ShortForm => false,
        }
    }
}

/// Reads a short header whose destination connection ID is `dcid_len` bytes
/// long, and the protected packet number and payload after it, to the end of
/// the source.
///
/// # Errors
///
/// [`ReadShortHeaderError::FirstByte`] if the source is empty,
/// [`ReadShortHeaderError::LongForm`] if the first byte announces a long
/// header, [`ReadShortHeaderError::Dcid`] if the source ends within the
/// connection ID, and [`ReadShortHeaderError::Protected`] if the rest cannot
/// be read as one chunk. Whether a packet number and enough protected
/// payload follow is for the removal of header protection to check.
#[call(sync)]
pub async fn read_short_header<F, A>(
    io: &mut A,
    dcid_len: ConnectionIdLength,
) -> Result<ShortHeader<F::Chunk>, ReadShortHeaderError<F::Error>>
where
    F: ReadChunk<Chunk: Default>,
    A: ReceiverAccess<Family = F>,
{
    let [first_byte] = io
        .read_array::<1>()
        .await
        .context(read_short_header_error::FirstByteSnafu)?;
    if HeaderForm::of(first_byte) == HeaderForm::Long {
        return read_short_header_error::LongFormSnafu.fail();
    }
    let length = usize::from(dcid_len);
    let mut dcid = RawConnectionId::EMPTY;
    let mut destination = &mut dcid.bytes[..length];
    io.read_exact(&mut destination, length)
        .await
        .context(read_short_header_error::DcidSnafu)?;
    dcid.len = u8::from(dcid_len);
    let protected = read_payload_to_end(io)
        .await
        .context(read_short_header_error::ProtectedSnafu)?;
    Ok(ShortHeader {
        first_byte,
        dcid,
        protected,
    })
}

/// Failures that [`read_short_header`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_short_header_error), visibility(pub(crate)))]
pub enum ReadShortHeaderError<E> {
    /// The first byte could not be read.
    #[snafu(display("first byte read failed"))]
    FirstByte {
        /// The failure of reading the byte.
        source: ReadArrayError<E>,
    },
    /// The first byte announces a long header.
    #[snafu(display("first byte announces a long header"))]
    LongForm,
    /// The destination connection ID could not be read.
    #[snafu(display("destination connection ID read failed"))]
    Dcid {
        /// The failure of reading the connection ID.
        source: ReadExactError<E>,
    },
    /// The protected rest of the packet could not be read.
    #[snafu(display("protected packet read failed"))]
    Protected {
        /// The failure of reading the rest.
        source: ReadPayloadError<E>,
    },
}

impl<E> ReadShortHeaderError<E> {
    /// Whether the source ended within the header.
    pub fn is_incomplete(&self) -> bool {
        match self {
            Self::FirstByte { source } => matches!(source, ReadArrayError::Incomplete { .. }),
            Self::Dcid { source } => matches!(source, ReadExactError::Incomplete { .. }),
            Self::Protected { source } => source.is_incomplete(),
            Self::LongForm => false,
        }
    }
}

/// Reads the supported version list of a Version Negotiation packet whose
/// long header `header` has been read: the rest of the source.
///
/// # Errors
///
/// [`ReadVersionNegotiationError::Version`] for a header of another version,
/// without reading; [`ReadVersionNegotiationError::Versions`] if the list
/// cannot be read as one chunk, and [`ReadVersionNegotiationError::VersionList`]
/// if it is not a multiple of four bytes.
#[call(sync)]
pub async fn read_version_negotiation<F, A>(
    io: &mut A,
    header: LongHeader,
) -> Result<VersionNegotiation<F::Chunk>, ReadVersionNegotiationError<F::Error>>
where
    F: ReadChunk<Chunk: Default>,
    A: ReceiverAccess<Family = F>,
{
    NotNegotiationVersionError::check(header.version())?;
    let versions = read_payload_to_end(io)
        .await
        .context(read_version_negotiation_error::VersionsSnafu)?;
    VersionListError::check(versions.remaining())?;
    Ok(VersionNegotiation { header, versions })
}

/// Failures that [`read_version_negotiation`] can produce.
#[derive(Debug, Snafu)]
#[snafu(module(read_version_negotiation_error), visibility(pub(crate)))]
pub enum ReadVersionNegotiationError<E> {
    /// The version field is not zero.
    #[snafu(transparent)]
    Version {
        /// The broken rule.
        source: NotNegotiationVersionError,
    },
    /// The supported version list could not be read.
    #[snafu(display("supported version list read failed"))]
    Versions {
        /// The failure of reading the list.
        source: ReadPayloadError<E>,
    },
    /// The supported version list does not end on a version boundary.
    #[snafu(transparent)]
    VersionList {
        /// The broken rule.
        source: VersionListError,
    },
}

/// The Version field of a long header read as a Version Negotiation packet
/// is not zero.
///
/// It is constructed only when the check fails, so the version it holds is
/// never [`Version::NEGOTIATION`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("version {version} is not version negotiation"))]
pub struct NotNegotiationVersionError {
    version: Version,
}

impl NotNegotiationVersionError {
    /// The version field, not [`Version::NEGOTIATION`].
    pub const fn version(self) -> Version {
        self.version
    }

    /// Checks that `version` marks a Version Negotiation packet.
    fn check(version: Version) -> Result<(), Self> {
        if version != Version::NEGOTIATION {
            return Err(Self { version });
        }
        Ok(())
    }
}

/// The supported version list of a Version Negotiation packet does not end
/// on a version boundary.
///
/// It is constructed only when the check fails, so the length it holds is
/// never a multiple of 4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("supported version list of {length} bytes is not a multiple of 4"))]
pub struct VersionListError {
    length: usize,
}

impl VersionListError {
    /// The length of the list, not a multiple of 4.
    pub const fn length(self) -> usize {
        self.length
    }

    /// Checks that a list of `length` bytes holds whole versions.
    fn check(length: usize) -> Result<(), Self> {
        if !length.is_multiple_of(VERSION_LEN) {
            return Err(Self { length });
        }
        Ok(())
    }
}

/// The longest version-independent long header: the first byte, the version
/// and two connection IDs of 255 bytes with their length bytes.
const LONG_HEADER_MAX: usize =
    1 + VERSION_LEN + 1 + RawConnectionId::MAX_LEN + 1 + RawConnectionId::MAX_LEN;

/// Writes a Version Negotiation packet ([RFC 8999 §6], [RFC 9000 §17.2.1]):
/// the first byte, [`Version::NEGOTIATION`], the two connection IDs with their
/// lengths and the supported version list `versions`, in order.
///
/// The low seven bits of `unused` fill the Unused field; the most
/// significant bit of the first byte is the Header Form and always 1. The
/// sender chooses the Unused field freely, and [RFC 9000 §17.2.1] asks a
/// server to set its `0x40` bit so that the packet appears to have the
/// Fixed Bit. A server responding to a client packet puts that packet's
/// source connection ID in `dcid` and its destination connection ID in
/// `scid`; either may be up to 255 bytes long.
///
/// A packet written and read back with [`read_long_header`] and
/// [`read_version_negotiation`] reads as the same fields.
///
/// Acceptance by the receiver does not imply flushing or delivery.
///
/// # Errors
///
/// [`WriteAllError`] if the receiver stops accepting bytes or fails; bytes
/// accepted before stay written.
///
/// [RFC 8999 §6]: https://www.rfc-editor.org/rfc/rfc8999.html#section-6
/// [RFC 9000 §17.2.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.1
#[call(sync)]
pub async fn write_version_negotiation<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    unused: u8,
    dcid: &RawConnectionId,
    scid: &RawConnectionId,
    versions: &[Version],
) -> Result<(), WriteAllError<F::Error>> {
    let mut header = [0; LONG_HEADER_MAX];
    let mut len = 0;
    let mut put = |bytes: &[u8]| {
        // invariant: `LONG_HEADER_MAX` is the longest the pieces below add up
        // to.
        header[len..len + bytes.len()].copy_from_slice(bytes);
        len += bytes.len();
    };
    put(&[FORM_BIT | unused]);
    put(&Version::NEGOTIATION.to_be_bytes());
    put(&[dcid.len]);
    put(dcid.as_bytes());
    put(&[scid.len]);
    put(scid.as_bytes());
    io.write_all(header[..len].chain(VersionListBytes::new(versions)))
        .await
}

/// The bytes of a supported version list, each version in network byte
/// order.
struct VersionListBytes<'a> {
    /// The version being written.
    current: [u8; VERSION_LEN],
    /// How many bytes of `current` are written.
    position: usize,
    /// The versions after `current`.
    rest: &'a [Version],
}

impl<'a> VersionListBytes<'a> {
    fn new(versions: &'a [Version]) -> Self {
        let mut bytes = Self {
            current: [0; VERSION_LEN],
            position: VERSION_LEN,
            rest: versions,
        };
        bytes.next_version();
        bytes
    }

    /// Moves to the next version once `current` is written.
    fn next_version(&mut self) {
        if self.position == VERSION_LEN
            && let Some((next, rest)) = self.rest.split_first()
        {
            self.current = next.to_be_bytes();
            self.position = 0;
            self.rest = rest;
        }
    }
}

impl Buf for VersionListBytes<'_> {
    fn remaining(&self) -> usize {
        VERSION_LEN - self.position + self.rest.len() * VERSION_LEN
    }

    fn chunk(&self) -> &[u8] {
        &self.current[self.position..]
    }

    fn advance(&mut self, mut cnt: usize) {
        assert!(cnt <= self.remaining(), "advanced past the version list");
        while cnt > 0 {
            let step = cnt.min(VERSION_LEN - self.position);
            self.position += step;
            cnt -= step;
            self.next_version();
        }
    }
}
