//! Packet header interpretation before packet protection is removed.
//!
//! Interpretation proceeds in layers, each of which reads only what its rules
//! define:
//!
//! 1. [`HeaderForm::of`] reads the most significant bit of the first byte.
//! 2. [`LongHeader::parse`] reads the fields every QUIC version shares
//!    ([RFC 8999 §5.1]): version and the two connection IDs, each 0 to 255
//!    bytes long. [`ShortHeader::parse`] reads the destination connection ID
//!    of a short header, whose length the caller supplies because the header
//!    does not carry it ([RFC 8999 §5.2]).
//! 3. A long header with version 0 converts into a [`VersionNegotiation`]
//!    packet ([RFC 8999 §6]); one with version 1 converts into a
//!    [`v1::LongPacket`] ([RFC 9000 §17.2]). For any other version, only the
//!    version-independent fields of the [`LongHeader`] are known.
//!
//! The input of each layer is a datagram, or the part of it starting at the
//! packet to interpret; offsets reported by the layers count from the start of
//! that input. A version 1 long packet with a Length field reports where it
//! ends, so a datagram that coalesces several packets can be interpreted packet
//! by packet from [`v1::LongPacket::remainder`]. Version Negotiation packets,
//! Retry packets and short headers extend to the end of the datagram.
//!
//! No layer interprets protected bits or fields. The packet number offset
//! states where the protected packet number begins; its length, the reserved
//! bits and the Key Phase bit are known only after header protection is
//! removed.
//!
//! ```
//! use sakuya_wire::header::{HeaderForm, LongHeader, ShortHeader, VersionNegotiation, v1};
//!
//! fn describe(datagram: &[u8], short_dcid_len: usize) -> String {
//!     let Some(&first) = datagram.first() else { return "empty".into() };
//!     match HeaderForm::of(first) {
//!         HeaderForm::Short => match ShortHeader::parse(datagram, short_dcid_len) {
//!             Ok(short) => format!("short, packet number at {}", short.packet_number_offset()),
//!             Err(error) => error.to_string(),
//!         },
//!         HeaderForm::Long => {
//!             let long = match LongHeader::parse(datagram) {
//!                 Ok(long) => long,
//!                 Err(error) => return error.to_string(),
//!             };
//!             match long.version() {
//!                 VersionNegotiation::VERSION => match VersionNegotiation::try_from(long) {
//!                     Ok(packet) => format!("{} versions offered", packet.supported_versions().len()),
//!                     Err(error) => error.to_string(),
//!                 },
//!                 v1::VERSION => match v1::LongPacket::try_from(long) {
//!                     Ok(packet) => format!("{:?} ending at {}", packet.packet_type(), packet.end()),
//!                     Err(error) => error.to_string(),
//!                 },
//!                 version => format!("unsupported version {version:#010x}"),
//!             }
//!         }
//!     }
//! }
//!
//! assert_eq!(describe(&[0x40, 0xaa, 0xbb, 0x01], 2), "short, packet number at 3");
//! assert_eq!(
//!     describe(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 0),
//!     "1 versions offered",
//! );
//! assert_eq!(
//!     describe(&[0xe0, 0, 0, 0, 1, 0, 0, 0x01, 0xaa], 0),
//!     "Handshake ending at 9",
//! );
//! assert_eq!(
//!     describe(&[0xc0, 0x6b, 0x33, 0x43, 0xcf, 0, 0], 0),
//!     "unsupported version 0x6b3343cf",
//! );
//! ```
//!
//! [RFC 8999 §5.1]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
//! [RFC 8999 §5.2]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.2
//! [RFC 8999 §6]: https://www.rfc-editor.org/rfc/rfc8999.html#section-6
//! [RFC 9000 §17.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2
use crate::var_int::{DecodeError, VarInt};
use core::{iter::FusedIterator, slice};
use snafu::Snafu;

pub mod v1;

/// The Header Form bit: set for long headers.
const FORM_BIT: u8 = 0x80;

/// The length of a version field.
const VERSION_LEN: usize = 4;

/// Whether a packet has a long or a short header: the most significant bit of
/// its first byte, the only bit whose meaning every QUIC version shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeaderForm {
    /// The bit is 1.
    Long,
    /// The bit is 0.
    Short,
}

impl HeaderForm {
    /// The header form that `first_byte` announces.
    pub const fn of(first_byte: u8) -> Self {
        if first_byte & FORM_BIT == 0 {
            Self::Short
        } else {
            Self::Long
        }
    }
}

/// The version-independent fields of a long header ([RFC 8999 §5.1]).
///
/// The connection IDs may be up to 255 bytes long; only the rules of a
/// specific version restrict them further. The remaining seven bits of the
/// first byte and everything after the source connection ID belong to the
/// version.
///
/// [RFC 8999 §5.1]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.1
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongHeader<'a> {
    input: &'a [u8],
    version: u32,
    dcid: &'a [u8],
    scid: &'a [u8],
}

impl<'a> LongHeader<'a> {
    /// Reads the version-independent fields of the long header at the start of
    /// `input`.
    ///
    /// `input` is the datagram, or the part of it from the first byte of the
    /// packet. Only the first byte, version, and the connection IDs with their
    /// lengths are read.
    ///
    /// # Errors
    ///
    /// [`LongHeaderError::Empty`] for empty input,
    /// [`LongHeaderError::ShortForm`] if the first byte announces a short
    /// header, and [`LongHeaderError::Truncated`] if `input` ends within those
    /// fields.
    pub fn parse(input: &'a [u8]) -> Result<Self, LongHeaderError> {
        let Some(&first) = input.first() else {
            return Err(LongHeaderError::Empty);
        };
        if HeaderForm::of(first) == HeaderForm::Short {
            return Err(LongHeaderError::ShortForm);
        }
        let mut reader = Reader::new(input, 1);
        let version = reader.take(VERSION_LEN)?;
        let version = u32::from_be_bytes([version[0], version[1], version[2], version[3]]);
        let dcid_len = reader.take(1)?[0];
        let dcid = reader.take(usize::from(dcid_len))?;
        let scid_len = reader.take(1)?[0];
        let scid = reader.take(usize::from(scid_len))?;
        Ok(Self {
            input,
            version,
            dcid,
            scid,
        })
    }

    /// The first byte of the packet. Its low seven bits are version-specific
    /// and may be protected.
    pub fn first_byte(&self) -> u8 {
        self.input[0]
    }

    /// The version field.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The destination connection ID: 0 to 255 bytes.
    pub fn dcid(&self) -> &'a [u8] {
        self.dcid
    }

    /// The source connection ID: 0 to 255 bytes.
    pub fn scid(&self) -> &'a [u8] {
        self.scid
    }

    /// The offset of the first version-specific byte after the source
    /// connection ID.
    pub fn version_specific_offset(&self) -> usize {
        1 + VERSION_LEN + 1 + self.dcid.len() + 1 + self.scid.len()
    }

    /// The input this header was read from, starting at its first byte.
    pub fn input(&self) -> &'a [u8] {
        self.input
    }

    /// The bytes of the input after the version-independent fields.
    pub fn version_specific(&self) -> &'a [u8] {
        &self.input[self.version_specific_offset()..]
    }
}

/// Failures of [`LongHeader::parse`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(long_header_error), visibility(pub(crate)))]
pub enum LongHeaderError {
    /// The input has no bytes.
    #[snafu(display("no bytes for a long header"))]
    Empty,
    /// The first byte announces a short header.
    #[snafu(display("first byte announces a short header"))]
    ShortForm,
    /// The input ends within the version-independent fields.
    #[snafu(transparent)]
    Truncated {
        /// Where the input ended.
        source: TruncatedError,
    },
}

/// The input ends before a field it announces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("header needs {required} bytes, but the input has {available}"))]
pub struct TruncatedError {
    /// The input length the field requires, counted from the start of the
    /// input.
    pub required: usize,
    /// The input length.
    pub available: usize,
}

/// A short header with the destination connection ID length the caller
/// supplied ([RFC 8999 §5.2], [RFC 9000 §17.3]).
///
/// A short header does not state the length of its destination connection
/// ID; the endpoint that chose the connection ID knows it. Different lengths
/// give different interpretations of the same bytes, and the header itself
/// cannot tell which is right. A short header extends to the end of the
/// datagram.
///
/// [RFC 8999 §5.2]: https://www.rfc-editor.org/rfc/rfc8999.html#section-5.2
/// [RFC 9000 §17.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShortHeader<'a> {
    input: &'a [u8],
    dcid: &'a [u8],
}

impl<'a> ShortHeader<'a> {
    /// Reads the destination connection ID of `dcid_len` bytes that follows
    /// the first byte of `input`.
    ///
    /// `input` is the datagram, or the part of it from the first byte of the
    /// packet. Nothing after the connection ID is read; whether a packet
    /// number and enough protected payload follow is for the removal of
    /// header protection to check.
    ///
    /// # Errors
    ///
    /// [`ShortHeaderError::Empty`] for empty input,
    /// [`ShortHeaderError::LongForm`] if the first byte announces a long
    /// header, and [`ShortHeaderError::Truncated`] if `input` ends within the
    /// connection ID.
    pub fn parse(input: &'a [u8], dcid_len: usize) -> Result<Self, ShortHeaderError> {
        let Some(&first) = input.first() else {
            return Err(ShortHeaderError::Empty);
        };
        if HeaderForm::of(first) == HeaderForm::Long {
            return Err(ShortHeaderError::LongForm);
        }
        let dcid = Reader::new(input, 1).take(dcid_len)?;
        Ok(Self { input, dcid })
    }

    /// The first byte of the packet. Its low seven bits are version-specific
    /// and some of them are protected.
    pub fn first_byte(&self) -> u8 {
        self.input[0]
    }

    /// The destination connection ID, of the length given to
    /// [`ShortHeader::parse`].
    pub fn dcid(&self) -> &'a [u8] {
        self.dcid
    }

    /// The offset of the packet number field, the first byte after the
    /// destination connection ID.
    ///
    /// The field is protected; its length is known only after header
    /// protection is removed.
    pub fn packet_number_offset(&self) -> usize {
        1 + self.dcid.len()
    }

    /// The input this header was read from, starting at its first byte; the
    /// whole packet, since a short header extends to the end of the datagram.
    pub fn input(&self) -> &'a [u8] {
        self.input
    }
}

/// Failures of [`ShortHeader::parse`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(short_header_error), visibility(pub(crate)))]
pub enum ShortHeaderError {
    /// The input has no bytes.
    #[snafu(display("no bytes for a short header"))]
    Empty,
    /// The first byte announces a long header.
    #[snafu(display("first byte announces a long header"))]
    LongForm,
    /// The input ends within the destination connection ID.
    #[snafu(transparent)]
    Truncated {
        /// Where the input ended.
        source: TruncatedError,
    },
}

/// A Version Negotiation packet ([RFC 8999 §6]): a long header with version 0.
///
/// The connection IDs echo those of the packet that prompted it and may be up
/// to 255 bytes long. The supported version list fills the rest of the
/// datagram. The other bits of the first byte are unused. Whether the packet
/// answers a packet this endpoint sent is for the client that sent it to
/// decide.
///
/// [RFC 8999 §6]: https://www.rfc-editor.org/rfc/rfc8999.html#section-6
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionNegotiation<'a> {
    header: LongHeader<'a>,
}

impl<'a> VersionNegotiation<'a> {
    /// The version field of a Version Negotiation packet.
    pub const VERSION: u32 = 0;

    /// The version-independent fields.
    pub fn header(&self) -> &LongHeader<'a> {
        &self.header
    }

    /// The destination connection ID: 0 to 255 bytes.
    pub fn dcid(&self) -> &'a [u8] {
        self.header.dcid()
    }

    /// The source connection ID: 0 to 255 bytes.
    pub fn scid(&self) -> &'a [u8] {
        self.header.scid()
    }

    /// The versions the list offers, in order. The list may be empty.
    pub fn supported_versions(&self) -> SupportedVersions<'a> {
        let (versions, _) = self.header.version_specific().as_chunks::<VERSION_LEN>();
        SupportedVersions(versions.iter())
    }
}

impl<'a> TryFrom<LongHeader<'a>> for VersionNegotiation<'a> {
    type Error = VersionNegotiationError;

    /// Accepts a long header with version 0 whose remaining input is a whole
    /// number of versions.
    ///
    /// # Errors
    ///
    /// [`VersionNegotiationError::Version`] for another version and
    /// [`VersionNegotiationError::VersionList`] if the input after the
    /// connection IDs is not a multiple of four bytes.
    fn try_from(header: LongHeader<'a>) -> Result<Self, Self::Error> {
        if header.version() != Self::VERSION {
            return Err(VersionNegotiationError::Version {
                version: header.version(),
            });
        }
        let length = header.version_specific().len();
        if !length.is_multiple_of(VERSION_LEN) {
            return Err(VersionNegotiationError::VersionList { length });
        }
        Ok(Self { header })
    }
}

/// Failures of converting a [`LongHeader`] into a [`VersionNegotiation`]
/// packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(version_negotiation_error), visibility(pub(crate)))]
pub enum VersionNegotiationError {
    /// The version field is not 0.
    #[snafu(display("version {version:#010x} is not version negotiation"))]
    Version {
        /// The version field.
        version: u32,
    },
    /// The supported version list does not end on a version boundary.
    #[snafu(display("supported version list of {length} bytes is not a multiple of 4"))]
    VersionList {
        /// The length of the input after the connection IDs.
        length: usize,
    },
}

/// The versions a [`VersionNegotiation`] packet offers, in order.
#[derive(Clone, Debug)]
pub struct SupportedVersions<'a>(slice::Iter<'a, [u8; VERSION_LEN]>);

impl Iterator for SupportedVersions<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        self.0.next().copied().map(u32::from_be_bytes)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl DoubleEndedIterator for SupportedVersions<'_> {
    fn next_back(&mut self) -> Option<u32> {
        self.0.next_back().copied().map(u32::from_be_bytes)
    }
}

impl ExactSizeIterator for SupportedVersions<'_> {}

impl FusedIterator for SupportedVersions<'_> {}

/// Reads consecutive fields of an input, tracking the offset.
struct Reader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(input: &'a [u8], offset: usize) -> Self {
        Self { input, offset }
    }

    /// Takes the next `length` bytes.
    fn take(&mut self, length: usize) -> Result<&'a [u8], TruncatedError> {
        let available = self.input.len();
        let end = self
            .offset
            .checked_add(length)
            .filter(|&end| end <= available)
            .ok_or(TruncatedError {
                required: self.offset.saturating_add(length),
                available,
            })?;
        let field = &self.input[self.offset..end];
        self.offset = end;
        Ok(field)
    }

    /// Takes the next variable-length integer.
    fn take_var_int(&mut self) -> Result<VarInt, TruncatedError> {
        let encoded_len = match VarInt::decode(&self.input[self.offset..]) {
            Ok((value, encoded_len)) => {
                self.offset += encoded_len;
                return Ok(value);
            }
            Err(DecodeError::Empty) => 1,
            Err(DecodeError::Truncated { encoded_len, .. }) => encoded_len,
        };
        Err(TruncatedError {
            required: self.offset + encoded_len,
            available: self.input.len(),
        })
    }

    /// The offset of the next field.
    fn offset(&self) -> usize {
        self.offset
    }
}

#[cfg(test)]
mod tests;
