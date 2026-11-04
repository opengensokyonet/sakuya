//! TLS extensions (RFC 8446 §4.2) and what their blocks share.
//!
//! An extension is a two-byte [`ExtensionType`] and its data, of up to
//! 2<sup>16</sup> − 1 bytes; a message carries its extensions as a block,
//! a list with a two-byte length. Each message type has its own enum of the
//! extensions it may carry, with the data of each in its structured form,
//! and keeps the extensions in their order on the wire.
//!
//! The readers recognize the extensions of [`RestrictedExtension`]. Each of
//! them may appear only in the messages RFC 8446 §4.2, RFC 9001 §8.2 and
//! RFC 9849 list for it, and a recognized extension in another message is
//! [`ExtensionNotAllowed`], which calls for illegal_parameter; each message
//! names the recognized extensions it may not carry in an enum of its own,
//! which is the payload of that failure. An extension
//! of any other type is kept as an [`UnknownExtension`], with its data as it
//! is, for the handshake to ignore (RFC 8446 §9.3). No type may appear twice
//! in a block ([`DuplicateExtension`]).
//!
//! The structured data of the recognized extensions lives in the child
//! modules; extensions whose data is a list of code points use the lists of
//! [`code_point`](crate::code_point). `quic_transport_parameters` and
//! `encrypted_client_hello` are kept as opaque bytes.

use crate::{
    alert::AlertDescription,
    code_point::code_point,
    message::MessageSource,
    vector::{LengthOutOfRange, ReadVectorError, read_u16, read_vector},
    width::Width,
};
use bytes::Buf;
use nitori_call::{ReceiverAccess, call};
use nitori_io::error::Incomplete;
use smallvec::SmallVec;
use snafu::{ResultExt, Snafu};

pub mod alpn;
pub mod certificate_type;
pub mod cookie;
pub mod early_data;
pub mod key_share;
pub mod pre_shared_key;
pub mod psk_key_exchange_modes;
pub mod server_name;
pub mod signed_certificate_timestamp;

code_point! {
    /// An ExtensionType code point.
    ///
    /// Any two-byte value is a code point.
    ExtensionType(u16);
    /// server_name (RFC 6066).
    SERVER_NAME = 0 => "server_name",
    /// supported_groups (RFC 8422, RFC 7919).
    SUPPORTED_GROUPS = 10 => "supported_groups",
    /// signature_algorithms.
    SIGNATURE_ALGORITHMS = 13 => "signature_algorithms",
    /// application_layer_protocol_negotiation (RFC 7301).
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16 => "application_layer_protocol_negotiation",
    /// signed_certificate_timestamp (RFC 6962).
    SIGNED_CERTIFICATE_TIMESTAMP = 18 => "signed_certificate_timestamp",
    /// client_certificate_type (RFC 7250).
    CLIENT_CERTIFICATE_TYPE = 19 => "client_certificate_type",
    /// server_certificate_type (RFC 7250).
    SERVER_CERTIFICATE_TYPE = 20 => "server_certificate_type",
    /// pre_shared_key.
    PRE_SHARED_KEY = 41 => "pre_shared_key",
    /// early_data.
    EARLY_DATA = 42 => "early_data",
    /// supported_versions.
    SUPPORTED_VERSIONS = 43 => "supported_versions",
    /// cookie.
    COOKIE = 44 => "cookie",
    /// psk_key_exchange_modes.
    PSK_KEY_EXCHANGE_MODES = 45 => "psk_key_exchange_modes",
    /// signature_algorithms_cert.
    SIGNATURE_ALGORITHMS_CERT = 50 => "signature_algorithms_cert",
    /// key_share.
    KEY_SHARE = 51 => "key_share",
    /// quic_transport_parameters (RFC 9001).
    QUIC_TRANSPORT_PARAMETERS = 57 => "quic_transport_parameters",
    /// encrypted_client_hello (RFC 9849).
    ENCRYPTED_CLIENT_HELLO = 0xfe0d => "encrypted_client_hello",
}

impl ExtensionType {
    /// The recognized extension of this type, or `None` for a type the
    /// readers keep as an [`UnknownExtension`].
    pub const fn restricted(self) -> Option<RestrictedExtension> {
        use RestrictedExtension::*;
        Some(match self {
            Self::SERVER_NAME => ServerName,
            Self::SUPPORTED_GROUPS => SupportedGroups,
            Self::SIGNATURE_ALGORITHMS => SignatureAlgorithms,
            Self::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => ApplicationLayerProtocolNegotiation,
            Self::SIGNED_CERTIFICATE_TIMESTAMP => SignedCertificateTimestamp,
            Self::CLIENT_CERTIFICATE_TYPE => ClientCertificateType,
            Self::SERVER_CERTIFICATE_TYPE => ServerCertificateType,
            Self::PRE_SHARED_KEY => PreSharedKey,
            Self::EARLY_DATA => EarlyData,
            Self::SUPPORTED_VERSIONS => SupportedVersions,
            Self::COOKIE => Cookie,
            Self::PSK_KEY_EXCHANGE_MODES => PskKeyExchangeModes,
            Self::SIGNATURE_ALGORITHMS_CERT => SignatureAlgorithmsCert,
            Self::KEY_SHARE => KeyShare,
            Self::QUIC_TRANSPORT_PARAMETERS => QuicTransportParameters,
            Self::ENCRYPTED_CLIENT_HELLO => EncryptedClientHello,
            _ => return None,
        })
    }
}

/// An extension the readers recognize. Each may appear only in some
/// messages.
///
/// | Extension | Messages |
/// | --- | --- |
/// | `server_name` | ClientHello, EncryptedExtensions |
/// | `supported_groups` | ClientHello, EncryptedExtensions |
/// | `signature_algorithms` | ClientHello, CertificateRequest |
/// | `application_layer_protocol_negotiation` | ClientHello, EncryptedExtensions |
/// | `signed_certificate_timestamp` | ClientHello, CertificateRequest, Certificate |
/// | `client_certificate_type` | ClientHello, EncryptedExtensions |
/// | `server_certificate_type` | ClientHello, EncryptedExtensions |
/// | `pre_shared_key` | ClientHello, ServerHello |
/// | `early_data` | ClientHello, EncryptedExtensions, NewSessionTicket |
/// | `supported_versions` | ClientHello, ServerHello, HelloRetryRequest |
/// | `cookie` | ClientHello, HelloRetryRequest |
/// | `psk_key_exchange_modes` | ClientHello |
/// | `signature_algorithms_cert` | ClientHello, CertificateRequest |
/// | `key_share` | ClientHello, ServerHello, HelloRetryRequest |
/// | `quic_transport_parameters` | ClientHello, EncryptedExtensions |
/// | `encrypted_client_hello` | ClientHello, EncryptedExtensions, HelloRetryRequest |
///
/// In Certificate the extensions are those of each certificate entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum RestrictedExtension {
    ServerName,
    SupportedGroups,
    SignatureAlgorithms,
    ApplicationLayerProtocolNegotiation,
    SignedCertificateTimestamp,
    ClientCertificateType,
    ServerCertificateType,
    PreSharedKey,
    EarlyData,
    SupportedVersions,
    Cookie,
    PskKeyExchangeModes,
    SignatureAlgorithmsCert,
    KeyShare,
    QuicTransportParameters,
    EncryptedClientHello,
}

impl RestrictedExtension {
    /// Every recognized extension.
    #[cfg(test)]
    pub(crate) const ALL: [Self; 16] = [
        Self::ServerName,
        Self::SupportedGroups,
        Self::SignatureAlgorithms,
        Self::ApplicationLayerProtocolNegotiation,
        Self::SignedCertificateTimestamp,
        Self::ClientCertificateType,
        Self::ServerCertificateType,
        Self::PreSharedKey,
        Self::EarlyData,
        Self::SupportedVersions,
        Self::Cookie,
        Self::PskKeyExchangeModes,
        Self::SignatureAlgorithmsCert,
        Self::KeyShare,
        Self::QuicTransportParameters,
        Self::EncryptedClientHello,
    ];

    /// The extension type.
    pub const fn extension_type(self) -> ExtensionType {
        match self {
            Self::ServerName => ExtensionType::SERVER_NAME,
            Self::SupportedGroups => ExtensionType::SUPPORTED_GROUPS,
            Self::SignatureAlgorithms => ExtensionType::SIGNATURE_ALGORITHMS,
            Self::ApplicationLayerProtocolNegotiation => {
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            }
            Self::SignedCertificateTimestamp => ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP,
            Self::ClientCertificateType => ExtensionType::CLIENT_CERTIFICATE_TYPE,
            Self::ServerCertificateType => ExtensionType::SERVER_CERTIFICATE_TYPE,
            Self::PreSharedKey => ExtensionType::PRE_SHARED_KEY,
            Self::EarlyData => ExtensionType::EARLY_DATA,
            Self::SupportedVersions => ExtensionType::SUPPORTED_VERSIONS,
            Self::Cookie => ExtensionType::COOKIE,
            Self::PskKeyExchangeModes => ExtensionType::PSK_KEY_EXCHANGE_MODES,
            Self::SignatureAlgorithmsCert => ExtensionType::SIGNATURE_ALGORITHMS_CERT,
            Self::KeyShare => ExtensionType::KEY_SHARE,
            Self::QuicTransportParameters => ExtensionType::QUIC_TRANSPORT_PARAMETERS,
            Self::EncryptedClientHello => ExtensionType::ENCRYPTED_CLIENT_HELLO,
        }
    }
}

/// An extension of a type the readers do not recognize, with its data as
/// it is.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnknownExtension<C> {
    extension_type: ExtensionType,
    data: C,
}

impl<C: AsRef<[u8]>> UnknownExtension<C> {
    /// The extension of type `extension_type` with `data`.
    ///
    /// # Errors
    ///
    /// [`InvalidUnknownExtension::Recognized`] for a type the readers
    /// recognize, whose data they would read in its structured form, and
    /// [`InvalidUnknownExtension::Data`] for data above 2<sup>16</sup> − 1
    /// bytes.
    pub fn new(extension_type: ExtensionType, data: C) -> Result<Self, InvalidUnknownExtension> {
        if let Some(extension) = extension_type.restricted() {
            return Err(InvalidUnknownExtension::Recognized { extension });
        }
        LengthOutOfRange::check(data.as_ref().len(), 0..=Width::U16.max())
            .context(invalid_unknown_extension::DataSnafu)?;
        Ok(Self {
            extension_type,
            data,
        })
    }

    /// The number of bytes the extension takes in a block.
    pub fn encoded_len(&self) -> usize {
        4 + self.data.as_ref().len()
    }
}

impl<C> UnknownExtension<C> {
    pub(crate) fn read(extension_type: ExtensionType, data: C) -> Self {
        Self {
            extension_type,
            data,
        }
    }

    /// The extension type.
    pub fn extension_type(&self) -> ExtensionType {
        self.extension_type
    }

    /// The data.
    pub fn data(&self) -> &C {
        &self.data
    }
}

/// Failures of [`UnknownExtension::new`].
#[derive(Debug, Snafu)]
#[snafu(module(invalid_unknown_extension), visibility(pub(crate)))]
pub enum InvalidUnknownExtension {
    /// The type is one the readers recognize.
    #[snafu(display("{extension:?} is a recognized extension"))]
    Recognized {
        /// The extension.
        extension: RestrictedExtension,
    },
    /// The data is too long.
    #[snafu(display("unknown extension data too long"))]
    Data {
        /// The broken range.
        source: LengthOutOfRange,
    },
}

/// An extension type appears twice in one block (RFC 8446 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("{extension:?} appears more than once"))]
pub struct DuplicateExtension {
    extension: ExtensionType,
}

impl DuplicateExtension {
    /// The extension type.
    pub const fn extension(self) -> ExtensionType {
        self.extension
    }

    /// The alert the failure calls for: illegal_parameter.
    pub fn alert(&self) -> AlertDescription {
        AlertDescription::ILLEGAL_PARAMETER
    }
}

/// A recognized extension appears in a message it may not appear in
/// (RFC 8446 §4.2).
///
/// `X` is the enum of the message's disallowed extensions: the recognized
/// extensions that message may not carry, and only those.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("{extension:?} is not allowed in this message"))]
pub struct ExtensionNotAllowed<X: core::fmt::Debug> {
    extension: X,
}

impl<X: Copy + core::fmt::Debug> ExtensionNotAllowed<X> {
    pub(crate) fn new(extension: X) -> Self {
        Self { extension }
    }

    /// The extension.
    pub const fn extension(self) -> X {
        self.extension
    }

    /// The alert the failure calls for: illegal_parameter.
    pub fn alert(&self) -> AlertDescription {
        AlertDescription::ILLEGAL_PARAMETER
    }
}

/// Defines the enum of the recognized extensions a message may not carry,
/// each variant named as in [`RestrictedExtension`].
macro_rules! disallowed_extensions {
    (
        $(#[$meta:meta])*
        $name:ident { $($variant:ident,)* }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[allow(missing_docs)]
        pub enum $name {
            $($variant,)*
        }

        impl $name {
            /// The recognized extension.
            pub const fn restricted(self) -> $crate::extension::RestrictedExtension {
                match self {
                    $(Self::$variant => $crate::extension::RestrictedExtension::$variant,)*
                }
            }

            /// The extension type.
            pub const fn extension_type(self) -> $crate::extension::ExtensionType {
                self.restricted().extension_type()
            }

            /// `extension`, if the message may not carry it.
            pub(crate) const fn of(
                extension: $crate::extension::RestrictedExtension,
            ) -> Option<Self> {
                match extension {
                    $($crate::extension::RestrictedExtension::$variant => Some(Self::$variant),)*
                    _ => None,
                }
            }
        }
    };
}

pub(crate) use disallowed_extensions;

/// The failure for `extension`, which a message may not carry; `of` is the
/// `of` of the message's disallowed enum.
pub(crate) fn not_allowed<X: Copy + core::fmt::Debug>(
    extension: RestrictedExtension,
    of: fn(RestrictedExtension) -> Option<X>,
) -> ExtensionNotAllowed<X> {
    match of(extension) {
        Some(extension) => ExtensionNotAllowed::new(extension),
        // invariant: the caller has matched every extension the message may
        // carry, and the disallowed enum names every other one.
        None => unreachable!("{extension:?} may appear in this message"),
    }
}

/// Failures of reading the structure of an extension block, which every
/// message with extensions shares.
#[derive(Debug, Snafu)]
#[snafu(module(extension_block_error), visibility(pub(crate)))]
pub enum ExtensionBlockError {
    /// The block could not be read.
    #[snafu(display("extension block read failed"))]
    Block {
        /// The failure of reading the block.
        source: ReadVectorError,
    },
    /// The type of an extension could not be read.
    #[snafu(display("extension type read failed"))]
    Type {
        /// The shortfall.
        source: Incomplete,
    },
    /// The data of an extension could not be read.
    #[snafu(display("{extension:?} data read failed"))]
    Data {
        /// The extension type.
        extension: ExtensionType,
        /// The failure of reading the data.
        source: ReadVectorError,
    },
    /// An extension type appears twice.
    #[snafu(transparent)]
    Duplicate {
        /// The type.
        source: DuplicateExtension,
    },
}

impl ExtensionBlockError {
    /// The alert the failure calls for: illegal_parameter for a duplicate
    /// type, decode_error otherwise.
    pub fn alert(&self) -> AlertDescription {
        match self {
            Self::Duplicate { source } => source.alert(),
            Self::Block { .. } | Self::Type { .. } | Self::Data { .. } => {
                AlertDescription::DECODE_ERROR
            }
        }
    }
}

/// Failures of building the extension block of a message to write.
#[derive(Debug, Snafu)]
#[snafu(module(invalid_extensions), visibility(pub(crate)))]
pub enum InvalidExtensions {
    /// An extension type appears twice.
    #[snafu(transparent)]
    Duplicate {
        /// The type.
        source: DuplicateExtension,
    },
    /// The data of an extension is longer than 2<sup>16</sup> − 1 bytes.
    #[snafu(display("{extension:?} data too long"))]
    Data {
        /// The extension type.
        extension: ExtensionType,
        /// The broken range.
        source: LengthOutOfRange,
    },
    /// The block is shorter or longer than the message allows.
    #[snafu(display("extension block length out of range"))]
    Length {
        /// The broken range.
        source: LengthOutOfRange,
    },
}

/// An entry of an extension block of some message.
pub(crate) trait BlockEntry {
    /// The type of the extension.
    fn extension_type(&self) -> ExtensionType;

    /// The number of bytes of the extension data.
    fn data_len(&self) -> usize;
}

/// Checks the extensions of a message to write: no type twice, and a block
/// length in `range`. Returns the block length.
pub(crate) fn check_block<X: BlockEntry>(
    extensions: &[X],
    range: core::ops::RangeInclusive<usize>,
) -> Result<usize, InvalidExtensions> {
    let mut seen = Seen::default();
    let mut len = 0;
    for extension in extensions {
        let extension_type = extension.extension_type();
        seen.insert(extension_type)?;
        let data_len = extension.data_len();
        LengthOutOfRange::check(data_len, 0..=Width::U16.max()).context(
            invalid_extensions::DataSnafu {
                extension: extension_type,
            },
        )?;
        len += 4 + data_len;
    }
    LengthOutOfRange::check(len, range).context(invalid_extensions::LengthSnafu)?;
    Ok(len)
}

/// The extension types seen so far in a block.
#[derive(Default)]
pub(crate) struct Seen(SmallVec<[ExtensionType; 24]>);

impl Seen {
    /// Records `extension`, which must not have been seen before.
    pub(crate) fn insert(&mut self, extension: ExtensionType) -> Result<(), DuplicateExtension> {
        if self.0.contains(&extension) {
            return Err(DuplicateExtension { extension });
        }
        self.0.push(extension);
        Ok(())
    }
}

/// Reads the two-byte length of an extension block and the block.
#[call(sync)]
pub(crate) async fn read_extension_block<F: MessageSource, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<F::Bytes, ExtensionBlockError> {
    read_vector(io, Width::U16)
        .await
        .context(extension_block_error::BlockSnafu)
}

/// Reads the type and data of the next extension of a block.
#[call(sync)]
pub(crate) async fn read_extension_entry<F: MessageSource, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<(ExtensionType, F::Bytes), ExtensionBlockError> {
    use extension_block_error::*;
    let extension = ExtensionType(read_u16(io).await.context(TypeSnafu)?);
    let data = read_vector(io, Width::U16)
        .await
        .context(DataSnafu { extension })?;
    Ok((extension, data))
}

/// Iterates over the extensions of a block, checking that no type appears
/// twice.
pub(crate) struct BlockReader<B> {
    block: B,
    seen: Seen,
}

impl<B: Buf + nitori_call::Receiver<Family: MessageSource<Bytes = B>> + Unpin> BlockReader<B> {
    pub(crate) fn new(block: B) -> Self {
        Self {
            block,
            seen: Seen::default(),
        }
    }

    /// The type and data of the next extension, or `None` at the end of the
    /// block.
    pub(crate) fn next(&mut self) -> Result<Option<(ExtensionType, B)>, ExtensionBlockError> {
        if !self.block.has_remaining() {
            return Ok(None);
        }
        let (extension, data) = self.block.sync_read_extension_entry_unpin()?;
        self.seen.insert(extension)?;
        Ok(Some((extension, data)))
    }
}
