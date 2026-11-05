//! Certificate (RFC 9846 §4.5.1).
//!
//! The entries of a Certificate message hold X.509 certificates in DER, or
//! one SubjectPublicKeyInfo when the endpoints negotiated raw public keys
//! (RFC 7250); the encoding does not say which, so the reader takes the
//! [`CertificateFormat`] the handshake negotiated.

use crate::extension::extension_subset;
use crate::{
    extension::{
        BlockEntry, ExtensionType, InvalidExtensionBlockError, UnknownExtension,
        certificate_type::CertificateType, check_block,
        signed_certificate_timestamp::SignedCertificateTimestampList,
    },
    vector::LengthOutOfRangeError,
    width::Width,
};
use snafu::{ResultExt, Snafu};

/// The form of the entries of a Certificate message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CertificateFormat {
    /// X.509 certificates, the leaf first.
    X509,
    /// At most one raw public key (RFC 7250).
    RawPublicKey,
}

impl CertificateFormat {
    /// The certificate type that negotiates this form.
    pub const fn certificate_type(self) -> CertificateType {
        match self {
            Self::X509 => CertificateType::X509,
            Self::RawPublicKey => CertificateType::RAW_PUBLIC_KEY,
        }
    }
}

/// One entry of a Certificate message: a certificate or a public key, with
/// extensions that apply to it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificateEntry<C> {
    data: C,
    extensions: Vec<CertificateEntryExtension<C>>,
}

/// An extension of a certificate entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CertificateEntryExtension<C> {
    /// `signed_certificate_timestamp`: SCTs for the certificate.
    SignedCertificateTimestamp(SignedCertificateTimestampList<C>),
    /// An extension the readers do not recognize, such as `status_request`.
    Unknown(UnknownExtension<C>),
}

impl<C: AsRef<[u8]>> BlockEntry for CertificateEntryExtension<C> {
    fn extension_type(&self) -> ExtensionType {
        match self {
            Self::SignedCertificateTimestamp(_) => ExtensionType::SIGNED_CERTIFICATE_TIMESTAMP,
            Self::Unknown(extension) => extension.extension_type(),
        }
    }

    fn data_len(&self) -> usize {
        match self {
            Self::SignedCertificateTimestamp(list) => list.encoded_len(),
            Self::Unknown(extension) => extension.data().as_ref().len(),
        }
    }
}

impl<C: AsRef<[u8]>> CertificateEntry<C> {
    /// The entry of `data`, a DER certificate or SubjectPublicKeyInfo, with
    /// `extensions`.
    ///
    /// # Errors
    ///
    /// [`InvalidCertificateEntryError::Data`] for empty data or data above
    /// 2<sup>24</sup> − 1 bytes, and [`InvalidCertificateEntryError::Extensions`]
    /// for an extension type that appears twice or a block above 65535 bytes.
    pub fn new(
        data: C,
        extensions: Vec<CertificateEntryExtension<C>>,
    ) -> Result<Self, InvalidCertificateEntryError> {
        LengthOutOfRangeError::check(data.as_ref().len(), 1..=Width::U24.max())
            .context(invalid_certificate_entry::DataSnafu)?;
        check_block(&extensions, 0..=Width::U16.max())
            .context(invalid_certificate_entry::ExtensionsSnafu)?;
        Ok(Self { data, extensions })
    }

    fn block_len(&self) -> usize {
        self.extensions
            .iter()
            .map(|extension| 4 + extension.data_len())
            .sum()
    }

    fn encoded_len(&self) -> usize {
        3 + self.data.as_ref().len() + 2 + self.block_len()
    }
}

impl<C> CertificateEntry<C> {
    /// The DER certificate or SubjectPublicKeyInfo.
    pub fn data(&self) -> &C {
        &self.data
    }

    /// The extensions, in the order of the wire.
    pub fn extensions(&self) -> &[CertificateEntryExtension<C>] {
        &self.extensions
    }
}

/// Failures of [`CertificateEntry::new`].
#[derive(Debug, Snafu)]
#[snafu(module(invalid_certificate_entry), visibility(pub(crate)))]
pub enum InvalidCertificateEntryError {
    /// The data is empty or too long.
    #[snafu(display("certificate entry data length out of range"))]
    Data {
        /// The broken range.
        source: LengthOutOfRangeError,
    },
    /// The extension block is invalid.
    #[snafu(display("certificate entry extensions invalid"))]
    Extensions {
        /// Why.
        source: InvalidExtensionBlockError,
    },
}

/// The entries of a Certificate message, in their form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CertificateList<C> {
    /// X.509 certificates, the leaf first; empty for a client without a
    /// certificate.
    X509(Vec<CertificateEntry<C>>),
    /// A raw public key, or none.
    RawPublicKey(Option<CertificateEntry<C>>),
}

impl<C> CertificateList<C> {
    /// The entries.
    pub fn entries(&self) -> &[CertificateEntry<C>] {
        match self {
            Self::X509(entries) => entries,
            Self::RawPublicKey(entry) => entry.as_slice(),
        }
    }

    /// The form of the entries.
    pub fn format(&self) -> CertificateFormat {
        match self {
            Self::X509(_) => CertificateFormat::X509,
            Self::RawPublicKey(_) => CertificateFormat::RawPublicKey,
        }
    }
}

/// A Certificate message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Certificate<C> {
    certificate_request_context: C,
    certificates: CertificateList<C>,
}

impl<C: AsRef<[u8]>> Certificate<C> {
    /// The message with `certificate_request_context`, empty except in
    /// response to a CertificateRequest with a context, and `certificates`.
    ///
    /// # Errors
    ///
    /// [`InvalidCertificateError::Context`] for a context above 255 bytes, and
    /// [`InvalidCertificateError::Length`] for a message body above
    /// 2<sup>24</sup> − 1 bytes.
    pub fn new(
        certificate_request_context: C,
        certificates: CertificateList<C>,
    ) -> Result<Self, InvalidCertificateError> {
        LengthOutOfRangeError::check(
            certificate_request_context.as_ref().len(),
            0..=Width::U8.max(),
        )
        .context(invalid_certificate::ContextSnafu)?;
        let certificate = Self {
            certificate_request_context,
            certificates,
        };
        LengthOutOfRangeError::check(certificate.body_len(), 0..=Width::U24.max())
            .context(invalid_certificate::LengthSnafu)?;
        Ok(certificate)
    }

    fn list_len(&self) -> usize {
        self.certificates
            .entries()
            .iter()
            .map(CertificateEntry::encoded_len)
            .sum()
    }

    fn body_len(&self) -> usize {
        1 + self.certificate_request_context.as_ref().len() + 3 + self.list_len()
    }

    /// The number of bytes [`codec::write_certificate`] writes, the message
    /// header included.
    pub fn encoded_len(&self) -> usize {
        4 + self.body_len()
    }
}

impl<C> Certificate<C> {
    /// The certificate_request_context field.
    pub fn certificate_request_context(&self) -> &C {
        &self.certificate_request_context
    }

    /// The entries.
    pub fn certificates(&self) -> &CertificateList<C> {
        &self.certificates
    }
}

/// Failures of [`Certificate::new`].
#[derive(Debug, Snafu)]
#[snafu(module(invalid_certificate), visibility(pub(crate)))]
pub enum InvalidCertificateError {
    /// The context is too long.
    #[snafu(display("certificate_request_context too long"))]
    Context {
        /// The broken range.
        source: LengthOutOfRangeError,
    },
    /// The message body is too long.
    #[snafu(display("Certificate message too long"))]
    Length {
        /// The broken range.
        source: LengthOutOfRangeError,
    },
}

extension_subset! {
    /// A recognized extension that a certificate entry of a Certificate message may not carry:
    /// every one but `signed_certificate_timestamp`.
    CertificateEntryDisallowedExtension {
        ServerName,
        SupportedGroups,
        SignatureAlgorithms,
        ApplicationLayerProtocolNegotiation,
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
}

pub mod codec {
    //! Reading and writing Certificate messages as `nitori_call` operations.
    //!
    //! [`read_certificate`] and [`write_certificate`] are also operation
    //! structs, with `{Name}Ext` on receiver accesses and `{Name}HostExt` on
    //! call executors, including the `sync_` methods.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{
        Certificate, CertificateEntry, CertificateEntryDisallowedExtension,
        CertificateEntryExtension, CertificateFormat, CertificateList,
    };
    use crate::{
        alert::AlertDescription,
        extension::{
            BlockEntry as _, BlockReader, ExtensionNotAllowedError, ReadExtensionBlockError,
            RestrictedExtension, UnknownExtension, not_allowed, read_extension_block,
            signed_certificate_timestamp::codec::{
                ReadSignedCertificateTimestampListError,
                ReadSignedCertificateTimestampListHostExt as _,
            },
        },
        message::{HandshakeType, MessageSource, ReadHeaderError, read_body},
        vector::{
            ExcessBytesError, Out, ReadBoundedVectorError, ReadVectorError, read_bounded_vector,
            read_vector,
        },
        width::Width,
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{Write, calls::WriteAllError};
    use snafu::{ResultExt, Snafu};

    /// Reads a Certificate message, header included, whose entries have the
    /// form `format`.
    ///
    /// # Errors
    ///
    /// [`ReadCertificateError`].
    #[call(sync)]
    pub async fn read_certificate<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        format: CertificateFormat,
    ) -> Result<Certificate<F::Bytes>, ReadCertificateError> {
        use read_certificate_error::*;
        let mut body = read_body(io, HandshakeType::CERTIFICATE).await?;
        let (certificate_request_context, mut list) = body.sync_read_certificate_fields_unpin()?;
        ExcessBytesError::check(body.remaining()).context(ExcessSnafu)?;
        let mut entries = Vec::new();
        while list.has_remaining() {
            entries.push(
                list.sync_read_certificate_entry_unpin()
                    .context(EntrySnafu)?,
            );
        }
        let certificates = match format {
            CertificateFormat::X509 => CertificateList::X509(entries),
            CertificateFormat::RawPublicKey => {
                if entries.len() > 1 {
                    return MoreThanOneRawPublicKeySnafu.fail();
                }
                CertificateList::RawPublicKey(entries.pop())
            }
        };
        Ok(Certificate {
            certificate_request_context,
            certificates,
        })
    }

    /// Reads the context and the list of entries.
    #[call(sync)]
    async fn read_certificate_fields<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<(F::Bytes, F::Bytes), ReadCertificateError> {
        use read_certificate_error::*;
        let context = read_vector(io, Width::U8).await.context(ContextSnafu)?;
        let list = read_vector(io, Width::U24).await.context(ListSnafu)?;
        Ok((context, list))
    }

    /// Reads one certificate entry.
    #[call(sync)]
    async fn read_certificate_entry<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<CertificateEntry<F::Bytes>, ReadCertificateEntryError> {
        use CertificateEntryExtension as X;
        use read_certificate_entry_error::*;
        let data = read_bounded_vector(io, Width::U24, 1..=Width::U24.max())
            .await
            .context(DataSnafu)?;
        let block = read_extension_block(io).await.context(ExtensionsSnafu)?;
        let mut block = BlockReader::new(block);
        let mut extensions = Vec::new();
        while let Some((extension_type, mut data)) = block.next().context(ExtensionsSnafu)? {
            let Some(restricted) = extension_type.restricted() else {
                extensions.push(X::Unknown(UnknownExtension::read(extension_type, data)));
                continue;
            };
            extensions.push(match restricted {
                RestrictedExtension::SignedCertificateTimestamp => X::SignedCertificateTimestamp(
                    data.sync_read_signed_certificate_timestamp_list_unpin()
                        .context(SignedCertificateTimestampSnafu)?,
                ),
                other => {
                    return Err(not_allowed(other, CertificateEntryDisallowedExtension::of).into());
                }
            });
            // signed_certificate_timestamp is the one recognized extension an
            // entry may carry, and the only one read here.
            ExcessBytesError::check(data.remaining())
                .context(SignedCertificateTimestampExcessSnafu)?;
        }
        Ok(CertificateEntry { data, extensions })
    }

    /// Failures that [`read_certificate`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_certificate_error), visibility(pub(crate)))]
    pub enum ReadCertificateError {
        /// The header could not be read, or the message is of another type.
        #[snafu(transparent)]
        Header {
            /// The failure.
            source: ReadHeaderError,
        },
        /// The body is longer than its fields.
        #[snafu(display("Certificate body has excess bytes"))]
        Excess {
            /// The excess.
            source: ExcessBytesError,
        },
        /// certificate_request_context could not be read.
        #[snafu(display("certificate_request_context read failed"))]
        Context {
            /// The failure.
            source: ReadVectorError,
        },
        /// certificate_list could not be read.
        #[snafu(display("certificate_list read failed"))]
        List {
            /// The failure.
            source: ReadVectorError,
        },
        /// An entry could not be read.
        #[snafu(display("certificate entry read failed"))]
        Entry {
            /// The failure.
            source: ReadCertificateEntryError,
        },
        /// The list holds more than one raw public key (RFC 9846 §4.5.1).
        #[snafu(display("certificate_list holds more than one raw public key"))]
        MoreThanOneRawPublicKey,
    }

    impl ReadCertificateError {
        /// The alert the failure calls for: illegal_parameter for more than
        /// one raw public key, and that of the entry for a failing entry.
        pub fn alert(&self) -> AlertDescription {
            match self {
                Self::Header { source } => source.alert(),
                Self::Entry { source } => source.alert(),
                Self::MoreThanOneRawPublicKey => AlertDescription::ILLEGAL_PARAMETER,
                Self::Excess { .. } | Self::Context { .. } | Self::List { .. } => {
                    AlertDescription::DECODE_ERROR
                }
            }
        }
    }

    /// Failures of reading one certificate entry.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_certificate_entry_error), visibility(pub(crate)))]
    pub enum ReadCertificateEntryError {
        /// The certificate or public key could not be read.
        #[snafu(display("certificate data read failed"))]
        Data {
            /// The failure.
            source: ReadBoundedVectorError,
        },
        /// The extension block could not be read, or a type appears twice.
        #[snafu(display("certificate entry extensions read failed"))]
        Extensions {
            /// The failure.
            source: ReadExtensionBlockError,
        },
        /// A recognized extension that an entry may not carry.
        #[snafu(transparent)]
        ExtensionNotAllowed {
            /// The extension.
            source: ExtensionNotAllowedError<CertificateEntryDisallowedExtension>,
        },
        /// The data of `signed_certificate_timestamp`, the one recognized
        /// extension an entry may carry, is longer than its fields.
        #[snafu(display("signed_certificate_timestamp data has excess bytes"))]
        SignedCertificateTimestampExcess {
            /// The excess.
            source: ExcessBytesError,
        },
        /// `signed_certificate_timestamp` could not be read.
        #[snafu(display("signed_certificate_timestamp read failed"))]
        SignedCertificateTimestamp {
            /// The failure.
            source: ReadSignedCertificateTimestampListError,
        },
    }

    impl ReadCertificateEntryError {
        /// The alert the failure calls for: illegal_parameter for a type that
        /// appears twice and for a recognized extension an entry may not
        /// carry, decode_error for every failure to decode.
        pub fn alert(&self) -> AlertDescription {
            match self {
                Self::Extensions { source } => source.alert(),
                Self::ExtensionNotAllowed { source } => source.alert(),
                Self::Data { .. }
                | Self::SignedCertificateTimestampExcess { .. }
                | Self::SignedCertificateTimestamp { .. } => AlertDescription::DECODE_ERROR,
            }
        }
    }

    /// Writes `certificate`, header included.
    ///
    /// The length of every part is known before writing, so the message
    /// can go through a sink that hashes it as it is written.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written, and the error counts them over the
    /// whole message.
    #[call(sync)]
    pub async fn write_certificate<F: Write, A: ReceiverAccess<Family = F>, C: AsRef<[u8]>>(
        io: &mut A,
        certificate: &Certificate<C>,
    ) -> Result<(), WriteAllError<F::Error>> {
        let mut out = Out::new(io);
        out.header(HandshakeType::CERTIFICATE, certificate.body_len())
            .await?;
        out.vector(Width::U8, certificate.certificate_request_context.as_ref())
            .await?;
        out.length(Width::U24, certificate.list_len()).await?;
        for entry in certificate.certificates.entries() {
            out.vector(Width::U24, entry.data.as_ref()).await?;
            out.length(Width::U16, entry.block_len()).await?;
            for extension in &entry.extensions {
                out.u16(extension.extension_type().get()).await?;
                out.length(Width::U16, extension.data_len()).await?;
                match extension {
                    CertificateEntryExtension::SignedCertificateTimestamp(list) => {
                        list.encode(&mut out).await?
                    }
                    CertificateEntryExtension::Unknown(extension) => {
                        out.put(extension.data().as_ref()).await?
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CertificateFormat, CertificateList,
        codec::{
            ReadCertificateEntryError, ReadCertificateError, ReadCertificateHostExt as _,
            WriteCertificateHostExt as _,
        },
    };
    use crate::{
        alert::AlertDescription,
        test_support::{concat, extension, message, vector},
    };

    fn entry(data: &[u8], extensions: &[u8]) -> Vec<u8> {
        concat(&[&vector(3, data), &vector(2, extensions)])
    }

    fn certificate(entries: &[u8]) -> Vec<u8> {
        message(11, &concat(&[&[0], &vector(3, entries)]))
    }

    #[test]
    fn entries_keep_their_extensions() {
        let sct = extension(18, &[0x00, 0x04, 0x00, 0x02, 0xab, 0xcd]);
        let bytes = certificate(&concat(&[
            &entry(&[0x30, 0x00], &concat(&[&sct, &extension(5, &[1])])),
            &entry(&[0x30, 0x01, 0x00], &[]),
        ]));
        let read = bytes
            .as_slice()
            .sync_read_certificate_unpin(CertificateFormat::X509)
            .unwrap();
        assert_eq!(read.certificates().entries().len(), 2);
        assert_eq!(read.certificates().entries()[0].extensions().len(), 2);
        let mut output = Vec::new();
        output.sync_write_certificate_unpin(&read).unwrap();
        assert_eq!(output, bytes);
    }

    #[test]
    fn a_raw_public_key_is_one_entry_at_most() {
        let one = certificate(&entry(&[0x30, 0x00], &[]));
        let read = one
            .as_slice()
            .sync_read_certificate_unpin(CertificateFormat::RawPublicKey)
            .unwrap();
        assert!(matches!(
            read.certificates(),
            CertificateList::RawPublicKey(Some(_))
        ));
        let empty = certificate(&[]);
        let read = empty
            .as_slice()
            .sync_read_certificate_unpin(CertificateFormat::RawPublicKey)
            .unwrap();
        assert!(matches!(
            read.certificates(),
            CertificateList::RawPublicKey(None)
        ));
        let two = certificate(&concat(&[&entry(&[1], &[]), &entry(&[2], &[])]));
        let error = two
            .as_slice()
            .sync_read_certificate_unpin(CertificateFormat::RawPublicKey)
            .unwrap_err();
        assert!(matches!(
            error,
            ReadCertificateError::MoreThanOneRawPublicKey
        ));
        assert_eq!(error.alert(), AlertDescription::ILLEGAL_PARAMETER);
    }

    #[test]
    fn entry_rules() {
        let bytes = certificate(&entry(&[], &[]));
        let error = bytes
            .as_slice()
            .sync_read_certificate_unpin(CertificateFormat::X509)
            .unwrap_err();
        assert!(matches!(
            error,
            ReadCertificateError::Entry {
                source: ReadCertificateEntryError::Data { .. }
            }
        ));
        assert_eq!(error.alert(), AlertDescription::DECODE_ERROR);
        let bytes = certificate(&entry(&[1], &extension(16, &[0x00, 0x02, 0x01, b'a'])));
        let error = bytes
            .as_slice()
            .sync_read_certificate_unpin(CertificateFormat::X509)
            .unwrap_err();
        let ReadCertificateError::Entry {
            source: ReadCertificateEntryError::ExtensionNotAllowed { source },
        } = &error
        else {
            panic!("{error:?}")
        };
        assert_eq!(
            source.extension(),
            super::CertificateEntryDisallowedExtension::ApplicationLayerProtocolNegotiation
        );
        assert_eq!(error.alert(), AlertDescription::ILLEGAL_PARAMETER);
        let sct = extension(18, &[0x00, 0x04, 0x00, 0x02, 0xab, 0xcd, 0x00]);
        let bytes = certificate(&entry(&[1], &sct));
        let error = bytes
            .as_slice()
            .sync_read_certificate_unpin(CertificateFormat::X509)
            .unwrap_err();
        assert!(matches!(
            error,
            ReadCertificateError::Entry {
                source: ReadCertificateEntryError::SignedCertificateTimestampExcess { .. }
            }
        ));
    }
}
