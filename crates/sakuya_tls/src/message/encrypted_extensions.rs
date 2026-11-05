//! EncryptedExtensions (RFC 9846 §4.4.1).

use crate::extension::{OpaqueData, extension_subset};
use crate::{
    code_point::CodePointList,
    extension::{
        BlockEntry, ExtensionType, InvalidExtensionBlockError, UnknownExtension,
        alpn::ProtocolName, certificate_type::CertificateType, check_block,
    },
    width::Width,
};
use nitori_crypto::NamedGroup;

/// An EncryptedExtensions message: the extensions of the server that are
/// not needed to establish the cryptographic context.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EncryptedExtensions<C> {
    extensions: Vec<EncryptedExtensionsExtension<C>>,
}

/// An extension of EncryptedExtensions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EncryptedExtensionsExtension<C> {
    /// `server_name`, with empty data: the server used the name.
    ServerName,
    /// `supported_groups`: the groups the server supports.
    SupportedGroups(CodePointList<NamedGroup>),
    /// `application_layer_protocol_negotiation`: the selected protocol.
    ApplicationLayerProtocolNegotiation(ProtocolName<C>),
    /// `client_certificate_type`: the selected type.
    ClientCertificateType(CertificateType),
    /// `server_certificate_type`: the selected type.
    ServerCertificateType(CertificateType),
    /// `early_data`, with empty data: the server accepts 0-RTT.
    EarlyData,
    /// `quic_transport_parameters`, as opaque bytes.
    QuicTransportParameters(OpaqueData<C>),
    /// `encrypted_client_hello`: the retry configurations, as opaque bytes.
    EncryptedClientHello(OpaqueData<C>),
    /// An extension the readers do not recognize.
    Unknown(UnknownExtension<C>),
}

impl<C: AsRef<[u8]>> BlockEntry for EncryptedExtensionsExtension<C> {
    fn extension_type(&self) -> ExtensionType {
        match self {
            Self::ServerName => ExtensionType::SERVER_NAME,
            Self::SupportedGroups(_) => ExtensionType::SUPPORTED_GROUPS,
            Self::ApplicationLayerProtocolNegotiation(_) => {
                ExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            }
            Self::ClientCertificateType(_) => ExtensionType::CLIENT_CERTIFICATE_TYPE,
            Self::ServerCertificateType(_) => ExtensionType::SERVER_CERTIFICATE_TYPE,
            Self::EarlyData => ExtensionType::EARLY_DATA,
            Self::QuicTransportParameters(_) => ExtensionType::QUIC_TRANSPORT_PARAMETERS,
            Self::EncryptedClientHello(_) => ExtensionType::ENCRYPTED_CLIENT_HELLO,
            Self::Unknown(extension) => extension.extension_type(),
        }
    }

    fn data_len(&self) -> usize {
        match self {
            Self::ServerName | Self::EarlyData => 0,
            Self::SupportedGroups(list) => list.encoded_len(),
            Self::ApplicationLayerProtocolNegotiation(name) => name.encoded_len(),
            Self::ClientCertificateType(_) | Self::ServerCertificateType(_) => 1,
            Self::QuicTransportParameters(data) | Self::EncryptedClientHello(data) => {
                data.data().as_ref().len()
            }
            Self::Unknown(extension) => extension.data().as_ref().len(),
        }
    }
}

impl<C: AsRef<[u8]>> EncryptedExtensions<C> {
    /// The message with `extensions`.
    ///
    /// # Errors
    ///
    /// [`InvalidExtensionBlockError`] for an extension type that appears twice or a block above 65535 bytes.
    pub fn new(
        extensions: Vec<EncryptedExtensionsExtension<C>>,
    ) -> Result<Self, InvalidExtensionBlockError> {
        check_block(&extensions, 0..=Width::U16.max())?;
        Ok(Self { extensions })
    }

    fn block_len(&self) -> usize {
        self.extensions
            .iter()
            .map(|extension| 4 + extension.data_len())
            .sum()
    }

    /// The number of bytes [`codec::write_encrypted_extensions`] writes, the
    /// message header included.
    pub fn encoded_len(&self) -> usize {
        4 + 2 + self.block_len()
    }
}

impl<C> EncryptedExtensions<C> {
    /// The extensions, in the order of the wire.
    pub fn extensions(&self) -> &[EncryptedExtensionsExtension<C>] {
        &self.extensions
    }

    /// The transport parameters, if present.
    pub fn quic_transport_parameters(&self) -> Option<&C> {
        self.extensions
            .iter()
            .find_map(|extension| match extension {
                EncryptedExtensionsExtension::QuicTransportParameters(data) => Some(data.data()),
                _ => None,
            })
    }
}

extension_subset! {
    /// A recognized extension that EncryptedExtensions may not carry: every one but `server_name`,
    /// `supported_groups`, `application_layer_protocol_negotiation`, `client_certificate_type`,
    /// `server_certificate_type`, `early_data`, `quic_transport_parameters` and
    /// `encrypted_client_hello`.
    EncryptedExtensionsDisallowedExtension {
        SignatureAlgorithms,
        SignedCertificateTimestamp,
        PreSharedKey,
        SupportedVersions,
        Cookie,
        PskKeyExchangeModes,
        SignatureAlgorithmsCert,
        KeyShare,
    }
}

extension_subset! {
    /// An extension EncryptedExtensions may carry whose data has a structure, so that bytes can
    /// follow it: every extension it may carry but `quic_transport_parameters` and
    /// `encrypted_client_hello`, whose data is kept whole.
    EncryptedExtensionsStructuredExtension {
        ServerName,
        SupportedGroups,
        ApplicationLayerProtocolNegotiation,
        ClientCertificateType,
        ServerCertificateType,
        EarlyData,
    }
}

pub mod codec {
    //! Reading and writing EncryptedExtensions messages as `nitori_call`
    //! operations.
    //!
    //! [`read_encrypted_extensions`] and [`write_encrypted_extensions`] are
    //! also operation structs, with `{Name}Ext` on receiver accesses and
    //! `{Name}HostExt` on call executors, including the `sync_` methods.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{
        EncryptedExtensions, EncryptedExtensionsDisallowedExtension, EncryptedExtensionsExtension,
    };
    use crate::{
        alert::AlertDescription,
        code_point::codec::{ReadCodePointListError, ReadCodePointListHostExt as _},
        extension::{
            BlockEntry as _, BlockReader, ExtensionNotAllowedError, ReadExtensionBlockError,
            ReadExtensionBlockHostExt as _, RestrictedExtension, UnknownExtension,
            alpn::codec::{ReadSelectedProtocolError, ReadSelectedProtocolHostExt as _},
            certificate_type::CertificateType,
            excess, not_allowed,
        },
        message::{HandshakeType, MessageSource, ReadHeaderError, read_body},
        vector::{ExcessBytesError, Out, read_u8},
        width::Width,
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{Write, calls::WriteAllError, error::Incomplete};
    use snafu::{ResultExt, Snafu};

    /// Reads an EncryptedExtensions message, header included.
    ///
    /// # Errors
    ///
    /// [`ReadEncryptedExtensionsError`].
    #[call(sync)]
    pub async fn read_encrypted_extensions<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<EncryptedExtensions<F::Bytes>, ReadEncryptedExtensionsError> {
        use read_encrypted_extensions_error::*;
        let mut body = read_body(io, HandshakeType::ENCRYPTED_EXTENSIONS).await?;
        let block = body
            .sync_read_extension_block_unpin()
            .context(ExtensionsSnafu)?;
        ExcessBytesError::check(body.remaining()).context(ExcessSnafu)?;
        let mut block = BlockReader::new(block);
        let mut extensions = Vec::new();
        while let Some((extension_type, mut data)) = block.next().context(ExtensionsSnafu)? {
            let Some(restricted) = extension_type.restricted() else {
                let extension = UnknownExtension::read(extension_type, data);
                extensions.push(EncryptedExtensionsExtension::Unknown(extension));
                continue;
            };
            extensions.push(read_extension(restricted, &mut data)?);
            let of = super::EncryptedExtensionsStructuredExtension::of;
            if let Some((extension, source)) = excess(restricted, data.remaining(), of) {
                return Err(ReadEncryptedExtensionsError::ExtensionExcess { extension, source });
            }
        }
        Ok(EncryptedExtensions { extensions })
    }

    /// Reads the data of a recognized extension.
    fn read_extension<B>(
        extension: RestrictedExtension,
        data: &mut B,
    ) -> Result<EncryptedExtensionsExtension<B>, ReadEncryptedExtensionsError>
    where
        B: Buf + nitori_call::Receiver<Family: MessageSource<Bytes = B>> + Unpin + Default,
    {
        use EncryptedExtensionsExtension as X;
        use RestrictedExtension as R;
        use read_encrypted_extensions_error::*;
        Ok(match extension {
            R::ServerName => X::ServerName,
            R::SupportedGroups => X::SupportedGroups(
                data.sync_read_code_point_list_unpin()
                    .context(SupportedGroupsSnafu)?,
            ),
            R::ApplicationLayerProtocolNegotiation => X::ApplicationLayerProtocolNegotiation(
                data.sync_read_selected_protocol_unpin()
                    .context(ApplicationLayerProtocolNegotiationSnafu)?,
            ),
            R::ClientCertificateType => X::ClientCertificateType(CertificateType::new(
                data.sync_read_certificate_type_unpin()
                    .context(ClientCertificateTypeSnafu)?,
            )),
            R::ServerCertificateType => X::ServerCertificateType(CertificateType::new(
                data.sync_read_certificate_type_unpin()
                    .context(ServerCertificateTypeSnafu)?,
            )),
            R::EarlyData => X::EarlyData,
            R::QuicTransportParameters => X::QuicTransportParameters(
                crate::extension::OpaqueData::read(core::mem::take(data)),
            ),
            R::EncryptedClientHello => {
                X::EncryptedClientHello(crate::extension::OpaqueData::read(core::mem::take(data)))
            }
            other => {
                return Err(not_allowed(other, EncryptedExtensionsDisallowedExtension::of).into());
            }
        })
    }

    #[call(sync)]
    async fn read_certificate_type<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<u8, Incomplete> {
        read_u8(io).await
    }

    /// Failures that [`read_encrypted_extensions`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_encrypted_extensions_error), visibility(pub(crate)))]
    pub enum ReadEncryptedExtensionsError {
        /// The header could not be read, or the message is of another type.
        #[snafu(transparent)]
        Header {
            /// The failure.
            source: ReadHeaderError,
        },
        /// The body is longer than the extension block.
        #[snafu(display("EncryptedExtensions body has excess bytes"))]
        Excess {
            /// The excess.
            source: ExcessBytesError,
        },
        /// The extension block could not be read, or a type appears twice.
        #[snafu(display("EncryptedExtensions extensions read failed"))]
        Extensions {
            /// The failure.
            source: ReadExtensionBlockError,
        },
        /// A recognized extension that this message may not carry.
        #[snafu(transparent)]
        ExtensionNotAllowed {
            /// The extension.
            source: ExtensionNotAllowedError<EncryptedExtensionsDisallowedExtension>,
        },
        /// The data of a recognized extension is longer than its fields.
        #[snafu(display("{extension:?} data has excess bytes"))]
        ExtensionExcess {
            /// The extension.
            extension: crate::message::encrypted_extensions::EncryptedExtensionsStructuredExtension,
            /// The excess.
            source: ExcessBytesError,
        },
        /// `supported_groups` could not be read.
        #[snafu(display("supported_groups read failed"))]
        SupportedGroups {
            /// The failure.
            source: ReadCodePointListError,
        },
        /// `application_layer_protocol_negotiation` could not be read or
        /// does not hold exactly one name.
        #[snafu(display("application_layer_protocol_negotiation read failed"))]
        ApplicationLayerProtocolNegotiation {
            /// The failure.
            source: ReadSelectedProtocolError,
        },
        /// `client_certificate_type` could not be read.
        #[snafu(display("client_certificate_type read failed"))]
        ClientCertificateType {
            /// The shortfall.
            source: Incomplete,
        },
        /// `server_certificate_type` could not be read.
        #[snafu(display("server_certificate_type read failed"))]
        ServerCertificateType {
            /// The shortfall.
            source: Incomplete,
        },
    }

    impl ReadEncryptedExtensionsError {
        /// The alert the failure calls for.
        ///
        /// illegal_parameter for a type that appears twice, for a recognized
        /// extension this message may not carry (RFC 9846 §4.4.1) and for a
        /// protocol list that does not hold exactly one name; decode_error
        /// for every failure to decode.
        pub fn alert(&self) -> AlertDescription {
            match self {
                Self::Header { source } => source.alert(),
                Self::Extensions { source } => source.alert(),
                Self::ExtensionNotAllowed { source } => source.alert(),
                Self::ApplicationLayerProtocolNegotiation { source } => source.alert(),
                Self::Excess { .. }
                | Self::ExtensionExcess { .. }
                | Self::SupportedGroups { .. }
                | Self::ClientCertificateType { .. }
                | Self::ServerCertificateType { .. } => AlertDescription::DECODE_ERROR,
            }
        }
    }

    /// Writes `message`, header included.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written, and the error counts them over the
    /// whole message.
    #[call(sync)]
    pub async fn write_encrypted_extensions<
        F: Write,
        A: ReceiverAccess<Family = F>,
        C: AsRef<[u8]>,
    >(
        io: &mut A,
        message: &EncryptedExtensions<C>,
    ) -> Result<(), WriteAllError<F::Error>> {
        use EncryptedExtensionsExtension as X;
        let mut out = Out::new(io);
        let block_len = message.block_len();
        out.header(HandshakeType::ENCRYPTED_EXTENSIONS, 2 + block_len)
            .await?;
        out.length(Width::U16, block_len).await?;
        for extension in &message.extensions {
            out.u16(extension.extension_type().get()).await?;
            out.length(Width::U16, extension.data_len()).await?;
            match extension {
                X::ServerName | X::EarlyData => {}
                X::SupportedGroups(list) => out.code_point_list(list).await?,
                X::ApplicationLayerProtocolNegotiation(name) => {
                    name.encode_selected(&mut out).await?
                }
                X::ClientCertificateType(kind) | X::ServerCertificateType(kind) => {
                    out.u8(kind.get()).await?
                }
                X::QuicTransportParameters(data) | X::EncryptedClientHello(data) => {
                    out.put(data.data().as_ref()).await?
                }
                X::Unknown(extension) => out.put(extension.data().as_ref()).await?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
