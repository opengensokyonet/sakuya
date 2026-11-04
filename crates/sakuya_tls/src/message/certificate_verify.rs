//! CertificateVerify (RFC 8446 §4.4.3).

use crate::{vector::LengthOutOfRange, width::Width};
use nitori_crypto::SignatureScheme;

/// A CertificateVerify: a signature over the transcript, with its scheme.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CertificateVerify<C> {
    algorithm: SignatureScheme,
    signature: C,
}

impl<C: AsRef<[u8]>> CertificateVerify<C> {
    /// The message with `signature`, made with `algorithm`.
    ///
    /// # Errors
    ///
    /// [`LengthOutOfRange`] for a signature above 65535 bytes.
    pub fn new(algorithm: SignatureScheme, signature: C) -> Result<Self, LengthOutOfRange> {
        LengthOutOfRange::check(signature.as_ref().len(), 0..=Width::U16.max())?;
        Ok(Self {
            algorithm,
            signature,
        })
    }

    fn body_len(&self) -> usize {
        2 + 2 + self.signature.as_ref().len()
    }

    /// The number of bytes [`codec::write_certificate_verify`] writes, the
    /// message header included.
    pub fn encoded_len(&self) -> usize {
        4 + self.body_len()
    }
}

impl<C> CertificateVerify<C> {
    /// The signature scheme.
    pub fn algorithm(&self) -> SignatureScheme {
        self.algorithm
    }

    /// The signature.
    pub fn signature(&self) -> &C {
        &self.signature
    }
}

pub mod codec {
    //! Reading and writing CertificateVerify messages as `nitori_call`
    //! operations.
    //!
    //! [`read_certificate_verify`] and [`write_certificate_verify`] are also
    //! operation structs, with `{Name}Ext` on receiver accesses and
    //! `{Name}HostExt` on call executors, including the `sync_` methods.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::CertificateVerify;
    use crate::{
        alert::AlertDescription,
        message::{HandshakeType, MessageSource, ReadHeaderError, read_body},
        vector::{ExcessBytes, Out, ReadVectorError, read_u16, read_vector},
        width::Width,
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_crypto::SignatureScheme;
    use nitori_io::{Write, calls::WriteAllError, error::Incomplete};
    use snafu::{ResultExt, Snafu};

    /// Reads a CertificateVerify message, header included.
    ///
    /// # Errors
    ///
    /// [`ReadCertificateVerifyError`].
    #[call(sync)]
    pub async fn read_certificate_verify<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<CertificateVerify<F::Bytes>, ReadCertificateVerifyError> {
        let mut body = read_body(io, HandshakeType::CERTIFICATE_VERIFY).await?;
        let verify = body.sync_read_certificate_verify_body_unpin()?;
        ExcessBytes::check(body.remaining()).context(read_certificate_verify_error::ExcessSnafu)?;
        Ok(verify)
    }

    #[call(sync)]
    async fn read_certificate_verify_body<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<CertificateVerify<F::Bytes>, ReadCertificateVerifyError> {
        use read_certificate_verify_error::*;
        let algorithm = SignatureScheme::new(read_u16(io).await.context(AlgorithmSnafu)?);
        let signature = read_vector(io, Width::U16).await.context(SignatureSnafu)?;
        Ok(CertificateVerify {
            algorithm,
            signature,
        })
    }

    /// Failures that [`read_certificate_verify`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_certificate_verify_error), visibility(pub(crate)))]
    pub enum ReadCertificateVerifyError {
        /// The header could not be read, or the message is of another type.
        #[snafu(transparent)]
        Header {
            /// The failure.
            source: ReadHeaderError,
        },
        /// The body is longer than its fields.
        #[snafu(display("CertificateVerify body has excess bytes"))]
        Excess {
            /// The excess.
            source: ExcessBytes,
        },
        /// algorithm could not be read.
        #[snafu(display("CertificateVerify algorithm read failed"))]
        Algorithm {
            /// The shortfall.
            source: Incomplete,
        },
        /// signature could not be read.
        #[snafu(display("CertificateVerify signature read failed"))]
        Signature {
            /// The failure.
            source: ReadVectorError,
        },
    }

    impl ReadCertificateVerifyError {
        /// The alert the failure calls for: unexpected_message for a message
        /// of another type, decode_error otherwise.
        pub fn alert(&self) -> AlertDescription {
            match self {
                Self::Header { source } => source.alert(),
                Self::Excess { .. } | Self::Algorithm { .. } | Self::Signature { .. } => {
                    AlertDescription::DECODE_ERROR
                }
            }
        }
    }

    /// Writes `verify`, header included.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written, and the error counts them over the
    /// whole message.
    #[call(sync)]
    pub async fn write_certificate_verify<
        F: Write,
        A: ReceiverAccess<Family = F>,
        C: AsRef<[u8]>,
    >(
        io: &mut A,
        verify: &CertificateVerify<C>,
    ) -> Result<(), WriteAllError<F::Error>> {
        let mut out = Out::new(io);
        out.header(HandshakeType::CERTIFICATE_VERIFY, verify.body_len())
            .await?;
        out.u16(verify.algorithm.get()).await?;
        out.vector(Width::U16, verify.signature.as_ref()).await
    }
}

#[cfg(test)]
mod tests {
    use super::codec::{ReadCertificateVerifyError, ReadCertificateVerifyHostExt as _};
    use crate::{alert::AlertDescription, test_support::message};

    #[test]
    fn the_signature_fills_the_body() {
        let short = message(15, &[0x08, 0x04, 0x00, 0x03, 1, 2]);
        let error = short
            .as_slice()
            .sync_read_certificate_verify_unpin()
            .unwrap_err();
        assert!(matches!(
            error,
            ReadCertificateVerifyError::Signature { .. }
        ));
        assert_eq!(error.alert(), AlertDescription::DECODE_ERROR);
        let long = message(15, &[0x08, 0x04, 0x00, 0x01, 1, 2]);
        let error = long
            .as_slice()
            .sync_read_certificate_verify_unpin()
            .unwrap_err();
        assert!(matches!(error, ReadCertificateVerifyError::Excess { .. }));
    }
}
