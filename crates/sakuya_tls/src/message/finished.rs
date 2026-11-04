//! Finished (RFC 9846 §4.5.3).
//!
//! The body of a Finished message is its verify_data, as long as the hash of
//! the cipher suite, so the reader takes that hash.

use nitori_crypto::Digest;

/// A Finished message: an HMAC over the transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Finished {
    verify_data: Digest,
}

impl Finished {
    /// The message with `verify_data`.
    pub const fn new(verify_data: Digest) -> Self {
        Self { verify_data }
    }

    /// The verify_data.
    pub const fn verify_data(&self) -> &Digest {
        &self.verify_data
    }

    /// The number of bytes [`codec::write_finished`] writes, the message
    /// header included.
    pub fn encoded_len(&self) -> usize {
        4 + self.verify_data.as_bytes().len()
    }
}

pub mod codec {
    //! Reading and writing Finished messages as `nitori_call` operations.
    //!
    //! [`read_finished`] and [`write_finished`] are also operation structs,
    //! with `{Name}Ext` on receiver accesses and `{Name}HostExt` on call
    //! executors, including the `sync_` methods.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::Finished;
    use crate::{
        alert::AlertDescription,
        message::{HandshakeType, MessageSource, ReadHeaderError, read_body},
        vector::Out,
    };
    use nitori_call::{ReceiverAccess, call};
    use nitori_crypto::{Digest, DigestLengthMismatch, HashAlgorithm};
    use nitori_io::{Write, calls::WriteAllError};
    use snafu::{ResultExt, Snafu};

    /// Reads a Finished message, header included, whose verify_data is as
    /// long as the output of `hash`.
    ///
    /// # Errors
    ///
    /// [`ReadFinishedError`].
    #[call(sync)]
    pub async fn read_finished<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        hash: HashAlgorithm,
    ) -> Result<Finished, ReadFinishedError> {
        let body = read_body(io, HandshakeType::FINISHED).await?;
        let verify_data =
            Digest::new(hash, body.as_ref()).context(read_finished_error::VerifyDataSnafu)?;
        Ok(Finished { verify_data })
    }

    /// Failures that [`read_finished`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_finished_error), visibility(pub(crate)))]
    pub enum ReadFinishedError {
        /// The header could not be read, or the message is of another type.
        #[snafu(transparent)]
        Header {
            /// The failure.
            source: ReadHeaderError,
        },
        /// The body is not as long as the hash.
        #[snafu(display("Finished verify_data has the wrong length"))]
        VerifyData {
            /// The lengths.
            source: DigestLengthMismatch,
        },
    }

    impl ReadFinishedError {
        /// The alert the failure calls for: unexpected_message for a message
        /// of another type, decode_error otherwise.
        pub fn alert(&self) -> AlertDescription {
            match self {
                Self::Header { source } => source.alert(),
                Self::VerifyData { .. } => AlertDescription::DECODE_ERROR,
            }
        }
    }

    /// Writes `finished`, header included.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_finished<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        finished: &Finished,
    ) -> Result<(), WriteAllError<F::Error>> {
        let verify_data = finished.verify_data.as_bytes();
        let mut out = Out::new(io);
        out.header(HandshakeType::FINISHED, verify_data.len())
            .await?;
        out.put(verify_data).await
    }
}

#[cfg(test)]
mod tests {
    use super::codec::{ReadFinishedError, ReadFinishedHostExt as _};
    use crate::{alert::AlertDescription, test_support::message};
    use nitori_crypto::HashAlgorithm;

    #[test]
    fn verify_data_is_as_long_as_the_hash() {
        let bytes = message(20, &[0; 32]);
        let error = bytes
            .as_slice()
            .sync_read_finished_unpin(HashAlgorithm::Sha384)
            .unwrap_err();
        let ReadFinishedError::VerifyData { source } = &error else {
            panic!("{error:?}")
        };
        assert_eq!(source.requested_len(), 32);
        assert_eq!(error.alert(), AlertDescription::DECODE_ERROR);
    }
}
