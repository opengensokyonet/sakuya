//! The `signed_certificate_timestamp` extension (RFC 6962 §3.3).
//!
//! In ClientHello and CertificateRequest its data is empty, a request; in
//! a certificate entry of a Certificate message it is
//! [`SignedCertificateTimestampList`], the serialized SCTs for the
//! certificate, which this crate does not interpret.

use crate::{vector::LengthOutOfRangeError, width::Width};

/// A nonempty list of serialized SCTs, each of 1 to 65535 bytes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignedCertificateTimestampList<C> {
    timestamps: Vec<C>,
}

impl<C: AsRef<[u8]>> SignedCertificateTimestampList<C> {
    /// The list of `timestamps`.
    ///
    /// # Errors
    ///
    /// [`LengthOutOfRangeError`] if the list is empty, a timestamp is empty, or
    /// the encoding is longer than 65533 bytes, so that the list fits the
    /// extension.
    pub fn new(timestamps: Vec<C>) -> Result<Self, LengthOutOfRangeError> {
        for timestamp in &timestamps {
            LengthOutOfRangeError::check(timestamp.as_ref().len(), 1..=Width::U16.max())?;
        }
        let len = timestamps.iter().map(|sct| 2 + sct.as_ref().len()).sum();
        LengthOutOfRangeError::check(len, 1..=Width::U16.max() - 2)?;
        Ok(Self { timestamps })
    }

    /// The number of bytes [`codec::write_signed_certificate_timestamp_list`]
    /// writes.
    pub fn encoded_len(&self) -> usize {
        2 + self
            .timestamps
            .iter()
            .map(|sct| 2 + sct.as_ref().len())
            .sum::<usize>()
    }
}

impl<C> SignedCertificateTimestampList<C> {
    /// The serialized SCTs.
    pub fn timestamps(&self) -> &[C] {
        &self.timestamps
    }
}

pub mod codec {
    //! Reading and writing SCT lists as `nitori_call` operations.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::SignedCertificateTimestampList;
    use crate::{
        alert::AlertDescription,
        message::MessageSource,
        vector::{Out, ReadBoundedVectorError, read_bounded_vector},
        width::Width,
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{Write, calls::WriteAllError};
    use snafu::{ResultExt, Snafu};

    /// Reads the SCT list of a certificate entry.
    ///
    /// # Errors
    ///
    /// [`ReadSignedCertificateTimestampListError`].
    #[call(sync)]
    pub async fn read_signed_certificate_timestamp_list<
        F: MessageSource,
        A: ReceiverAccess<Family = F>,
    >(
        io: &mut A,
    ) -> Result<SignedCertificateTimestampList<F::Bytes>, ReadSignedCertificateTimestampListError>
    {
        use read_signed_certificate_timestamp_list_error::*;
        let range = 1..=Width::U16.max();
        let mut list = read_bounded_vector(io, Width::U16, range.clone())
            .await
            .context(ListSnafu)?;
        let mut timestamps = Vec::new();
        while list.has_remaining() {
            timestamps.push(list.sync_read_serialized_sct_unpin()?);
        }
        Ok(SignedCertificateTimestampList { timestamps })
    }

    #[call(sync)]
    async fn read_serialized_sct<F: MessageSource, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<F::Bytes, ReadSignedCertificateTimestampListError> {
        read_bounded_vector(io, Width::U16, 1..=Width::U16.max())
            .await
            .context(read_signed_certificate_timestamp_list_error::TimestampSnafu)
    }

    /// Failures that [`read_signed_certificate_timestamp_list`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(
        module(read_signed_certificate_timestamp_list_error),
        visibility(pub(crate))
    )]
    pub enum ReadSignedCertificateTimestampListError {
        /// The list could not be read.
        #[snafu(display("SCT list read failed"))]
        List {
            /// The failure of reading the list.
            source: ReadBoundedVectorError,
        },
        /// A serialized SCT could not be read.
        #[snafu(display("serialized SCT read failed"))]
        Timestamp {
            /// The failure of reading the SCT.
            source: ReadBoundedVectorError,
        },
    }

    impl ReadSignedCertificateTimestampListError {
        /// The alert the failure calls for: always decode_error.
        pub fn alert(&self) -> AlertDescription {
            AlertDescription::DECODE_ERROR
        }
    }

    /// Writes the SCT list of a certificate entry.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails.
    #[call(sync)]
    pub async fn write_signed_certificate_timestamp_list<
        F: Write,
        A: ReceiverAccess<Family = F>,
        C: AsRef<[u8]>,
    >(
        io: &mut A,
        list: &SignedCertificateTimestampList<C>,
    ) -> Result<(), WriteAllError<F::Error>> {
        list.encode(&mut Out::new(io)).await
    }

    impl<C: AsRef<[u8]>> SignedCertificateTimestampList<C> {
        pub(crate) async fn encode<F: Write, A: ReceiverAccess<Family = F>>(
            &self,
            out: &mut Out<'_, A>,
        ) -> Result<(), WriteAllError<F::Error>> {
            out.length(Width::U16, self.encoded_len() - 2).await?;
            for timestamp in &self.timestamps {
                out.vector(Width::U16, timestamp.as_ref()).await?;
            }
            Ok(())
        }
    }
}
