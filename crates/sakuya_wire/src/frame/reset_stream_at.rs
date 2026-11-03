//! RESET_STREAM_AT frames, type `0x24`, as specified by the Internet-Draft
//! [draft-ietf-quic-reliable-stream-reset-11] §4.
//!
//! [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-4
use super::{Head, type_value, type_var_int};
use crate::{
    application_error::ApplicationErrorCode,
    stream_id::StreamId,
    var_int::{VarInt, VarIntField},
};
use snafu::Snafu;

/// A RESET_STREAM_AT frame, type `0x24`, as specified by the Internet-Draft
/// [draft-ietf-quic-reliable-stream-reset-11] §4.
///
/// It is a RESET_STREAM that also states how much of the stream must still
/// be delivered reliably. `reliable_size` is at most `final_size`:
/// [`ResetStreamAt::new`] checks it, so every value writes an encoding that
/// reads back to the same value; the fields are read through methods of the
/// same names. Each field keeps the width of its variable-length integer
/// encoding.
///
/// [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResetStreamAt {
    stream_id: VarIntField<StreamId>,
    application_error_code: VarIntField<ApplicationErrorCode>,
    final_size: VarIntField<VarInt>,
    reliable_size: VarIntField<VarInt>,
}

impl ResetStreamAt {
    /// The RESET_STREAM_AT frame with these fields.
    ///
    /// # Errors
    ///
    /// [`ReliableSizeError`] if `reliable_size` exceeds `final_size`.
    pub fn new(
        stream_id: VarIntField<StreamId>,
        application_error_code: VarIntField<ApplicationErrorCode>,
        final_size: VarIntField<VarInt>,
        reliable_size: VarIntField<VarInt>,
    ) -> Result<Self, ReliableSizeError> {
        ReliableSizeError::check(final_size.get(), reliable_size.get())?;
        Ok(Self {
            stream_id,
            application_error_code,
            final_size,
            reliable_size,
        })
    }

    /// The stream being terminated.
    pub const fn stream_id(&self) -> VarIntField<StreamId> {
        self.stream_id
    }

    /// The application protocol error code.
    pub const fn application_error_code(&self) -> VarIntField<ApplicationErrorCode> {
        self.application_error_code
    }

    /// The final size of the stream, in bytes.
    pub const fn final_size(&self) -> VarIntField<VarInt> {
        self.final_size
    }

    /// The amount of data, from the start of the stream, that must be
    /// delivered to the application despite the reset.
    pub const fn reliable_size(&self) -> VarIntField<VarInt> {
        self.reliable_size
    }

    /// The Frame Type value, `0x24`.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::RESET_STREAM_AT)
    }

    /// The number of bytes [`codec::write_reset_stream_at`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<33> {
        Head::new(self.type_value())
            .field(self.stream_id)
            .field(self.application_error_code)
            .field(self.final_size)
            .field(self.reliable_size)
    }
}

/// A RESET_STREAM_AT reliable size exceeds its final size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "RESET_STREAM_AT reliable size {reliable_size} is beyond final size {final_size}"
))]
pub struct ReliableSizeError {
    /// The Final Size field.
    pub final_size: VarInt,
    /// The Reliable Size field.
    pub reliable_size: VarInt,
}

impl ReliableSizeError {
    fn check(final_size: VarInt, reliable_size: VarInt) -> Result<(), Self> {
        if reliable_size > final_size {
            return Err(Self {
                final_size,
                reliable_size,
            });
        }
        Ok(())
    }
}

pub mod codec {
    //! Writing RESET_STREAM_AT frames as a `nitori_call` operation; reading
    //! is part of [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_reset_stream_at`] is also the operation struct
    //! [`WriteResetStreamAt`], with `WriteResetStreamAtExt` on receiver
    //! accesses and `WriteResetStreamAtHostExt` on call executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{ReliableSizeError, ResetStreamAt};
    use crate::{frame::read_field, var_int::codec::ReadVarIntError};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_reset_stream_at<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<ResetStreamAt, ReadResetStreamAtError<F::Error>> {
        use read_reset_stream_at_error::*;
        let stream_id = read_field(io).await.context(StreamIdSnafu)?;
        let application_error_code = read_field(io)
            .await
            .context(ApplicationProtocolErrorCodeSnafu)?;
        let final_size = read_field(io).await.context(FinalSizeSnafu)?;
        let reliable_size = read_field(io).await.context(ReliableSizeSnafu)?;
        let frame =
            ResetStreamAt::new(stream_id, application_error_code, final_size, reliable_size)?;
        Ok(frame)
    }

    /// Failures of reading a RESET_STREAM_AT frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_reset_stream_at_error), visibility(pub(crate)))]
    pub enum ReadResetStreamAtError<E> {
        /// The Stream ID field could not be read.
        #[snafu(display("RESET_STREAM_AT Stream ID read failed"))]
        StreamId {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Application Protocol Error Code field could not be read.
        #[snafu(display("RESET_STREAM_AT Application Protocol Error Code read failed"))]
        ApplicationProtocolErrorCode {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Final Size field could not be read.
        #[snafu(display("RESET_STREAM_AT Final Size read failed"))]
        FinalSize {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Reliable Size field could not be read.
        #[snafu(display("RESET_STREAM_AT Reliable Size read failed"))]
        ReliableSize {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The reliable size exceeds the final size.
        #[snafu(transparent)]
        ReliableSizeAboveFinalSize {
            /// The broken rule.
            source: ReliableSizeError,
        },
    }

    /// Writes `frame`; [`ResetStreamAt::new`] checked its rule.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_reset_stream_at<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: ResetStreamAt,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::{ReliableSizeError, ResetStreamAt, codec::ReadResetStreamAtError};
    use crate::{
        application_error::ApplicationErrorCode,
        frame::{
            Extensions, Frame,
            codec::{ReadFrameError, ReadFrameHostExt as _},
            tests::assert_round_trip,
        },
        stream_id::StreamId,
        var_int::{VarInt, VarIntField},
    };

    fn frame(final_size: u16, reliable_size: u16) -> Result<ResetStreamAt, ReliableSizeError> {
        ResetStreamAt::new(
            VarIntField::shortest(StreamId::from_var_int(VarInt::ZERO)),
            VarIntField::shortest(ApplicationErrorCode::new(VarInt::from(1u8))),
            VarIntField::shortest(VarInt::from(final_size)),
            VarIntField::shortest(VarInt::from(reliable_size)),
        )
    }

    #[test]
    fn round_trips() {
        assert_round_trip(Frame::ResetStreamAt(frame(800, 300).unwrap()));
        assert_round_trip(Frame::ResetStreamAt(frame(5, 5).unwrap()));
    }

    #[test]
    fn reliable_size_beyond_final_size_is_rejected() {
        let expected = ReliableSizeError {
            final_size: VarInt::from(5u8),
            reliable_size: VarInt::from(6u8),
        };
        let mut input = &[0x24, 0x00, 0x00, 0x05, 0x06][..];
        assert!(matches!(
            input.sync_read_frame_unpin(Extensions::ALL),
            Err(ReadFrameError::ResetStreamAt {
                source: ReadResetStreamAtError::ReliableSizeAboveFinalSize { source },
                ..
            }) if source == expected
        ));
        assert_eq!(frame(5, 6), Err(expected));
    }

    #[test]
    fn each_field_has_its_own_failure() {
        fn read(encoding: &[u8]) -> ReadResetStreamAtError<core::convert::Infallible> {
            let mut input = encoding;
            match input.sync_read_frame_unpin(Extensions::ALL) {
                Err(ReadFrameError::ResetStreamAt { source, .. }) => source,
                other => panic!("{other:?}"),
            }
        }
        // A two-byte encoding cut short in each field.
        assert!(matches!(
            read(&[0x24, 0x40]),
            ReadResetStreamAtError::StreamId { source } if source.is_incomplete()
        ));
        assert!(matches!(
            read(&[0x24, 0x00, 0x40]),
            ReadResetStreamAtError::ApplicationProtocolErrorCode { source } if source.is_incomplete()
        ));
        assert!(matches!(
            read(&[0x24, 0x00, 0x00, 0x40]),
            ReadResetStreamAtError::FinalSize { source } if source.is_incomplete()
        ));
        assert!(matches!(
            read(&[0x24, 0x00, 0x00, 0x05, 0x40]),
            ReadResetStreamAtError::ReliableSize { source } if source.is_incomplete()
        ));
    }
}
