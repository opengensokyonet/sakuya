//! RESET_STREAM_AT frames, type `0x24`, as specified by the Internet-Draft
//! [draft-ietf-quic-reliable-stream-reset-11] §4.
//!
//! [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-4
use super::{Head, type_value, type_var_int};
use crate::{application_error::ApplicationErrorCode, stream_id::StreamId, var_int::VarInt};
use snafu::Snafu;

/// A RESET_STREAM_AT frame, type `0x24`, as specified by the Internet-Draft
/// [draft-ietf-quic-reliable-stream-reset-11] §4.
///
/// It is a RESET_STREAM that also states how much of the stream must still
/// be delivered reliably. `reliable_size` is at most `final_size`.
///
/// [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResetStreamAt {
    /// The stream being terminated.
    pub stream_id: StreamId,
    /// The application protocol error code.
    pub application_error_code: ApplicationErrorCode,
    /// The final size of the stream, in bytes.
    pub final_size: VarInt,
    /// The amount of data, from the start of the stream, that must be
    /// delivered to the application despite the reset.
    pub reliable_size: VarInt,
}

impl ResetStreamAt {
    /// The Frame Type value, `0x24`.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::RESET_STREAM_AT)
    }

    /// The number of bytes [`codec::write_reset_stream_at`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// Checks that `reliable_size` is at most `final_size`.
    ///
    /// # Errors
    ///
    /// [`ReliableSizeError`] otherwise.
    pub fn validate(&self) -> Result<(), ReliableSizeError> {
        ReliableSizeError::check(self.final_size, self.reliable_size)
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<33> {
        Head::new(self.type_value())
            .var_int(self.stream_id.get())
            .var_int(self.application_error_code.get())
            .var_int(self.final_size)
            .var_int(self.reliable_size)
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
    use crate::{
        application_error::ApplicationErrorCode,
        stream_id::StreamId,
        var_int::{
            VarInt,
            codec::{ReadVarIntError, ReadVarIntExt as _},
        },
    };
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_reset_stream_at<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<ResetStreamAt, ReadResetStreamAtError<F::Error>> {
        let stream_id = StreamId::from_var_int(field(io).await?);
        let application_error_code = ApplicationErrorCode::new(field(io).await?);
        let final_size = field(io).await?;
        let reliable_size = field(io).await?;
        ReliableSizeError::check(final_size, reliable_size)?;
        Ok(ResetStreamAt {
            stream_id,
            application_error_code,
            final_size,
            reliable_size,
        })
    }

    async fn field<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<VarInt, ReadResetStreamAtError<F::Error>> {
        io.read_var_int()
            .await
            .context(read_reset_stream_at_error::FieldSnafu)
    }

    /// Failures of reading a RESET_STREAM_AT frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_reset_stream_at_error), visibility(pub(crate)))]
    pub enum ReadResetStreamAtError<E> {
        /// A field could not be read.
        #[snafu(display("RESET_STREAM_AT field read failed"))]
        Field {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The reliable size exceeds the final size.
        #[snafu(transparent)]
        ReliableSize {
            /// The broken rule.
            source: ReliableSizeError,
        },
    }

    /// Writes `frame`, after checking it with [`ResetStreamAt::validate`].
    ///
    /// # Errors
    ///
    /// [`WriteResetStreamAtError::Invalid`] before writing anything, and
    /// [`WriteResetStreamAtError::Write`] if the receiver stops accepting
    /// bytes or fails; bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_reset_stream_at<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: ResetStreamAt,
    ) -> Result<(), WriteResetStreamAtError<F::Error>> {
        frame.validate()?;
        io.write_all(frame.head().as_slice())
            .await
            .context(write_reset_stream_at_error::WriteSnafu)
    }

    /// Failures that [`write_reset_stream_at`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(write_reset_stream_at_error), visibility(pub(crate)))]
    pub enum WriteResetStreamAtError<E> {
        /// The frame breaks a rule of the encoding; nothing was written.
        #[snafu(transparent)]
        Invalid {
            /// The broken rule.
            source: ReliableSizeError,
        },
        /// The receiver stopped accepting bytes or failed.
        #[snafu(display("RESET_STREAM_AT write failed"))]
        Write {
            /// The failure of writing.
            source: WriteAllError<E>,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ReliableSizeError, ResetStreamAt,
        codec::{ReadResetStreamAtError, WriteResetStreamAtError, WriteResetStreamAtHostExt as _},
    };
    use crate::{
        application_error::ApplicationErrorCode,
        frame::{
            Extensions, Frame,
            codec::{ReadFrameError, ReadFrameHostExt as _},
            tests::assert_round_trip,
        },
        stream_id::StreamId,
        var_int::VarInt,
    };

    fn frame(final_size: u16, reliable_size: u16) -> ResetStreamAt {
        ResetStreamAt {
            stream_id: StreamId::from_var_int(VarInt::ZERO),
            application_error_code: ApplicationErrorCode::new(VarInt::from(1u8)),
            final_size: VarInt::from(final_size),
            reliable_size: VarInt::from(reliable_size),
        }
    }

    #[test]
    fn round_trips() {
        assert_round_trip(Frame::ResetStreamAt(frame(800, 300)));
        assert_round_trip(Frame::ResetStreamAt(frame(5, 5)));
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
                source: ReadResetStreamAtError::ReliableSize { source },
                ..
            }) if source == expected
        ));
        let invalid = frame(5, 6);
        assert_eq!(invalid.validate(), Err(expected));
        let mut written = Vec::new();
        assert!(matches!(
            written.sync_write_reset_stream_at_unpin(invalid),
            Err(WriteResetStreamAtError::Invalid { .. })
        ));
        assert!(written.is_empty());
        // A field cut short.
        let mut input = &[0x24, 0x05, 0x06][..];
        assert!(matches!(
            input.sync_read_frame_unpin(Extensions::ALL),
            Err(ReadFrameError::ResetStreamAt {
                source: ReadResetStreamAtError::Field { .. },
                ..
            })
        ));
    }
}
