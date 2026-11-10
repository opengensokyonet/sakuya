//! CONNECTION_CLOSE frames ([RFC 9000 §19.19]).
//!
//! [RFC 9000 §19.19]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19
use super::{FrameType, type_value};
use crate::frame::{Head, LengthError, type_var_int};
use crate::{
    v1::application_error::ApplicationErrorCode,
    v1::transport_error::TransportErrorCode,
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use bytes::Buf;

/// A CONNECTION_CLOSE frame ([RFC 9000 §19.19]).
///
/// The Reason Phrase Length field holds the length of the reason phrase, so
/// only its width is stored; the other variable-length integers keep the
/// widths of their encodings. [`ConnectionCloseFrame::new`] checks that the
/// Reason Phrase Length field can state the length of the reason phrase, so
/// every value writes an encoding that reads back to the same value; the
/// fields are read through methods of the same names. `D` holds the reason
/// phrase: the source's chunk type for a frame that was read, any [`Buf`]
/// for one to write.
///
/// [RFC 9000 §19.19]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionCloseFrame<D> {
    error_code: CloseErrorCode,
    reason_phrase_length_width: VarIntWidth,
    reason_phrase: D,
}

/// The error fields of a CONNECTION_CLOSE frame, which select its type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseErrorCode {
    /// Type `0x1c`: an error of the QUIC layer.
    Transport {
        /// The Error Code field: the transport error code.
        code: VarIntField<TransportErrorCode>,
        /// The Frame Type field: the type of the frame that triggered the
        /// error, or 0 if it is unknown.
        frame_type: VarIntField<VarInt>,
    },
    /// Type `0x1d`: an error of the application.
    Application {
        /// The Error Code field: the application protocol error code.
        code: VarIntField<ApplicationErrorCode>,
    },
}

impl<D> ConnectionCloseFrame<D> {
    /// The error that closes the connection; it selects the frame type.
    pub const fn error_code(&self) -> CloseErrorCode {
        self.error_code
    }

    /// The width of the Reason Phrase Length field, which holds the length
    /// of the reason phrase.
    pub const fn reason_phrase_length_width(&self) -> VarIntWidth {
        self.reason_phrase_length_width
    }

    /// The reason phrase; UTF-8 is expected but not checked.
    pub const fn reason_phrase(&self) -> &D {
        &self.reason_phrase
    }

    /// Takes the reason phrase.
    pub fn into_reason_phrase(self) -> D {
        self.reason_phrase
    }

    /// The kind of the frame: [`FrameType::ConnectionCloseTransport`] for
    /// a transport error, [`FrameType::ConnectionCloseApplication`] for an
    /// application error.
    pub const fn frame_type(&self) -> FrameType {
        match self.error_code {
            CloseErrorCode::Transport { .. } => FrameType::ConnectionCloseTransport,
            CloseErrorCode::Application { .. } => FrameType::ConnectionCloseApplication,
        }
    }

    /// The Frame Type value: `0x1c` for a transport error, `0x1d` for an
    /// application error.
    pub const fn type_value(&self) -> VarInt {
        type_value_of(matches!(
            self.error_code,
            CloseErrorCode::Application { .. }
        ))
    }
}

impl<D: Buf> ConnectionCloseFrame<D> {
    /// The CONNECTION_CLOSE frame with these fields.
    ///
    /// # Errors
    ///
    /// [`LengthError`] if the Reason Phrase Length field is too narrow for
    /// the length of the reason phrase.
    pub fn new(
        error_code: CloseErrorCode,
        reason_phrase_length_width: VarIntWidth,
        reason_phrase: D,
    ) -> Result<Self, LengthError> {
        LengthError::check(reason_phrase.remaining(), reason_phrase_length_width)?;
        Ok(Self {
            error_code,
            reason_phrase_length_width,
            reason_phrase,
        })
    }

    /// The number of bytes [`codec::write_connection_close_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        self.fields().len()
            + self.reason_phrase_length_width.encoded_len()
            + self.reason_phrase.remaining()
    }

    /// The Frame Type and error fields.
    fn fields(&self) -> Head<25> {
        let head = Head::new(self.type_value());
        match self.error_code {
            CloseErrorCode::Transport { code, frame_type } => head.field(code).field(frame_type),
            CloseErrorCode::Application { code } => head.field(code),
        }
    }

    /// The fields before the reason phrase.
    pub(in crate::v1) fn head(&self) -> Head<25> {
        // Construction checked that the width holds the reason phrase length.
        let length = VarInt::try_from(self.reason_phrase.remaining()).unwrap_or(VarInt::ZERO);
        self.fields()
            .var_int_of(length, self.reason_phrase_length_width)
    }
}

/// The Frame Type value of an application CONNECTION_CLOSE frame if
/// `application` is set: `0x1d`, or `0x1c` for a transport one.
pub(in crate::v1) const fn type_value_of(application: bool) -> VarInt {
    type_var_int(if application {
        type_value::CONNECTION_CLOSE_APPLICATION
    } else {
        type_value::CONNECTION_CLOSE
    })
}

pub mod codec {
    //! Writing CONNECTION_CLOSE frames as a `nitori_call` operation; reading
    //! is done by [`Frames`](crate::v1::frame::set::Frames).
    //!
    //! [`write_connection_close_frame`] is also the operation struct
    //! [`WriteConnectionCloseFrame`], with `WriteConnectionCloseFrameExt` on receiver
    //! accesses and `WriteConnectionCloseFrameHostExt` on call executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{CloseErrorCode, ConnectionCloseFrame};
    use crate::{
        frame::read_field,
        payload::{ReadPayloadError, read_payload},
        var_int::{VarInt, VarIntField, VarIntWidth, codec::ReadVarIntError},
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type of a transport
    /// CONNECTION_CLOSE frame, type `0x1c`, and the reason phrase as one
    /// chunk of the source.
    pub(in crate::v1) async fn read_connection_close_frame_transport<F, A>(
        io: &mut A,
    ) -> Result<ConnectionCloseFrame<F::Chunk>, ReadConnectionCloseFrameTransportError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        use read_connection_close_transport_error::*;
        let error_code = CloseErrorCode::Transport {
            code: read_field(io).await.context(ErrorCodeSnafu)?,
            frame_type: read_field(io).await.context(FrameTypeSnafu)?,
        };
        let (width, reason_phrase) = read_reason_phrase(io).await?;
        Ok(close(error_code, width, reason_phrase))
    }

    /// Reads the fields that follow the Frame Type of an application
    /// CONNECTION_CLOSE frame, type `0x1d`, and the reason phrase as one
    /// chunk of the source.
    pub(in crate::v1) async fn read_connection_close_frame_application<F, A>(
        io: &mut A,
    ) -> Result<ConnectionCloseFrame<F::Chunk>, ReadConnectionCloseFrameApplicationError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        use read_connection_close_application_error::*;
        let error_code = CloseErrorCode::Application {
            code: read_field(io).await.context(ErrorCodeSnafu)?,
        };
        let (width, reason_phrase) = read_reason_phrase(io).await?;
        Ok(close(error_code, width, reason_phrase))
    }

    /// Reads the Reason Phrase Length field and the reason phrase, and
    /// returns the width of the field and the reason phrase.
    async fn read_reason_phrase<F, A>(
        io: &mut A,
    ) -> Result<(VarIntWidth, F::Chunk), ReadReasonPhraseError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        use read_reason_phrase_error::*;
        let length: VarIntField<VarInt> = read_field(io).await.context(ReasonPhraseLengthSnafu)?;
        let reason_phrase_len = usize::try_from(length.get().get()).unwrap_or(usize::MAX);
        let reason_phrase = read_payload(io, reason_phrase_len)
            .await
            .context(ReasonPhraseSnafu)?;
        Ok((length.width(), reason_phrase))
    }

    /// The frame with the fields that were read.
    fn close<D: Buf>(
        error_code: CloseErrorCode,
        width: VarIntWidth,
        reason_phrase: D,
    ) -> ConnectionCloseFrame<D> {
        let frame = ConnectionCloseFrame::new(error_code, width, reason_phrase);
        // invariant: the Reason Phrase Length field was read at this width,
        // and `read_payload` returns a reason phrase of exactly the length it
        // states: it fails on a shorter one and panics on a longer chunk.
        frame.unwrap_or_else(|error| unreachable!("{error}"))
    }

    /// Failures of reading a transport CONNECTION_CLOSE frame, type `0x1c`.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_connection_close_transport_error), visibility(pub(in crate::v1)))]
    pub enum ReadConnectionCloseFrameTransportError<E> {
        /// The Error Code field, a transport error code, could not be read.
        #[snafu(display("CONNECTION_CLOSE Error Code read failed"))]
        ErrorCode {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Frame Type field could not be read.
        #[snafu(display("CONNECTION_CLOSE Frame Type read failed"))]
        FrameType {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Reason Phrase Length field or the reason phrase could not be
        /// read.
        #[snafu(transparent)]
        ReasonPhrase {
            /// The failure.
            source: ReadReasonPhraseError<E>,
        },
    }

    impl<E> ReadConnectionCloseFrameTransportError<E> {
        /// Whether the source ended within the frame.
        pub(in crate::v1) fn is_incomplete(&self) -> bool {
            match self {
                Self::ErrorCode { source } | Self::FrameType { source } => source.is_incomplete(),
                Self::ReasonPhrase { source } => source.is_incomplete(),
            }
        }
    }

    /// Failures of reading an application CONNECTION_CLOSE frame, type
    /// `0x1d`.
    #[derive(Debug, Snafu)]
    #[snafu(
        module(read_connection_close_application_error),
        visibility(pub(in crate::v1))
    )]
    pub enum ReadConnectionCloseFrameApplicationError<E> {
        /// The Error Code field, an application protocol error code, could
        /// not be read.
        #[snafu(display("CONNECTION_CLOSE Error Code read failed"))]
        ErrorCode {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Reason Phrase Length field or the reason phrase could not be
        /// read.
        #[snafu(transparent)]
        ReasonPhrase {
            /// The failure.
            source: ReadReasonPhraseError<E>,
        },
    }

    impl<E> ReadConnectionCloseFrameApplicationError<E> {
        /// Whether the source ended within the frame.
        pub(in crate::v1) fn is_incomplete(&self) -> bool {
            match self {
                Self::ErrorCode { source } => source.is_incomplete(),
                Self::ReasonPhrase { source } => source.is_incomplete(),
            }
        }
    }

    /// Failures of reading the fields that both CONNECTION_CLOSE frame types
    /// end with: the Reason Phrase Length field and the reason phrase.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_reason_phrase_error), visibility(pub(in crate::v1)))]
    pub enum ReadReasonPhraseError<E> {
        /// The Reason Phrase Length field could not be read.
        #[snafu(display("CONNECTION_CLOSE Reason Phrase Length read failed"))]
        ReasonPhraseLength {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The reason phrase could not be read.
        #[snafu(display("CONNECTION_CLOSE reason phrase read failed"))]
        ReasonPhrase {
            /// The failure of reading the reason phrase.
            source: ReadPayloadError<E>,
        },
    }

    impl<E> ReadReasonPhraseError<E> {
        /// Whether the source ended within the frame.
        pub(in crate::v1) fn is_incomplete(&self) -> bool {
            match self {
                Self::ReasonPhraseLength { source } => source.is_incomplete(),
                Self::ReasonPhrase { source } => source.is_incomplete(),
            }
        }
    }

    /// Writes `frame`; [`ConnectionCloseFrame::new`] checked its limits.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_connection_close_frame<F, A, D>(
        io: &mut A,
        frame: ConnectionCloseFrame<D>,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        let head = frame.head();
        io.write_all(head.as_slice().chain(frame.reason_phrase))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::{CloseErrorCode, ConnectionCloseFrame};
    use crate::v1::frame::tests::ReadOneFrame as _;
    use crate::{
        frame::LengthError,
        v1::application_error::ApplicationErrorCode,
        v1::frame::{
            Frame,
            tests::{assert_round_trip, short, wide},
        },
        v1::transport_error::TransportErrorCode,
        var_int::{VarInt, VarIntWidth},
    };

    #[test]
    fn transport_and_application_types() {
        let transport = [0x1c, 0x07, 0x06, 0x03, b'b', b'a', b'd'];
        let frame = transport.as_slice().read_one_frame().unwrap();
        let Frame::ConnectionClose(close) = frame else {
            panic!("{frame:?}")
        };
        assert_eq!(
            close.error_code(),
            CloseErrorCode::Transport {
                code: short(TransportErrorCode::FRAME_ENCODING_ERROR),
                frame_type: short(VarInt::from(0x06u8)),
            }
        );
        assert_eq!(*close.reason_phrase(), b"bad");
        assert!(!frame.is_ack_eliciting());
        assert_eq!(assert_round_trip(frame), transport);

        let application = [0x1d, 0x41, 0x00, 0x00];
        let frame = application.as_slice().read_one_frame().unwrap();
        let code = short(ApplicationErrorCode::new(VarInt::from(0x100u16)));
        assert_eq!(
            frame,
            Frame::ConnectionClose(
                ConnectionCloseFrame::new(
                    CloseErrorCode::Application { code },
                    VarIntWidth::One,
                    &b""[..],
                )
                .unwrap()
            )
        );
        assert_eq!(assert_round_trip(frame), application);

        // The same codes in longer encodings, with a longer Reason Phrase
        // Length field.
        let long = [0x1c, 0x80, 0, 0, 0x07, 0x40, 0x06, 0x40, 0x01, b'!'];
        let frame = long.as_slice().read_one_frame().unwrap();
        let error_code = CloseErrorCode::Transport {
            code: wide(TransportErrorCode::FRAME_ENCODING_ERROR, VarIntWidth::Four),
            frame_type: wide(VarInt::from(0x06u8), VarIntWidth::Two),
        };
        assert_eq!(
            frame,
            Frame::ConnectionClose(
                ConnectionCloseFrame::new(error_code, VarIntWidth::Two, &b"!"[..]).unwrap()
            )
        );
        assert_eq!(assert_round_trip(frame), long);
    }

    #[test]
    fn narrow_reason_phrase_length_fields_are_rejected() {
        let reason_phrase = [b'x'; 64];
        let error_code = CloseErrorCode::Application {
            code: short(ApplicationErrorCode::new(VarInt::ZERO)),
        };
        assert_eq!(
            ConnectionCloseFrame::new(error_code, VarIntWidth::One, &reason_phrase[..]),
            Err(LengthError::check(64, VarIntWidth::One).unwrap_err())
        );
        let frame = ConnectionCloseFrame::new(error_code, VarIntWidth::Two, &reason_phrase[..]);
        assert_eq!(frame.unwrap().into_reason_phrase(), &reason_phrase[..]);
    }
}
