//! CONNECTION_CLOSE frames ([RFC 9000 §19.19]).
//!
//! [RFC 9000 §19.19]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19
use super::{Head, LengthError, type_value, type_var_int};
use crate::{
    application_error::ApplicationErrorCode,
    transport_error::TransportErrorCode,
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use bytes::Buf;

/// A CONNECTION_CLOSE frame ([RFC 9000 §19.19]).
///
/// The Reason Phrase Length field holds the length of the reason phrase, so
/// only its width is stored; the other variable-length integers keep the
/// widths of their encodings. `D` holds the reason phrase: the source's
/// chunk type for a frame that was read, any [`Buf`] for one to write.
///
/// [RFC 9000 §19.19]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionClose<D> {
    /// The error that closes the connection; it selects the frame type.
    pub error_code: CloseErrorCode,
    /// The width of the Reason Phrase Length field, which holds the length
    /// of `reason_phrase`.
    pub reason_phrase_length_width: VarIntWidth,
    /// The reason phrase; UTF-8 is expected but not checked.
    pub reason_phrase: D,
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

impl<D> ConnectionClose<D> {
    /// The Frame Type value: `0x1c` for a transport error, `0x1d` for an
    /// application error.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(match self.error_code {
            CloseErrorCode::Transport { .. } => type_value::CONNECTION_CLOSE,
            CloseErrorCode::Application { .. } => type_value::CONNECTION_CLOSE_APPLICATION,
        })
    }
}

impl<D: Buf> ConnectionClose<D> {
    /// The number of bytes [`codec::write_connection_close`] writes.
    pub fn encoded_len(&self) -> usize {
        self.fields().len()
            + self.reason_phrase_length_width.encoded_len()
            + self.reason_phrase.remaining()
    }

    /// Checks that the Reason Phrase Length field can state the length of the
    /// reason phrase.
    ///
    /// # Errors
    ///
    /// [`LengthError`] for a longer reason phrase.
    pub fn validate(&self) -> Result<(), LengthError> {
        LengthError::check(
            self.reason_phrase.remaining(),
            self.reason_phrase_length_width,
        )
        .map(|_| ())
    }

    /// The Frame Type and error fields.
    fn fields(&self) -> Head<25> {
        let head = Head::new(self.type_value());
        match self.error_code {
            CloseErrorCode::Transport { code, frame_type } => head.field(code).field(frame_type),
            CloseErrorCode::Application { code } => head.field(code),
        }
    }

    /// The fields before the reason phrase of a frame that passed validation.
    pub(crate) fn head(&self) -> Head<25> {
        // Validation checked that the width holds the reason phrase length.
        let length = VarInt::try_from(self.reason_phrase.remaining()).unwrap_or(VarInt::ZERO);
        self.fields()
            .var_int_of(length, self.reason_phrase_length_width)
    }
}

pub mod codec {
    //! Writing CONNECTION_CLOSE frames as a `nitori_call` operation; reading
    //! is part of [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_connection_close`] is also the operation struct
    //! [`WriteConnectionClose`], with `WriteConnectionCloseExt` on receiver
    //! accesses and `WriteConnectionCloseHostExt` on call executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{CloseErrorCode, ConnectionClose};
    use crate::{
        frame::{LengthError, read_field},
        payload::{ReadPayloadError, read_payload},
        var_int::{VarInt, VarIntField, codec::ReadVarIntError},
    };
    use bytes::Buf;
    use core::convert::Infallible;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type of a transport
    /// (`0x1c`) or, with `application`, an application (`0x1d`)
    /// CONNECTION_CLOSE frame, and the reason phrase as one chunk of the
    /// source.
    pub(crate) async fn read_connection_close<F, A>(
        io: &mut A,
        application: bool,
    ) -> Result<ConnectionClose<F::Chunk>, ReadConnectionCloseError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        let error_code = if application {
            CloseErrorCode::Application {
                code: field(io).await?,
            }
        } else {
            CloseErrorCode::Transport {
                code: field(io).await?,
                frame_type: field(io).await?,
            }
        };
        let length: VarIntField<VarInt> = field(io).await?;
        let reason_phrase_len = usize::try_from(length.get().get()).unwrap_or(usize::MAX);
        let reason_phrase = read_payload(io, reason_phrase_len)
            .await
            .context(read_connection_close_error::ReasonPhraseSnafu)?;
        Ok(ConnectionClose {
            error_code,
            reason_phrase_length_width: length.width(),
            reason_phrase,
        })
    }

    async fn field<T, F, A>(
        io: &mut A,
    ) -> Result<VarIntField<T>, ReadConnectionCloseError<F::Error>>
    where
        T: Copy + Into<VarInt> + TryFrom<VarInt, Error = Infallible>,
        F: Read,
        A: ReceiverAccess<Family = F>,
    {
        read_field(io)
            .await
            .context(read_connection_close_error::FieldSnafu)
    }

    /// Failures of reading a CONNECTION_CLOSE frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_connection_close_error), visibility(pub(crate)))]
    pub enum ReadConnectionCloseError<E> {
        /// A field before the reason phrase could not be read.
        #[snafu(display("CONNECTION_CLOSE field read failed"))]
        Field {
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

    /// Writes `frame`, after checking it with [`ConnectionClose::validate`].
    ///
    /// # Errors
    ///
    /// [`WriteConnectionCloseError::Invalid`] before writing anything, and
    /// [`WriteConnectionCloseError::Write`] if the receiver stops accepting
    /// bytes or fails; bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_connection_close<F, A, D>(
        io: &mut A,
        frame: ConnectionClose<D>,
    ) -> Result<(), WriteConnectionCloseError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        frame.validate()?;
        write_body(io, frame)
            .await
            .context(write_connection_close_error::WriteSnafu)
    }

    /// Writes a frame that has been checked.
    pub(crate) async fn write_body<F, A, D>(
        io: &mut A,
        frame: ConnectionClose<D>,
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

    /// Failures that [`write_connection_close`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(write_connection_close_error), visibility(pub(crate)))]
    pub enum WriteConnectionCloseError<E> {
        /// The frame breaks a limit of the encoding; nothing was written.
        #[snafu(transparent)]
        Invalid {
            /// The broken limit.
            source: LengthError,
        },
        /// The receiver stopped accepting bytes or failed.
        #[snafu(display("CONNECTION_CLOSE write failed"))]
        Write {
            /// The failure of writing.
            source: WriteAllError<E>,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{CloseErrorCode, ConnectionClose};
    use crate::{
        application_error::ApplicationErrorCode,
        frame::{
            Extensions, Frame,
            codec::ReadFrameHostExt as _,
            tests::{assert_round_trip, short, wide},
        },
        transport_error::TransportErrorCode,
        var_int::{VarInt, VarIntWidth},
    };

    #[test]
    fn transport_and_application_types() {
        let transport = [0x1c, 0x07, 0x06, 0x03, b'b', b'a', b'd'];
        let frame = transport
            .as_slice()
            .sync_read_frame_unpin(Extensions::NONE)
            .unwrap();
        let Frame::ConnectionClose(close) = frame else {
            panic!("{frame:?}")
        };
        assert_eq!(
            close.error_code,
            CloseErrorCode::Transport {
                code: short(TransportErrorCode::FRAME_ENCODING_ERROR),
                frame_type: short(VarInt::from(0x06u8)),
            }
        );
        assert_eq!(close.reason_phrase, b"bad");
        assert!(!frame.is_ack_eliciting());
        assert_eq!(assert_round_trip(frame), transport);

        let application = [0x1d, 0x41, 0x00, 0x00];
        let frame = application
            .as_slice()
            .sync_read_frame_unpin(Extensions::NONE)
            .unwrap();
        assert_eq!(
            frame,
            Frame::ConnectionClose(ConnectionClose {
                error_code: CloseErrorCode::Application {
                    code: short(ApplicationErrorCode::new(VarInt::from(0x100u16))),
                },
                reason_phrase_length_width: VarIntWidth::One,
                reason_phrase: &b""[..],
            })
        );
        assert_eq!(assert_round_trip(frame), application);

        // The same codes in longer encodings, with a longer Reason Phrase
        // Length field.
        let long = [0x1c, 0x80, 0, 0, 0x07, 0x40, 0x06, 0x40, 0x01, b'!'];
        let frame = long
            .as_slice()
            .sync_read_frame_unpin(Extensions::NONE)
            .unwrap();
        assert_eq!(
            frame,
            Frame::ConnectionClose(ConnectionClose {
                error_code: CloseErrorCode::Transport {
                    code: wide(TransportErrorCode::FRAME_ENCODING_ERROR, VarIntWidth::Four),
                    frame_type: wide(VarInt::from(0x06u8), VarIntWidth::Two),
                },
                reason_phrase_length_width: VarIntWidth::Two,
                reason_phrase: &b"!"[..],
            })
        );
        assert_eq!(assert_round_trip(frame), long);
    }
}
