//! CONNECTION_CLOSE frames ([RFC 9000 §19.19]).
//!
//! [RFC 9000 §19.19]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19
use super::{Head, LengthError, length_field_len, type_value, type_var_int};
use crate::{
    application_error::ApplicationErrorCode, transport_error::TransportErrorCode, var_int::VarInt,
};
use bytes::Buf;

/// A CONNECTION_CLOSE frame ([RFC 9000 §19.19]).
///
/// `D` holds the reason phrase: the source's chunk type for a frame that was
/// read, any [`Buf`] for one to write.
///
/// [RFC 9000 §19.19]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.19
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionClose<D> {
    /// The error that closes the connection; it selects the frame type.
    pub error_code: CloseErrorCode,
    /// The reason phrase; UTF-8 is expected but not checked.
    pub reason_phrase: D,
}

/// The error a CONNECTION_CLOSE frame states, which selects its type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CloseErrorCode {
    /// Type `0x1c`: an error of the QUIC layer.
    Transport {
        /// The transport error code.
        code: TransportErrorCode,
        /// The Frame Type of the frame that triggered the error, or 0 if it
        /// is unknown.
        frame_type: VarInt,
    },
    /// Type `0x1d`: an error of the application.
    Application {
        /// The application protocol error code.
        code: ApplicationErrorCode,
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
        let length = self.reason_phrase.remaining();
        self.fields().len() + length_field_len(length) + length
    }

    /// Checks that a Length field can state the length of the reason phrase.
    ///
    /// # Errors
    ///
    /// [`LengthError`] for a longer reason phrase.
    pub fn validate(&self) -> Result<(), LengthError> {
        LengthError::length_field(self.reason_phrase.remaining()).map(|_| ())
    }

    /// The Frame Type and error fields.
    fn fields(&self) -> Head<25> {
        let head = Head::new(self.type_value());
        match self.error_code {
            CloseErrorCode::Transport { code, frame_type } => {
                head.var_int(code.get()).var_int(frame_type)
            }
            CloseErrorCode::Application { code } => head.var_int(code.get()),
        }
    }

    /// The fields before the reason phrase of a frame that passed validation.
    pub(crate) fn head(&self) -> Head<25> {
        let length =
            LengthError::length_field(self.reason_phrase.remaining()).unwrap_or(VarInt::MAX);
        self.fields().var_int(length)
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
        application_error::ApplicationErrorCode,
        frame::LengthError,
        payload::{ReadPayloadError, read_payload},
        transport_error::TransportErrorCode,
        var_int::{
            VarInt,
            codec::{ReadVarIntError, ReadVarIntExt as _},
        },
    };
    use bytes::Buf;
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
        let code = field(io).await?;
        let error_code = if application {
            CloseErrorCode::Application {
                code: ApplicationErrorCode::new(code),
            }
        } else {
            CloseErrorCode::Transport {
                code: TransportErrorCode::from(code),
                frame_type: field(io).await?,
            }
        };
        let length = usize::try_from(field(io).await?.get()).unwrap_or(usize::MAX);
        let reason_phrase = read_payload(io, length)
            .await
            .context(read_connection_close_error::ReasonPhraseSnafu)?;
        Ok(ConnectionClose {
            error_code,
            reason_phrase,
        })
    }

    async fn field<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<VarInt, ReadConnectionCloseError<F::Error>> {
        io.read_var_int()
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
        frame::{Extensions, Frame, codec::ReadFrameHostExt as _, tests::assert_round_trip},
        transport_error::TransportErrorCode,
        var_int::VarInt,
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
                code: TransportErrorCode::FRAME_ENCODING_ERROR,
                frame_type: VarInt::from(0x06u8),
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
                    code: ApplicationErrorCode::new(VarInt::from(0x100u16)),
                },
                reason_phrase: &b""[..],
            })
        );
        assert_eq!(assert_round_trip(frame), application);
    }
}
