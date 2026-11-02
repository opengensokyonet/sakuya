//! NEW_TOKEN frames ([RFC 9000 §19.7]).
//!
//! [RFC 9000 §19.7]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.7
use super::{Head, LengthError, type_value, type_var_int};
use crate::var_int::{VarInt, VarIntWidth};
use bytes::Buf;
use snafu::Snafu;

/// A NEW_TOKEN frame ([RFC 9000 §19.7]).
///
/// The token is not empty. The Token Length field holds the length of the
/// token, so only its width is stored. `D` holds the token: the source's
/// chunk type for a frame that was read, any [`Buf`] for one to write.
///
/// [RFC 9000 §19.7]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.7
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NewToken<D> {
    /// The width of the Token Length field, which holds the length of
    /// `token`.
    pub token_length_width: VarIntWidth,
    /// The opaque token for a future Initial packet.
    pub token: D,
}

impl<D> NewToken<D> {
    /// The Frame Type value, `0x07`.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::NEW_TOKEN)
    }
}

impl<D: Buf> NewToken<D> {
    /// The number of bytes [`codec::write_new_token`] writes.
    pub fn encoded_len(&self) -> usize {
        1 + self.token_length_width.encoded_len() + self.token.remaining()
    }

    /// Checks that the token is not empty and that the Token Length field can
    /// state its length.
    ///
    /// # Errors
    ///
    /// [`InvalidNewTokenError`] for the broken rule.
    pub fn validate(&self) -> Result<(), InvalidNewTokenError> {
        let length = self.token.remaining();
        if length == 0 {
            return Err(InvalidNewTokenError::Empty);
        }
        LengthError::check(length, self.token_length_width)?;
        Ok(())
    }

    /// The fields before the token of a frame that passed validation.
    pub(crate) fn head(&self) -> Head<9> {
        // Validation checked that the width holds the token length.
        let length = VarInt::try_from(self.token.remaining()).unwrap_or(VarInt::ZERO);
        Head::new(self.type_value()).var_int_of(length, self.token_length_width)
    }
}

/// A NEW_TOKEN frame to write breaks a rule of the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(invalid_new_token_error), visibility(pub(crate)))]
pub enum InvalidNewTokenError {
    /// The token is empty.
    #[snafu(display("NEW_TOKEN token is empty"))]
    Empty,
    /// The token is longer than the Token Length field can state.
    #[snafu(transparent)]
    Length {
        /// The broken limit.
        source: LengthError,
    },
}

pub mod codec {
    //! Writing NEW_TOKEN frames as a `nitori_call` operation; reading is part
    //! of [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_new_token`] is also the operation struct [`WriteNewToken`],
    //! with `WriteNewTokenExt` on receiver accesses and `WriteNewTokenHostExt`
    //! on call executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{InvalidNewTokenError, NewToken};
    use crate::{
        frame::read_field,
        payload::{ReadPayloadError, read_payload},
        var_int::{VarInt, VarIntField, codec::ReadVarIntError},
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the Token Length field that follows the Frame Type, and the
    /// token as one chunk of the source.
    pub(crate) async fn read_new_token<F, A>(
        io: &mut A,
    ) -> Result<NewToken<F::Chunk>, ReadNewTokenError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        let length: VarIntField<VarInt> = read_field(io)
            .await
            .context(read_new_token_error::FieldSnafu)?;
        if length.get() == VarInt::ZERO {
            return read_new_token_error::EmptySnafu.fail();
        }
        let token_len = usize::try_from(length.get().get()).unwrap_or(usize::MAX);
        let token = read_payload(io, token_len)
            .await
            .context(read_new_token_error::TokenSnafu)?;
        Ok(NewToken {
            token_length_width: length.width(),
            token,
        })
    }

    /// Failures of reading a NEW_TOKEN frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_new_token_error), visibility(pub(crate)))]
    pub enum ReadNewTokenError<E> {
        /// The Token Length field could not be read.
        #[snafu(display("NEW_TOKEN field read failed"))]
        Field {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Token Length is zero.
        #[snafu(display("NEW_TOKEN token is empty"))]
        Empty,
        /// The token could not be read.
        #[snafu(display("NEW_TOKEN token read failed"))]
        Token {
            /// The failure of reading the token.
            source: ReadPayloadError<E>,
        },
    }

    /// Writes `frame`, after checking it with [`NewToken::validate`].
    ///
    /// # Errors
    ///
    /// [`WriteNewTokenError::Invalid`] before writing anything, and
    /// [`WriteNewTokenError::Write`] if the receiver stops accepting bytes or
    /// fails; bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_new_token<F, A, D>(
        io: &mut A,
        frame: NewToken<D>,
    ) -> Result<(), WriteNewTokenError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        frame.validate()?;
        write_body(io, frame)
            .await
            .context(write_new_token_error::WriteSnafu)
    }

    /// Writes a frame that has been checked.
    pub(crate) async fn write_body<F, A, D>(
        io: &mut A,
        frame: NewToken<D>,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        let head = frame.head();
        io.write_all(head.as_slice().chain(frame.token)).await
    }

    /// Failures that [`write_new_token`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(write_new_token_error), visibility(pub(crate)))]
    pub enum WriteNewTokenError<E> {
        /// The frame breaks a rule of the encoding; nothing was written.
        #[snafu(transparent)]
        Invalid {
            /// The broken rule.
            source: InvalidNewTokenError,
        },
        /// The receiver stopped accepting bytes or failed.
        #[snafu(display("NEW_TOKEN write failed"))]
        Write {
            /// The failure of writing.
            source: WriteAllError<E>,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InvalidNewTokenError, NewToken,
        codec::{ReadNewTokenError, WriteNewTokenError, WriteNewTokenHostExt as _},
    };
    use crate::{
        frame::{
            Extensions, Frame, LengthError,
            codec::{ReadFrameError, ReadFrameHostExt as _},
            tests::assert_round_trip,
        },
        var_int::VarIntWidth,
    };

    #[test]
    fn round_trips() {
        let encoding = assert_round_trip(Frame::NewToken(NewToken {
            token_length_width: VarIntWidth::One,
            token: &b"token"[..],
        }));
        assert_eq!(encoding, [0x07, 0x05, b't', b'o', b'k', b'e', b'n']);
        let encoding = assert_round_trip(Frame::NewToken(NewToken {
            token_length_width: VarIntWidth::Two,
            token: &b"token"[..],
        }));
        assert_eq!(encoding, [0x07, 0x40, 0x05, b't', b'o', b'k', b'e', b'n']);
    }

    #[test]
    fn narrow_token_length_fields_are_rejected() {
        let token = [0; 64];
        let frame = NewToken {
            token_length_width: VarIntWidth::One,
            token: &token[..],
        };
        let expected = InvalidNewTokenError::Length {
            source: LengthError {
                length: 64,
                width: VarIntWidth::One,
            },
        };
        assert_eq!(frame.validate(), Err(expected));
        let mut written = Vec::new();
        assert!(matches!(
            written.sync_write_new_token_unpin(frame),
            Err(WriteNewTokenError::Invalid { source }) if source == expected
        ));
        assert!(written.is_empty());
    }

    #[test]
    fn empty_tokens_are_rejected() {
        let mut input = &[0x07, 0x00][..];
        assert!(matches!(
            input.sync_read_frame_unpin(Extensions::NONE),
            Err(ReadFrameError::NewToken {
                source: ReadNewTokenError::Empty,
                ..
            })
        ));
        let frame = NewToken {
            token_length_width: VarIntWidth::One,
            token: &b""[..],
        };
        assert_eq!(frame.validate(), Err(InvalidNewTokenError::Empty));
        let mut written = Vec::new();
        assert!(matches!(
            written.sync_write_new_token_unpin(frame),
            Err(WriteNewTokenError::Invalid {
                source: InvalidNewTokenError::Empty
            })
        ));
        assert!(written.is_empty());
    }
}
