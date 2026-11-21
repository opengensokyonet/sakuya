//! NEW_TOKEN frames ([RFC 9000 §19.7]).
//!
//! [RFC 9000 §19.7]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.7
use super::{FrameType, type_value};
use crate::frame::{Head, LengthError, type_var_int};
use crate::var_int::{VarInt, VarIntWidth};
use bytes::Buf;
use snafu::Snafu;

/// A NEW_TOKEN frame ([RFC 9000 §19.7]).
///
/// The token is not empty. The Token Length field holds the length of the
/// token, so only its width is stored. [`NewTokenFrame::new`] checks that the
/// token is not empty and that the Token Length field can state its length,
/// so every value writes an encoding that reads back to the same value; the
/// fields are read through methods of the same names. `D` holds the token:
/// the type of the source for a frame that was read, any [`Buf`] for one to
/// write.
///
/// [RFC 9000 §19.7]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.7
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NewTokenFrame<D> {
    token_length_width: VarIntWidth,
    token: D,
}

impl<D> NewTokenFrame<D> {
    /// The width of the Token Length field, which holds the length of the
    /// token.
    pub const fn token_length_width(&self) -> VarIntWidth {
        self.token_length_width
    }

    /// The opaque token for a future Initial packet.
    pub const fn token(&self) -> &D {
        &self.token
    }

    /// Takes the token.
    pub fn into_token(self) -> D {
        self.token
    }

    /// The kind of the frame, [`FrameType::NewToken`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::NewToken
    }

    /// The Frame Type value, `0x07`.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::NEW_TOKEN)
    }
}

impl<D: Buf> NewTokenFrame<D> {
    /// The NEW_TOKEN frame with these fields.
    ///
    /// # Errors
    ///
    /// [`InvalidNewTokenError::Empty`] for an empty token, and
    /// [`InvalidNewTokenError::Length`] if the Token Length field is too
    /// narrow for the length of the token.
    pub fn new(token_length_width: VarIntWidth, token: D) -> Result<Self, InvalidNewTokenError> {
        let length = token.remaining();
        EmptyTokenError::check(length)?;
        LengthError::check(length, token_length_width)?;
        Ok(Self {
            token_length_width,
            token,
        })
    }

    /// The number of bytes [`codec::write_new_token_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        1 + self.token_length_width.encoded_len() + self.token.remaining()
    }

    /// The fields before the token.
    pub(crate) fn head(&self) -> Head<9> {
        // Construction checked that the width holds the token length.
        let length = VarInt::try_from(self.token.remaining()).unwrap_or(VarInt::ZERO);
        // invariant: `9` is the longest encoding of the frame's fields
        // here, so they fit.
        Head::new(self.type_value())
            .and_then(|head| head.var_int_of(length, self.token_length_width))
            .expect("the head holds the fields")
    }
}

/// The token of a NEW_TOKEN frame is empty ([RFC 9000 §19.7]).
///
/// [`NewTokenFrame::new`] reports it as [`InvalidNewTokenError::Empty`], and
/// reading as [`codec::ReadNewTokenFrameError::Empty`].
///
/// [RFC 9000 §19.7]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.7
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("NEW_TOKEN token is empty"))]
pub struct EmptyTokenError;

impl EmptyTokenError {
    /// Checks that a token of `length` bytes is not empty.
    pub(crate) fn check(length: usize) -> Result<(), Self> {
        if length == 0 {
            return Err(Self);
        }
        Ok(())
    }
}

/// A NEW_TOKEN frame would break a rule of the encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum InvalidNewTokenError {
    /// The token is empty.
    #[snafu(transparent)]
    Empty {
        /// The broken rule.
        source: EmptyTokenError,
    },
    /// The token is longer than the Token Length field can state.
    #[snafu(transparent)]
    Length {
        /// The broken limit.
        source: LengthError,
    },
}

pub mod codec {
    //! Writing NEW_TOKEN frames; reading is done by
    //! [`Frames`](crate::frame::set::Frames).

    use super::{EmptyTokenError, InvalidNewTokenError, NewTokenFrame};
    use crate::{
        frame::read_field,
        var_int::{VarInt, VarIntField},
    };
    use bytes::{Buf, BufMut};
    use nitori_io::{SplitTo, error::IncompleteError};
    use sakuya_wire::source::read_payload;
    use snafu::{ResultExt, Snafu};

    /// Reads the Token Length field that follows the Frame Type, and the
    /// token as one piece of the source.
    pub(crate) fn read_new_token_frame<S: Buf + SplitTo>(
        src: &mut S,
    ) -> Result<NewTokenFrame<S>, ReadNewTokenFrameError> {
        let length: VarIntField<VarInt> =
            read_field(src).context(read_new_token_error::TokenLengthSnafu)?;
        let token_len = usize::try_from(length.get().get()).unwrap_or(usize::MAX);
        let token = read_payload(src, token_len).context(read_new_token_error::TokenSnafu)?;
        NewTokenFrame::new(length.width(), token).map_err(|error| match error {
            InvalidNewTokenError::Empty { source } => ReadNewTokenFrameError::Empty { source },
            // invariant: the Token Length field was read at this width, and
            // `read_payload` returns a token of exactly the length it states:
            // it fails on a shorter one.
            InvalidNewTokenError::Length { source } => unreachable!("{source}"),
        })
    }

    /// Failures of reading a NEW_TOKEN frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_new_token_error), visibility(pub(crate)))]
    pub enum ReadNewTokenFrameError {
        /// The Token Length field could not be read.
        #[snafu(display("NEW_TOKEN Token Length read failed"))]
        TokenLength {
            /// The failure of reading the field.
            source: IncompleteError,
        },
        /// The Token Length is zero.
        #[snafu(transparent)]
        Empty {
            /// The broken rule.
            source: EmptyTokenError,
        },
        /// The token could not be read.
        #[snafu(display("NEW_TOKEN token read failed"))]
        Token {
            /// The failure of reading the token.
            source: IncompleteError,
        },
    }

    /// Writes `frame`; [`NewTokenFrame::new`] checked its rules.
    ///
    /// # Panics
    ///
    /// If `dst` has no room for the frame, as [`BufMut`] does.
    pub fn write_new_token_frame<D: Buf>(dst: &mut impl BufMut, frame: NewTokenFrame<D>) {
        let head = frame.head();
        dst.put_slice(head.as_slice());
        dst.put(frame.token);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EmptyTokenError, InvalidNewTokenError, NewTokenFrame, codec::ReadNewTokenFrameError,
    };
    use crate::frame::codec::ReadFieldsError;
    use crate::frame::set::codec::ReadFrameError;
    use crate::frame::tests::ReadOneFrame as _;
    use crate::frame::{Frame, tests::assert_round_trip};
    use crate::{frame::LengthError, var_int::VarIntWidth};
    use sakuya_wire::parts::{Coproduct, PartsError};

    #[test]
    fn round_trips() {
        let encoding = assert_round_trip(Frame::NewToken(
            NewTokenFrame::new(VarIntWidth::One, &b"token"[..]).unwrap(),
        ));
        assert_eq!(encoding, [0x07, 0x05, b't', b'o', b'k', b'e', b'n']);
        let encoding = assert_round_trip(Frame::NewToken(
            NewTokenFrame::new(VarIntWidth::Two, &b"token"[..]).unwrap(),
        ));
        assert_eq!(encoding, [0x07, 0x40, 0x05, b't', b'o', b'k', b'e', b'n']);
    }

    #[test]
    fn narrow_token_length_fields_are_rejected() {
        let token = [0; 64];
        let expected = InvalidNewTokenError::Length {
            source: LengthError::check(64, VarIntWidth::One).unwrap_err(),
        };
        assert_eq!(
            NewTokenFrame::new(VarIntWidth::One, &token[..]),
            Err(expected)
        );
    }

    #[test]
    fn empty_tokens_are_rejected() {
        let mut input = &[0x07, 0x00][..];
        assert!(matches!(
            input.read_one_frame(),
            Err(ReadFrameError::Fields {
                source: PartsError(Coproduct::Inl(ReadFieldsError::NewToken {
                    source: ReadNewTokenFrameError::Empty {
                        source: EmptyTokenError
                    },
                }))
            })
        ));
        // Construction reports the same failure.
        assert_eq!(
            NewTokenFrame::new(VarIntWidth::One, &b""[..]),
            Err(InvalidNewTokenError::Empty {
                source: EmptyTokenError
            })
        );
    }
}
