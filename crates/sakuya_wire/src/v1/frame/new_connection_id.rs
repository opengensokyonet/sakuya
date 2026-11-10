//! NEW_CONNECTION_ID frames ([RFC 9000 §19.15]).
//!
//! [RFC 9000 §19.15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
use super::{FrameType, type_value};
use crate::frame::{Head, type_var_int};
use crate::{
    connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken},
    var_int::{VarInt, VarIntField},
};
use snafu::Snafu;

/// A NEW_CONNECTION_ID frame ([RFC 9000 §19.15]).
///
/// `retire_prior_to` is at most `sequence_number`: [`NewConnectionIdFrame::new`]
/// checks it, so every value writes an encoding that reads back to the same
/// value; the fields are read through methods of the same names. Each
/// variable-length integer field keeps the width of its encoding.
///
/// [RFC 9000 §19.15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NewConnectionIdFrame {
    sequence_number: VarIntField<VarInt>,
    retire_prior_to: VarIntField<VarInt>,
    connection_id: NonEmptyCid,
    stateless_reset_token: StatelessResetToken,
}

/// The longest encoding of the frame.
const ENCODED_MAX: usize = 1 + 8 + 8 + 1 + ConnectionId::MAX_LEN + StatelessResetToken::LEN;

impl NewConnectionIdFrame {
    /// The NEW_CONNECTION_ID frame with these fields.
    ///
    /// # Errors
    ///
    /// [`RetirePriorToError`] if `retire_prior_to` exceeds
    /// `sequence_number`.
    pub fn new(
        sequence_number: VarIntField<VarInt>,
        retire_prior_to: VarIntField<VarInt>,
        connection_id: NonEmptyCid,
        stateless_reset_token: StatelessResetToken,
    ) -> Result<Self, RetirePriorToError> {
        RetirePriorToError::check(sequence_number.get(), retire_prior_to.get())?;
        Ok(Self {
            sequence_number,
            retire_prior_to,
            connection_id,
            stateless_reset_token,
        })
    }

    /// The sequence number the sender assigned to the connection ID.
    pub const fn sequence_number(&self) -> VarIntField<VarInt> {
        self.sequence_number
    }

    /// The sequence number below which connection IDs are to be retired.
    pub const fn retire_prior_to(&self) -> VarIntField<VarInt> {
        self.retire_prior_to
    }

    /// The connection ID: 1 to 20 bytes.
    pub const fn connection_id(&self) -> NonEmptyCid {
        self.connection_id
    }

    /// The Stateless Reset Token for the connection ID.
    pub const fn stateless_reset_token(&self) -> StatelessResetToken {
        self.stateless_reset_token
    }

    /// The kind of the frame, [`FrameType::NewConnectionId`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::NewConnectionId
    }

    /// The Frame Type value, `0x18`.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::NEW_CONNECTION_ID)
    }

    /// The number of bytes [`codec::write_new_connection_id_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(in crate::v1) fn head(&self) -> Head<ENCODED_MAX> {
        let connection_id = self.connection_id.as_bytes();
        // A connection ID has at most 20 bytes, so its length fits a byte.
        Head::new(self.type_value())
            .field(self.sequence_number)
            .field(self.retire_prior_to)
            .bytes(&[connection_id.len() as u8])
            .bytes(connection_id)
            .bytes(self.stateless_reset_token.as_bytes())
    }
}

/// A NEW_CONNECTION_ID frame retires sequence numbers beyond its own.
///
/// Only [`NewConnectionIdFrame::new`] constructs it, when the check fails, so its
/// Retire Prior To always exceeds its Sequence Number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "NEW_CONNECTION_ID retires prior to {retire_prior_to}, beyond its sequence number {sequence_number}"
))]
pub struct RetirePriorToError {
    sequence_number: VarInt,
    retire_prior_to: VarInt,
}

impl RetirePriorToError {
    /// The Sequence Number field.
    pub const fn sequence_number(self) -> VarInt {
        self.sequence_number
    }

    /// The Retire Prior To field, which exceeds
    /// [`sequence_number`](Self::sequence_number).
    pub const fn retire_prior_to(self) -> VarInt {
        self.retire_prior_to
    }

    /// Checks that `retire_prior_to` is at most `sequence_number`.
    fn check(sequence_number: VarInt, retire_prior_to: VarInt) -> Result<(), Self> {
        if retire_prior_to > sequence_number {
            return Err(Self {
                sequence_number,
                retire_prior_to,
            });
        }
        Ok(())
    }
}

pub mod codec {
    //! Writing NEW_CONNECTION_ID frames as a `nitori_call` operation; reading
    //! is done by [`Frames`](crate::v1::frame::set::Frames).
    //!
    //! [`write_new_connection_id_frame`] is also the operation struct
    //! [`WriteNewConnectionIdFrame`], with `WriteNewConnectionIdFrameExt` on receiver
    //! accesses and `WriteNewConnectionIdFrameHostExt` on call executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{NewConnectionIdFrame, RetirePriorToError};
    use crate::{
        connection_id::{
            EmptyCidError, NonEmptyCid, StatelessResetToken,
            codec::{ReadConnectionIdError, ReadConnectionIdExt as _},
        },
        frame::read_field,
        var_int::codec::ReadVarIntError,
    };
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{
        calls::{ReadArrayError, WriteAllError},
        prelude::*,
    };
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type.
    pub(in crate::v1) async fn read_new_connection_id_frame<
        F: Read,
        A: ReceiverAccess<Family = F>,
    >(
        io: &mut A,
    ) -> Result<NewConnectionIdFrame, ReadNewConnectionIdFrameError<F::Error>> {
        let sequence_number = read_field(io)
            .await
            .context(read_new_connection_id_error::SequenceNumberSnafu)?;
        let retire_prior_to = read_field(io)
            .await
            .context(read_new_connection_id_error::RetirePriorToSnafu)?;
        let connection_id = io
            .read_connection_id()
            .await
            .context(read_new_connection_id_error::ConnectionIdSnafu)?;
        let connection_id = NonEmptyCid::new(connection_id)
            .context(read_new_connection_id_error::EmptyConnectionIdSnafu)?;
        let stateless_reset_token = io
            .read_array::<{ StatelessResetToken::LEN }>()
            .await
            .context(read_new_connection_id_error::StatelessResetTokenSnafu)?;
        let frame = NewConnectionIdFrame::new(
            sequence_number,
            retire_prior_to,
            connection_id,
            StatelessResetToken::new(stateless_reset_token),
        )?;
        Ok(frame)
    }

    /// Failures of reading a NEW_CONNECTION_ID frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_new_connection_id_error), visibility(pub(in crate::v1)))]
    pub enum ReadNewConnectionIdFrameError<E> {
        /// The Sequence Number field could not be read.
        #[snafu(display("NEW_CONNECTION_ID Sequence Number read failed"))]
        SequenceNumber {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Retire Prior To field could not be read.
        #[snafu(display("NEW_CONNECTION_ID Retire Prior To read failed"))]
        RetirePriorTo {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The connection ID could not be read, or its length exceeds 20.
        #[snafu(display("NEW_CONNECTION_ID connection ID read failed"))]
        ConnectionId {
            /// The failure of reading the connection ID.
            source: ReadConnectionIdError<E>,
        },
        /// The connection ID is empty.
        #[snafu(display("NEW_CONNECTION_ID has an empty connection ID"))]
        EmptyConnectionId {
            /// The rejected connection ID.
            source: EmptyCidError,
        },
        /// The Stateless Reset Token could not be read.
        #[snafu(display("NEW_CONNECTION_ID Stateless Reset Token read failed"))]
        StatelessResetToken {
            /// The failure of reading the token.
            source: ReadArrayError<E>,
        },
        /// The frame retires sequence numbers beyond its own.
        #[snafu(transparent)]
        RetirePriorToAboveSequenceNumber {
            /// The broken rule.
            source: RetirePriorToError,
        },
    }

    /// Writes `frame`; [`NewConnectionIdFrame::new`] checked its rule.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_new_connection_id_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: NewConnectionIdFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::{NewConnectionIdFrame, RetirePriorToError, codec::ReadNewConnectionIdFrameError};
    use crate::parts::{Coproduct, PartsError};
    use crate::v1::frame::codec::ReadFieldsError;
    use crate::v1::frame::set::codec::ReadFrameError;
    use crate::v1::frame::tests::ReadOneFrame as _;
    use crate::{
        connection_id::{NonEmptyCid, StatelessResetToken, codec::ReadConnectionIdError},
        v1::frame::{Frame, tests::assert_round_trip},
        var_int::{VarInt, VarIntField},
    };

    const TOKEN: [u8; 16] = *b"0123456789abcdef";

    fn frame(
        sequence_number: u8,
        retire_prior_to: u8,
        cid: &[u8],
    ) -> Result<NewConnectionIdFrame, RetirePriorToError> {
        NewConnectionIdFrame::new(
            VarIntField::shortest(VarInt::from(sequence_number)),
            VarIntField::shortest(VarInt::from(retire_prior_to)),
            NonEmptyCid::try_from(cid).unwrap(),
            StatelessResetToken::new(TOKEN),
        )
    }

    #[test]
    fn round_trips_connection_id_lengths() {
        for cid in [&[0xaa; 20][..], &[0x01]] {
            let encoding = assert_round_trip(Frame::NewConnectionId(frame(2, 1, cid).unwrap()));
            assert_eq!(encoding.len(), 1 + 1 + 1 + 1 + cid.len() + 16);
            assert_eq!(encoding[3] as usize, cid.len());
        }
    }

    fn read(encoding: &[u8]) -> ReadNewConnectionIdFrameError<core::convert::Infallible> {
        let mut input = encoding;
        match input.read_one_frame() {
            Err(ReadFrameError::Fields {
                source: PartsError(Coproduct::Inl(ReadFieldsError::NewConnectionId { source, .. })),
            }) => source,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn connection_id_lengths_outside_1_to_20_are_rejected() {
        assert!(matches!(
            read(&[0x18, 0x01, 0x00, 0x00]),
            ReadNewConnectionIdFrameError::EmptyConnectionId { .. }
        ));
        // A length above 20 is rejected before the bytes are read.
        assert!(matches!(
            read(&[0x18, 0x01, 0x00, 21]),
            ReadNewConnectionIdFrameError::ConnectionId {
                source: ReadConnectionIdError::Length { source }
            } if source.length() == 21
        ));
    }

    #[test]
    fn retire_prior_to_beyond_the_sequence_number_is_rejected() {
        let mut encoding = vec![0x18, 0x01, 0x02, 0x01, 0xaa];
        encoding.extend_from_slice(&TOKEN);
        let expected = RetirePriorToError::check(VarInt::from(1u8), VarInt::from(2u8)).unwrap_err();
        assert_eq!(
            (expected.sequence_number(), expected.retire_prior_to()),
            (VarInt::from(1u8), VarInt::from(2u8))
        );
        assert_eq!(
            RetirePriorToError::check(VarInt::from(2u8), VarInt::from(2u8)),
            Ok(())
        );
        assert!(matches!(
            read(&encoding),
            ReadNewConnectionIdFrameError::RetirePriorToAboveSequenceNumber { source } if source == expected
        ));
        assert_eq!(frame(1, 2, &[1]), Err(expected));
        assert!(frame(2, 2, &[1]).is_ok());
    }

    #[test]
    fn each_variable_length_integer_field_has_its_own_failure() {
        // A two-byte encoding cut short in each field.
        assert!(matches!(
            read(&[0x18, 0x40]),
            ReadNewConnectionIdFrameError::SequenceNumber { source } if source.is_incomplete()
        ));
        assert!(matches!(
            read(&[0x18, 0x01, 0x40]),
            ReadNewConnectionIdFrameError::RetirePriorTo { source } if source.is_incomplete()
        ));
    }

    #[test]
    fn truncated_token_is_incomplete() {
        let encoding = [0x18, 0x01, 0x00, 0x04, 1, 2, 3, 4, 0, 0];
        let error = read(&encoding);
        assert!(matches!(
            error,
            ReadNewConnectionIdFrameError::StatelessResetToken { .. }
        ));
    }
}
