//! NEW_CONNECTION_ID frames ([RFC 9000 §19.15]).
//!
//! [RFC 9000 §19.15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
use super::{Head, type_value, type_var_int};
use crate::{
    connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken},
    var_int::{VarInt, VarIntField},
};
use snafu::Snafu;

/// A NEW_CONNECTION_ID frame ([RFC 9000 §19.15]).
///
/// `retire_prior_to` is at most `sequence_number`. Each variable-length
/// integer field keeps the width of its encoding.
///
/// [RFC 9000 §19.15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NewConnectionId {
    /// The sequence number the sender assigned to the connection ID.
    pub sequence_number: VarIntField<VarInt>,
    /// The sequence number below which connection IDs are to be retired.
    pub retire_prior_to: VarIntField<VarInt>,
    /// The connection ID: 1 to 20 bytes.
    pub connection_id: NonEmptyCid,
    /// The Stateless Reset Token for the connection ID.
    pub stateless_reset_token: StatelessResetToken,
}

/// The longest encoding of the frame.
const ENCODED_MAX: usize = 1 + 8 + 8 + 1 + ConnectionId::MAX_LEN + StatelessResetToken::LEN;

impl NewConnectionId {
    /// The Frame Type value, `0x18`.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::NEW_CONNECTION_ID)
    }

    /// The number of bytes [`codec::write_new_connection_id`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// Checks that `retire_prior_to` is at most `sequence_number`.
    ///
    /// # Errors
    ///
    /// [`RetirePriorToError`] otherwise.
    pub fn validate(&self) -> Result<(), RetirePriorToError> {
        RetirePriorToError::check(self.sequence_number.get(), self.retire_prior_to.get())
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<ENCODED_MAX> {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "NEW_CONNECTION_ID retires prior to {retire_prior_to}, beyond its sequence number {sequence_number}"
))]
pub struct RetirePriorToError {
    /// The Sequence Number field.
    pub sequence_number: VarInt,
    /// The Retire Prior To field.
    pub retire_prior_to: VarInt,
}

impl RetirePriorToError {
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
    //! is part of [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_new_connection_id`] is also the operation struct
    //! [`WriteNewConnectionId`], with `WriteNewConnectionIdExt` on receiver
    //! accesses and `WriteNewConnectionIdHostExt` on call executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{NewConnectionId, RetirePriorToError};
    use crate::{
        connection_id::{
            EmptyCidError, NonEmptyCid, StatelessResetToken,
            codec::{ReadConnectionIdError, ReadConnectionIdExt as _},
        },
        frame::read_field,
        var_int::{VarInt, VarIntField, codec::ReadVarIntError},
    };
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{
        calls::{ReadArrayError, WriteAllError},
        prelude::*,
    };
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_new_connection_id<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<NewConnectionId, ReadNewConnectionIdError<F::Error>> {
        let sequence_number = field(io).await?;
        let retire_prior_to = field(io).await?;
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
        RetirePriorToError::check(sequence_number.get(), retire_prior_to.get())?;
        Ok(NewConnectionId {
            sequence_number,
            retire_prior_to,
            connection_id,
            stateless_reset_token: StatelessResetToken::new(stateless_reset_token),
        })
    }

    async fn field<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<VarIntField<VarInt>, ReadNewConnectionIdError<F::Error>> {
        read_field(io)
            .await
            .context(read_new_connection_id_error::FieldSnafu)
    }

    /// Failures of reading a NEW_CONNECTION_ID frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_new_connection_id_error), visibility(pub(crate)))]
    pub enum ReadNewConnectionIdError<E> {
        /// The Sequence Number or Retire Prior To field could not be read.
        #[snafu(display("NEW_CONNECTION_ID field read failed"))]
        Field {
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
        RetirePriorTo {
            /// The broken rule.
            source: RetirePriorToError,
        },
    }

    /// Writes `frame`, after checking it with [`NewConnectionId::validate`].
    ///
    /// # Errors
    ///
    /// [`WriteNewConnectionIdError::Invalid`] before writing anything, and
    /// [`WriteNewConnectionIdError::Write`] if the receiver stops accepting
    /// bytes or fails; bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_new_connection_id<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: NewConnectionId,
    ) -> Result<(), WriteNewConnectionIdError<F::Error>> {
        frame.validate()?;
        io.write_all(frame.head().as_slice())
            .await
            .context(write_new_connection_id_error::WriteSnafu)
    }

    /// Failures that [`write_new_connection_id`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(write_new_connection_id_error), visibility(pub(crate)))]
    pub enum WriteNewConnectionIdError<E> {
        /// The frame breaks a rule of the encoding; nothing was written.
        #[snafu(transparent)]
        Invalid {
            /// The broken rule.
            source: RetirePriorToError,
        },
        /// The receiver stopped accepting bytes or failed.
        #[snafu(display("NEW_CONNECTION_ID write failed"))]
        Write {
            /// The failure of writing.
            source: WriteAllError<E>,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        NewConnectionId, RetirePriorToError,
        codec::{
            ReadNewConnectionIdError, WriteNewConnectionIdError, WriteNewConnectionIdHostExt as _,
        },
    };
    use crate::{
        connection_id::{
            ConnectionIdLengthError, NonEmptyCid, StatelessResetToken, codec::ReadConnectionIdError,
        },
        frame::{
            Extensions, Frame,
            codec::{ReadFrameError, ReadFrameHostExt as _},
            tests::assert_round_trip,
        },
        var_int::{VarInt, VarIntField},
    };

    const TOKEN: [u8; 16] = *b"0123456789abcdef";

    fn frame(sequence_number: u8, retire_prior_to: u8, cid: &[u8]) -> NewConnectionId {
        NewConnectionId {
            sequence_number: VarIntField::shortest(VarInt::from(sequence_number)),
            retire_prior_to: VarIntField::shortest(VarInt::from(retire_prior_to)),
            connection_id: NonEmptyCid::try_from(cid).unwrap(),
            stateless_reset_token: StatelessResetToken::new(TOKEN),
        }
    }

    #[test]
    fn round_trips_connection_id_lengths() {
        for cid in [&[0xaa; 20][..], &[0x01]] {
            let encoding = assert_round_trip(Frame::NewConnectionId(frame(2, 1, cid)));
            assert_eq!(encoding.len(), 1 + 1 + 1 + 1 + cid.len() + 16);
            assert_eq!(encoding[3] as usize, cid.len());
        }
    }

    fn read(encoding: &[u8]) -> ReadNewConnectionIdError<core::convert::Infallible> {
        let mut input = encoding;
        match input.sync_read_frame_unpin(Extensions::NONE) {
            Err(ReadFrameError::NewConnectionId { source, .. }) => source,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn connection_id_lengths_outside_1_to_20_are_rejected() {
        assert!(matches!(
            read(&[0x18, 0x01, 0x00, 0x00]),
            ReadNewConnectionIdError::EmptyConnectionId { .. }
        ));
        // A length above 20 is rejected before the bytes are read.
        assert!(matches!(
            read(&[0x18, 0x01, 0x00, 21]),
            ReadNewConnectionIdError::ConnectionId {
                source: ReadConnectionIdError::Length {
                    source: ConnectionIdLengthError { length: 21 }
                }
            }
        ));
    }

    #[test]
    fn retire_prior_to_beyond_the_sequence_number_is_rejected() {
        let mut encoding = vec![0x18, 0x01, 0x02, 0x01, 0xaa];
        encoding.extend_from_slice(&TOKEN);
        let expected = RetirePriorToError {
            sequence_number: VarInt::from(1u8),
            retire_prior_to: VarInt::from(2u8),
        };
        assert!(matches!(
            read(&encoding),
            ReadNewConnectionIdError::RetirePriorTo { source } if source == expected
        ));
        let invalid = frame(1, 2, &[1]);
        assert_eq!(invalid.validate(), Err(expected));
        let mut written = Vec::new();
        assert!(matches!(
            written.sync_write_new_connection_id_unpin(invalid),
            Err(WriteNewConnectionIdError::Invalid { .. })
        ));
        assert!(written.is_empty());
    }

    #[test]
    fn truncated_token_is_incomplete() {
        let encoding = [0x18, 0x01, 0x00, 0x04, 1, 2, 3, 4, 0, 0];
        let error = read(&encoding);
        assert!(matches!(
            error,
            ReadNewConnectionIdError::StatelessResetToken { .. }
        ));
    }
}
