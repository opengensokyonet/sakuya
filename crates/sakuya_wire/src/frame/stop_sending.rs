//! STOP_SENDING frames ([RFC 9000 §19.5]).
//!
//! [RFC 9000 §19.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.5
use super::{Head, type_value, type_var_int};
use crate::application_error::ApplicationErrorCode;
use crate::stream_id::StreamId;
use crate::var_int::{VarInt, VarIntField};

/// A STOP_SENDING frame ([RFC 9000 §19.5]): the receiver asks the peer to stop sending on a stream.
///
/// Each field keeps the width of its variable-length integer encoding.
///
/// [RFC 9000 §19.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.5
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StopSending {
    /// The stream whose data is being discarded.
    pub stream_id: VarIntField<StreamId>,
    /// The application protocol error code.
    pub application_error_code: VarIntField<ApplicationErrorCode>,
}

impl StopSending {
    /// The Frame Type value.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(type_value::STOP_SENDING)
    }

    /// The number of bytes [`codec::write_stop_sending`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    pub(crate) fn head(&self) -> Head<17> {
        Head::new(self.type_value())
            .field(self.stream_id)
            .field(self.application_error_code)
    }
}

pub mod codec {
    //! Writing STOP_SENDING as a `nitori_call` operation; reading is part of
    //! [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_stop_sending`] is also the operation struct [`WriteStopSending`], with
    //! `WriteStopSendingExt` on receiver accesses and `WriteStopSendingHostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::StopSending;
    use crate::{frame::read_field, var_int::codec::ReadVarIntError};
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};

    /// Reads the fields that follow the Frame Type.
    pub(crate) async fn read_stop_sending<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<StopSending, ReadVarIntError<F::Error>> {
        Ok(StopSending {
            stream_id: read_field(io).await?,
            application_error_code: read_field(io).await?,
        })
    }

    /// Writes the frame.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_stop_sending<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: StopSending,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::StopSending;
    use crate::application_error::ApplicationErrorCode;
    use crate::stream_id::StreamId;
    use crate::{
        frame::{Frame, tests::assert_round_trip},
        var_int::{VarInt, VarIntField},
    };

    #[test]
    fn round_trips() {
        let frame = StopSending {
            stream_id: VarIntField::shortest(StreamId::from_var_int(VarInt::from(3u8))),
            application_error_code: VarIntField::shortest(ApplicationErrorCode::new(VarInt::from(
                7u8,
            ))),
        };
        assert_eq!(
            assert_round_trip(Frame::StopSending(frame)),
            [0x05, 0x03, 0x07]
        );
    }
}
