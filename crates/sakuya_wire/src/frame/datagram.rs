//! DATAGRAM frames ([RFC 9221 §4]).
//!
//! [RFC 9221 §4]: https://www.rfc-editor.org/rfc/rfc9221.html#section-4
use super::{Head, LengthError, type_value, type_var_int};
use crate::var_int::{VarInt, VarIntWidth};
use bytes::Buf;

/// A DATAGRAM frame ([RFC 9221 §4]): type `0x31` with a Length field, `0x30`
/// without.
///
/// The Length field holds the length of the data, so only its width is
/// stored. `D` holds the data: the source's chunk type for a frame that was
/// read, any [`Buf`] for one to write.
///
/// [RFC 9221 §4]: https://www.rfc-editor.org/rfc/rfc9221.html#section-4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Datagram<D> {
    /// The width of the Length field, present in type `0x31`; the field holds
    /// the length of `data`. Without a Length field, the data extends to the
    /// end of the packet.
    pub length_width: Option<VarIntWidth>,
    /// The application data.
    pub data: D,
}

impl<D> Datagram<D> {
    /// The Frame Type value: `0x31` with a Length field, `0x30` without.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(if self.length_width.is_some() {
            type_value::DATAGRAM_WITH_LENGTH
        } else {
            type_value::DATAGRAM
        })
    }
}

impl<D: Buf> Datagram<D> {
    /// The number of bytes [`codec::write_datagram`] writes.
    pub fn encoded_len(&self) -> usize {
        1 + self.length_width.map_or(0, VarIntWidth::encoded_len) + self.data.remaining()
    }

    /// Checks that the Length field, if present, can state the length of the
    /// data.
    ///
    /// # Errors
    ///
    /// [`LengthError`] for longer data.
    pub fn validate(&self) -> Result<(), LengthError> {
        match self.length_width {
            Some(width) => LengthError::check(self.data.remaining(), width).map(|_| ()),
            None => Ok(()),
        }
    }

    /// The fields before the data of a frame that passed validation.
    pub(crate) fn head(&self) -> Head<9> {
        let head = Head::new(self.type_value());
        match self.length_width {
            Some(width) => {
                // Validation checked that the width holds the data length.
                let length = VarInt::try_from(self.data.remaining()).unwrap_or(VarInt::ZERO);
                head.var_int_of(length, width)
            }
            None => head,
        }
    }
}

pub mod codec {
    //! Writing DATAGRAM frames as a `nitori_call` operation; reading is part
    //! of [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! [`write_datagram`] is also the operation struct [`WriteDatagram`],
    //! with `WriteDatagramExt` on receiver accesses and
    //! `WriteDatagramHostExt` on call executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::Datagram;
    use crate::{
        frame::{LengthError, read_field},
        payload::{ReadPayloadError, read_payload, read_payload_to_end},
        var_int::{VarInt, VarIntField, codec::ReadVarIntError},
    };
    use bytes::Buf;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type, and the data as one chunk
    /// of the source: of the Length field's length if `has_length`, or to the
    /// end of the source.
    pub(crate) async fn read_datagram<F, A>(
        io: &mut A,
        has_length: bool,
    ) -> Result<Datagram<F::Chunk>, ReadDatagramError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        let (length_width, data) = if has_length {
            let length: VarIntField<VarInt> = read_field(io)
                .await
                .context(read_datagram_error::FieldSnafu)?;
            let data_len = usize::try_from(length.get().get()).unwrap_or(usize::MAX);
            let data = read_payload(io, data_len).await;
            (Some(length.width()), data)
        } else {
            (None, read_payload_to_end(io).await)
        };
        let data = data.context(read_datagram_error::DataSnafu)?;
        Ok(Datagram { length_width, data })
    }

    /// Failures of reading a DATAGRAM frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_datagram_error), visibility(pub(crate)))]
    pub enum ReadDatagramError<E> {
        /// The Length field could not be read.
        #[snafu(display("DATAGRAM field read failed"))]
        Field {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The data could not be read.
        #[snafu(display("DATAGRAM data read failed"))]
        Data {
            /// The failure of reading the data.
            source: ReadPayloadError<E>,
        },
    }

    /// Writes `frame`, after checking it with [`Datagram::validate`].
    ///
    /// A frame without a Length field extends to the end of the packet;
    /// nothing may be written after it.
    ///
    /// # Errors
    ///
    /// [`WriteDatagramError::Invalid`] before writing anything, and
    /// [`WriteDatagramError::Write`] if the receiver stops accepting bytes or
    /// fails; bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_datagram<F, A, D>(
        io: &mut A,
        frame: Datagram<D>,
    ) -> Result<(), WriteDatagramError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        frame.validate()?;
        write_body(io, frame)
            .await
            .context(write_datagram_error::WriteSnafu)
    }

    /// Writes a frame that has been checked.
    pub(crate) async fn write_body<F, A, D>(
        io: &mut A,
        frame: Datagram<D>,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        let head = frame.head();
        io.write_all(head.as_slice().chain(frame.data)).await
    }

    /// Failures that [`write_datagram`] can produce.
    #[derive(Debug, Snafu)]
    #[snafu(module(write_datagram_error), visibility(pub(crate)))]
    pub enum WriteDatagramError<E> {
        /// The frame breaks a limit of the encoding; nothing was written.
        #[snafu(transparent)]
        Invalid {
            /// The broken limit.
            source: LengthError,
        },
        /// The receiver stopped accepting bytes or failed.
        #[snafu(display("DATAGRAM write failed"))]
        Write {
            /// The failure of writing.
            source: WriteAllError<E>,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{Datagram, codec::WriteDatagramError, codec::WriteDatagramHostExt as _};
    use crate::{
        frame::{
            Extensions, Frame, Frames, LengthError,
            codec::{ReadFrameError, ReadFrameHostExt as _},
            tests::assert_round_trip,
        },
        var_int::VarIntWidth,
    };

    #[test]
    fn round_trips_with_and_without_length() {
        let with = assert_round_trip(Frame::Datagram(Datagram {
            length_width: Some(VarIntWidth::One),
            data: &b"datagram"[..],
        }));
        assert_eq!(with[..2], [0x31, 0x08]);
        let long = assert_round_trip(Frame::Datagram(Datagram {
            length_width: Some(VarIntWidth::Four),
            data: &b"datagram"[..],
        }));
        assert_eq!(long[..5], [0x31, 0x80, 0, 0, 0x08]);
        let without = assert_round_trip(Frame::Datagram(Datagram {
            length_width: None,
            data: &b"to the end"[..],
        }));
        assert_eq!(without[0], 0x30);
        // An empty DATAGRAM without a Length field is the type alone.
        let mut input = &[0x30][..];
        assert_eq!(
            input.sync_read_frame_unpin(Extensions::ALL).unwrap(),
            Frame::Datagram(Datagram {
                length_width: None,
                data: &b""[..],
            })
        );
    }

    #[test]
    fn narrow_length_fields_are_rejected() {
        let data = [0; 64];
        let frame = Datagram {
            length_width: Some(VarIntWidth::One),
            data: &data[..],
        };
        let expected = LengthError {
            length: 64,
            width: VarIntWidth::One,
        };
        assert_eq!(frame.validate(), Err(expected));
        let mut written = Vec::new();
        assert!(matches!(
            written.sync_write_datagram_unpin(frame),
            Err(WriteDatagramError::Invalid { source }) if source == expected
        ));
        assert!(written.is_empty());
        // Without a Length field, any length can be written.
        let frame = Datagram {
            length_width: None,
            data: &data[..],
        };
        assert_eq!(frame.validate(), Ok(()));
    }

    #[test]
    fn requires_the_extension() {
        let payload = [0x30, 0x01];
        let mut frames = Frames::new(&payload[..], Extensions::NONE);
        assert!(matches!(
            frames.next(),
            Some(Err(ReadFrameError::UnknownType { .. }))
        ));
    }
}
