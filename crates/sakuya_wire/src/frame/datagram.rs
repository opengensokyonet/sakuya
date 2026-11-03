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
/// stored. [`Datagram::new`] checks that the Length field can state the
/// length of the data, so every value writes an encoding that reads back to
/// the same value; the fields are read through methods of the same names.
/// `D` holds the data: the source's chunk type for a frame that was read,
/// any [`Buf`] for one to write.
///
/// [RFC 9221 §4]: https://www.rfc-editor.org/rfc/rfc9221.html#section-4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Datagram<D> {
    length_width: Option<VarIntWidth>,
    data: D,
}

impl<D> Datagram<D> {
    /// The width of the Length field, present in type `0x31`; the field holds
    /// the length of the data. Without a Length field, the data extends to the
    /// end of the packet.
    pub const fn length_width(&self) -> Option<VarIntWidth> {
        self.length_width
    }

    /// The application data.
    pub const fn data(&self) -> &D {
        &self.data
    }

    /// Takes the application data.
    pub fn into_data(self) -> D {
        self.data
    }

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
    /// The DATAGRAM frame with these fields.
    ///
    /// # Errors
    ///
    /// [`LengthError`] if the Length field is too narrow for the length of
    /// the data. Without a Length field, any data is accepted.
    pub fn new(length_width: Option<VarIntWidth>, data: D) -> Result<Self, LengthError> {
        if let Some(width) = length_width {
            LengthError::check(data.remaining(), width)?;
        }
        Ok(Self { length_width, data })
    }

    /// The number of bytes [`codec::write_datagram`] writes.
    pub fn encoded_len(&self) -> usize {
        1 + self.length_width.map_or(0, VarIntWidth::encoded_len) + self.data.remaining()
    }

    /// The fields before the data.
    pub(crate) fn head(&self) -> Head<9> {
        let head = Head::new(self.type_value());
        match self.length_width {
            Some(width) => {
                // Construction checked that the width holds the data length.
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
        frame::read_field,
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
                .context(read_datagram_error::LengthSnafu)?;
            let data_len = usize::try_from(length.get().get()).unwrap_or(usize::MAX);
            let data = read_payload(io, data_len).await;
            (Some(length.width()), data)
        } else {
            (None, read_payload_to_end(io).await)
        };
        let data = data.context(read_datagram_error::DataSnafu)?;
        let frame = Datagram::new(length_width, data);
        // invariant: the Length field, if any, was read at this width, and
        // `read_payload` returns data of exactly the length it states: it
        // fails on shorter data and panics on a longer chunk.
        Ok(frame.unwrap_or_else(|error| unreachable!("{error}")))
    }

    /// Failures of reading a DATAGRAM frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_datagram_error), visibility(pub(crate)))]
    pub enum ReadDatagramError<E> {
        /// The Length field could not be read.
        #[snafu(display("DATAGRAM Length read failed"))]
        Length {
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

    /// Writes `frame`; [`Datagram::new`] checked its limits.
    ///
    /// A frame without a Length field extends to the end of the packet;
    /// nothing may be written after it.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_datagram<F, A, D>(
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
}

#[cfg(test)]
mod tests {
    use super::Datagram;
    use crate::{
        frame::{
            Extensions, Frame, Frames, LengthError,
            codec::{ReadFrameError, ReadFrameHostExt as _},
            tests::assert_round_trip,
        },
        var_int::{VarInt, VarIntWidth},
    };

    #[test]
    fn round_trips_with_and_without_length() {
        let with = assert_round_trip(Frame::Datagram(
            Datagram::new(Some(VarIntWidth::One), &b"datagram"[..]).unwrap(),
        ));
        assert_eq!(with[..2], [0x31, 0x08]);
        let long = assert_round_trip(Frame::Datagram(
            Datagram::new(Some(VarIntWidth::Four), &b"datagram"[..]).unwrap(),
        ));
        assert_eq!(long[..5], [0x31, 0x80, 0, 0, 0x08]);
        let without = assert_round_trip(Frame::Datagram(
            Datagram::new(None, &b"to the end"[..]).unwrap(),
        ));
        assert_eq!(without[0], 0x30);
        // An empty DATAGRAM without a Length field is the type alone.
        let mut input = &[0x30][..];
        assert_eq!(
            input.sync_read_frame_unpin(Extensions::ALL).unwrap(),
            Frame::Datagram(Datagram::new(None, &b""[..]).unwrap())
        );
    }

    #[test]
    fn narrow_length_fields_are_rejected() {
        let data = [0; 64];
        let expected = LengthError {
            length: 64,
            width: VarIntWidth::One,
        };
        assert_eq!(
            Datagram::new(Some(VarIntWidth::One), &data[..]),
            Err(expected)
        );
        // Without a Length field, any length can be written.
        let frame = Datagram::new(None, &data[..]).unwrap();
        assert_eq!(*frame.data(), &data[..]);
    }

    #[test]
    fn requires_the_extension() {
        let payload = [0x30, 0x01];
        let mut frames = Frames::new(&payload[..], Extensions::NONE);
        assert!(matches!(
            frames.next(),
            Some(Err(ReadFrameError::ExtensionNotEnabled { frame_type }))
                if frame_type.get() == VarInt::from(0x30u8)
        ));
    }
}
