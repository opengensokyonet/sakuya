//! DATAGRAM frames ([RFC 9221 §4]).
//!
//! [RFC 9221 §4]: https://www.rfc-editor.org/rfc/rfc9221.html#section-4
use super::{Head, LengthError, LengthKind, NoLength, length_width, type_value, type_var_int};
use crate::var_int::{VarInt, VarIntWidth};
use bytes::Buf;
use either::Either;

/// A DATAGRAM frame ([RFC 9221 §4]): type `0x31` with a Length field, `0x30`
/// without.
///
/// The Length field holds the length of the data, so only its width is
/// stored. `L` states the Length field, as a [`LengthKind`]: [`VarIntWidth`]
/// for a frame with a Length field of that width, [`NoLength`] for one
/// without, whose data extends to the end of the packet, and, by default,
/// [`Either<NoLength, VarIntWidth>`](Either) for either of the two. Reading
/// gives `Datagram<D>`, the default; `From` converts the other two into it.
///
/// The `new` of each kind of `L` checks that a Length field can state the
/// length of the data, so every value writes an encoding that reads back to
/// the same value; the fields are read through methods of the same names.
/// `D` holds the data: the source's chunk type for a frame that was read,
/// any [`Buf`] for one to write.
///
/// [RFC 9221 §4]: https://www.rfc-editor.org/rfc/rfc9221.html#section-4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Datagram<D, L = Either<NoLength, VarIntWidth>> {
    length: L,
    data: D,
}

impl<D, L: LengthKind> Datagram<D, L> {
    /// The Length field, present in type `0x31`: its width, since the field
    /// holds the length of the data, or [`NoLength`] without it, in type
    /// `0x30`, when the data extends to the end of the packet.
    pub const fn length(&self) -> L {
        self.length
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
    pub fn type_value(&self) -> VarInt {
        type_var_int(if length_width(self.length).is_some() {
            type_value::DATAGRAM_WITH_LENGTH
        } else {
            type_value::DATAGRAM
        })
    }

    /// The same frame with the Length field stated as `length`, which states
    /// the same field.
    fn with_length<M: LengthKind>(self, length: M) -> Datagram<D, M> {
        Datagram {
            length,
            data: self.data,
        }
    }
}

impl<D: Buf, L: LengthKind> Datagram<D, L> {
    /// The number of bytes the write operations of [`codec`] write.
    pub fn encoded_len(&self) -> usize {
        1 + length_width(self.length).map_or(0, VarIntWidth::encoded_len) + self.data.remaining()
    }

    /// The fields before the data.
    pub(crate) fn head(&self) -> Head<9> {
        let head = Head::new(self.type_value());
        match length_width(self.length) {
            Some(width) => {
                // Construction checked that the width holds the data length.
                let length = VarInt::try_from(self.data.remaining()).unwrap_or(VarInt::ZERO);
                head.var_int_of(length, width)
            }
            None => head,
        }
    }
}

impl<D: Buf> Datagram<D, VarIntWidth> {
    /// The DATAGRAM frame with a Length field of width `length` and `data`.
    ///
    /// # Errors
    ///
    /// [`LengthError`] if the Length field is too narrow for the length of
    /// the data.
    pub fn new(length: VarIntWidth, data: D) -> Result<Self, LengthError> {
        LengthError::check(data.remaining(), length)?;
        Ok(Self { length, data })
    }
}

impl<D: Buf> Datagram<D, NoLength> {
    /// The DATAGRAM frame without a Length field and with `data`; any data
    /// is accepted.
    pub fn new(length: NoLength, data: D) -> Self {
        Self { length, data }
    }
}

impl<D: Buf> Datagram<D> {
    /// The DATAGRAM frame with `data`, with or without a Length field as
    /// `length` states.
    ///
    /// # Errors
    ///
    /// [`LengthError`] if there is a Length field and it is too narrow for
    /// the length of the data. Without a Length field, any data is accepted.
    pub fn new(length: Either<NoLength, VarIntWidth>, data: D) -> Result<Self, LengthError> {
        Ok(match length {
            Either::Left(length) => Datagram::<D, NoLength>::new(length, data).into(),
            Either::Right(length) => Datagram::<D, VarIntWidth>::new(length, data)?.into(),
        })
    }
}

impl<D> From<Datagram<D, VarIntWidth>> for Datagram<D> {
    /// The same frame, which has a Length field.
    fn from(frame: Datagram<D, VarIntWidth>) -> Self {
        let length = Either::Right(frame.length);
        frame.with_length(length)
    }
}

impl<D> From<Datagram<D, NoLength>> for Datagram<D> {
    /// The same frame, which has no Length field.
    fn from(frame: Datagram<D, NoLength>) -> Self {
        let length = Either::Left(frame.length);
        frame.with_length(length)
    }
}

/// The Frame Type value of a DATAGRAM frame: `0x30`, or `0x31` with a Length
/// field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DatagramTypeValue(VarInt);

impl DatagramTypeValue {
    /// The Frame Type value `value` if it is that of a DATAGRAM frame, and
    /// `None` otherwise.
    pub(crate) const fn new(value: VarInt) -> Option<Self> {
        match value.get() {
            type_value::DATAGRAM | type_value::DATAGRAM_WITH_LENGTH => Some(Self(value)),
            _ => None,
        }
    }

    /// The Frame Type value.
    pub const fn get(self) -> VarInt {
        self.0
    }

    /// Whether the type is `0x31`, with a Length field.
    const fn has_length(self) -> bool {
        self.0.get() == type_value::DATAGRAM_WITH_LENGTH
    }
}

impl From<DatagramTypeValue> for VarInt {
    fn from(value: DatagramTypeValue) -> Self {
        value.0
    }
}

pub mod codec {
    //! Writing DATAGRAM frames as `nitori_call` operations; reading is part
    //! of [`read_frame`](crate::frame::codec::read_frame).
    //!
    //! There is a write operation for each kind of Length field:
    //! [`write_datagram_with_length`] for `Datagram<D, VarIntWidth>`,
    //! [`write_datagram_without_length`] for `Datagram<D, NoLength>`, and
    //! [`write_datagram`] for `Datagram<D>`, which writes as one of the two.
    //! Each is also an operation struct, such as [`WriteDatagram`], with
    //! `{Name}Ext` on receiver accesses and `{Name}HostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{Datagram, DatagramTypeValue};
    use crate::{
        frame::{NoLength, read_field},
        payload::{ReadPayloadError, read_payload, read_payload_to_end},
        var_int::{VarInt, VarIntField, VarIntWidth, codec::ReadVarIntError},
    };
    use bytes::Buf;
    use either::Either;
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type `frame_type`, and the data
    /// as one chunk of the source: of the Length field's length in type
    /// `0x31`, or to the end of the source.
    pub(crate) async fn read_datagram<F, A>(
        io: &mut A,
        frame_type: DatagramTypeValue,
    ) -> Result<Datagram<F::Chunk>, ReadDatagramError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        let (length, data) = if frame_type.has_length() {
            let length: VarIntField<VarInt> = read_field(io)
                .await
                .context(read_datagram_error::LengthSnafu)?;
            let data_len = usize::try_from(length.get().get()).unwrap_or(usize::MAX);
            let data = read_payload(io, data_len).await;
            (Either::Right(length.width()), data)
        } else {
            (Either::Left(NoLength), read_payload_to_end(io).await)
        };
        let data = data.context(read_datagram_error::DataSnafu)?;
        let frame = Datagram::<_>::new(length, data);
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

    /// Writes `frame`, as [`write_datagram_with_length`] or
    /// [`write_datagram_without_length`] as its Length field states; its
    /// `new` checked its limits.
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
        match frame.length {
            Either::Left(length) => {
                write_datagram_without_length(io, frame.with_length(length)).await
            }
            Either::Right(length) => {
                write_datagram_with_length(io, frame.with_length(length)).await
            }
        }
    }

    /// Writes `frame`, which has a Length field; its `new` checked its
    /// limits.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_datagram_with_length<F, A, D>(
        io: &mut A,
        frame: Datagram<D, VarIntWidth>,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        let head = frame.head();
        io.write_all(head.as_slice().chain(frame.data)).await
    }

    /// Writes `frame`, which has no Length field.
    ///
    /// The frame extends to the end of the packet; nothing may be written
    /// after it.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_datagram_without_length<F, A, D>(
        io: &mut A,
        frame: Datagram<D, NoLength>,
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
    use super::{
        Datagram,
        codec::{
            WriteDatagramHostExt as _, WriteDatagramWithLengthHostExt as _,
            WriteDatagramWithoutLengthHostExt as _,
        },
    };
    use crate::{
        frame::{
            Extensions, Frame, Frames, LengthError, NoLength,
            codec::{ReadFrameError, ReadFrameHostExt as _},
            tests::{assert_round_trip, datagram_frame},
        },
        var_int::{VarInt, VarIntWidth},
    };
    use either::Either;

    #[test]
    fn round_trips_with_and_without_length() {
        let with = assert_round_trip(Frame::Datagram(
            datagram_frame(Some(VarIntWidth::One), &b"datagram"[..]).unwrap(),
        ));
        assert_eq!(with[..2], [0x31, 0x08]);
        let long = assert_round_trip(Frame::Datagram(
            datagram_frame(Some(VarIntWidth::Four), &b"datagram"[..]).unwrap(),
        ));
        assert_eq!(long[..5], [0x31, 0x80, 0, 0, 0x08]);
        let without = assert_round_trip(Frame::Datagram(
            datagram_frame(None, &b"to the end"[..]).unwrap(),
        ));
        assert_eq!(without[0], 0x30);
        // An empty DATAGRAM without a Length field is the type alone.
        let mut input = &[0x30][..];
        assert_eq!(
            input.sync_read_frame_unpin(Extensions::ALL).unwrap(),
            Frame::Datagram(Datagram::<_, NoLength>::new(NoLength, &b""[..]).into())
        );
        // Reading keeps which of the two types it was.
        for (encoding, length) in [
            (&with, Either::Right(VarIntWidth::One)),
            (&long, Either::Right(VarIntWidth::Four)),
            (&without, Either::Left(NoLength)),
        ] {
            let mut input = encoding.as_slice();
            let Frame::Datagram(frame) = input.sync_read_frame_unpin(Extensions::ALL).unwrap()
            else {
                panic!()
            };
            assert_eq!(frame.length(), length);
        }
    }

    #[test]
    fn each_kind_of_length_field_writes_its_type() {
        let with = Datagram::<_, VarIntWidth>::new(VarIntWidth::Two, &b"hi"[..]).unwrap();
        let without = Datagram::<_, NoLength>::new(NoLength, &b"hi"[..]);
        assert_eq!(with.type_value(), VarInt::from(0x31u8));
        assert_eq!(without.type_value(), VarInt::from(0x30u8));
        let mut written = Vec::new();
        written.sync_write_datagram_with_length_unpin(with).unwrap();
        assert_eq!(written, [0x31, 0x40, 0x02, b'h', b'i']);
        assert_eq!(with.encoded_len(), written.len());
        let mut written = Vec::new();
        written
            .sync_write_datagram_without_length_unpin(without)
            .unwrap();
        assert_eq!(written, [0x30, b'h', b'i']);
        assert_eq!(without.encoded_len(), written.len());
        // Both convert into the frame that reading gives, which writes the
        // same bytes.
        for (frame, length) in [
            (Datagram::from(with), Either::Right(VarIntWidth::Two)),
            (Datagram::from(without), Either::Left(NoLength)),
        ] {
            assert_eq!(frame.length(), length);
            assert_eq!(frame, Datagram::<_>::new(length, &b"hi"[..]).unwrap());
            let mut written = Vec::new();
            written.sync_write_datagram_unpin(frame).unwrap();
            let mut input = written.as_slice();
            assert_eq!(
                input.sync_read_frame_unpin(Extensions::ALL).unwrap(),
                Frame::Datagram(frame)
            );
        }
    }

    #[test]
    fn narrow_length_fields_are_rejected() {
        let data = [0; 64];
        let expected = LengthError {
            length: 64,
            width: VarIntWidth::One,
        };
        assert_eq!(
            Datagram::<_, VarIntWidth>::new(VarIntWidth::One, &data[..]),
            Err(expected)
        );
        assert_eq!(
            Datagram::<_>::new(Either::Right(VarIntWidth::One), &data[..]),
            Err(expected)
        );
        // Without a Length field, any length can be written.
        let frame = Datagram::<_, NoLength>::new(NoLength, &data[..]);
        assert_eq!(*frame.data(), &data[..]);
        let frame = Datagram::<_>::new(Either::Left(NoLength), &data[..]).unwrap();
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

    #[test]
    fn failures_hold_the_frame_type() {
        let mut input = &[0x31][..];
        let error = input.sync_read_frame_unpin(Extensions::ALL).unwrap_err();
        assert!(
            matches!(
                error,
                ReadFrameError::Datagram { frame_type, .. } if frame_type.get() == VarInt::from(0x31u8)
            ),
            "{error:?}"
        );
        assert_eq!(error.frame_type(), Some(VarInt::from(0x31u8)));
    }
}
