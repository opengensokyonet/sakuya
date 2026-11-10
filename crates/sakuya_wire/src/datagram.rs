//! The DATAGRAM extension ([RFC 9221]): the DATAGRAM frame, types `0x30`
//! and `0x31` (§4).
//!
//! [`Part`] is the part of a frame set that holds this one frame. A frame
//! set without it reads types `0x30` and `0x31` as unknown Frame Types
//! ([RFC 9000 §12.4]). Reading a DATAGRAM frame checks its encoding only:
//! whether this endpoint announced support and whether the frame is larger
//! than the `max_datagram_frame_size` it announced ([RFC 9221 §3]) are for
//! the receiver of the frame to check, with [`DatagramFrame::encoded_len`].
//!
//! ```
//! use core::marker::PhantomData;
//! use sakuya_wire::{
//!     assert_frame_types_disjoint,
//!     datagram,
//!     parts::HList,
//!     v1::{self, frame::{FrameRun, set::Frames}},
//! };
//!
//! type Set = HList![v1::Part, datagram::Part];
//! assert_frame_types_disjoint!(Set);
//!
//! // A DATAGRAM frame with a Length field, then PING.
//! let payload = [0x31, 0x02, b'h', b'i', 0x01];
//! let mut frames = Frames::new(&payload[..], PhantomData::<Set>);
//! let Some(Ok(run)) = frames.next() else { panic!() };
//! let Ok(frame) = run.uninject::<datagram::DatagramFrame<&[u8]>, _>() else { panic!() };
//! assert_eq!(*frame.data(), b"hi");
//! assert_eq!(frame.encoded_len(), 4);
//! let Some(Ok(run)) = frames.next() else { panic!() };
//! assert!(matches!(run.get::<FrameRun<&[u8]>, _>(), Some(FrameRun::Ping(_))));
//! ```
//!
//! [RFC 9221]: https://www.rfc-editor.org/rfc/rfc9221.html
//! [RFC 9221 §3]: https://www.rfc-editor.org/rfc/rfc9221.html#section-3
//! [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
use self::codec::ReadDatagramFrameHostExt as _;
use crate::{
    frame::{Head, LengthError, LengthKind, NoLength, length_width, type_var_int},
    v1::{
        encryption_level::EncryptionLevel,
        frame::set::{FrameKind, FrameSetPart, FrameTypeValues},
        role::Role,
    },
    var_int::{VarInt, VarIntWidth},
};
use bytes::Buf;
use core::ops::RangeInclusive;
use either::Either;
use nitori_call::{Direct, Receiver};
use nitori_io::{Read, ReadChunk};

/// Frame Type values.
mod type_value {
    pub(super) const DATAGRAM: u64 = 0x30;
    pub(super) const DATAGRAM_WITH_LENGTH: u64 = 0x31;
}

/// The DATAGRAM frame as a part of a frame set: frames [`DatagramFrame`],
/// of the kind [`FrameType`], read with the failures
/// [`codec::ReadDatagramFrameError`]. It claims the Frame Types `0x30` and
/// `0x31`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Part;

impl FrameSetPart for Part {
    type Run<D> = DatagramFrame<D>;
    type Kind = FrameType;
    type FieldsError<E> = codec::ReadDatagramFrameError<E>;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues =
        &FrameTypeValues::new(&[RangeInclusive::new(
            VarInt::from_u32(type_value::DATAGRAM as u32),
            VarInt::from_u32(type_value::DATAGRAM_WITH_LENGTH as u32),
        )]);

    fn kind_of(value: VarInt) -> Option<FrameType> {
        DatagramTypeValue::new(value).map(|_| FrameType::Datagram)
    }

    fn read_run<H>(
        source: &mut H,
        _kind: FrameType,
        value: VarInt,
    ) -> Result<
        DatagramFrame<<Direct<H> as ReadChunk>::Chunk>,
        codec::ReadDatagramFrameError<<Direct<H> as Read>::Error>,
    >
    where
        H: Buf + Receiver<Family = Direct<H>> + Unpin,
        Direct<H>: ReadChunk<Chunk: Default>,
    {
        let frame_type = DatagramTypeValue::new(value);
        // invariant: `kind_of` gives a kind for exactly the DATAGRAM Frame
        // Type values.
        let frame_type = frame_type.unwrap_or_else(|| unreachable!("DATAGRAM {value}"));
        source.sync_read_datagram_frame_unpin(frame_type)
    }
}

/// The kind of a frame of this extension: DATAGRAM, its only frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// DATAGRAM, `0x30` and `0x31`.
    Datagram,
}

impl FrameKind for FrameType {
    /// 0-RTT and 1-RTT, as STREAM ([RFC 9221 §3]).
    ///
    /// [RFC 9221 §3]: https://www.rfc-editor.org/rfc/rfc9221.html#section-3
    fn can_appear_in(self, level: EncryptionLevel) -> bool {
        matches!(level, EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt)
    }

    /// DATAGRAM frames are ack-eliciting ([RFC 9221 §5.2]).
    ///
    /// [RFC 9221 §5.2]: https://www.rfc-editor.org/rfc/rfc9221.html#section-5.2
    fn is_ack_eliciting(self) -> bool {
        true
    }

    /// As every ack-eliciting frame ([RFC 9002 §2]).
    ///
    /// [RFC 9002 §2]: https://www.rfc-editor.org/rfc/rfc9002.html#section-2
    fn counts_in_flight(self) -> bool {
        true
    }

    fn is_probing(self) -> bool {
        false
    }

    /// Either endpoint can send DATAGRAM frames.
    fn receivable_by(self, _role: Role) -> bool {
        true
    }
}

/// A DATAGRAM frame ([RFC 9221 §4]): type `0x31` with a Length field, `0x30`
/// without.
///
/// The Length field holds the length of the data, so only its width is
/// stored. `L` states the Length field, as a [`LengthKind`]: [`VarIntWidth`]
/// for a frame with a Length field of that width, [`NoLength`] for one
/// without, whose data extends to the end of the packet, and
/// [`Either<NoLength, VarIntWidth>`](Either) or
/// [`Either<VarIntWidth, NoLength>`](Either) for either of the two. Reading
/// gives `DatagramFrame<D>`, the default, `Either<NoLength, VarIntWidth>`. `From`
/// converts the two single kinds into either `Either` kind, a frame of an
/// `Either` kind into an `Either` of frames of its two kinds in the same
/// order and back, and one `Either` kind into the other.
///
/// [`with_length`](DatagramFrame::with_length) checks that the Length field can
/// state the length of the data, and [`new`](DatagramFrame::new) does so when
/// there is one; [`without_length`](DatagramFrame::without_length) accepts any
/// data. So every value writes an encoding that reads back to the same
/// value; the fields are read through methods of the same names.
/// `D` holds the data: the source's chunk type for a frame that was read,
/// any [`Buf`] for one to write.
///
/// [RFC 9221 §4]: https://www.rfc-editor.org/rfc/rfc9221.html#section-4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DatagramFrame<D, L = Either<NoLength, VarIntWidth>> {
    length: L,
    data: D,
}

impl<D, L: LengthKind> DatagramFrame<D, L> {
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
}

impl<D, L> DatagramFrame<D, L> {
    /// The kind of the frame, [`FrameType::Datagram`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::Datagram
    }

    /// The same frame with the Length field stated as `length`, which states
    /// the same field.
    fn restate_length<M>(self, length: M) -> DatagramFrame<D, M> {
        DatagramFrame {
            length,
            data: self.data,
        }
    }
}

impl<D: Buf, L: LengthKind> DatagramFrame<D, L> {
    /// The number of bytes the write operations of [`codec`] write.
    pub fn encoded_len(&self) -> usize {
        1 + length_width(self.length).map_or(0, VarIntWidth::encoded_len) + self.data.remaining()
    }

    /// The fields before the data.
    fn head(&self) -> Head<9> {
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

impl<D: Buf> DatagramFrame<D, VarIntWidth> {
    /// The DATAGRAM frame with a Length field of width `width` and `data`.
    ///
    /// # Errors
    ///
    /// [`LengthError`] if the Length field is too narrow for the length of
    /// the data.
    pub fn with_length(width: VarIntWidth, data: D) -> Result<Self, LengthError> {
        LengthError::check(data.remaining(), width)?;
        Ok(Self {
            length: width,
            data,
        })
    }
}

impl<D: Buf> DatagramFrame<D, NoLength> {
    /// The DATAGRAM frame without a Length field and with `data`; any data
    /// is accepted.
    pub fn without_length(data: D) -> Self {
        Self {
            length: NoLength,
            data,
        }
    }
}

impl<D: Buf> DatagramFrame<D> {
    /// The DATAGRAM frame with `data`, with or without a Length field as
    /// `length` states: [`with_length`](DatagramFrame::with_length) or
    /// [`without_length`](DatagramFrame::without_length), as a frame that was
    /// read.
    ///
    /// # Errors
    ///
    /// [`LengthError`] if there is a Length field and it is too narrow for
    /// the length of the data. Without a Length field, any data is accepted.
    pub fn new(length: Either<NoLength, VarIntWidth>, data: D) -> Result<Self, LengthError> {
        Ok(match length {
            Either::Left(NoLength) => DatagramFrame::without_length(data).into(),
            Either::Right(width) => DatagramFrame::with_length(width, data)?.into(),
        })
    }
}

impl<D> From<DatagramFrame<D, VarIntWidth>> for DatagramFrame<D, Either<NoLength, VarIntWidth>> {
    /// The same frame, which has a Length field.
    fn from(frame: DatagramFrame<D, VarIntWidth>) -> Self {
        let length = Either::Right(frame.length);
        frame.restate_length(length)
    }
}

impl<D> From<DatagramFrame<D, NoLength>> for DatagramFrame<D, Either<NoLength, VarIntWidth>> {
    /// The same frame, which has no Length field.
    fn from(frame: DatagramFrame<D, NoLength>) -> Self {
        let length = Either::Left(frame.length);
        frame.restate_length(length)
    }
}

impl<D> From<DatagramFrame<D, VarIntWidth>> for DatagramFrame<D, Either<VarIntWidth, NoLength>> {
    /// The same frame, which has a Length field.
    fn from(frame: DatagramFrame<D, VarIntWidth>) -> Self {
        let length = Either::Left(frame.length);
        frame.restate_length(length)
    }
}

impl<D> From<DatagramFrame<D, NoLength>> for DatagramFrame<D, Either<VarIntWidth, NoLength>> {
    /// The same frame, which has no Length field.
    fn from(frame: DatagramFrame<D, NoLength>) -> Self {
        let length = Either::Right(frame.length);
        frame.restate_length(length)
    }
}

impl<D, A, B> From<DatagramFrame<D, Either<A, B>>>
    for Either<DatagramFrame<D, A>, DatagramFrame<D, B>>
where
    A: LengthKind,
    B: LengthKind,
    Either<A, B>: LengthKind,
{
    /// The same frame as the side of `Either` that its Length field is on:
    /// `DatagramFrame<D, Either<A, B>>` becomes
    /// `Either<DatagramFrame<D, A>, DatagramFrame<D, B>>`, in the same order.
    fn from(frame: DatagramFrame<D, Either<A, B>>) -> Self {
        match frame.length {
            Either::Left(length) => Either::Left(frame.restate_length(length)),
            Either::Right(length) => Either::Right(frame.restate_length(length)),
        }
    }
}

impl<D, A, B> From<Either<DatagramFrame<D, A>, DatagramFrame<D, B>>>
    for DatagramFrame<D, Either<A, B>>
where
    A: LengthKind,
    B: LengthKind,
    Either<A, B>: LengthKind,
{
    /// The frame on either side, with its Length field on the same side:
    /// `Either<DatagramFrame<D, A>, DatagramFrame<D, B>>` becomes
    /// `DatagramFrame<D, Either<A, B>>`, in the same order.
    fn from(frame: Either<DatagramFrame<D, A>, DatagramFrame<D, B>>) -> Self {
        match frame {
            Either::Left(frame) => {
                let length = Either::Left(frame.length);
                frame.restate_length(length)
            }
            Either::Right(frame) => {
                let length = Either::Right(frame.length);
                frame.restate_length(length)
            }
        }
    }
}

impl<D> From<DatagramFrame<D, Either<NoLength, VarIntWidth>>>
    for DatagramFrame<D, Either<VarIntWidth, NoLength>>
{
    /// The same frame, with the sides of `Either` swapped.
    fn from(frame: DatagramFrame<D, Either<NoLength, VarIntWidth>>) -> Self {
        let length = frame.length.flip();
        frame.restate_length(length)
    }
}

impl<D> From<DatagramFrame<D, Either<VarIntWidth, NoLength>>>
    for DatagramFrame<D, Either<NoLength, VarIntWidth>>
{
    /// The same frame, with the sides of `Either` swapped.
    fn from(frame: DatagramFrame<D, Either<VarIntWidth, NoLength>>) -> Self {
        let length = frame.length.flip();
        frame.restate_length(length)
    }
}

/// The Frame Type value of a DATAGRAM frame: `0x30`, or `0x31` with a Length
/// field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DatagramTypeValue(VarInt);

impl DatagramTypeValue {
    /// The Frame Type value `value` if it is that of a DATAGRAM frame, and
    /// `None` otherwise.
    const fn new(value: VarInt) -> Option<Self> {
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
    //! of [`Frames`](crate::v1::frame::set::Frames) over a frame set that has
    //! [`Part`](super::Part).
    //!
    //! There is a write operation for each kind of Length field:
    //! [`write_datagram_frame_with_length`] for `DatagramFrame<D, VarIntWidth>`,
    //! [`write_datagram_frame_without_length`] for `DatagramFrame<D, NoLength>`, and
    //! [`write_datagram_frame`] for `DatagramFrame<D>`, which writes as one of the two.
    //! Each is also an operation struct, such as [`WriteDatagramFrame`], with
    //! `{Name}Ext` on receiver accesses and `{Name}HostExt` on call
    //! executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{DatagramFrame, DatagramTypeValue, type_value};
    use crate::{
        frame::{NoLength, read_field, type_var_int},
        payload::{ReadPayloadError, read_payload, read_payload_to_end},
        v1::{frame::set::FrameFieldsError, transport_error::TransportErrorCode},
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
    #[call(sync)]
    pub(super) async fn read_datagram_frame<F, A>(
        io: &mut A,
        frame_type: DatagramTypeValue,
    ) -> Result<DatagramFrame<F::Chunk>, ReadDatagramFrameError<F::Error>>
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
        let data = data.context(read_datagram_error::DataSnafu { frame_type })?;
        let frame = DatagramFrame::new(length, data);
        // invariant: the Length field, if any, was read at this width, and
        // `read_payload` returns data of exactly the length it states: it
        // fails on shorter data and panics on a longer chunk.
        Ok(frame.unwrap_or_else(|error| unreachable!("{error}")))
    }

    /// Failures of reading a DATAGRAM frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_datagram_error))]
    pub enum ReadDatagramFrameError<E> {
        /// The Length field of type `0x31` could not be read.
        #[snafu(display("DATAGRAM Length read failed"))]
        Length {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The data could not be read.
        #[snafu(display("DATAGRAM data read failed"))]
        Data {
            /// The Frame Type.
            frame_type: DatagramTypeValue,
            /// The failure of reading the data.
            source: ReadPayloadError<E>,
        },
    }

    impl<E> FrameFieldsError for ReadDatagramFrameError<E> {
        fn frame_type(&self) -> VarInt {
            match self {
                Self::Length { .. } => type_var_int(type_value::DATAGRAM_WITH_LENGTH),
                Self::Data { frame_type, .. } => frame_type.get(),
            }
        }

        fn is_incomplete(&self) -> bool {
            match self {
                Self::Length { source } => source.is_incomplete(),
                Self::Data { source, .. } => source.is_incomplete(),
            }
        }

        /// FRAME_ENCODING_ERROR for every failure ([RFC 9000 §12.4]).
        ///
        /// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
        fn transport_error_code(&self) -> TransportErrorCode {
            TransportErrorCode::FRAME_ENCODING_ERROR
        }
    }

    /// Writes `frame`, as [`write_datagram_frame_with_length`] or
    /// [`write_datagram_frame_without_length`] as its Length field states; its
    /// constructor checked its limits.
    ///
    /// A frame without a Length field extends to the end of the packet;
    /// nothing may be written after it.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_datagram_frame<F, A, D>(
        io: &mut A,
        frame: DatagramFrame<D>,
    ) -> Result<(), WriteAllError<F::Error>>
    where
        F: Write,
        A: ReceiverAccess<Family = F>,
        D: Buf,
    {
        match frame.length {
            Either::Left(length) => {
                write_datagram_frame_without_length(io, frame.restate_length(length)).await
            }
            Either::Right(length) => {
                write_datagram_frame_with_length(io, frame.restate_length(length)).await
            }
        }
    }

    /// Writes `frame`, which has a Length field;
    /// [`DatagramFrame::with_length`] checked its limits.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_datagram_frame_with_length<F, A, D>(
        io: &mut A,
        frame: DatagramFrame<D, VarIntWidth>,
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
    pub async fn write_datagram_frame_without_length<F, A, D>(
        io: &mut A,
        frame: DatagramFrame<D, NoLength>,
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
        DatagramFrame,
        codec::{
            WriteDatagramFrameHostExt as _, WriteDatagramFrameWithLengthHostExt as _,
            WriteDatagramFrameWithoutLengthHostExt as _,
        },
    };
    use crate::{
        frame::{LengthError, NoLength},
        parts::{Coprod, Coproduct, HList, PartsError},
        v1::{
            encryption_level::EncryptionLevel,
            frame::set::{
                FrameFieldsError, FrameKind, FrameSetPart, Frames, OnlyPart as _,
                codec::ReadFrameError,
            },
            role::Role,
        },
        var_int::{VarInt, VarIntWidth},
    };
    use bytes::Buf;
    use core::{convert::Infallible, marker::PhantomData};
    use either::Either;

    type ReadError =
        ReadFrameError<Infallible, Coprod![super::codec::ReadDatagramFrameError<Infallible>]>;

    fn read<'a>(encoding: &mut &'a [u8]) -> Result<DatagramFrame<&'a [u8]>, ReadError> {
        let mut frames = Frames::new(*encoding, PhantomData::<HList![super::Part]>);
        let item = frames.next().only_part();
        *encoding = frames.into_remainder();
        item.expect("the encoding is not empty")
    }

    fn datagram_frame<D: Buf>(
        width: Option<VarIntWidth>,
        data: D,
    ) -> Result<DatagramFrame<D>, LengthError> {
        DatagramFrame::new(width.map_or(Either::Left(NoLength), Either::Right), data)
    }

    /// Writes `frame`, reads it back and returns the encoding.
    fn assert_round_trip(frame: DatagramFrame<&[u8]>) -> Vec<u8> {
        let mut written = Vec::new();
        written.sync_write_datagram_frame_unpin(frame).unwrap();
        assert_eq!(written.len(), frame.encoded_len());
        let mut input = written.as_slice();
        assert_eq!(read(&mut input).unwrap(), frame);
        assert!(input.is_empty());
        written
    }

    #[test]
    fn round_trips_with_and_without_length() {
        let with =
            assert_round_trip(datagram_frame(Some(VarIntWidth::One), &b"datagram"[..]).unwrap());
        assert_eq!(with[..2], [0x31, 0x08]);
        let long =
            assert_round_trip(datagram_frame(Some(VarIntWidth::Four), &b"datagram"[..]).unwrap());
        assert_eq!(long[..5], [0x31, 0x80, 0, 0, 0x08]);
        let without = assert_round_trip(datagram_frame(None, &b"to the end"[..]).unwrap());
        assert_eq!(without[0], 0x30);
        // An empty DATAGRAM without a Length field is the type alone.
        let mut input = &[0x30][..];
        assert_eq!(
            read(&mut input).unwrap(),
            DatagramFrame::without_length(&b""[..]).into()
        );
        // Reading keeps which of the two types it was.
        for (encoding, length) in [
            (&with, Either::Right(VarIntWidth::One)),
            (&long, Either::Right(VarIntWidth::Four)),
            (&without, Either::Left(NoLength)),
        ] {
            let mut input = encoding.as_slice();
            assert_eq!(read(&mut input).unwrap().length(), length);
        }
    }

    #[test]
    fn each_kind_of_length_field_writes_its_type() {
        let with = DatagramFrame::with_length(VarIntWidth::Two, &b"hi"[..]).unwrap();
        let without = DatagramFrame::without_length(&b"hi"[..]);
        assert_eq!(with.type_value(), VarInt::from(0x31u8));
        assert_eq!(without.type_value(), VarInt::from(0x30u8));
        let mut written = Vec::new();
        written
            .sync_write_datagram_frame_with_length_unpin(with)
            .unwrap();
        assert_eq!(written, [0x31, 0x40, 0x02, b'h', b'i']);
        assert_eq!(with.encoded_len(), written.len());
        let mut written = Vec::new();
        written
            .sync_write_datagram_frame_without_length_unpin(without)
            .unwrap();
        assert_eq!(written, [0x30, b'h', b'i']);
        assert_eq!(without.encoded_len(), written.len());
        // Both convert into the frame that reading gives, which writes the
        // same bytes.
        for (frame, length) in [
            (DatagramFrame::from(with), Either::Right(VarIntWidth::Two)),
            (DatagramFrame::from(without), Either::Left(NoLength)),
        ] {
            assert_eq!(frame.length(), length);
            assert_eq!(frame, DatagramFrame::new(length, &b"hi"[..]).unwrap());
            let mut written = Vec::new();
            written.sync_write_datagram_frame_unpin(frame).unwrap();
            let mut input = written.as_slice();
            assert_eq!(read(&mut input).unwrap(), frame);
        }
    }

    #[test]
    fn narrow_length_fields_are_rejected() {
        let data = [0; 64];
        let expected = LengthError::check(64, VarIntWidth::One).unwrap_err();
        assert_eq!(
            DatagramFrame::with_length(VarIntWidth::One, &data[..]),
            Err(expected)
        );
        assert_eq!(
            DatagramFrame::new(Either::Right(VarIntWidth::One), &data[..]),
            Err(expected)
        );
        // Without a Length field, any length can be written.
        let frame = DatagramFrame::without_length(&data[..]);
        assert_eq!(*frame.data(), &data[..]);
        let frame = DatagramFrame::new(Either::Left(NoLength), &data[..]).unwrap();
        assert_eq!(*frame.data(), &data[..]);
    }

    #[test]
    fn constructors_state_the_length_field_in_the_type() {
        let with: DatagramFrame<&[u8], VarIntWidth> =
            DatagramFrame::with_length(VarIntWidth::Two, &b"hi"[..]).unwrap();
        assert_eq!(with.length(), VarIntWidth::Two);
        let without: DatagramFrame<&[u8], NoLength> = DatagramFrame::without_length(&b"hi"[..]);
        assert_eq!(without.length(), NoLength);
        let read: DatagramFrame<&[u8]> =
            DatagramFrame::new(Either::Right(VarIntWidth::Two), &b"hi"[..]).unwrap();
        assert_eq!(read, with.into());
        let read: DatagramFrame<&[u8]> =
            DatagramFrame::new(Either::Left(NoLength), &b"hi"[..]).unwrap();
        assert_eq!(read, without.into());
    }

    #[test]
    fn every_kind_of_length_field_writes_the_same_frame() {
        let with = DatagramFrame::with_length(VarIntWidth::Two, &b"hi"[..]).unwrap();
        let without = DatagramFrame::without_length(&b"hi"[..]);
        for (width, type_value, encoded_len) in
            [(Some(VarIntWidth::Two), 0x31u8, 5), (None, 0x30, 3)]
        {
            let read: DatagramFrame<&[u8]> = match width {
                Some(_) => with.into(),
                None => without.into(),
            };
            let swapped: DatagramFrame<&[u8], Either<VarIntWidth, NoLength>> = match width {
                Some(_) => with.into(),
                None => without.into(),
            };
            assert_eq!(
                swapped.length(),
                width.map_or(Either::Right(NoLength), Either::Left)
            );
            assert_eq!(swapped.type_value(), VarInt::from(type_value));
            assert_eq!(read.type_value(), VarInt::from(type_value));
            assert_eq!(swapped.encoded_len(), encoded_len);
            assert_eq!(read.encoded_len(), encoded_len);
            assert_eq!(DatagramFrame::<_>::from(swapped), read);
            assert_eq!(
                DatagramFrame::<_, Either<VarIntWidth, NoLength>>::from(read),
                swapped
            );
        }
    }

    #[test]
    fn either_kinds_convert_to_either_of_frames_in_the_same_order() {
        let with = DatagramFrame::with_length(VarIntWidth::Two, &b"hi"[..]).unwrap();
        let without = DatagramFrame::without_length(&b"hi"[..]);

        // `Either<NoLength, VarIntWidth>`, as read.
        let read: DatagramFrame<&[u8]> = without.into();
        let split: Either<DatagramFrame<_, NoLength>, DatagramFrame<_, VarIntWidth>> = read.into();
        assert_eq!(split, Either::Left(without));
        assert_eq!(DatagramFrame::from(split), read);
        let read: DatagramFrame<&[u8]> = with.into();
        let split: Either<DatagramFrame<_, NoLength>, DatagramFrame<_, VarIntWidth>> = read.into();
        assert_eq!(split, Either::Right(with));
        assert_eq!(DatagramFrame::from(split), read);

        // `Either<VarIntWidth, NoLength>`, the other order.
        let swapped: DatagramFrame<&[u8], Either<VarIntWidth, NoLength>> = with.into();
        let split: Either<DatagramFrame<_, VarIntWidth>, DatagramFrame<_, NoLength>> =
            swapped.into();
        assert_eq!(split, Either::Left(with));
        assert_eq!(DatagramFrame::from(split), swapped);
        let swapped: DatagramFrame<&[u8], Either<VarIntWidth, NoLength>> = without.into();
        let split: Either<DatagramFrame<_, VarIntWidth>, DatagramFrame<_, NoLength>> =
            swapped.into();
        assert_eq!(split, Either::Right(without));
        assert_eq!(DatagramFrame::from(split), swapped);
    }

    #[test]
    fn the_part_claims_only_its_frame_types() {
        for value in [0x30u8, 0x31] {
            assert_eq!(
                super::Part::kind_of(VarInt::from(value)),
                Some(super::FrameType::Datagram)
            );
            assert!(super::Part::FRAME_TYPE_VALUES.contains(VarInt::from(value)));
        }
        for value in (0..0x30u8).chain(0x32..=0x3f) {
            assert_eq!(
                super::Part::kind_of(VarInt::from(value)),
                None,
                "{value:#x}"
            );
            assert!(!super::Part::FRAME_TYPE_VALUES.contains(VarInt::from(value)));
        }
        // PING is a frame of version 1, unknown here.
        let mut input = &[0x01][..];
        assert!(matches!(
            read(&mut input),
            Err(ReadFrameError::UnknownType { frame_type }) if frame_type == VarInt::from(1u8)
        ));
    }

    #[test]
    fn the_kind_is_that_of_rfc_9221() {
        let kind = DatagramFrame::without_length(&b""[..]).frame_type();
        assert!(kind.is_ack_eliciting());
        assert!(kind.counts_in_flight());
        assert!(!kind.is_probing());
        assert!(kind.receivable_by(Role::Client) && kind.receivable_by(Role::Server));
        for (level, allowed) in [
            (EncryptionLevel::Initial, false),
            (EncryptionLevel::ZeroRtt, true),
            (EncryptionLevel::Handshake, false),
            (EncryptionLevel::OneRtt, true),
        ] {
            assert_eq!(kind.can_appear_in(level), allowed, "{level:?}");
        }
    }

    #[test]
    fn failures_hold_the_frame_type() {
        for (encoding, value) in [(&[0x31][..], 0x31u8), (&[0x31, 0x05, b'x'][..], 0x31)] {
            let mut input = encoding;
            let error = read(&mut input).unwrap_err();
            assert!(error.is_incomplete(), "{error:?}");
            assert_eq!(error.frame_type(), Some(VarInt::from(value)));
        }
        let mut input = &[0x31, 0x05, b'x'][..];
        assert!(matches!(
            read(&mut input),
            Err(ReadFrameError::Fields {
                source: PartsError(Coproduct::Inl(super::codec::ReadDatagramFrameError::Data { frame_type, .. })),
            }) if frame_type.get() == VarInt::from(0x31u8)
        ));
        let mut input = &[0x31][..];
        let Err(ReadFrameError::Fields {
            source: PartsError(Coproduct::Inl(source)),
        }) = read(&mut input)
        else {
            panic!()
        };
        assert_eq!(source.frame_type(), VarInt::from(0x31u8));
    }
}
