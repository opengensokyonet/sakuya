//! The reliable stream reset extension, as specified by the Internet-Draft
//! [draft-ietf-quic-reliable-stream-reset-11]: the RESET_STREAM_AT frame,
//! type `0x24` (§4), and the rule that ties its Reliable Size to its Final
//! Size ([`ReliableSizeError`]). The draft is not an RFC and may still
//! change.
//!
//! [`Part`] is the part of a frame set that holds this one frame. A frame
//! set without it reads type `0x24` as an unknown Frame Type
//! ([RFC 9000 §12.4]).
//!
//! ```
//! use core::marker::PhantomData;
//! use sakuya_wire::{
//!     assert_frame_types_disjoint,
//!     frame::{PartSum, codec::ReadFrameHostExt as _},
//!     reset_stream_at, v1,
//! };
//!
//! type Set = PartSum<v1::Part, reset_stream_at::Part>;
//! assert_frame_types_disjoint!(Set);
//!
//! // RESET_STREAM_AT on stream 4, error code 1, final size 9, reliable size 5.
//! let mut input = &[0x24, 0x04, 0x01, 0x09, 0x05][..];
//! let Ok(PartSum::Rest(frame)) = input.sync_read_frame_unpin(PhantomData::<Set>) else {
//!     panic!()
//! };
//! assert_eq!(frame.reliable_size().get().get(), 5);
//! ```
//!
//! [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-4
//! [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
use crate::{
    frame::{FrameKind, FrameSetPart, FrameTypeValues, Head, MergePadding, type_var_int},
    v1::{
        application_error::ApplicationErrorCode, encryption_level::EncryptionLevel, role::Role,
        stream_id::StreamId,
    },
    var_int::{VarInt, VarIntField},
};
use core::ops::RangeInclusive;
use nitori_call::ReceiverAccess;
use nitori_io::ReadChunk;
use snafu::Snafu;

/// The Frame Type value of RESET_STREAM_AT.
const TYPE_VALUE: u64 = 0x24;

/// The RESET_STREAM_AT frame as a part of a frame set: frames
/// [`ResetStreamAtFrame`], of the kind [`FrameType`], read with the failures
/// [`codec::ReadResetStreamAtFrameError`]. It claims the Frame Type `0x24`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Part;

impl FrameSetPart for Part {
    type Frame<D> = ResetStreamAtFrame;
    type Kind = FrameType;
    type FieldsError<E> = codec::ReadResetStreamAtFrameError<E>;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues =
        &FrameTypeValues::new(&[RangeInclusive::new(
            VarInt::from_u32(TYPE_VALUE as u32),
            VarInt::from_u32(TYPE_VALUE as u32),
        )]);

    fn kind_of(value: VarInt) -> Option<FrameType> {
        (value.get() == TYPE_VALUE).then_some(FrameType::ResetStreamAt)
    }

    async fn read_fields<F, A>(
        io: &mut A,
        _kind: FrameType,
        _value: VarInt,
    ) -> Result<ResetStreamAtFrame, codec::ReadResetStreamAtFrameError<F::Error>>
    where
        F: ReadChunk<Chunk: Default>,
        A: ReceiverAccess<Family = F>,
    {
        codec::read_reset_stream_at_frame(io).await
    }
}

/// The kind of a frame of this extension: RESET_STREAM_AT, its only frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameType {
    /// RESET_STREAM_AT, `0x24`.
    ResetStreamAt,
}

/// RESET_STREAM_AT has the properties of RESET_STREAM: the draft calls it a
/// RESET_STREAM frame with a Reliable Size field, and states none of its own.
impl FrameKind for FrameType {
    /// 0-RTT and 1-RTT, as RESET_STREAM. The draft allows the extension in
    /// 0-RTT packets, but gives no table of its own.
    fn can_appear_in(self, level: EncryptionLevel) -> bool {
        matches!(level, EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt)
    }

    fn is_ack_eliciting(self) -> bool {
        true
    }

    fn counts_in_flight(self) -> bool {
        true
    }

    fn is_probing(self) -> bool {
        false
    }

    /// Either endpoint can reset a stream it sends on.
    fn receivable_by(self, _role: Role) -> bool {
        true
    }
}

/// A RESET_STREAM_AT frame, type `0x24`, as specified by the Internet-Draft
/// [draft-ietf-quic-reliable-stream-reset-11] §4.
///
/// It is a RESET_STREAM that also states how much of the stream must still
/// be delivered reliably. `reliable_size` is at most `final_size`:
/// [`ResetStreamAtFrame::new`] checks it, so every value writes an encoding that
/// reads back to the same value; the fields are read through methods of the
/// same names. Each field keeps the width of its variable-length integer
/// encoding.
///
/// [draft-ietf-quic-reliable-stream-reset-11]: https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-11.html#section-4
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ResetStreamAtFrame {
    stream_id: VarIntField<StreamId>,
    application_error_code: VarIntField<ApplicationErrorCode>,
    final_size: VarIntField<VarInt>,
    reliable_size: VarIntField<VarInt>,
}

impl ResetStreamAtFrame {
    /// The RESET_STREAM_AT frame with these fields.
    ///
    /// # Errors
    ///
    /// [`ReliableSizeError`] if `reliable_size` exceeds `final_size`.
    pub fn new(
        stream_id: VarIntField<StreamId>,
        application_error_code: VarIntField<ApplicationErrorCode>,
        final_size: VarIntField<VarInt>,
        reliable_size: VarIntField<VarInt>,
    ) -> Result<Self, ReliableSizeError> {
        ReliableSizeError::check(final_size.get(), reliable_size.get())?;
        Ok(Self {
            stream_id,
            application_error_code,
            final_size,
            reliable_size,
        })
    }

    /// The stream being terminated.
    pub const fn stream_id(&self) -> VarIntField<StreamId> {
        self.stream_id
    }

    /// The application protocol error code.
    pub const fn application_error_code(&self) -> VarIntField<ApplicationErrorCode> {
        self.application_error_code
    }

    /// The final size of the stream, in bytes.
    pub const fn final_size(&self) -> VarIntField<VarInt> {
        self.final_size
    }

    /// The amount of data, from the start of the stream, that must be
    /// delivered to the application despite the reset.
    pub const fn reliable_size(&self) -> VarIntField<VarInt> {
        self.reliable_size
    }

    /// The kind of the frame, [`FrameType::ResetStreamAt`].
    pub const fn frame_type(&self) -> FrameType {
        FrameType::ResetStreamAt
    }

    /// The Frame Type value, `0x24`.
    pub const fn type_value(&self) -> VarInt {
        type_var_int(TYPE_VALUE)
    }

    /// The number of bytes [`codec::write_reset_stream_at_frame`] writes.
    pub fn encoded_len(&self) -> usize {
        self.head().len()
    }

    /// The encoded frame.
    fn head(&self) -> Head<33> {
        Head::new(self.type_value())
            .field(self.stream_id)
            .field(self.application_error_code)
            .field(self.final_size)
            .field(self.reliable_size)
    }
}

/// RESET_STREAM_AT is not PADDING.
impl MergePadding for ResetStreamAtFrame {}

/// A RESET_STREAM_AT reliable size exceeds its final size.
///
/// Only [`check`](Self::check) constructs it, when the check fails, so its
/// Reliable Size always exceeds its Final Size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "RESET_STREAM_AT reliable size {reliable_size} is beyond final size {final_size}"
))]
pub struct ReliableSizeError {
    final_size: VarInt,
    reliable_size: VarInt,
}

impl ReliableSizeError {
    /// The Final Size field.
    pub const fn final_size(self) -> VarInt {
        self.final_size
    }

    /// The Reliable Size field, which exceeds
    /// [`final_size`](Self::final_size).
    pub const fn reliable_size(self) -> VarInt {
        self.reliable_size
    }

    /// Checks that `reliable_size` is at most `final_size`, the rule
    /// [`ResetStreamAtFrame::new`] applies.
    ///
    /// # Errors
    ///
    /// [`ReliableSizeError`] if `reliable_size` exceeds `final_size`.
    pub fn check(final_size: VarInt, reliable_size: VarInt) -> Result<(), Self> {
        if reliable_size > final_size {
            return Err(Self {
                final_size,
                reliable_size,
            });
        }
        Ok(())
    }
}

pub mod codec {
    //! Writing RESET_STREAM_AT frames as a `nitori_call` operation; reading
    //! is part of [`read_frame`](crate::frame::codec::read_frame) of a frame
    //! set that has [`Part`](super::Part).
    //!
    //! [`write_reset_stream_at_frame`] is also the operation struct
    //! [`WriteResetStreamAtFrame`], with `WriteResetStreamAtFrameExt` on receiver
    //! accesses and `WriteResetStreamAtFrameHostExt` on call executors.
    // `#[call]` generates constructors, fields and extension traits without
    // documentation comments; the module documentation above describes them.
    #![allow(missing_docs)]

    use super::{ReliableSizeError, ResetStreamAtFrame, TYPE_VALUE};
    use crate::{
        frame::{FrameFieldsError, read_field, type_var_int},
        v1::transport_error::TransportErrorCode,
        var_int::{VarInt, codec::ReadVarIntError},
    };
    use nitori_call::{ReceiverAccess, call};
    use nitori_io::{calls::WriteAllError, prelude::*};
    use snafu::{ResultExt, Snafu};

    /// Reads the fields that follow the Frame Type.
    pub(super) async fn read_reset_stream_at_frame<F: Read, A: ReceiverAccess<Family = F>>(
        io: &mut A,
    ) -> Result<ResetStreamAtFrame, ReadResetStreamAtFrameError<F::Error>> {
        use read_reset_stream_at_error::*;
        let stream_id = read_field(io).await.context(StreamIdSnafu)?;
        let application_error_code = read_field(io)
            .await
            .context(ApplicationProtocolErrorCodeSnafu)?;
        let final_size = read_field(io).await.context(FinalSizeSnafu)?;
        let reliable_size = read_field(io).await.context(ReliableSizeSnafu)?;
        let frame =
            ResetStreamAtFrame::new(stream_id, application_error_code, final_size, reliable_size)?;
        Ok(frame)
    }

    /// Failures of reading a RESET_STREAM_AT frame.
    #[derive(Debug, Snafu)]
    #[snafu(module(read_reset_stream_at_error))]
    pub enum ReadResetStreamAtFrameError<E> {
        /// The Stream ID field could not be read.
        #[snafu(display("RESET_STREAM_AT Stream ID read failed"))]
        StreamId {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Application Protocol Error Code field could not be read.
        #[snafu(display("RESET_STREAM_AT Application Protocol Error Code read failed"))]
        ApplicationProtocolErrorCode {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Final Size field could not be read.
        #[snafu(display("RESET_STREAM_AT Final Size read failed"))]
        FinalSize {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The Reliable Size field could not be read.
        #[snafu(display("RESET_STREAM_AT Reliable Size read failed"))]
        ReliableSize {
            /// The failure of reading the field.
            source: ReadVarIntError<E>,
        },
        /// The reliable size exceeds the final size.
        #[snafu(transparent)]
        ReliableSizeAboveFinalSize {
            /// The broken rule.
            source: ReliableSizeError,
        },
    }

    impl<E> FrameFieldsError for ReadResetStreamAtFrameError<E> {
        /// `0x24`.
        fn frame_type(&self) -> VarInt {
            type_var_int(TYPE_VALUE)
        }

        fn is_incomplete(&self) -> bool {
            match self {
                Self::StreamId { source }
                | Self::ApplicationProtocolErrorCode { source }
                | Self::FinalSize { source }
                | Self::ReliableSize { source } => source.is_incomplete(),
                Self::ReliableSizeAboveFinalSize { .. } => false,
            }
        }

        /// FRAME_ENCODING_ERROR for every failure ([RFC 9000 §12.4]).
        ///
        /// [RFC 9000 §12.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4
        fn transport_error_code(&self) -> TransportErrorCode {
            TransportErrorCode::FRAME_ENCODING_ERROR
        }
    }

    /// Writes `frame`; [`ResetStreamAtFrame::new`] checked its rule.
    ///
    /// # Errors
    ///
    /// [`WriteAllError`] if the receiver stops accepting bytes or fails;
    /// bytes accepted before stay written.
    #[call(sync)]
    pub async fn write_reset_stream_at_frame<F: Write, A: ReceiverAccess<Family = F>>(
        io: &mut A,
        frame: ResetStreamAtFrame,
    ) -> Result<(), WriteAllError<F::Error>> {
        io.write_all(frame.head().as_slice()).await
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FrameType, Part, ReliableSizeError, ResetStreamAtFrame,
        codec::{ReadResetStreamAtFrameError, WriteResetStreamAtFrameHostExt as _},
    };
    use crate::{
        frame::{
            FrameFieldsError, FrameKind, FrameSetPart,
            codec::{ReadFrameError, ReadFrameHostExt as _},
        },
        v1::{
            application_error::ApplicationErrorCode, encryption_level::EncryptionLevel, role::Role,
            stream_id::StreamId, transport_error::TransportErrorCode,
        },
        var_int::{VarInt, VarIntField, VarIntWidth},
    };
    use core::{convert::Infallible, marker::PhantomData};

    type ReadError = ReadFrameError<Infallible, ReadResetStreamAtFrameError<Infallible>>;

    fn frame(final_size: u16, reliable_size: u16) -> Result<ResetStreamAtFrame, ReliableSizeError> {
        ResetStreamAtFrame::new(
            VarIntField::shortest(StreamId::from_var_int(VarInt::ZERO)),
            VarIntField::shortest(ApplicationErrorCode::new(VarInt::from(1u8))),
            VarIntField::shortest(VarInt::from(final_size)),
            VarIntField::shortest(VarInt::from(reliable_size)),
        )
    }

    fn read(encoding: &[u8]) -> Result<ResetStreamAtFrame, ReadError> {
        let mut input = encoding;
        input.sync_read_frame_unpin(PhantomData::<Part>)
    }

    fn assert_round_trip(frame: ResetStreamAtFrame) {
        let mut written = Vec::new();
        written
            .sync_write_reset_stream_at_frame_unpin(frame)
            .unwrap();
        assert_eq!(written.len(), frame.encoded_len());
        assert_eq!(written[0], 0x24);
        assert_eq!(read(&written).unwrap(), frame);
    }

    #[test]
    fn round_trips() {
        assert_round_trip(frame(800, 300).unwrap());
        assert_round_trip(frame(5, 5).unwrap());
        // A longer field encoding is kept.
        let wide = ResetStreamAtFrame::new(
            VarIntField::new(
                StreamId::from_var_int(VarInt::from(4u8)),
                VarIntWidth::Eight,
            )
            .unwrap(),
            VarIntField::shortest(ApplicationErrorCode::new(VarInt::ZERO)),
            VarIntField::shortest(VarInt::from(9u8)),
            VarIntField::new(VarInt::from(5u8), VarIntWidth::Two).unwrap(),
        )
        .unwrap();
        assert_round_trip(wide);
    }

    #[test]
    fn reliable_size_beyond_final_size_is_rejected() {
        let expected = ReliableSizeError::check(VarInt::from(5u8), VarInt::from(6u8)).unwrap_err();
        assert_eq!(
            (expected.final_size(), expected.reliable_size()),
            (VarInt::from(5u8), VarInt::from(6u8))
        );
        assert_eq!(
            ReliableSizeError::check(VarInt::from(5u8), VarInt::from(5u8)),
            Ok(())
        );
        let error = read(&[0x24, 0x00, 0x00, 0x05, 0x06]).unwrap_err();
        assert!(matches!(
            error,
            ReadFrameError::Fields {
                source: ReadResetStreamAtFrameError::ReliableSizeAboveFinalSize { source },
            } if source == expected
        ));
        assert_eq!(error.frame_type(), Some(VarInt::from(0x24u8)));
        assert!(!error.is_incomplete());
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR
        );
        assert_eq!(frame(5, 6), Err(expected));
    }

    #[test]
    fn each_field_has_its_own_failure() {
        fn fields(encoding: &[u8]) -> ReadResetStreamAtFrameError<Infallible> {
            match read(encoding) {
                Err(ReadFrameError::Fields { source }) => {
                    assert!(source.is_incomplete());
                    assert_eq!(source.frame_type(), VarInt::from(0x24u8));
                    source
                }
                other => panic!("{other:?}"),
            }
        }
        // A two-byte encoding cut short in each field.
        assert!(matches!(
            fields(&[0x24, 0x40]),
            ReadResetStreamAtFrameError::StreamId { source } if source.is_incomplete()
        ));
        assert!(matches!(
            fields(&[0x24, 0x00, 0x40]),
            ReadResetStreamAtFrameError::ApplicationProtocolErrorCode { source } if source.is_incomplete()
        ));
        assert!(matches!(
            fields(&[0x24, 0x00, 0x00, 0x40]),
            ReadResetStreamAtFrameError::FinalSize { source } if source.is_incomplete()
        ));
        assert!(matches!(
            fields(&[0x24, 0x00, 0x00, 0x05, 0x40]),
            ReadResetStreamAtFrameError::ReliableSize { source } if source.is_incomplete()
        ));
    }

    #[test]
    fn the_part_claims_only_its_frame_type() {
        assert_eq!(
            Part::kind_of(VarInt::from(0x24u8)),
            Some(FrameType::ResetStreamAt)
        );
        for value in (0..0x24u8).chain(0x25..=0x3f) {
            assert_eq!(Part::kind_of(VarInt::from(value)), None, "{value:#x}");
            assert!(!Part::FRAME_TYPE_VALUES.contains(VarInt::from(value)));
        }
        assert!(Part::FRAME_TYPE_VALUES.contains(VarInt::from(0x24u8)));
        // A RESET_STREAM frame is a frame of version 1, unknown here.
        assert!(matches!(
            read(&[0x04, 0, 0, 0]),
            Err(ReadFrameError::UnknownType { frame_type }) if frame_type == VarInt::from(4u8)
        ));
        assert_eq!(frame(1, 0).unwrap().frame_type(), FrameType::ResetStreamAt);
    }

    #[test]
    fn the_kind_follows_reset_stream() {
        let kind = FrameType::ResetStreamAt;
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
}
