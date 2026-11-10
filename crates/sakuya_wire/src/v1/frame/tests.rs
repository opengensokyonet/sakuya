//! Tests that cover every frame type, and the helpers the tests of the frame
//! modules share.
use super::{
    Frame, FrameRun, FrameType,
    ack::{AckFrame, AckRange, AckRanges, EcnCounts},
    codec::{
        ReadFieldsError, ReadFieldsHostExt as _, WriteFrameHostExt as _, WriteFrameRunHostExt as _,
    },
    connection_close::{CloseErrorCode, ConnectionCloseFrame},
    crypto::CryptoFrame,
    data_blocked::DataBlockedFrame,
    handshake_done::HandshakeDoneFrame,
    max_data::MaxDataFrame,
    max_stream_data::MaxStreamDataFrame,
    max_streams::MaxStreamsFrame,
    new_connection_id::NewConnectionIdFrame,
    new_token::{InvalidNewTokenError, NewTokenFrame},
    padding::{PaddingFrame, PaddingRun},
    path_challenge::PathChallengeFrame,
    path_response::PathResponseFrame,
    ping::PingFrame,
    reset_stream::ResetStreamFrame,
    retire_connection_id::RetireConnectionIdFrame,
    stop_sending::StopSendingFrame,
    stream::StreamFrame,
    stream_data_blocked::StreamDataBlockedFrame,
    streams_blocked::StreamsBlockedFrame,
};
use crate::frame::{InvalidDataError, LengthError, length_width};
use crate::parts::{Coprod, Coproduct, HList, PartsError};
use crate::v1::frame::set::{
    FrameKind, FrameSetPart, Frames, OnlyPart as _,
    codec::{LongerTypeEncodingError, ReadFrameError, ReadFrameTypeHostExt as _},
};
use crate::{
    connection_id::{NonEmptyCid, StatelessResetToken},
    v1::application_error::ApplicationErrorCode,
    v1::encryption_level::EncryptionLevel,
    v1::packet_number::PacketNumber,
    v1::stream_count::StreamCount,
    v1::stream_id::{Directionality, StreamId},
    v1::transport_error::TransportErrorCode,
    var_int::{
        VarInt, VarIntField, VarIntWidth,
        codec::{ReadVarIntHostExt as _, WriteVarIntFieldHostExt as _},
    },
};
use bytes::{Buf, Bytes};
use core::{marker::PhantomData, num::NonZeroUsize};
use nitori_call::{Direct, Receiver};
use nitori_io::{Read, ReadChunk};

/// The frame set of version 1 alone.
pub(in crate::v1) const V1: PhantomData<HList![crate::v1::Part]> = PhantomData;

/// Reading one frame of version 1 from a memory source: its Frame Type, then
/// its fields with `read_fields`, which takes one PADDING frame at a time.
pub(in crate::v1) trait ReadOneFrame: Sized {
    /// The chunks of the payload fields of the frame.
    type Chunk;

    /// The failure of the source.
    type Error;

    /// Reads one frame from the start of the source. Bytes read before a
    /// failure stay consumed.
    #[allow(clippy::type_complexity)]
    fn read_one_frame(
        &mut self,
    ) -> Result<
        Frame<Self::Chunk>,
        ReadFrameError<Self::Error, Coprod![ReadFieldsError<Self::Error>]>,
    >;
}

impl<H> ReadOneFrame for H
where
    H: Buf + Receiver<Family = Direct<H>> + Unpin,
    Direct<H>: ReadChunk<Chunk: Default>,
{
    type Chunk = <Direct<H> as ReadChunk>::Chunk;
    type Error = <Direct<H> as Read>::Error;

    fn read_one_frame(
        &mut self,
    ) -> Result<
        Frame<Self::Chunk>,
        ReadFrameError<Self::Error, Coprod![ReadFieldsError<Self::Error>]>,
    > {
        let (kind, value) = self.sync_read_frame_type_unpin(V1)?;
        self.sync_read_fields_unpin(kind.extract(), value)
            .map_err(|error| ReadFrameError::Fields {
                source: PartsError(Coproduct::Inl(error)),
            })
    }
}

/// The STREAM frame as `StreamFrame::new` and a decision of its Length field
/// construct it, with a Length field of width `length` if there is one, as a
/// frame that was read.
pub(in crate::v1) fn stream_frame<D: Buf>(
    stream_id: VarIntField<StreamId>,
    offset: Option<VarIntField<VarInt>>,
    length: Option<VarIntWidth>,
    data: D,
    fin: bool,
) -> Result<StreamFrame<D>, InvalidDataError> {
    let frame = StreamFrame::new(stream_id, offset, data, fin)?;
    Ok(match length {
        None => frame.into_without_length().into(),
        Some(width) => frame.into_with_length(width)?.into(),
    })
}

pub(in crate::v1) fn vi(value: u64) -> VarInt {
    VarInt::try_from(value).unwrap()
}

pub(in crate::v1) fn sid(value: u64) -> StreamId {
    StreamId::from_var_int(vi(value))
}

/// The field holding `value` in its shortest encoding.
pub(in crate::v1) fn short<T: Copy + Into<VarInt> + TryFrom<VarInt>>(value: T) -> VarIntField<T> {
    VarIntField::shortest(value)
}

/// The field holding `value` in an encoding of `width`.
pub(in crate::v1) fn wide<T: Copy + Into<VarInt> + TryFrom<VarInt>>(
    value: T,
    width: VarIntWidth,
) -> VarIntField<T> {
    VarIntField::new(value, width).unwrap()
}

/// Values at the edges of each width, and the largest stream count.
pub(in crate::v1) const EDGES: [u64; 9] = [
    0,
    63,
    64,
    16_383,
    16_384,
    (1 << 30) - 1,
    1 << 30,
    1 << 60,
    (1 << 62) - 1,
];

/// Every edge value in every width that holds it.
pub(in crate::v1) fn edge_fields() -> Vec<VarIntField<VarInt>> {
    EDGES
        .into_iter()
        .flat_map(|value| {
            VarIntWidth::ALL
                .into_iter()
                .filter_map(move |width| VarIntField::new(vi(value), width).ok())
        })
        .collect()
}

/// `field` with its value converted by `convert`, at the same width.
pub(in crate::v1) fn as_field<T: Copy + Into<VarInt> + TryFrom<VarInt>>(
    field: VarIntField<VarInt>,
    convert: impl Fn(VarInt) -> T,
) -> VarIntField<T> {
    wide(convert(field.get()), field.width())
}

/// Writes `frame` with [`write_frame`](super::codec::write_frame), checks
/// its length and type, reads it back from a byte slice and from `Bytes`,
/// writes what was read again, and returns the encoding.
///
/// This checks both directions for the bytes of `frame`: the value reads
/// back unchanged, and reading then writing reproduces the bytes.
pub(in crate::v1) fn assert_round_trip(frame: Frame<&[u8]>) -> Vec<u8> {
    let mut encoding = Vec::new();
    encoding.sync_write_frame_unpin(frame.clone()).unwrap();
    assert_eq!(encoding.len(), frame.encoded_len(), "{frame:?}");
    assert_eq!(
        encoding.as_slice().sync_read_var_int_unpin().unwrap(),
        frame.type_value(),
        "{frame:?}"
    );

    let mut input = encoding.as_slice();
    assert_eq!(input.read_one_frame().unwrap(), frame, "{encoding:02x?}");
    assert!(input.is_empty(), "{frame:?}");

    // A `Bytes` source reads the same frame, which writes the same bytes.
    let mut input = Bytes::from(encoding.clone());
    let from_bytes = input.read_one_frame().unwrap();
    assert!(input.is_empty());
    let mut rewritten = Vec::new();
    rewritten.sync_write_frame_unpin(from_bytes).unwrap();
    assert_eq!(rewritten, encoding, "{frame:?}");

    // A slice of exactly the encoded length takes the frame.
    let mut exact = vec![0; encoding.len()];
    let mut sink = exact.as_mut_slice();
    sink.sync_write_frame_unpin(frame).unwrap();
    assert!(sink.is_empty());
    assert_eq!(exact, encoding);
    encoding
}

/// Reads one frame that takes all of `encoding`, checks that writing it
/// reproduces `encoding` and that the frame round-trips, and returns it.
pub(in crate::v1) fn assert_bytes_round_trip(encoding: &[u8]) -> Frame<&[u8]> {
    let mut input = encoding;
    let frame = input.read_one_frame().unwrap();
    assert!(input.is_empty(), "{encoding:02x?}: {frame:?}");
    assert_eq!(assert_round_trip(frame.clone()), encoding, "{frame:?}");
    frame
}

pub(in crate::v1) const TOKEN: [u8; 16] = *b"0123456789abcdef";

/// An ACK frame read from `encoding`.
pub(in crate::v1) fn read_ack_frame(encoding: &[u8]) -> Frame<&[u8]> {
    let mut input = encoding;
    let frame = input.read_one_frame().unwrap();
    assert!(matches!(frame, Frame::Ack(_)), "{frame:?}");
    assert!(input.is_empty());
    frame
}

/// One frame of every type and form, in the shortest encodings.
fn sample_frames() -> Vec<Frame<&'static [u8]>> {
    let mut frames = vec![
        Frame::Padding(PaddingFrame),
        Frame::Ping(PingFrame),
        // Largest 100, delay 5, ranges 97..=100, 90..=94 and 88..=88; ECN
        // counts 1, 2, 3.
        read_ack_frame(&[
            0x03, 0x40, 100, 0x05, 0x02, 0x03, 0x01, 0x04, 0x00, 0x00, 0x01, 0x02, 0x03,
        ]),
        read_ack_frame(&[0x02, 0x00, 0x00, 0x00, 0x00]),
        Frame::ResetStream(ResetStreamFrame::new(
            short(sid(4)),
            short(ApplicationErrorCode::new(vi(0x100))),
            short(vi(70_000)),
        )),
        Frame::StopSending(StopSendingFrame::new(
            short(sid(3)),
            short(ApplicationErrorCode::new(vi(7))),
        )),
        Frame::Crypto(
            CryptoFrame::new(short(vi(1000)), VarIntWidth::One, &b"client hello"[..]).unwrap(),
        ),
        Frame::Crypto(CryptoFrame::new(short(VarInt::ZERO), VarIntWidth::One, &b""[..]).unwrap()),
        Frame::NewToken(NewTokenFrame::new(VarIntWidth::One, &b"token"[..]).unwrap()),
        Frame::MaxData(MaxDataFrame::new(short(vi(1 << 40)))),
        Frame::MaxStreamData(MaxStreamDataFrame::new(short(sid(8)), short(vi(65_536)))),
        Frame::MaxStreams(MaxStreamsFrame::new(
            Directionality::Bidirectional,
            short(StreamCount::MAX),
        )),
        Frame::MaxStreams(MaxStreamsFrame::new(
            Directionality::Unidirectional,
            short(StreamCount::new(3).unwrap()),
        )),
        Frame::DataBlocked(DataBlockedFrame::new(short(vi(16_384)))),
        Frame::StreamDataBlocked(StreamDataBlockedFrame::new(short(sid(2)), short(vi(63)))),
        Frame::StreamsBlocked(StreamsBlockedFrame::new(
            Directionality::Bidirectional,
            short(StreamCount::new(100).unwrap()),
        )),
        Frame::StreamsBlocked(StreamsBlockedFrame::new(
            Directionality::Unidirectional,
            short(StreamCount::ZERO),
        )),
        Frame::NewConnectionId(
            NewConnectionIdFrame::new(
                short(vi(2)),
                short(vi(1)),
                NonEmptyCid::try_from(&[0xaa; 20][..]).unwrap(),
                StatelessResetToken::new(TOKEN),
            )
            .unwrap(),
        ),
        Frame::NewConnectionId(
            NewConnectionIdFrame::new(
                short(vi(1)),
                short(vi(1)),
                NonEmptyCid::try_from(&[0x01][..]).unwrap(),
                StatelessResetToken::new(TOKEN),
            )
            .unwrap(),
        ),
        Frame::RetireConnectionId(RetireConnectionIdFrame::new(short(vi(9)))),
        Frame::PathChallenge(PathChallengeFrame::new(*b"challeng")),
        Frame::PathResponse(PathResponseFrame::new(*b"response")),
        Frame::ConnectionClose(
            ConnectionCloseFrame::new(
                CloseErrorCode::Transport {
                    code: short(TransportErrorCode::PROTOCOL_VIOLATION),
                    frame_type: short(vi(0x08)),
                },
                VarIntWidth::One,
                &b"bad stream"[..],
            )
            .unwrap(),
        ),
        Frame::ConnectionClose(
            ConnectionCloseFrame::new(
                CloseErrorCode::Application {
                    code: short(ApplicationErrorCode::new(vi(0x42))),
                },
                VarIntWidth::One,
                &b""[..],
            )
            .unwrap(),
        ),
        Frame::HandshakeDone(HandshakeDoneFrame),
    ];
    for bits in 0..8u64 {
        let stream = stream_frame(
            short(sid(4)),
            (bits & 0x04 != 0).then(|| short(vi(1 << 20))),
            (bits & 0x02 != 0).then_some(VarIntWidth::One),
            &b"stream data"[..],
            bits & 0x01 != 0,
        );
        frames.push(Frame::Stream(stream.unwrap()));
    }
    frames
}

#[test]
fn every_frame_round_trips() {
    for frame in sample_frames() {
        assert_round_trip(frame);
    }
}

/// A run is written as its frames are, and `Frames` reads it back; a frame
/// is a run of one frame.
#[test]
fn every_frame_round_trips_as_a_run() {
    for frame in sample_frames() {
        let mut encoding = Vec::new();
        encoding.sync_write_frame_unpin(frame.clone()).unwrap();
        let run = FrameRun::from(frame.clone());
        assert_eq!(run.frame_type(), frame.frame_type());
        assert_eq!(run.type_value(), frame.type_value());
        assert_eq!(run.encoded_len(), encoding.len(), "{run:?}");
        let mut written = Vec::new();
        written.sync_write_frame_run_unpin(run.clone()).unwrap();
        assert_eq!(written, encoding, "{run:?}");
        let mut frames = Frames::new(written.as_slice(), V1);
        let read = frames.next().only_part().unwrap().unwrap();
        assert_eq!(read, run);
        assert!(frames.next().only_part().is_none());
    }

    // Runs of several PADDING frames.
    for len in [2, 3, 200] {
        let run = FrameRun::<&[u8]>::Padding(PaddingRun::new(NonZeroUsize::new(len).unwrap()));
        assert_eq!(run.frame_type(), FrameType::Padding);
        assert_eq!(run.type_value(), VarInt::ZERO);
        assert_eq!(run.encoded_len(), len);
        let mut written = Vec::new();
        written.sync_write_frame_run_unpin(run.clone()).unwrap();
        assert_eq!(written, vec![0; len]);
        let mut frames = Frames::new(written.as_slice(), V1);
        assert_eq!(
            frames.next().only_part().map(Result::unwrap),
            Some(run.clone())
        );
        assert!(frames.next().only_part().is_none());
    }
}

/// The PADDING frame of `Frame` is one byte, whatever follows it, and
/// becomes a run of one.
#[test]
fn a_padding_frame_is_a_run_of_one() {
    let frame = Frame::<&[u8]>::Padding(PaddingFrame);
    assert_eq!(frame.encoded_len(), 1);
    assert_eq!(
        FrameRun::from(frame),
        FrameRun::Padding(PaddingRun::new(NonZeroUsize::MIN))
    );
}

#[test]
fn writing_into_a_short_slice_keeps_the_accepted_prefix() {
    for frame in sample_frames() {
        let required = frame.encoded_len();
        let mut encoding = Vec::new();
        encoding.sync_write_frame_unpin(frame.clone()).unwrap();
        let mut buffer = vec![0xee; required - 1];
        let mut sink = buffer.as_mut_slice();
        let error = sink.sync_write_frame_unpin(frame.clone()).unwrap_err();
        assert_eq!(error.completed(), required - 1, "{frame:?}");
        assert_eq!(buffer, encoding[..required - 1], "{frame:?}");
    }
}

#[test]
fn stream_without_length_takes_the_rest_of_the_payload() {
    // PING, then STREAM 0x09 (FIN, no OFF, no LEN) on stream 1.
    let payload = [0x01, 0x09, 0x01, b'a', b'b', 0x01, 0x00];
    let frames: Vec<_> = Frames::new(&payload[..], V1)
        .map(|frame| frame.unwrap().extract())
        .collect();
    assert_eq!(
        frames,
        [
            FrameRun::Ping(PingFrame),
            FrameRun::Stream(
                stream_frame(
                    short(sid(1)),
                    None,
                    None,
                    &[b'a', b'b', 0x01, 0x00][..],
                    true
                )
                .unwrap()
            ),
        ]
    );
}

#[test]
fn bytes_sources_share_their_storage() {
    let payload = Bytes::from_static(&[0x0b, 0x04, 0x02, b'h', b'i', 0x01]);
    let mut frames = Frames::new(payload.clone(), V1);
    let Some(Ok(FrameRun::Stream(stream))) = frames.next().only_part() else {
        panic!()
    };
    assert_eq!(*stream.data(), &b"hi"[..]);
    assert_eq!(stream.data().as_ptr(), payload[3..].as_ptr());
    assert_eq!(
        frames.next().only_part().map(Result::unwrap),
        Some(FrameRun::Ping(PingFrame))
    );
    assert!(frames.next().only_part().is_none());
}

#[test]
fn padding_runs_are_one_value() {
    let payload = [0x00, 0x00, 0x00, 0x01, 0x00];
    let mut frames = Frames::new(&payload[..], V1);
    assert_eq!(
        frames.next().only_part().map(Result::unwrap),
        Some(FrameRun::Padding(PaddingRun::new(
            NonZeroUsize::new(3).unwrap()
        )))
    );
    assert_eq!(frames.offset(), 3);
    assert_eq!(
        frames.next().only_part().map(Result::unwrap),
        Some(FrameRun::Ping(PingFrame))
    );
    assert_eq!(*frames.remainder(), [0x00]);
    assert_eq!(
        frames.next().only_part().map(Result::unwrap),
        Some(FrameRun::Padding(PaddingRun::new(NonZeroUsize::MIN)))
    );
    assert!(frames.next().only_part().is_none());

    // A longer encoding of type 0 is not PADDING; it ends the run and is
    // rejected.
    let payload = [0x00, 0x40, 0x00, 0x01];
    let mut frames = Frames::new(&payload[..], V1);
    assert_eq!(
        frames.next().only_part().map(Result::unwrap),
        Some(FrameRun::Padding(PaddingRun::new(NonZeroUsize::MIN)))
    );
    let error = frames.next().only_part().unwrap().unwrap_err();
    assert!(matches!(
        error,
        ReadFrameError::LongerTypeEncoding { source }
            if source == LongerTypeEncodingError::check(VarInt::ZERO, VarIntWidth::Two).unwrap_err()
    ));
    assert_eq!(frames.offset(), 1);
    assert!(frames.next().only_part().is_none());
}

#[test]
fn longer_frame_type_encodings_are_protocol_violations() {
    // Every value up to 0x3f has a one-byte shortest encoding; the known
    // types and an unknown one are rejected alike.
    for value in (0..=0x31u8).chain([0x3f]) {
        for width in [VarIntWidth::Two, VarIntWidth::Four, VarIntWidth::Eight] {
            let mut encoding = Vec::new();
            encoding
                .sync_write_var_int_field_unpin(
                    VarIntField::new(VarInt::from(value), width).unwrap(),
                )
                .unwrap();
            // A field that would follow stays unread.
            encoding.push(0x01);
            {
                let mut input = encoding.as_slice();
                let error = input.read_one_frame().unwrap_err();
                assert!(
                    matches!(
                        error,
                        ReadFrameError::LongerTypeEncoding { source }
                            if source.frame_type() == VarInt::from(value) && source.width() == width
                    ),
                    "{encoding:02x?}: {error:?}"
                );
                assert_eq!(
                    error.transport_error_code(),
                    TransportErrorCode::PROTOCOL_VIOLATION
                );
                assert_eq!(error.frame_type(), Some(VarInt::from(value)));
                assert!(!error.is_incomplete());
                assert_eq!(input, [0x01]);
            }
        }
    }
    let error = [0x40, 0x08].as_slice().read_one_frame().unwrap_err();
    assert_eq!(error.to_string(), "frame type encoding check failed");
    assert_eq!(
        std::error::Error::source(&error).map(ToString::to_string),
        Some("frame type 0x8 uses a 2-byte encoding, longer than necessary".into())
    );
    // A type whose shortest encoding takes two bytes is read; 0x4040 is
    // unknown.
    let error = [0x40, 0x40].as_slice().read_one_frame().unwrap_err();
    assert!(matches!(error, ReadFrameError::UnknownType { .. }));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::FRAME_ENCODING_ERROR
    );
}

#[test]
fn unknown_types_and_those_of_extensions_are_rejected() {
    // Values RFC 9000 does not define, among them those of RESET_STREAM_AT
    // (0x24) and DATAGRAM (0x30, 0x31), which version 1 alone does not know
    // (RFC 9000 §12.4).
    let cases: [&[u8]; 7] = [
        &[0x1f],
        &[0x21, 0x00],
        &[0x40, 0x40],
        &[0x7f, 0xff],
        &[0x24, 0x00, 0x00, 0x00, 0x00],
        &[0x30, 0x01],
        &[0x31, 0x00],
    ];
    for encoding in cases {
        let mut input = encoding;
        let frame_type = input.sync_read_var_int_unpin().unwrap();
        let mut input = encoding;
        let error = input.read_one_frame().unwrap_err();
        assert!(
            matches!(
                error,
                ReadFrameError::UnknownType { frame_type: rejected } if rejected == frame_type
            ),
            "{encoding:02x?}: {error:?}"
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR
        );
        assert_eq!(error.frame_type(), Some(frame_type));
        assert!(!error.is_incomplete());
        assert_eq!(<crate::v1::Part as FrameSetPart>::kind_of(frame_type), None);
    }
}

#[test]
fn truncated_frames_are_terminal() {
    let cases: [(&[u8], Option<u64>); 7] = [
        // The type itself is cut short.
        (&[0x40], None),
        (&[0x10], Some(0x10)),
        (&[0x10, 0x80, 0x00], Some(0x10)),
        // CRYPTO announcing 4 bytes with 2 present.
        (&[0x06, 0x00, 0x04, 0xaa, 0xbb], Some(0x06)),
        (&[0x1a, 1, 2, 3, 4, 5, 6, 7], Some(0x1a)),
        (&[0x18, 0x01, 0x00, 0x04, 1, 2, 3, 4, 0, 0], Some(0x18)),
        (&[0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02], Some(0x03)),
    ];
    for (encoding, frame_type) in cases {
        let mut input = encoding;
        let error = input.read_one_frame().unwrap_err();
        assert!(error.is_incomplete(), "{encoding:02x?}: {error:?}");
        assert_eq!(error.frame_type(), frame_type.map(vi), "{encoding:02x?}");
    }

    // In a payload, the offset names the frame that is cut short, and the
    // iteration ends with the error.
    let payload = [0x01, 0x01, 0x11, 0x04];
    let mut frames = Frames::new(&payload[..], V1);
    assert_eq!(
        frames.next().only_part().map(Result::unwrap),
        Some(FrameRun::Ping(PingFrame))
    );
    assert_eq!(
        frames.next().only_part().map(Result::unwrap),
        Some(FrameRun::Ping(PingFrame))
    );
    let error = frames.next().only_part().unwrap().unwrap_err();
    assert_eq!(frames.offset(), 2);
    assert!(matches!(
        error,
        ReadFrameError::Fields {
            source: PartsError(Coproduct::Inl(ReadFieldsError::MaxStreamData { .. }))
        }
    ));
    assert!(error.is_incomplete());
    assert!(frames.next().only_part().is_none());
}

/// The failure of reading `encoding`, which ends within a field.
fn cut_short(
    encoding: &[u8],
) -> ReadFrameError<core::convert::Infallible, Coprod![ReadFieldsError<core::convert::Infallible>]>
{
    let mut input = encoding;
    let error = input.read_one_frame().unwrap_err();
    assert!(error.is_incomplete(), "{encoding:02x?}: {error:?}");
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::FRAME_ENCODING_ERROR
    );
    assert!(input.is_empty(), "{encoding:02x?}");
    error
}

#[test]
fn a_field_cut_short_is_named_by_its_variant() {
    use super::{
        connection_close::codec::{
            ReadConnectionCloseFrameApplicationError as ApplicationClose,
            ReadConnectionCloseFrameTransportError as TransportClose,
            ReadReasonPhraseError as Reason,
        },
        crypto::codec::ReadCryptoFrameError as CryptoFrame,
        max_stream_data::codec::ReadMaxStreamDataFrameError as MaxStreamDataFrame,
        new_token::codec::ReadNewTokenFrameError as NewTokenFrame,
        reset_stream::codec::ReadResetStreamFrameError as ResetStreamFrame,
        stop_sending::codec::ReadStopSendingFrameError as StopSendingFrame,
        stream::codec::ReadStreamFrameError as StreamFrame,
        stream_data_blocked::codec::ReadStreamDataBlockedFrameError as StreamDataBlockedFrame,
    };
    use ReadFieldsError as F;
    type Check = fn(&ReadFieldsError<core::convert::Infallible>) -> bool;
    let cases: [(&[u8], Check); 23] = [
        (&[0x04], |e| {
            matches!(
                e,
                F::ResetStream {
                    source: ResetStreamFrame::StreamId { .. },
                    ..
                }
            )
        }),
        (&[0x04, 0x00], |e| {
            matches!(
                e,
                F::ResetStream {
                    source: ResetStreamFrame::ApplicationProtocolErrorCode { .. },
                    ..
                }
            )
        }),
        (&[0x04, 0x00, 0x00], |e| {
            matches!(
                e,
                F::ResetStream {
                    source: ResetStreamFrame::FinalSize { .. },
                    ..
                }
            )
        }),
        (&[0x05, 0x40], |e| {
            matches!(
                e,
                F::StopSending {
                    source: StopSendingFrame::StreamId { .. },
                    ..
                }
            )
        }),
        (&[0x05, 0x00, 0x40], |e| {
            matches!(
                e,
                F::StopSending {
                    source: StopSendingFrame::ApplicationProtocolErrorCode { .. },
                    ..
                }
            )
        }),
        (&[0x06], |e| {
            matches!(
                e,
                F::Crypto {
                    source: CryptoFrame::Offset { .. },
                    ..
                }
            )
        }),
        (&[0x06, 0x00], |e| {
            matches!(
                e,
                F::Crypto {
                    source: CryptoFrame::Length { .. },
                    ..
                }
            )
        }),
        (&[0x07, 0x80, 0x00], |e| {
            matches!(
                e,
                F::NewToken {
                    source: NewTokenFrame::TokenLength { .. },
                    ..
                }
            )
        }),
        (&[0x0e], |e| {
            matches!(
                e,
                F::Stream {
                    source: StreamFrame::StreamId { .. },
                    ..
                }
            )
        }),
        (&[0x0e, 0x04], |e| {
            matches!(
                e,
                F::Stream {
                    source: StreamFrame::Offset { .. },
                    ..
                }
            )
        }),
        (&[0x0e, 0x04, 0x00], |e| {
            matches!(
                e,
                F::Stream {
                    source: StreamFrame::Length { .. },
                    ..
                }
            )
        }),
        // Without OFF, the field after the Stream ID is the Length.
        (&[0x0a, 0x04, 0x40], |e| {
            matches!(
                e,
                F::Stream {
                    source: StreamFrame::Length { .. },
                    ..
                }
            )
        }),
        (&[0x11], |e| {
            matches!(
                e,
                F::MaxStreamData {
                    source: MaxStreamDataFrame::StreamId { .. },
                    ..
                }
            )
        }),
        (&[0x11, 0x00], |e| {
            matches!(
                e,
                F::MaxStreamData {
                    source: MaxStreamDataFrame::MaximumStreamData { .. },
                    ..
                }
            )
        }),
        (&[0x15, 0x80], |e| {
            matches!(
                e,
                F::StreamDataBlocked {
                    source: StreamDataBlockedFrame::StreamId { .. },
                    ..
                }
            )
        }),
        (&[0x15, 0x00, 0xc0], |e| {
            matches!(
                e,
                F::StreamDataBlocked {
                    source: StreamDataBlockedFrame::MaximumStreamData { .. },
                    ..
                }
            )
        }),
        (&[0x1c], |e| {
            matches!(
                e,
                F::ConnectionCloseTransport {
                    source: TransportClose::ErrorCode { .. },
                }
            )
        }),
        (&[0x1c, 0x07], |e| {
            matches!(
                e,
                F::ConnectionCloseTransport {
                    source: TransportClose::FrameType { .. },
                }
            )
        }),
        (&[0x1c, 0x07, 0x00], |e| {
            matches!(
                e,
                F::ConnectionCloseTransport {
                    source: TransportClose::ReasonPhrase {
                        source: Reason::ReasonPhraseLength { .. },
                    },
                }
            )
        }),
        (&[0x1c, 0x07, 0x00, 0x02, b'x'], |e| {
            matches!(
                e,
                F::ConnectionCloseTransport {
                    source: TransportClose::ReasonPhrase {
                        source: Reason::ReasonPhrase { .. },
                    },
                }
            )
        }),
        (&[0x1d], |e| {
            matches!(
                e,
                F::ConnectionCloseApplication {
                    source: ApplicationClose::ErrorCode { .. },
                }
            )
        }),
        // An application CONNECTION_CLOSE has no Frame Type field.
        (&[0x1d, 0x00], |e| {
            matches!(
                e,
                F::ConnectionCloseApplication {
                    source: ApplicationClose::ReasonPhrase {
                        source: Reason::ReasonPhraseLength { .. },
                    },
                }
            )
        }),
        (&[0x1d, 0x00, 0x01], |e| {
            matches!(
                e,
                F::ConnectionCloseApplication {
                    source: ApplicationClose::ReasonPhrase {
                        source: Reason::ReasonPhrase { .. },
                    },
                }
            )
        }),
    ];
    for (encoding, expected) in cases {
        let error = cut_short(encoding);
        let ReadFrameError::Fields {
            source: PartsError(Coproduct::Inl(source)),
        } = &error
        else {
            panic!("{encoding:02x?}: {error:?}")
        };
        assert!(expected(source), "{encoding:02x?}: {error:?}");
        assert_eq!(error.frame_type(), Some(vi(u64::from(encoding[0]))));
    }
    let chain = |error: &dyn std::error::Error| {
        let mut chain = vec![error.to_string()];
        let mut source = error.source();
        while let Some(error) = source {
            chain.push(error.to_string());
            source = error.source();
        }
        chain
    };
    assert_eq!(
        chain(&cut_short(&[0x04, 0x00])),
        [
            "RESET_STREAM frame read failed",
            "RESET_STREAM Application Protocol Error Code read failed",
            "read incomplete after 0 of 1 bytes"
        ]
    );
}

/// The "Pkts" column of RFC 9000 Table 3; one character
/// per level: `I`, `H`, `0`, `1`, and `_` for a level the type may not
/// appear in. CONNECTION_CLOSE is "ih01" in the table, where the lower-case
/// "ih" says that only type `0x1c` can appear in Initial and Handshake
/// packets, so type `0x1d` is "__01".
#[test]
fn packet_types() {
    use FrameType::*;
    let table = [
        (Padding, "IH01"),
        (Ping, "IH01"),
        (Ack, "IH_1"),
        (ResetStream, "__01"),
        (StopSending, "__01"),
        (Crypto, "IH_1"),
        (NewToken, "___1"),
        (Stream, "__01"),
        (MaxData, "__01"),
        (MaxStreamData, "__01"),
        (MaxStreams, "__01"),
        (DataBlocked, "__01"),
        (StreamDataBlocked, "__01"),
        (StreamsBlocked, "__01"),
        (NewConnectionId, "__01"),
        (RetireConnectionId, "__01"),
        (PathChallenge, "__01"),
        (PathResponse, "___1"),
        (ConnectionCloseTransport, "IH01"),
        (ConnectionCloseApplication, "__01"),
        (HandshakeDone, "___1"),
    ];
    for (kind, pkts) in table {
        // The table lists the levels as I, H, 0, 1.
        let levels = [
            EncryptionLevel::Initial,
            EncryptionLevel::Handshake,
            EncryptionLevel::ZeroRtt,
            EncryptionLevel::OneRtt,
        ];
        for (level, mark) in levels.into_iter().zip(pkts.chars()) {
            assert_eq!(
                kind.can_appear_in(level),
                mark != '_',
                "{kind:?} in {level:?}"
            );
        }
    }
    // Every frame type has an entry, and every frame can appear in 1-RTT
    // packets (RFC 9000 §12.4).
    for frame in sample_frames() {
        assert!(frame.frame_type().can_appear_in(EncryptionLevel::OneRtt));
        assert!(table.iter().any(|&(kind, _)| kind == frame.frame_type()));
    }
}

#[test]
fn recovery_properties() {
    use FrameType::*;
    let table = [
        (Padding, false, true),
        (Ping, true, true),
        (Ack, false, false),
        (ResetStream, true, true),
        (StopSending, true, true),
        (Crypto, true, true),
        (NewToken, true, true),
        (Stream, true, true),
        (MaxData, true, true),
        (MaxStreamData, true, true),
        (MaxStreams, true, true),
        (DataBlocked, true, true),
        (StreamDataBlocked, true, true),
        (StreamsBlocked, true, true),
        (NewConnectionId, true, true),
        (RetireConnectionId, true, true),
        (PathChallenge, true, true),
        (PathResponse, true, true),
        (ConnectionCloseTransport, false, false),
        (ConnectionCloseApplication, false, false),
        (HandshakeDone, true, true),
    ];
    for (kind, ack_eliciting, in_flight) in table {
        assert_eq!(kind.is_ack_eliciting(), ack_eliciting, "{kind:?}");
        assert_eq!(kind.counts_in_flight(), in_flight, "{kind:?}");
    }
    for frame in sample_frames() {
        let kind = frame.frame_type();
        assert_eq!(FrameType::of(frame.type_value()), Some(kind));
        assert_eq!(
            <crate::v1::Part as FrameSetPart>::kind_of(frame.type_value()),
            Some(kind)
        );
        assert_eq!(frame.is_ack_eliciting(), kind.is_ack_eliciting());
        assert_eq!(frame.counts_in_flight(), kind.counts_in_flight());
    }
    // Every value from 0x00 to 0x31 is either a known type or unknown.
    let known = (0..=0x31u32)
        .filter(|&value| FrameType::of(VarInt::from(value)).is_some())
        .count();
    assert_eq!(known, 0x1f);
    assert_eq!(FrameType::of(vi(0x1f)), None);
}

#[test]
fn probing_frames_and_receiving_roles() {
    use crate::v1::role::Role;
    use FrameType::*;
    for frame in sample_frames() {
        let kind = frame.frame_type();
        // RFC 9000 §9.1.
        assert_eq!(
            kind.is_probing(),
            matches!(
                kind,
                PathChallenge | PathResponse | NewConnectionId | Padding
            ),
            "{kind:?}"
        );
        // RFC 9000 §19.7 and §19.20: only a client receives NEW_TOKEN and
        // HANDSHAKE_DONE.
        assert!(kind.receivable_by(Role::Client), "{kind:?}");
        assert_eq!(
            kind.receivable_by(Role::Server),
            !matches!(kind, NewToken | HandshakeDone),
            "{kind:?}"
        );
    }
}

/// `FrameType::of` and the part of version 1 reject exactly the values that
/// RFC 9000 does not define, which are those the part does not claim.
#[test]
fn frame_type_value_sets() {
    let values = <crate::v1::Part as FrameSetPart>::FRAME_TYPE_VALUES;
    let defined = |value: u64| matches!(value, 0x00..=0x1e);
    for value in (0..=0x4040).chain([VarInt::MAX.get()]) {
        let frame_type = vi(value);
        assert_eq!(
            FrameType::of(frame_type).is_some(),
            defined(value),
            "{value:#x}"
        );
        assert_eq!(
            <crate::v1::Part as FrameSetPart>::kind_of(frame_type),
            FrameType::of(frame_type)
        );
        assert_eq!(values.contains(frame_type), defined(value), "{value:#x}");
    }
}

/// Every failure after the Frame Type gives the Frame Type value back, and
/// the variants of frame types with two values say which one was read: ACK
/// and CONNECTION_CLOSE by a variant for each value, MAX_STREAMS and
/// STREAMS_BLOCKED by their directionality.
#[test]
fn failures_give_the_frame_type_value() {
    use ReadFieldsError as F;
    use TransportErrorCode as Code;
    // Types with fields: only the type byte is present, so the first field
    // is cut short.
    let values = 0x02..=0x1du64;
    for value in values {
        let encoding = [value as u8];
        let mut input = &encoding[..];
        let error = input.read_one_frame().unwrap_err();
        assert!(error.is_incomplete(), "{value:#x}: {error:?}");
        assert_eq!(error.frame_type(), Some(vi(value)), "{value:#x}");
        assert_eq!(error.transport_error_code(), Code::FRAME_ENCODING_ERROR);
        let ReadFrameError::Fields {
            source: PartsError(Coproduct::Inl(error)),
        } = error
        else {
            panic!("{value:#x}: {error:?}")
        };
        let bidi = Directionality::Bidirectional;
        let uni = Directionality::Unidirectional;
        let attribute = match value {
            0x02 => matches!(error, F::Ack { .. }),
            0x03 => matches!(error, F::AckEcn { .. }),
            0x12 => {
                matches!(error, F::MaxStreams { directionality, .. } if directionality == bidi)
            }
            0x13 => {
                matches!(error, F::MaxStreams { directionality, .. } if directionality == uni)
            }
            0x16 => {
                matches!(error, F::StreamsBlocked { directionality, .. } if directionality == bidi)
            }
            0x17 => {
                matches!(error, F::StreamsBlocked { directionality, .. } if directionality == uni)
            }
            0x1c => matches!(error, F::ConnectionCloseTransport { .. }),
            0x1d => matches!(error, F::ConnectionCloseApplication { .. }),
            _ => true,
        };
        assert!(attribute, "{value:#x}: {error:?}");
    }

    let error = [0x1f].as_slice().read_one_frame().unwrap_err();
    assert_eq!(error.to_string(), "unknown frame type 0x1f");
    assert_eq!(error.transport_error_code(), Code::FRAME_ENCODING_ERROR);
}

#[test]
fn errors_describe_the_frame() {
    let mut input = &[0x06, 0x00, 0x04, 0xaa][..];
    let error = input.read_one_frame().unwrap_err();
    assert_eq!(error.to_string(), "CRYPTO frame read failed");
    let mut chain = vec![error.to_string()];
    let mut source = std::error::Error::source(&error);
    while let Some(error) = source {
        chain.push(error.to_string());
        source = error.source();
    }
    assert_eq!(
        chain,
        [
            "CRYPTO frame read failed",
            "CRYPTO data read failed",
            "read incomplete after 1 of 4 bytes"
        ]
    );
}

pub(in crate::v1) fn length_field(len: usize) -> usize {
    VarInt::try_from(len).unwrap().encoded_len()
}

pub(in crate::v1) fn check_max(
    room: usize,
    max: Option<usize>,
    frame_len: impl Fn(usize) -> usize,
    offset: VarInt,
) {
    let limit = VarInt::MAX.get() - offset.get();
    match max {
        None => assert!(frame_len(0) > room, "room {room}"),
        Some(max) => {
            assert!(frame_len(max) <= room, "room {room}, max {max}");
            assert!(
                max as u64 == limit || frame_len(max + 1) > room,
                "room {room}, max {max}"
            );
        }
    }
}

/// Frames that hold each edge value, in every width that holds it, in each
/// variable-length integer field of each frame type in turn, and every width
/// of each Length and count field.
fn edge_frames() -> Vec<Frame<&'static [u8]>> {
    let zero = short(VarInt::ZERO);
    let largest = short(PacketNumber::MAX);
    let ack = |largest_acknowledged, ack_delay, first_ack_range, ranges: Vec<AckRange>, ecn| {
        let ranges = AckRanges::from(ranges);
        let frame = AckFrame::new(
            largest_acknowledged,
            ack_delay,
            VarIntWidth::One,
            first_ack_range,
            ranges,
            ecn,
        );
        Frame::Ack(frame.unwrap())
    };
    let mut frames = Vec::new();
    for x in edge_fields() {
        let value = x.get();
        let stream_id = as_field(x, StreamId::from_var_int);
        let application = as_field(x, ApplicationErrorCode::new);
        let application_zero = short(ApplicationErrorCode::new(VarInt::ZERO));
        let cid = NonEmptyCid::try_from(&[0x01][..]).unwrap();
        // Data that ends at most at 2^62 - 1 after the offset `value`.
        let data: &'static [u8] = if value.get() <= VarInt::MAX.get() - 5 {
            b"hello"
        } else {
            b""
        };
        frames.extend([
            ack(
                as_field(x, PacketNumber::from_var_int),
                zero,
                zero,
                vec![],
                None,
            ),
            ack(largest, x, zero, vec![], None),
            ack(largest, zero, x, vec![], None),
            ack(
                largest,
                zero,
                zero,
                vec![],
                Some(EcnCounts {
                    ect0: x,
                    ect1: x,
                    ce: x,
                }),
            ),
            Frame::ResetStream(ResetStreamFrame::new(stream_id, application_zero, zero)),
            Frame::ResetStream(ResetStreamFrame::new(short(sid(0)), application, x)),
            Frame::StopSending(StopSendingFrame::new(stream_id, application)),
            Frame::Crypto(CryptoFrame::new(x, VarIntWidth::One, data).unwrap()),
            Frame::Stream(stream_frame(stream_id, None, None, &b"hello"[..], false).unwrap()),
            Frame::Stream(
                stream_frame(short(sid(0)), Some(x), Some(VarIntWidth::One), data, true).unwrap(),
            ),
            Frame::Stream(stream_frame(short(sid(0)), Some(x), None, data, false).unwrap()),
            Frame::MaxData(MaxDataFrame::new(x)),
            Frame::MaxStreamData(MaxStreamDataFrame::new(stream_id, x)),
            Frame::DataBlocked(DataBlockedFrame::new(x)),
            Frame::StreamDataBlocked(StreamDataBlockedFrame::new(stream_id, x)),
            Frame::NewConnectionId(
                NewConnectionIdFrame::new(x, zero, cid, StatelessResetToken::new(TOKEN)).unwrap(),
            ),
            Frame::NewConnectionId(
                NewConnectionIdFrame::new(short(value), x, cid, StatelessResetToken::new(TOKEN))
                    .unwrap(),
            ),
            Frame::RetireConnectionId(RetireConnectionIdFrame::new(x)),
            Frame::ConnectionClose(
                ConnectionCloseFrame::new(
                    CloseErrorCode::Transport {
                        code: as_field(x, TransportErrorCode::from),
                        frame_type: zero,
                    },
                    VarIntWidth::One,
                    &b""[..],
                )
                .unwrap(),
            ),
            Frame::ConnectionClose(
                ConnectionCloseFrame::new(
                    CloseErrorCode::Transport {
                        code: short(TransportErrorCode::FRAME_ENCODING_ERROR),
                        frame_type: x,
                    },
                    VarIntWidth::One,
                    &b"why"[..],
                )
                .unwrap(),
            ),
            Frame::ConnectionClose(
                ConnectionCloseFrame::new(
                    CloseErrorCode::Application { code: application },
                    VarIntWidth::One,
                    &b""[..],
                )
                .unwrap(),
            ),
        ]);
        // A gap or range length that keeps the range at or above zero.
        if value.get() <= VarInt::MAX.get() - 2 {
            frames.extend([
                ack(
                    largest,
                    zero,
                    zero,
                    vec![AckRange {
                        gap: x,
                        ack_range_length: zero,
                    }],
                    None,
                ),
                ack(
                    largest,
                    zero,
                    zero,
                    vec![AckRange {
                        gap: zero,
                        ack_range_length: x,
                    }],
                    None,
                ),
            ]);
        }
        if let Ok(count) = StreamCount::try_from(value) {
            let count = wide(count, x.width());
            for directionality in [
                Directionality::Bidirectional,
                Directionality::Unidirectional,
            ] {
                frames.extend([
                    Frame::MaxStreams(MaxStreamsFrame::new(directionality, count)),
                    Frame::StreamsBlocked(StreamsBlockedFrame::new(directionality, count)),
                ]);
            }
        }
    }
    for width in VarIntWidth::ALL {
        let one_range = vec![AckRange {
            gap: short(VarInt::ZERO),
            ack_range_length: short(VarInt::ZERO),
        }];
        for ranges in [vec![], one_range] {
            let frame = AckFrame::new(
                short(PacketNumber::new(10).unwrap()),
                zero,
                width,
                short(vi(1)),
                AckRanges::from(ranges),
                None,
            );
            frames.push(Frame::Ack(frame.unwrap()));
        }
        frames.extend([
            Frame::Crypto(CryptoFrame::new(zero, width, &b"hello"[..]).unwrap()),
            Frame::NewToken(NewTokenFrame::new(width, &b"token"[..]).unwrap()),
            Frame::Stream(stream_frame(short(sid(4)), None, Some(width), &b""[..], true).unwrap()),
            Frame::ConnectionClose(
                ConnectionCloseFrame::new(
                    CloseErrorCode::Application {
                        code: short(ApplicationErrorCode::new(VarInt::ZERO)),
                    },
                    width,
                    &b"reason"[..],
                )
                .unwrap(),
            ),
        ]);
    }
    frames
}

#[test]
fn frames_round_trip_with_every_width_and_edge_value() {
    let frames = edge_frames();
    // Every frame type with variable-length integer fields is covered.
    for kind in [
        FrameType::Ack,
        FrameType::ResetStream,
        FrameType::StopSending,
        FrameType::Crypto,
        FrameType::NewToken,
        FrameType::Stream,
        FrameType::MaxData,
        FrameType::MaxStreamData,
        FrameType::MaxStreams,
        FrameType::DataBlocked,
        FrameType::StreamDataBlocked,
        FrameType::StreamsBlocked,
        FrameType::NewConnectionId,
        FrameType::RetireConnectionId,
        FrameType::ConnectionCloseTransport,
        FrameType::ConnectionCloseApplication,
    ] {
        assert!(
            frames.iter().any(|frame| frame.frame_type() == kind),
            "{kind:?}"
        );
    }
    for frame in frames {
        assert_round_trip(frame);
    }
}

#[test]
fn longer_field_encodings_read_and_write_back_unchanged() {
    use Frame as F;
    let cases: Vec<(Vec<u8>, Frame<&[u8]>)> = vec![
        (
            vec![0x10, 0x40, 0x05],
            F::MaxData(MaxDataFrame::new(wide(vi(5), VarIntWidth::Two))),
        ),
        (
            // OFF set with a four-byte offset 0, LEN with an eight-byte
            // length.
            vec![
                0x0f, 0x40, 0x04, 0x80, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 2, b'h', b'i',
            ],
            F::Stream(
                stream_frame(
                    wide(sid(4), VarIntWidth::Two),
                    Some(wide(VarInt::ZERO, VarIntWidth::Four)),
                    Some(VarIntWidth::Eight),
                    &b"hi"[..],
                    true,
                )
                .unwrap(),
            ),
        ),
        (
            vec![
                0x06, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0x03, b'a', b'b', b'c',
            ],
            F::Crypto(
                CryptoFrame::new(
                    wide(VarInt::ZERO, VarIntWidth::Eight),
                    VarIntWidth::Two,
                    &b"abc"[..],
                )
                .unwrap(),
            ),
        ),
        (
            vec![0x07, 0x80, 0, 0, 1, b'x'],
            F::NewToken(NewTokenFrame::new(VarIntWidth::Four, &b"x"[..]).unwrap()),
        ),
        (
            // Largest 5, delay 0, one more range; ranges 4..=5 and 2..=2.
            vec![
                0x02, 0x40, 0x05, 0x80, 0, 0, 0, 0x40, 0x01, 0x40, 0x01, 0x40, 0x00, 0x00,
            ],
            F::Ack(
                AckFrame::new(
                    wide(PacketNumber::new(5).unwrap(), VarIntWidth::Two),
                    wide(VarInt::ZERO, VarIntWidth::Four),
                    VarIntWidth::Two,
                    wide(vi(1), VarIntWidth::Two),
                    AckRanges::from(vec![AckRange {
                        gap: wide(VarInt::ZERO, VarIntWidth::Two),
                        ack_range_length: short(VarInt::ZERO),
                    }]),
                    None,
                )
                .unwrap(),
            ),
        ),
        (
            vec![
                0x03, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x80, 0, 0, 3,
            ],
            F::Ack(
                AckFrame::new(
                    short(PacketNumber::ZERO),
                    short(VarInt::ZERO),
                    VarIntWidth::One,
                    short(VarInt::ZERO),
                    AckRanges::default(),
                    Some(EcnCounts {
                        ect0: wide(vi(1), VarIntWidth::Two),
                        ect1: short(VarInt::ZERO),
                        ce: wide(vi(3), VarIntWidth::Four),
                    }),
                )
                .unwrap(),
            ),
        ),
        (
            vec![0x04, 0x40, 0x04, 0x40, 0x00, 0x80, 0, 0, 7],
            F::ResetStream(ResetStreamFrame::new(
                wide(sid(4), VarIntWidth::Two),
                wide(ApplicationErrorCode::new(VarInt::ZERO), VarIntWidth::Two),
                wide(vi(7), VarIntWidth::Four),
            )),
        ),
        (
            vec![0x05, 0x40, 0x03, 0x40, 0x07],
            F::StopSending(StopSendingFrame::new(
                wide(sid(3), VarIntWidth::Two),
                wide(ApplicationErrorCode::new(vi(7)), VarIntWidth::Two),
            )),
        ),
        (
            vec![0x11, 0x40, 0x08, 0x40, 0x3f],
            F::MaxStreamData(MaxStreamDataFrame::new(
                wide(sid(8), VarIntWidth::Two),
                wide(vi(63), VarIntWidth::Two),
            )),
        ),
        (
            vec![0x12, 0xc0, 0, 0, 0, 0, 0, 0, 0x05],
            F::MaxStreams(MaxStreamsFrame::new(
                Directionality::Bidirectional,
                wide(StreamCount::new(5).unwrap(), VarIntWidth::Eight),
            )),
        ),
        (
            vec![0x14, 0x40, 0x00],
            F::DataBlocked(DataBlockedFrame::new(wide(VarInt::ZERO, VarIntWidth::Two))),
        ),
        (
            vec![0x15, 0x40, 0x02, 0x40, 0x3f],
            F::StreamDataBlocked(StreamDataBlockedFrame::new(
                wide(sid(2), VarIntWidth::Two),
                wide(vi(63), VarIntWidth::Two),
            )),
        ),
        (
            vec![0x17, 0x40, 0x01],
            F::StreamsBlocked(StreamsBlockedFrame::new(
                Directionality::Unidirectional,
                wide(StreamCount::new(1).unwrap(), VarIntWidth::Two),
            )),
        ),
        (
            [&[0x18, 0x40, 0x02, 0x40, 0x01, 0x01, 0xaa][..], &TOKEN[..]].concat(),
            F::NewConnectionId(
                NewConnectionIdFrame::new(
                    wide(vi(2), VarIntWidth::Two),
                    wide(vi(1), VarIntWidth::Two),
                    NonEmptyCid::try_from(&[0xaa][..]).unwrap(),
                    StatelessResetToken::new(TOKEN),
                )
                .unwrap(),
            ),
        ),
        (
            vec![0x19, 0x80, 0, 0, 9],
            F::RetireConnectionId(RetireConnectionIdFrame::new(wide(vi(9), VarIntWidth::Four))),
        ),
        (
            vec![0x1c, 0x40, 0x07, 0x40, 0x06, 0x40, 0x00],
            F::ConnectionClose(
                ConnectionCloseFrame::new(
                    CloseErrorCode::Transport {
                        code: wide(TransportErrorCode::FRAME_ENCODING_ERROR, VarIntWidth::Two),
                        frame_type: wide(vi(6), VarIntWidth::Two),
                    },
                    VarIntWidth::Two,
                    &b""[..],
                )
                .unwrap(),
            ),
        ),
        (
            vec![0x1d, 0x80, 0, 0, 0x42, 0x40, 0x02, b'n', b'o'],
            F::ConnectionClose(
                ConnectionCloseFrame::new(
                    CloseErrorCode::Application {
                        code: wide(ApplicationErrorCode::new(vi(0x42)), VarIntWidth::Four),
                    },
                    VarIntWidth::Two,
                    &b"no"[..],
                )
                .unwrap(),
            ),
        ),
    ];
    for (encoding, expected) in &cases {
        let frame = assert_bytes_round_trip(encoding);
        assert_eq!(frame, *expected, "{encoding:02x?}");
        // The shortest encoding of the same values is a different frame.
        assert!(frame.encoded_len() > shortest_len(&frame), "{frame:?}");
    }
}

/// The length of `frame` with every variable-length integer field in its
/// shortest encoding.
fn shortest_len(frame: &Frame<&[u8]>) -> usize {
    match frame {
        Frame::Ack(ack) => {
            let ecn = ack.ecn_counts().map(|counts| EcnCounts {
                ect0: short(counts.ect0.get()),
                ect1: short(counts.ect1.get()),
                ce: short(counts.ce.get()),
            });
            AckFrame::from_packet_ranges(ack.packet_ranges(), short(ack.ack_delay().get()), ecn)
                .unwrap()
                .encoded_len()
        }
        frame => shortest_frame(frame).encoded_len(),
    }
}

/// `frame` with every variable-length integer field in its shortest
/// encoding.
fn shortest_frame<'a>(frame: &Frame<&'a [u8]>) -> Frame<&'a [u8]> {
    fn s<T: Copy + Into<VarInt> + TryFrom<VarInt>>(field: VarIntField<T>) -> VarIntField<T> {
        short(field.get())
    }
    let length = |data: &[u8]| VarIntWidth::shortest(VarInt::try_from(data.len()).unwrap());
    match *frame {
        Frame::Stream(f) => Frame::Stream(
            stream_frame(
                s(f.stream_id()),
                f.offset().map(s),
                length_width(f.length()).map(|_| length(f.data())),
                *f.data(),
                f.fin(),
            )
            .unwrap(),
        ),
        Frame::Crypto(f) => {
            Frame::Crypto(CryptoFrame::new(s(f.offset()), length(f.data()), *f.data()).unwrap())
        }
        Frame::NewToken(f) => {
            Frame::NewToken(NewTokenFrame::new(length(f.token()), *f.token()).unwrap())
        }
        Frame::ResetStream(f) => Frame::ResetStream(ResetStreamFrame::new(
            s(f.stream_id()),
            s(f.application_error_code()),
            s(f.final_size()),
        )),
        Frame::StopSending(f) => Frame::StopSending(StopSendingFrame::new(
            s(f.stream_id()),
            s(f.application_error_code()),
        )),
        Frame::MaxData(f) => Frame::MaxData(MaxDataFrame::new(s(f.maximum_data()))),
        Frame::MaxStreamData(f) => Frame::MaxStreamData(MaxStreamDataFrame::new(
            s(f.stream_id()),
            s(f.maximum_stream_data()),
        )),
        Frame::MaxStreams(f) => Frame::MaxStreams(MaxStreamsFrame::new(
            f.directionality(),
            s(f.maximum_streams()),
        )),
        Frame::DataBlocked(f) => Frame::DataBlocked(DataBlockedFrame::new(s(f.maximum_data()))),
        Frame::StreamDataBlocked(f) => Frame::StreamDataBlocked(StreamDataBlockedFrame::new(
            s(f.stream_id()),
            s(f.maximum_stream_data()),
        )),
        Frame::StreamsBlocked(f) => Frame::StreamsBlocked(StreamsBlockedFrame::new(
            f.directionality(),
            s(f.maximum_streams()),
        )),
        Frame::NewConnectionId(f) => Frame::NewConnectionId(
            NewConnectionIdFrame::new(
                s(f.sequence_number()),
                s(f.retire_prior_to()),
                f.connection_id(),
                f.stateless_reset_token(),
            )
            .unwrap(),
        ),
        Frame::RetireConnectionId(f) => {
            Frame::RetireConnectionId(RetireConnectionIdFrame::new(s(f.sequence_number())))
        }
        Frame::ConnectionClose(f) => {
            let error_code = match f.error_code() {
                CloseErrorCode::Transport { code, frame_type } => CloseErrorCode::Transport {
                    code: s(code),
                    frame_type: s(frame_type),
                },
                CloseErrorCode::Application { code } => {
                    CloseErrorCode::Application { code: s(code) }
                }
            };
            let reason_phrase = *f.reason_phrase();
            Frame::ConnectionClose(
                ConnectionCloseFrame::new(error_code, length(reason_phrase), reason_phrase)
                    .unwrap(),
            )
        }
        ref other => other.clone(),
    }
}

#[test]
fn length_fields_must_hold_the_payload_length() {
    let payload = vec![0x5a; 16_384];
    let application = CloseErrorCode::Application {
        code: short(ApplicationErrorCode::new(VarInt::ZERO)),
    };
    for length in [0, 1, 63, 64, 16_383, 16_384] {
        let data = &payload[..length];
        for width in VarIntWidth::ALL {
            let fits = VarInt::try_from(length).is_ok_and(|value| width.fits(value));
            let crypto = CryptoFrame::new(short(VarInt::ZERO), width, data);
            let stream = stream_frame(short(sid(0)), None, Some(width), data, false);
            let close = ConnectionCloseFrame::new(application, width, data);
            // A token is never empty.
            let token = (length > 0).then(|| NewTokenFrame::new(width, data));
            if fits {
                let frames = [
                    Frame::Crypto(crypto.unwrap()),
                    Frame::Stream(stream.unwrap()),
                    Frame::ConnectionClose(close.unwrap()),
                ];
                for frame in frames
                    .into_iter()
                    .chain(token.map(|token| Frame::NewToken(token.unwrap())))
                {
                    assert_round_trip(frame);
                }
                continue;
            }
            // Construction rejects a Length field too narrow for the length.
            let error = LengthError::check(length, width).unwrap_err();
            assert_eq!(crypto, Err(InvalidDataError::Length { source: error }));
            assert_eq!(stream, Err(InvalidDataError::Length { source: error }));
            assert_eq!(close, Err(error));
            if let Some(token) = token {
                assert_eq!(token, Err(InvalidNewTokenError::Length { source: error }));
            }
        }
    }
    // The limits of each width, beyond the lengths a test can allocate.
    for (length, widest_rejected) in [
        (63u64, None),
        (64, Some(VarIntWidth::One)),
        (16_383, Some(VarIntWidth::One)),
        (16_384, Some(VarIntWidth::Two)),
        ((1 << 30) - 1, Some(VarIntWidth::Two)),
        (1 << 30, Some(VarIntWidth::Four)),
        ((1 << 62) - 1, Some(VarIntWidth::Four)),
        (1 << 62, Some(VarIntWidth::Eight)),
    ] {
        let Ok(length) = usize::try_from(length) else {
            continue;
        };
        for width in VarIntWidth::ALL {
            let result = LengthError::check(length, width);
            if widest_rejected.is_some_and(|widest| width <= widest) {
                let error = result.unwrap_err();
                assert_eq!((error.length(), error.width()), (length, width), "{length}");
            } else {
                assert_eq!(result, Ok(vi(length as u64)), "{length}");
            }
        }
    }
}

#[test]
fn stream_offset_fields_may_hold_zero() {
    // OFF set with offset 0, no LEN: distinct from the frame without OFF.
    let with_off = assert_bytes_round_trip(&[0x0c, 0x04, 0x00, b'a', b'b']);
    let without_off = assert_bytes_round_trip(&[0x08, 0x04, b'a', b'b']);
    let Frame::Stream(stream) = with_off else {
        panic!("{with_off:?}")
    };
    assert_eq!(stream.offset(), Some(short(VarInt::ZERO)));
    assert_eq!(stream.data_offset(), VarInt::ZERO);
    let Frame::Stream(plain) = without_off else {
        panic!("{without_off:?}")
    };
    assert_eq!(plain.offset(), None);
    assert_eq!(plain.data_offset(), VarInt::ZERO);
    assert_ne!(stream, plain);
    let with_offset = |offset| {
        stream_frame(
            stream.stream_id(),
            offset,
            length_width(stream.length()),
            *stream.data(),
            stream.fin(),
        )
        .unwrap()
    };
    assert_eq!(with_offset(None), plain);
    for width in VarIntWidth::ALL {
        let frame = with_offset(Some(wide(VarInt::ZERO, width)));
        assert_eq!(frame.type_value(), vi(0x0c));
        let encoding = assert_round_trip(Frame::Stream(frame));
        assert_eq!(encoding.len(), 2 + width.encoded_len() + 2);
    }
    // In a payload, each frame keeps its form.
    let payload = [0x0e, 0x04, 0x00, 0x01, b'a', 0x0a, 0x04, 0x01, b'b'];
    let frames: Vec<_> = Frames::new(&payload[..], V1)
        .map(|frame| frame.unwrap().extract())
        .collect();
    let one = Some(VarIntWidth::One);
    assert_eq!(
        frames,
        [
            FrameRun::Stream(
                stream_frame(
                    short(sid(4)),
                    Some(short(VarInt::ZERO)),
                    one,
                    &b"a"[..],
                    false
                )
                .unwrap()
            ),
            FrameRun::Stream(stream_frame(short(sid(4)), None, one, &b"b"[..], false).unwrap()),
        ]
    );
}
