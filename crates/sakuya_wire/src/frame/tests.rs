//! Tests that cover every frame type, and the helpers the tests of the frame
//! modules share.
use super::{
    Extensions, Frame, FrameType, Frames, InvalidDataError, LengthError, NoLength,
    UnknownFrameTypeError,
    ack::{Ack, AckRange, AckRanges, EcnCounts},
    codec::{ExtensionTypeValue, ReadFrameError, ReadFrameHostExt as _, WriteFrameHostExt as _},
    connection_close::{CloseErrorCode, ConnectionClose},
    crypto::Crypto,
    data_blocked::DataBlocked,
    datagram::Datagram,
    handshake_done::HandshakeDone,
    length_width,
    max_data::MaxData,
    max_stream_data::MaxStreamData,
    max_streams::MaxStreams,
    new_connection_id::NewConnectionId,
    new_token::{InvalidNewTokenError, NewToken},
    padding::Padding,
    path_challenge::PathChallenge,
    path_response::PathResponse,
    ping::Ping,
    reset_stream::ResetStream,
    reset_stream_at::ResetStreamAt,
    retire_connection_id::RetireConnectionId,
    stop_sending::StopSending,
    stream::Stream,
    stream_data_blocked::StreamDataBlocked,
    streams_blocked::StreamsBlocked,
};
use crate::{
    application_error::ApplicationErrorCode,
    connection_id::{NonEmptyCid, StatelessResetToken},
    packet_number::PacketNumber,
    stream_count::StreamCount,
    stream_id::{Directionality, StreamId},
    transport_error::TransportErrorCode,
    var_int::{
        VarInt, VarIntField, VarIntWidth,
        codec::{ReadVarIntHostExt as _, WriteVarIntFieldHostExt as _},
    },
};
use bytes::{Buf, Bytes};
use core::num::NonZeroUsize;
use either::Either;

/// The STREAM frame as `Stream::<_>::new` constructs it, with a Length field
/// of width `length` if there is one.
pub(crate) fn stream_frame<D: Buf>(
    stream_id: VarIntField<StreamId>,
    offset: Option<VarIntField<VarInt>>,
    length: Option<VarIntWidth>,
    data: D,
    fin: bool,
) -> Result<Stream<D>, InvalidDataError> {
    Stream::<_>::new(stream_id, offset, either_length(length), data, fin)
}

/// The DATAGRAM frame as `Datagram::<_>::new` constructs it, with a Length
/// field of width `length` if there is one.
pub(crate) fn datagram_frame<D: Buf>(
    length: Option<VarIntWidth>,
    data: D,
) -> Result<Datagram<D>, LengthError> {
    Datagram::<_>::new(either_length(length), data)
}

/// A Length field of width `length`, or none, as a frame that was read
/// states it.
pub(crate) fn either_length(length: Option<VarIntWidth>) -> Either<NoLength, VarIntWidth> {
    length.map_or(Either::Left(NoLength), Either::Right)
}

pub(crate) fn vi(value: u64) -> VarInt {
    VarInt::try_from(value).unwrap()
}

pub(crate) fn sid(value: u64) -> StreamId {
    StreamId::from_var_int(vi(value))
}

/// The field holding `value` in its shortest encoding.
pub(crate) fn short<T: Copy + Into<VarInt> + TryFrom<VarInt>>(value: T) -> VarIntField<T> {
    VarIntField::shortest(value)
}

/// The field holding `value` in an encoding of `width`.
pub(crate) fn wide<T: Copy + Into<VarInt> + TryFrom<VarInt>>(
    value: T,
    width: VarIntWidth,
) -> VarIntField<T> {
    VarIntField::new(value, width).unwrap()
}

/// Values at the edges of each width, and the largest stream count.
pub(crate) const EDGES: [u64; 9] = [
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
pub(crate) fn edge_fields() -> Vec<VarIntField<VarInt>> {
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
pub(crate) fn as_field<T: Copy + Into<VarInt> + TryFrom<VarInt>>(
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
pub(crate) fn assert_round_trip(frame: Frame<&[u8]>) -> Vec<u8> {
    let mut encoding = Vec::new();
    encoding.sync_write_frame_unpin(frame.clone()).unwrap();
    assert_eq!(encoding.len(), frame.encoded_len(), "{frame:?}");
    assert_eq!(
        encoding.as_slice().sync_read_var_int_unpin().unwrap(),
        frame.type_value(),
        "{frame:?}"
    );

    let mut input = encoding.as_slice();
    assert_eq!(
        input.sync_read_frame_unpin(Extensions::ALL).unwrap(),
        frame,
        "{encoding:02x?}"
    );
    assert!(input.is_empty(), "{frame:?}");

    // A `Bytes` source reads the same frame, which writes the same bytes.
    let mut input = Bytes::from(encoding.clone());
    let from_bytes = input.sync_read_frame_unpin(Extensions::ALL).unwrap();
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
pub(crate) fn assert_bytes_round_trip(encoding: &[u8]) -> Frame<&[u8]> {
    let mut input = encoding;
    let frame = input.sync_read_frame_unpin(Extensions::ALL).unwrap();
    assert!(input.is_empty(), "{encoding:02x?}: {frame:?}");
    assert_eq!(assert_round_trip(frame.clone()), encoding, "{frame:?}");
    frame
}

pub(crate) const TOKEN: [u8; 16] = *b"0123456789abcdef";

/// An ACK frame read from `encoding`.
pub(crate) fn read_ack(encoding: &[u8]) -> Frame<&[u8]> {
    let mut input = encoding;
    let frame = input.sync_read_frame_unpin(Extensions::NONE).unwrap();
    assert!(matches!(frame, Frame::Ack(_)), "{frame:?}");
    assert!(input.is_empty());
    frame
}

/// One frame of every type and form, in the shortest encodings.
fn sample_frames() -> Vec<Frame<&'static [u8]>> {
    let mut frames = vec![
        Frame::Padding(Padding::new(NonZeroUsize::new(3).unwrap())),
        Frame::Ping(Ping),
        // Largest 100, delay 5, ranges 97..=100, 90..=94 and 88..=88; ECN
        // counts 1, 2, 3.
        read_ack(&[
            0x03, 0x40, 100, 0x05, 0x02, 0x03, 0x01, 0x04, 0x00, 0x00, 0x01, 0x02, 0x03,
        ]),
        read_ack(&[0x02, 0x00, 0x00, 0x00, 0x00]),
        Frame::ResetStream(ResetStream::new(
            short(sid(4)),
            short(ApplicationErrorCode::new(vi(0x100))),
            short(vi(70_000)),
        )),
        Frame::StopSending(StopSending::new(
            short(sid(3)),
            short(ApplicationErrorCode::new(vi(7))),
        )),
        Frame::Crypto(
            Crypto::new(short(vi(1000)), VarIntWidth::One, &b"client hello"[..]).unwrap(),
        ),
        Frame::Crypto(Crypto::new(short(VarInt::ZERO), VarIntWidth::One, &b""[..]).unwrap()),
        Frame::NewToken(NewToken::new(VarIntWidth::One, &b"token"[..]).unwrap()),
        Frame::MaxData(MaxData::new(short(vi(1 << 40)))),
        Frame::MaxStreamData(MaxStreamData::new(short(sid(8)), short(vi(65_536)))),
        Frame::MaxStreams(MaxStreams::new(
            Directionality::Bidirectional,
            short(StreamCount::MAX),
        )),
        Frame::MaxStreams(MaxStreams::new(
            Directionality::Unidirectional,
            short(StreamCount::new(3).unwrap()),
        )),
        Frame::DataBlocked(DataBlocked::new(short(vi(16_384)))),
        Frame::StreamDataBlocked(StreamDataBlocked::new(short(sid(2)), short(vi(63)))),
        Frame::StreamsBlocked(StreamsBlocked::new(
            Directionality::Bidirectional,
            short(StreamCount::new(100).unwrap()),
        )),
        Frame::StreamsBlocked(StreamsBlocked::new(
            Directionality::Unidirectional,
            short(StreamCount::ZERO),
        )),
        Frame::NewConnectionId(
            NewConnectionId::new(
                short(vi(2)),
                short(vi(1)),
                NonEmptyCid::try_from(&[0xaa; 20][..]).unwrap(),
                StatelessResetToken::new(TOKEN),
            )
            .unwrap(),
        ),
        Frame::NewConnectionId(
            NewConnectionId::new(
                short(vi(1)),
                short(vi(1)),
                NonEmptyCid::try_from(&[0x01][..]).unwrap(),
                StatelessResetToken::new(TOKEN),
            )
            .unwrap(),
        ),
        Frame::RetireConnectionId(RetireConnectionId::new(short(vi(9)))),
        Frame::PathChallenge(PathChallenge::new(*b"challeng")),
        Frame::PathResponse(PathResponse::new(*b"response")),
        Frame::ConnectionClose(
            ConnectionClose::new(
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
            ConnectionClose::new(
                CloseErrorCode::Application {
                    code: short(ApplicationErrorCode::new(vi(0x42))),
                },
                VarIntWidth::One,
                &b""[..],
            )
            .unwrap(),
        ),
        Frame::HandshakeDone(HandshakeDone),
        Frame::ResetStreamAt(
            ResetStreamAt::new(
                short(sid(0)),
                short(ApplicationErrorCode::new(vi(1))),
                short(vi(800)),
                short(vi(300)),
            )
            .unwrap(),
        ),
        Frame::Datagram(datagram_frame(Some(VarIntWidth::One), &b"datagram"[..]).unwrap()),
        Frame::Datagram(datagram_frame(None, &b"to the end"[..]).unwrap()),
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
        match frame {
            // PADDING reads one byte at a time; a run is read by `Frames`.
            Frame::Padding(padding) => {
                let mut written = Vec::new();
                written.sync_write_frame_unpin(frame.clone()).unwrap();
                assert_eq!(written, vec![0; padding.len().get()]);
                let mut frames = Frames::new(written.as_slice(), Extensions::NONE);
                assert_eq!(frames.next().map(Result::unwrap), Some(frame));
                assert!(frames.next().is_none());
            }
            frame => {
                assert_round_trip(frame);
            }
        }
    }
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
    let frames: Vec<_> = Frames::new(&payload[..], Extensions::NONE)
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        frames,
        [
            Frame::Ping(Ping),
            Frame::Stream(
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
    let mut frames = Frames::new(payload.clone(), Extensions::NONE);
    let Some(Ok(Frame::Stream(stream))) = frames.next() else {
        panic!()
    };
    assert_eq!(*stream.data(), &b"hi"[..]);
    assert_eq!(stream.data().as_ptr(), payload[3..].as_ptr());
    assert_eq!(frames.next().map(Result::unwrap), Some(Frame::Ping(Ping)));
    assert!(frames.next().is_none());
}

#[test]
fn padding_runs_are_one_value() {
    let payload = [0x00, 0x00, 0x00, 0x01, 0x00];
    let mut frames = Frames::new(&payload[..], Extensions::NONE);
    assert_eq!(
        frames.next().map(Result::unwrap),
        Some(Frame::Padding(Padding::new(NonZeroUsize::new(3).unwrap())))
    );
    assert_eq!(frames.offset(), 3);
    assert_eq!(frames.next().map(Result::unwrap), Some(Frame::Ping(Ping)));
    assert_eq!(*frames.remainder(), [0x00]);
    assert_eq!(
        frames.next().map(Result::unwrap),
        Some(Frame::Padding(Padding::new(NonZeroUsize::MIN)))
    );
    assert!(frames.next().is_none());

    // A longer encoding of type 0 is not PADDING; it ends the run and is
    // rejected.
    let payload = [0x00, 0x40, 0x00, 0x01];
    let mut frames = Frames::new(&payload[..], Extensions::NONE);
    assert_eq!(
        frames.next().map(Result::unwrap),
        Some(Frame::Padding(Padding::new(NonZeroUsize::MIN)))
    );
    let error = frames.next().unwrap().unwrap_err();
    assert!(matches!(
        error,
        ReadFrameError::LongerTypeEncoding {
            frame_type: VarInt::ZERO,
            width: VarIntWidth::Two
        }
    ));
    assert_eq!(frames.offset(), 1);
    assert!(frames.next().is_none());
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
            for extensions in [Extensions::NONE, Extensions::ALL] {
                let mut input = encoding.as_slice();
                let error = input.sync_read_frame_unpin(extensions).unwrap_err();
                assert!(
                    matches!(
                        error,
                        ReadFrameError::LongerTypeEncoding { frame_type, width: rejected }
                            if frame_type == VarInt::from(value) && rejected == width
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
    let error = [0x40, 0x08]
        .as_slice()
        .sync_read_frame_unpin(Extensions::NONE)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "frame type 0x8 uses a 2-byte encoding, longer than necessary"
    );
    // A type whose shortest encoding takes two bytes is read; 0x4040 is
    // unknown.
    let error = [0x40, 0x40]
        .as_slice()
        .sync_read_frame_unpin(Extensions::ALL)
        .unwrap_err();
    assert!(matches!(error, ReadFrameError::UnknownType { .. }));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::FRAME_ENCODING_ERROR
    );
}

#[test]
fn unknown_and_disabled_types_are_rejected() {
    let cases: [(&[u8], Extensions); 7] = [
        (&[0x1f], Extensions::ALL),
        (&[0x21, 0x00], Extensions::ALL),
        (&[0x40, 0x40], Extensions::ALL),
        (&[0x7f, 0xff], Extensions::ALL),
        (&[0x30, 0x01], Extensions::NONE),
        (
            &[0x31, 0x00],
            Extensions {
                datagram: false,
                reset_stream_at: true,
            },
        ),
        (
            &[0x24, 0x00, 0x00, 0x00, 0x00],
            Extensions {
                datagram: true,
                reset_stream_at: false,
            },
        ),
    ];
    for (encoding, extensions) in cases {
        let mut input = encoding;
        let frame_type = input.sync_read_var_int_unpin().unwrap();
        let mut input = encoding;
        let error = input.sync_read_frame_unpin(extensions).unwrap_err();
        let extension = matches!(frame_type.get(), 0x24 | 0x30 | 0x31);
        if extension {
            assert!(
                matches!(
                    error,
                    ReadFrameError::ExtensionNotEnabled { frame_type: rejected }
                        if rejected.get() == frame_type
                ),
                "{encoding:02x?}: {error:?}"
            );
        } else {
            assert!(
                matches!(
                    error,
                    ReadFrameError::UnknownType {
                        source: UnknownFrameTypeError { frame_type: rejected }
                    } if rejected.get() == frame_type
                ),
                "{encoding:02x?}: {error:?}"
            );
        }
        let expected = if matches!(frame_type.get(), 0x30 | 0x31) {
            TransportErrorCode::PROTOCOL_VIOLATION
        } else {
            TransportErrorCode::FRAME_ENCODING_ERROR
        };
        assert_eq!(error.transport_error_code(), expected);
        assert_eq!(error.frame_type(), Some(frame_type));
        assert!(!error.is_incomplete());
    }
    let mut input = &[0x24, 0x00, 0x00, 0x00, 0x00][..];
    assert!(input.sync_read_frame_unpin(Extensions::ALL).is_ok());
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
        let error = input.sync_read_frame_unpin(Extensions::NONE).unwrap_err();
        assert!(error.is_incomplete(), "{encoding:02x?}: {error:?}");
        assert_eq!(error.frame_type(), frame_type.map(vi), "{encoding:02x?}");
    }

    // In a payload, the offset names the frame that is cut short, and the
    // iteration ends with the error.
    let payload = [0x01, 0x01, 0x11, 0x04];
    let mut frames = Frames::new(&payload[..], Extensions::NONE);
    assert_eq!(frames.next().map(Result::unwrap), Some(Frame::Ping(Ping)));
    assert_eq!(frames.next().map(Result::unwrap), Some(Frame::Ping(Ping)));
    let error = frames.next().unwrap().unwrap_err();
    assert_eq!(frames.offset(), 2);
    assert!(matches!(error, ReadFrameError::MaxStreamData { .. }));
    assert!(error.is_incomplete());
    assert!(frames.next().is_none());
}

/// The failure of reading `encoding`, which ends within a field.
fn cut_short(encoding: &[u8]) -> ReadFrameError<core::convert::Infallible> {
    let mut input = encoding;
    let error = input.sync_read_frame_unpin(Extensions::ALL).unwrap_err();
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
            ReadConnectionCloseApplicationError as ApplicationClose,
            ReadConnectionCloseTransportError as TransportClose, ReadReasonPhraseError as Reason,
        },
        crypto::codec::ReadCryptoError as Crypto,
        datagram::codec::ReadDatagramError as Datagram,
        max_stream_data::codec::ReadMaxStreamDataError as MaxStreamData,
        new_token::codec::ReadNewTokenError as NewToken,
        reset_stream::codec::ReadResetStreamError as ResetStream,
        stop_sending::codec::ReadStopSendingError as StopSending,
        stream::codec::ReadStreamError as Stream,
        stream_data_blocked::codec::ReadStreamDataBlockedError as StreamDataBlocked,
    };
    use ReadFrameError as F;
    type Check = fn(&ReadFrameError<core::convert::Infallible>) -> bool;
    let cases: [(&[u8], Check); 24] = [
        (&[0x04], |e| {
            matches!(
                e,
                F::ResetStream {
                    source: ResetStream::StreamId { .. },
                    ..
                }
            )
        }),
        (&[0x04, 0x00], |e| {
            matches!(
                e,
                F::ResetStream {
                    source: ResetStream::ApplicationProtocolErrorCode { .. },
                    ..
                }
            )
        }),
        (&[0x04, 0x00, 0x00], |e| {
            matches!(
                e,
                F::ResetStream {
                    source: ResetStream::FinalSize { .. },
                    ..
                }
            )
        }),
        (&[0x05, 0x40], |e| {
            matches!(
                e,
                F::StopSending {
                    source: StopSending::StreamId { .. },
                    ..
                }
            )
        }),
        (&[0x05, 0x00, 0x40], |e| {
            matches!(
                e,
                F::StopSending {
                    source: StopSending::ApplicationProtocolErrorCode { .. },
                    ..
                }
            )
        }),
        (&[0x06], |e| {
            matches!(
                e,
                F::Crypto {
                    source: Crypto::Offset { .. },
                    ..
                }
            )
        }),
        (&[0x06, 0x00], |e| {
            matches!(
                e,
                F::Crypto {
                    source: Crypto::Length { .. },
                    ..
                }
            )
        }),
        (&[0x07, 0x80, 0x00], |e| {
            matches!(
                e,
                F::NewToken {
                    source: NewToken::TokenLength { .. },
                    ..
                }
            )
        }),
        (&[0x0e], |e| {
            matches!(
                e,
                F::Stream {
                    source: Stream::StreamId { .. },
                    ..
                }
            )
        }),
        (&[0x0e, 0x04], |e| {
            matches!(
                e,
                F::Stream {
                    source: Stream::Offset { .. },
                    ..
                }
            )
        }),
        (&[0x0e, 0x04, 0x00], |e| {
            matches!(
                e,
                F::Stream {
                    source: Stream::Length { .. },
                    ..
                }
            )
        }),
        // Without OFF, the field after the Stream ID is the Length.
        (&[0x0a, 0x04, 0x40], |e| {
            matches!(
                e,
                F::Stream {
                    source: Stream::Length { .. },
                    ..
                }
            )
        }),
        (&[0x11], |e| {
            matches!(
                e,
                F::MaxStreamData {
                    source: MaxStreamData::StreamId { .. },
                    ..
                }
            )
        }),
        (&[0x11, 0x00], |e| {
            matches!(
                e,
                F::MaxStreamData {
                    source: MaxStreamData::MaximumStreamData { .. },
                    ..
                }
            )
        }),
        (&[0x15, 0x80], |e| {
            matches!(
                e,
                F::StreamDataBlocked {
                    source: StreamDataBlocked::StreamId { .. },
                    ..
                }
            )
        }),
        (&[0x15, 0x00, 0xc0], |e| {
            matches!(
                e,
                F::StreamDataBlocked {
                    source: StreamDataBlocked::MaximumStreamData { .. },
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
        (&[0x31, 0x40], |e| {
            matches!(
                e,
                F::Datagram {
                    source: Datagram::Length { .. },
                    ..
                }
            )
        }),
    ];
    for (encoding, expected) in cases {
        let error = cut_short(encoding);
        assert!(expected(&error), "{encoding:02x?}: {error:?}");
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
        (ConnectionClose, false, false),
        (HandshakeDone, true, true),
        (ResetStreamAt, true, true),
        (Datagram, true, true),
    ];
    for (kind, ack_eliciting, in_flight) in table {
        assert_eq!(kind.is_ack_eliciting(), ack_eliciting, "{kind:?}");
        assert_eq!(kind.counts_in_flight(), in_flight, "{kind:?}");
    }
    for frame in sample_frames() {
        let kind = frame.frame_type();
        assert_eq!(FrameType::of(frame.type_value()), Ok(kind));
        assert_eq!(FrameType::try_from(frame.type_value()), Ok(kind));
        assert_eq!(frame.is_ack_eliciting(), kind.is_ack_eliciting());
        assert_eq!(frame.counts_in_flight(), kind.counts_in_flight());
    }
    // Every value from 0x00 to 0x31 is either a known type or unknown.
    let known = (0..=0x31u32)
        .filter(|&value| FrameType::of(VarInt::from(value)).is_ok())
        .count();
    assert_eq!(known, 0x1f + 1 + 2);
    assert_eq!(
        FrameType::of(vi(0x1f)).map_err(|error| error.frame_type.get()),
        Err(vi(0x1f))
    );
}

/// `FrameType::of` rejects exactly the values that no frame type defines,
/// and `ExtensionTypeValue` holds exactly the values of extension frames.
#[test]
fn frame_type_value_sets() {
    let defined = |value: u64| matches!(value, 0x00..=0x1e | 0x24 | 0x30 | 0x31);
    for value in (0..=0x4040).chain([VarInt::MAX.get()]) {
        let frame_type = vi(value);
        match FrameType::of(frame_type) {
            Ok(_) => assert!(defined(value), "{value:#x}"),
            Err(error) => {
                assert!(!defined(value), "{value:#x}");
                assert_eq!(error.frame_type.get(), frame_type);
                assert_eq!(VarInt::from(error.frame_type), frame_type);
            }
        }
        let extension = ExtensionTypeValue::new(frame_type).map(ExtensionTypeValue::get);
        let expected = matches!(value, 0x24 | 0x30 | 0x31).then_some(frame_type);
        assert_eq!(extension, expected, "{value:#x}");
    }
}

/// Every failure after the Frame Type gives the Frame Type value back, and
/// the variants of frame types with two values say which one was read: ACK
/// and CONNECTION_CLOSE by a variant for each value, MAX_STREAMS and
/// STREAMS_BLOCKED by their directionality.
#[test]
fn failures_give_the_frame_type_value() {
    use ReadFrameError as F;
    use TransportErrorCode as Code;
    // Types with fields: only the type byte is present, so the first field
    // is cut short. DATAGRAM 0x30 takes the rest, so it gets one byte.
    let values = (0x02..=0x1du64).chain([0x24, 0x31]);
    for value in values {
        let encoding = [value as u8];
        let mut input = &encoding[..];
        let error = input.sync_read_frame_unpin(Extensions::ALL).unwrap_err();
        assert!(error.is_incomplete(), "{value:#x}: {error:?}");
        assert_eq!(error.frame_type(), Some(vi(value)), "{value:#x}");
        assert_eq!(error.transport_error_code(), Code::FRAME_ENCODING_ERROR);
        let bidi = Directionality::Bidirectional;
        let uni = Directionality::Unidirectional;
        let attribute = match value {
            0x02 => matches!(error, F::Ack { .. }),
            0x03 => matches!(error, F::AckEcn { .. }),
            0x12 => matches!(error, F::MaxStreams { directionality, .. } if directionality == bidi),
            0x13 => matches!(error, F::MaxStreams { directionality, .. } if directionality == uni),
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

    // Extension frame types that are not enabled keep their value and code.
    let cases = [
        (0x24u64, Code::FRAME_ENCODING_ERROR),
        (0x30, Code::PROTOCOL_VIOLATION),
        (0x31, Code::PROTOCOL_VIOLATION),
    ];
    for (value, code) in cases {
        let encoding = [value as u8, 0x00];
        let mut input = &encoding[..];
        let error = input.sync_read_frame_unpin(Extensions::NONE).unwrap_err();
        assert!(
            matches!(error, F::ExtensionNotEnabled { frame_type } if frame_type.get() == vi(value)),
            "{value:#x}: {error:?}"
        );
        assert_eq!(error.frame_type(), Some(vi(value)));
        assert_eq!(error.transport_error_code(), code, "{value:#x}");
        assert!(!error.is_incomplete());
        assert_eq!(input, [0x00]);
    }
    let error = [0x30]
        .as_slice()
        .sync_read_frame_unpin(Extensions::NONE)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "frame type 0x30 belongs to an extension that is not enabled"
    );
    let error = [0x1f]
        .as_slice()
        .sync_read_frame_unpin(Extensions::ALL)
        .unwrap_err();
    assert_eq!(error.to_string(), "unknown frame type 0x1f");
    assert_eq!(error.transport_error_code(), Code::FRAME_ENCODING_ERROR);
}

#[test]
fn errors_describe_the_frame() {
    let mut input = &[0x06, 0x00, 0x04, 0xaa][..];
    let error = input.sync_read_frame_unpin(Extensions::NONE).unwrap_err();
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

pub(crate) fn length_field(len: usize) -> usize {
    VarInt::try_from(len).unwrap().encoded_len()
}

pub(crate) fn check_max(
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
        let frame = Ack::new(
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
            Frame::ResetStream(ResetStream::new(stream_id, application_zero, zero)),
            Frame::ResetStream(ResetStream::new(short(sid(0)), application, x)),
            Frame::StopSending(StopSending::new(stream_id, application)),
            Frame::Crypto(Crypto::new(x, VarIntWidth::One, data).unwrap()),
            Frame::Stream(stream_frame(stream_id, None, None, &b"hello"[..], false).unwrap()),
            Frame::Stream(
                stream_frame(short(sid(0)), Some(x), Some(VarIntWidth::One), data, true).unwrap(),
            ),
            Frame::Stream(stream_frame(short(sid(0)), Some(x), None, data, false).unwrap()),
            Frame::MaxData(MaxData::new(x)),
            Frame::MaxStreamData(MaxStreamData::new(stream_id, x)),
            Frame::DataBlocked(DataBlocked::new(x)),
            Frame::StreamDataBlocked(StreamDataBlocked::new(stream_id, x)),
            Frame::NewConnectionId(
                NewConnectionId::new(x, zero, cid, StatelessResetToken::new(TOKEN)).unwrap(),
            ),
            Frame::NewConnectionId(
                NewConnectionId::new(short(value), x, cid, StatelessResetToken::new(TOKEN))
                    .unwrap(),
            ),
            Frame::RetireConnectionId(RetireConnectionId::new(x)),
            Frame::ConnectionClose(
                ConnectionClose::new(
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
                ConnectionClose::new(
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
                ConnectionClose::new(
                    CloseErrorCode::Application { code: application },
                    VarIntWidth::One,
                    &b""[..],
                )
                .unwrap(),
            ),
            Frame::ResetStreamAt(ResetStreamAt::new(stream_id, application, x, zero).unwrap()),
            Frame::ResetStreamAt(
                ResetStreamAt::new(short(sid(0)), application_zero, short(value), x).unwrap(),
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
                    Frame::MaxStreams(MaxStreams::new(directionality, count)),
                    Frame::StreamsBlocked(StreamsBlocked::new(directionality, count)),
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
            let frame = Ack::new(
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
            Frame::Crypto(Crypto::new(zero, width, &b"hello"[..]).unwrap()),
            Frame::NewToken(NewToken::new(width, &b"token"[..]).unwrap()),
            Frame::Stream(stream_frame(short(sid(4)), None, Some(width), &b""[..], true).unwrap()),
            Frame::ConnectionClose(
                ConnectionClose::new(
                    CloseErrorCode::Application {
                        code: short(ApplicationErrorCode::new(VarInt::ZERO)),
                    },
                    width,
                    &b"reason"[..],
                )
                .unwrap(),
            ),
            Frame::Datagram(datagram_frame(Some(width), &b"datagram"[..]).unwrap()),
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
        FrameType::ConnectionClose,
        FrameType::ResetStreamAt,
        FrameType::Datagram,
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
            F::MaxData(MaxData::new(wide(vi(5), VarIntWidth::Two))),
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
                Crypto::new(
                    wide(VarInt::ZERO, VarIntWidth::Eight),
                    VarIntWidth::Two,
                    &b"abc"[..],
                )
                .unwrap(),
            ),
        ),
        (
            vec![0x07, 0x80, 0, 0, 1, b'x'],
            F::NewToken(NewToken::new(VarIntWidth::Four, &b"x"[..]).unwrap()),
        ),
        (
            // Largest 5, delay 0, one more range; ranges 4..=5 and 2..=2.
            vec![
                0x02, 0x40, 0x05, 0x80, 0, 0, 0, 0x40, 0x01, 0x40, 0x01, 0x40, 0x00, 0x00,
            ],
            F::Ack(
                Ack::new(
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
                Ack::new(
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
            F::ResetStream(ResetStream::new(
                wide(sid(4), VarIntWidth::Two),
                wide(ApplicationErrorCode::new(VarInt::ZERO), VarIntWidth::Two),
                wide(vi(7), VarIntWidth::Four),
            )),
        ),
        (
            vec![0x05, 0x40, 0x03, 0x40, 0x07],
            F::StopSending(StopSending::new(
                wide(sid(3), VarIntWidth::Two),
                wide(ApplicationErrorCode::new(vi(7)), VarIntWidth::Two),
            )),
        ),
        (
            vec![0x11, 0x40, 0x08, 0x40, 0x3f],
            F::MaxStreamData(MaxStreamData::new(
                wide(sid(8), VarIntWidth::Two),
                wide(vi(63), VarIntWidth::Two),
            )),
        ),
        (
            vec![0x12, 0xc0, 0, 0, 0, 0, 0, 0, 0x05],
            F::MaxStreams(MaxStreams::new(
                Directionality::Bidirectional,
                wide(StreamCount::new(5).unwrap(), VarIntWidth::Eight),
            )),
        ),
        (
            vec![0x14, 0x40, 0x00],
            F::DataBlocked(DataBlocked::new(wide(VarInt::ZERO, VarIntWidth::Two))),
        ),
        (
            vec![0x15, 0x40, 0x02, 0x40, 0x3f],
            F::StreamDataBlocked(StreamDataBlocked::new(
                wide(sid(2), VarIntWidth::Two),
                wide(vi(63), VarIntWidth::Two),
            )),
        ),
        (
            vec![0x17, 0x40, 0x01],
            F::StreamsBlocked(StreamsBlocked::new(
                Directionality::Unidirectional,
                wide(StreamCount::new(1).unwrap(), VarIntWidth::Two),
            )),
        ),
        (
            [&[0x18, 0x40, 0x02, 0x40, 0x01, 0x01, 0xaa][..], &TOKEN[..]].concat(),
            F::NewConnectionId(
                NewConnectionId::new(
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
            F::RetireConnectionId(RetireConnectionId::new(wide(vi(9), VarIntWidth::Four))),
        ),
        (
            vec![0x1c, 0x40, 0x07, 0x40, 0x06, 0x40, 0x00],
            F::ConnectionClose(
                ConnectionClose::new(
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
                ConnectionClose::new(
                    CloseErrorCode::Application {
                        code: wide(ApplicationErrorCode::new(vi(0x42)), VarIntWidth::Four),
                    },
                    VarIntWidth::Two,
                    &b"no"[..],
                )
                .unwrap(),
            ),
        ),
        (
            vec![0x24, 0x40, 0x00, 0x40, 0x01, 0x40, 0x05, 0x80, 0, 0, 5],
            F::ResetStreamAt(
                ResetStreamAt::new(
                    wide(sid(0), VarIntWidth::Two),
                    wide(ApplicationErrorCode::new(vi(1)), VarIntWidth::Two),
                    wide(vi(5), VarIntWidth::Two),
                    wide(vi(5), VarIntWidth::Four),
                )
                .unwrap(),
            ),
        ),
        (
            vec![0x31, 0x40, 0x02, b'h', b'i'],
            F::Datagram(datagram_frame(Some(VarIntWidth::Two), &b"hi"[..]).unwrap()),
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
            Ack::from_packet_ranges(ack.packet_ranges(), short(ack.ack_delay().get()), ecn)
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
            Frame::Crypto(Crypto::new(s(f.offset()), length(f.data()), *f.data()).unwrap())
        }
        Frame::NewToken(f) => {
            Frame::NewToken(NewToken::new(length(f.token()), *f.token()).unwrap())
        }
        Frame::ResetStream(f) => Frame::ResetStream(ResetStream::new(
            s(f.stream_id()),
            s(f.application_error_code()),
            s(f.final_size()),
        )),
        Frame::StopSending(f) => Frame::StopSending(StopSending::new(
            s(f.stream_id()),
            s(f.application_error_code()),
        )),
        Frame::MaxData(f) => Frame::MaxData(MaxData::new(s(f.maximum_data()))),
        Frame::MaxStreamData(f) => Frame::MaxStreamData(MaxStreamData::new(
            s(f.stream_id()),
            s(f.maximum_stream_data()),
        )),
        Frame::MaxStreams(f) => {
            Frame::MaxStreams(MaxStreams::new(f.directionality(), s(f.maximum_streams())))
        }
        Frame::DataBlocked(f) => Frame::DataBlocked(DataBlocked::new(s(f.maximum_data()))),
        Frame::StreamDataBlocked(f) => Frame::StreamDataBlocked(StreamDataBlocked::new(
            s(f.stream_id()),
            s(f.maximum_stream_data()),
        )),
        Frame::StreamsBlocked(f) => Frame::StreamsBlocked(StreamsBlocked::new(
            f.directionality(),
            s(f.maximum_streams()),
        )),
        Frame::NewConnectionId(f) => Frame::NewConnectionId(
            NewConnectionId::new(
                s(f.sequence_number()),
                s(f.retire_prior_to()),
                f.connection_id(),
                f.stateless_reset_token(),
            )
            .unwrap(),
        ),
        Frame::RetireConnectionId(f) => {
            Frame::RetireConnectionId(RetireConnectionId::new(s(f.sequence_number())))
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
                ConnectionClose::new(error_code, length(reason_phrase), reason_phrase).unwrap(),
            )
        }
        Frame::ResetStreamAt(f) => Frame::ResetStreamAt(
            ResetStreamAt::new(
                s(f.stream_id()),
                s(f.application_error_code()),
                s(f.final_size()),
                s(f.reliable_size()),
            )
            .unwrap(),
        ),
        Frame::Datagram(f) => Frame::Datagram(
            datagram_frame(
                length_width(f.length()).map(|_| length(f.data())),
                *f.data(),
            )
            .unwrap(),
        ),
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
            let crypto = Crypto::new(short(VarInt::ZERO), width, data);
            let stream = stream_frame(short(sid(0)), None, Some(width), data, false);
            let close = ConnectionClose::new(application, width, data);
            let datagram = datagram_frame(Some(width), data);
            // A token is never empty.
            let token = (length > 0).then(|| NewToken::new(width, data));
            if fits {
                let frames = [
                    Frame::Crypto(crypto.unwrap()),
                    Frame::Stream(stream.unwrap()),
                    Frame::ConnectionClose(close.unwrap()),
                    Frame::Datagram(datagram.unwrap()),
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
            let error = LengthError { length, width };
            assert_eq!(crypto, Err(InvalidDataError::Length { source: error }));
            assert_eq!(stream, Err(InvalidDataError::Length { source: error }));
            assert_eq!(close, Err(error));
            assert_eq!(datagram, Err(error));
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
                assert_eq!(result, Err(LengthError { length, width }), "{length}");
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
    let frames: Vec<_> = Frames::new(&payload[..], Extensions::NONE)
        .map(Result::unwrap)
        .collect();
    let one = Some(VarIntWidth::One);
    assert_eq!(
        frames,
        [
            Frame::Stream(
                stream_frame(
                    short(sid(4)),
                    Some(short(VarInt::ZERO)),
                    one,
                    &b"a"[..],
                    false
                )
                .unwrap()
            ),
            Frame::Stream(stream_frame(short(sid(4)), None, one, &b"b"[..], false).unwrap()),
        ]
    );
}
