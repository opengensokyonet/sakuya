//! Tests that cover every frame type, and the helpers the tests of the frame
//! modules share.
use super::{
    Extensions, Frame, FrameType, Frames, LengthError, UnknownFrameTypeError,
    ack::{Ack, AckRange, AckRanges, EcnCounts},
    codec::{ReadFrameError, ReadFrameHostExt as _, WriteFrameError, WriteFrameHostExt as _},
    connection_close::{CloseErrorCode, ConnectionClose},
    crypto::Crypto,
    data_blocked::DataBlocked,
    datagram::Datagram,
    handshake_done::HandshakeDone,
    max_data::MaxData,
    max_stream_data::MaxStreamData,
    max_streams::MaxStreams,
    new_connection_id::NewConnectionId,
    new_token::NewToken,
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
use bytes::Bytes;
use core::num::NonZeroUsize;

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
        Frame::Padding(Padding {
            len: NonZeroUsize::new(3).unwrap(),
        }),
        Frame::Ping(Ping),
        // Largest 100, delay 5, ranges 97..=100, 90..=94 and 88..=88; ECN
        // counts 1, 2, 3.
        read_ack(&[
            0x03, 0x40, 100, 0x05, 0x02, 0x03, 0x01, 0x04, 0x00, 0x00, 0x01, 0x02, 0x03,
        ]),
        read_ack(&[0x02, 0x00, 0x00, 0x00, 0x00]),
        Frame::ResetStream(ResetStream {
            stream_id: short(sid(4)),
            application_error_code: short(ApplicationErrorCode::new(vi(0x100))),
            final_size: short(vi(70_000)),
        }),
        Frame::StopSending(StopSending {
            stream_id: short(sid(3)),
            application_error_code: short(ApplicationErrorCode::new(vi(7))),
        }),
        Frame::Crypto(Crypto {
            offset: short(vi(1000)),
            length_width: VarIntWidth::One,
            data: b"client hello",
        }),
        Frame::Crypto(Crypto {
            offset: short(VarInt::ZERO),
            length_width: VarIntWidth::One,
            data: b"",
        }),
        Frame::NewToken(NewToken {
            token_length_width: VarIntWidth::One,
            token: b"token",
        }),
        Frame::MaxData(MaxData {
            maximum_data: short(vi(1 << 40)),
        }),
        Frame::MaxStreamData(MaxStreamData {
            stream_id: short(sid(8)),
            maximum_stream_data: short(vi(65_536)),
        }),
        Frame::MaxStreams(MaxStreams {
            directionality: Directionality::Bidirectional,
            maximum_streams: short(StreamCount::MAX),
        }),
        Frame::MaxStreams(MaxStreams {
            directionality: Directionality::Unidirectional,
            maximum_streams: short(StreamCount::new(3).unwrap()),
        }),
        Frame::DataBlocked(DataBlocked {
            maximum_data: short(vi(16_384)),
        }),
        Frame::StreamDataBlocked(StreamDataBlocked {
            stream_id: short(sid(2)),
            maximum_stream_data: short(vi(63)),
        }),
        Frame::StreamsBlocked(StreamsBlocked {
            directionality: Directionality::Bidirectional,
            maximum_streams: short(StreamCount::new(100).unwrap()),
        }),
        Frame::StreamsBlocked(StreamsBlocked {
            directionality: Directionality::Unidirectional,
            maximum_streams: short(StreamCount::ZERO),
        }),
        Frame::NewConnectionId(NewConnectionId {
            sequence_number: short(vi(2)),
            retire_prior_to: short(vi(1)),
            connection_id: NonEmptyCid::try_from(&[0xaa; 20][..]).unwrap(),
            stateless_reset_token: StatelessResetToken::new(TOKEN),
        }),
        Frame::NewConnectionId(NewConnectionId {
            sequence_number: short(vi(1)),
            retire_prior_to: short(vi(1)),
            connection_id: NonEmptyCid::try_from(&[0x01][..]).unwrap(),
            stateless_reset_token: StatelessResetToken::new(TOKEN),
        }),
        Frame::RetireConnectionId(RetireConnectionId {
            sequence_number: short(vi(9)),
        }),
        Frame::PathChallenge(PathChallenge { data: *b"challeng" }),
        Frame::PathResponse(PathResponse { data: *b"response" }),
        Frame::ConnectionClose(ConnectionClose {
            error_code: CloseErrorCode::Transport {
                code: short(TransportErrorCode::PROTOCOL_VIOLATION),
                frame_type: short(vi(0x08)),
            },
            reason_phrase_length_width: VarIntWidth::One,
            reason_phrase: b"bad stream",
        }),
        Frame::ConnectionClose(ConnectionClose {
            error_code: CloseErrorCode::Application {
                code: short(ApplicationErrorCode::new(vi(0x42))),
            },
            reason_phrase_length_width: VarIntWidth::One,
            reason_phrase: b"",
        }),
        Frame::HandshakeDone(HandshakeDone),
        Frame::ResetStreamAt(ResetStreamAt {
            stream_id: short(sid(0)),
            application_error_code: short(ApplicationErrorCode::new(vi(1))),
            final_size: short(vi(800)),
            reliable_size: short(vi(300)),
        }),
        Frame::Datagram(Datagram {
            length_width: Some(VarIntWidth::One),
            data: b"datagram",
        }),
        Frame::Datagram(Datagram {
            length_width: None,
            data: b"to the end",
        }),
    ];
    for bits in 0..8u64 {
        frames.push(Frame::Stream(Stream {
            stream_id: short(sid(4)),
            offset: (bits & 0x04 != 0).then(|| short(vi(1 << 20))),
            length_width: (bits & 0x02 != 0).then_some(VarIntWidth::One),
            data: b"stream data",
            fin: bits & 0x01 != 0,
        }));
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
                assert_eq!(written, vec![0; padding.len.get()]);
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
        let WriteFrameError::Write { source } = &error else {
            panic!("{frame:?}: {error:?}");
        };
        assert_eq!(source.completed(), required - 1, "{frame:?}");
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
            Frame::Stream(Stream {
                stream_id: short(sid(1)),
                offset: None,
                length_width: None,
                data: &[b'a', b'b', 0x01, 0x00][..],
                fin: true,
            }),
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
    assert_eq!(stream.data, &b"hi"[..]);
    assert_eq!(stream.data.as_ptr(), payload[3..].as_ptr());
    assert_eq!(frames.next().map(Result::unwrap), Some(Frame::Ping(Ping)));
    assert!(frames.next().is_none());
}

#[test]
fn padding_runs_are_one_value() {
    let payload = [0x00, 0x00, 0x00, 0x01, 0x00];
    let mut frames = Frames::new(&payload[..], Extensions::NONE);
    assert_eq!(
        frames.next().map(Result::unwrap),
        Some(Frame::Padding(Padding {
            len: NonZeroUsize::new(3).unwrap()
        }))
    );
    assert_eq!(frames.offset(), 3);
    assert_eq!(frames.next().map(Result::unwrap), Some(Frame::Ping(Ping)));
    assert_eq!(*frames.remainder(), [0x00]);
    assert_eq!(
        frames.next().map(Result::unwrap),
        Some(Frame::Padding(Padding {
            len: NonZeroUsize::MIN
        }))
    );
    assert!(frames.next().is_none());

    // A longer encoding of type 0 is not PADDING; it ends the run and is
    // rejected.
    let payload = [0x00, 0x40, 0x00, 0x01];
    let mut frames = Frames::new(&payload[..], Extensions::NONE);
    assert_eq!(
        frames.next().map(Result::unwrap),
        Some(Frame::Padding(Padding {
            len: NonZeroUsize::MIN
        }))
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
        assert!(
            matches!(error, ReadFrameError::UnknownType { frame_type: rejected } if rejected == frame_type),
            "{encoding:02x?}: {error:?}"
        );
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
        FrameType::of(vi(0x1f)),
        Err(UnknownFrameTypeError {
            frame_type: vi(0x1f)
        })
    );
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
        Frame::Ack(Ack {
            largest_acknowledged,
            ack_delay,
            ack_range_count_width: VarIntWidth::One,
            first_ack_range,
            ranges: AckRanges::from(ranges),
            ecn_counts: ecn,
        })
    };
    let mut frames = Vec::new();
    for x in edge_fields() {
        let value = x.get();
        let stream_id = as_field(x, StreamId::from_var_int);
        let application = as_field(x, ApplicationErrorCode::new);
        let application_zero = short(ApplicationErrorCode::new(VarInt::ZERO));
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
            Frame::ResetStream(ResetStream {
                stream_id,
                application_error_code: application_zero,
                final_size: zero,
            }),
            Frame::ResetStream(ResetStream {
                stream_id: short(sid(0)),
                application_error_code: application,
                final_size: x,
            }),
            Frame::StopSending(StopSending {
                stream_id,
                application_error_code: application,
            }),
            Frame::Crypto(Crypto {
                offset: x,
                length_width: VarIntWidth::One,
                data,
            }),
            Frame::Stream(Stream {
                stream_id,
                offset: None,
                length_width: None,
                data: b"hello",
                fin: false,
            }),
            Frame::Stream(Stream {
                stream_id: short(sid(0)),
                offset: Some(x),
                length_width: Some(VarIntWidth::One),
                data,
                fin: true,
            }),
            Frame::Stream(Stream {
                stream_id: short(sid(0)),
                offset: Some(x),
                length_width: None,
                data,
                fin: false,
            }),
            Frame::MaxData(MaxData { maximum_data: x }),
            Frame::MaxStreamData(MaxStreamData {
                stream_id,
                maximum_stream_data: x,
            }),
            Frame::DataBlocked(DataBlocked { maximum_data: x }),
            Frame::StreamDataBlocked(StreamDataBlocked {
                stream_id,
                maximum_stream_data: x,
            }),
            Frame::NewConnectionId(NewConnectionId {
                sequence_number: x,
                retire_prior_to: zero,
                connection_id: NonEmptyCid::try_from(&[0x01][..]).unwrap(),
                stateless_reset_token: StatelessResetToken::new(TOKEN),
            }),
            Frame::NewConnectionId(NewConnectionId {
                sequence_number: short(value),
                retire_prior_to: x,
                connection_id: NonEmptyCid::try_from(&[0x01][..]).unwrap(),
                stateless_reset_token: StatelessResetToken::new(TOKEN),
            }),
            Frame::RetireConnectionId(RetireConnectionId { sequence_number: x }),
            Frame::ConnectionClose(ConnectionClose {
                error_code: CloseErrorCode::Transport {
                    code: as_field(x, TransportErrorCode::from),
                    frame_type: zero,
                },
                reason_phrase_length_width: VarIntWidth::One,
                reason_phrase: b"",
            }),
            Frame::ConnectionClose(ConnectionClose {
                error_code: CloseErrorCode::Transport {
                    code: short(TransportErrorCode::FRAME_ENCODING_ERROR),
                    frame_type: x,
                },
                reason_phrase_length_width: VarIntWidth::One,
                reason_phrase: b"why",
            }),
            Frame::ConnectionClose(ConnectionClose {
                error_code: CloseErrorCode::Application { code: application },
                reason_phrase_length_width: VarIntWidth::One,
                reason_phrase: b"",
            }),
            Frame::ResetStreamAt(ResetStreamAt {
                stream_id,
                application_error_code: application,
                final_size: x,
                reliable_size: zero,
            }),
            Frame::ResetStreamAt(ResetStreamAt {
                stream_id: short(sid(0)),
                application_error_code: application_zero,
                final_size: short(value),
                reliable_size: x,
            }),
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
                    Frame::MaxStreams(MaxStreams {
                        directionality,
                        maximum_streams: count,
                    }),
                    Frame::StreamsBlocked(StreamsBlocked {
                        directionality,
                        maximum_streams: count,
                    }),
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
            frames.push(Frame::Ack(Ack {
                largest_acknowledged: short(PacketNumber::new(10).unwrap()),
                ack_delay: zero,
                ack_range_count_width: width,
                first_ack_range: short(vi(1)),
                ranges: AckRanges::from(ranges),
                ecn_counts: None,
            }));
        }
        frames.extend([
            Frame::Crypto(Crypto {
                offset: zero,
                length_width: width,
                data: &b"hello"[..],
            }),
            Frame::NewToken(NewToken {
                token_length_width: width,
                token: &b"token"[..],
            }),
            Frame::Stream(Stream {
                stream_id: short(sid(4)),
                offset: None,
                length_width: Some(width),
                data: &b""[..],
                fin: true,
            }),
            Frame::ConnectionClose(ConnectionClose {
                error_code: CloseErrorCode::Application {
                    code: short(ApplicationErrorCode::new(VarInt::ZERO)),
                },
                reason_phrase_length_width: width,
                reason_phrase: &b"reason"[..],
            }),
            Frame::Datagram(Datagram {
                length_width: Some(width),
                data: &b"datagram"[..],
            }),
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
        assert_eq!(frame.validate(), Ok(()), "{frame:?}");
        assert_round_trip(frame);
    }
}

#[test]
fn longer_field_encodings_read_and_write_back_unchanged() {
    use Frame as F;
    let cases: Vec<(Vec<u8>, Frame<&[u8]>)> = vec![
        (
            vec![0x10, 0x40, 0x05],
            F::MaxData(MaxData {
                maximum_data: wide(vi(5), VarIntWidth::Two),
            }),
        ),
        (
            // OFF set with a four-byte offset 0, LEN with an eight-byte
            // length.
            vec![
                0x0f, 0x40, 0x04, 0x80, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 2, b'h', b'i',
            ],
            F::Stream(Stream {
                stream_id: wide(sid(4), VarIntWidth::Two),
                offset: Some(wide(VarInt::ZERO, VarIntWidth::Four)),
                length_width: Some(VarIntWidth::Eight),
                data: b"hi",
                fin: true,
            }),
        ),
        (
            vec![
                0x06, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0x40, 0x03, b'a', b'b', b'c',
            ],
            F::Crypto(Crypto {
                offset: wide(VarInt::ZERO, VarIntWidth::Eight),
                length_width: VarIntWidth::Two,
                data: b"abc",
            }),
        ),
        (
            vec![0x07, 0x80, 0, 0, 1, b'x'],
            F::NewToken(NewToken {
                token_length_width: VarIntWidth::Four,
                token: b"x",
            }),
        ),
        (
            // Largest 5, delay 0, one more range; ranges 4..=5 and 2..=2.
            vec![
                0x02, 0x40, 0x05, 0x80, 0, 0, 0, 0x40, 0x01, 0x40, 0x01, 0x40, 0x00, 0x00,
            ],
            F::Ack(Ack {
                largest_acknowledged: wide(PacketNumber::new(5).unwrap(), VarIntWidth::Two),
                ack_delay: wide(VarInt::ZERO, VarIntWidth::Four),
                ack_range_count_width: VarIntWidth::Two,
                first_ack_range: wide(vi(1), VarIntWidth::Two),
                ranges: AckRanges::from(vec![AckRange {
                    gap: wide(VarInt::ZERO, VarIntWidth::Two),
                    ack_range_length: short(VarInt::ZERO),
                }]),
                ecn_counts: None,
            }),
        ),
        (
            vec![
                0x03, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x80, 0, 0, 3,
            ],
            F::Ack(Ack {
                largest_acknowledged: short(PacketNumber::ZERO),
                ack_delay: short(VarInt::ZERO),
                ack_range_count_width: VarIntWidth::One,
                first_ack_range: short(VarInt::ZERO),
                ranges: AckRanges::default(),
                ecn_counts: Some(EcnCounts {
                    ect0: wide(vi(1), VarIntWidth::Two),
                    ect1: short(VarInt::ZERO),
                    ce: wide(vi(3), VarIntWidth::Four),
                }),
            }),
        ),
        (
            vec![0x04, 0x40, 0x04, 0x40, 0x00, 0x80, 0, 0, 7],
            F::ResetStream(ResetStream {
                stream_id: wide(sid(4), VarIntWidth::Two),
                application_error_code: wide(
                    ApplicationErrorCode::new(VarInt::ZERO),
                    VarIntWidth::Two,
                ),
                final_size: wide(vi(7), VarIntWidth::Four),
            }),
        ),
        (
            vec![0x05, 0x40, 0x03, 0x40, 0x07],
            F::StopSending(StopSending {
                stream_id: wide(sid(3), VarIntWidth::Two),
                application_error_code: wide(ApplicationErrorCode::new(vi(7)), VarIntWidth::Two),
            }),
        ),
        (
            vec![0x11, 0x40, 0x08, 0x40, 0x3f],
            F::MaxStreamData(MaxStreamData {
                stream_id: wide(sid(8), VarIntWidth::Two),
                maximum_stream_data: wide(vi(63), VarIntWidth::Two),
            }),
        ),
        (
            vec![0x12, 0xc0, 0, 0, 0, 0, 0, 0, 0x05],
            F::MaxStreams(MaxStreams {
                directionality: Directionality::Bidirectional,
                maximum_streams: wide(StreamCount::new(5).unwrap(), VarIntWidth::Eight),
            }),
        ),
        (
            vec![0x14, 0x40, 0x00],
            F::DataBlocked(DataBlocked {
                maximum_data: wide(VarInt::ZERO, VarIntWidth::Two),
            }),
        ),
        (
            vec![0x15, 0x40, 0x02, 0x40, 0x3f],
            F::StreamDataBlocked(StreamDataBlocked {
                stream_id: wide(sid(2), VarIntWidth::Two),
                maximum_stream_data: wide(vi(63), VarIntWidth::Two),
            }),
        ),
        (
            vec![0x17, 0x40, 0x01],
            F::StreamsBlocked(StreamsBlocked {
                directionality: Directionality::Unidirectional,
                maximum_streams: wide(StreamCount::new(1).unwrap(), VarIntWidth::Two),
            }),
        ),
        (
            [&[0x18, 0x40, 0x02, 0x40, 0x01, 0x01, 0xaa][..], &TOKEN[..]].concat(),
            F::NewConnectionId(NewConnectionId {
                sequence_number: wide(vi(2), VarIntWidth::Two),
                retire_prior_to: wide(vi(1), VarIntWidth::Two),
                connection_id: NonEmptyCid::try_from(&[0xaa][..]).unwrap(),
                stateless_reset_token: StatelessResetToken::new(TOKEN),
            }),
        ),
        (
            vec![0x19, 0x80, 0, 0, 9],
            F::RetireConnectionId(RetireConnectionId {
                sequence_number: wide(vi(9), VarIntWidth::Four),
            }),
        ),
        (
            vec![0x1c, 0x40, 0x07, 0x40, 0x06, 0x40, 0x00],
            F::ConnectionClose(ConnectionClose {
                error_code: CloseErrorCode::Transport {
                    code: wide(TransportErrorCode::FRAME_ENCODING_ERROR, VarIntWidth::Two),
                    frame_type: wide(vi(6), VarIntWidth::Two),
                },
                reason_phrase_length_width: VarIntWidth::Two,
                reason_phrase: b"",
            }),
        ),
        (
            vec![0x1d, 0x80, 0, 0, 0x42, 0x40, 0x02, b'n', b'o'],
            F::ConnectionClose(ConnectionClose {
                error_code: CloseErrorCode::Application {
                    code: wide(ApplicationErrorCode::new(vi(0x42)), VarIntWidth::Four),
                },
                reason_phrase_length_width: VarIntWidth::Two,
                reason_phrase: b"no",
            }),
        ),
        (
            vec![0x24, 0x40, 0x00, 0x40, 0x01, 0x40, 0x05, 0x80, 0, 0, 5],
            F::ResetStreamAt(ResetStreamAt {
                stream_id: wide(sid(0), VarIntWidth::Two),
                application_error_code: wide(ApplicationErrorCode::new(vi(1)), VarIntWidth::Two),
                final_size: wide(vi(5), VarIntWidth::Two),
                reliable_size: wide(vi(5), VarIntWidth::Four),
            }),
        ),
        (
            vec![0x31, 0x40, 0x02, b'h', b'i'],
            F::Datagram(Datagram {
                length_width: Some(VarIntWidth::Two),
                data: b"hi",
            }),
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
            let ecn = ack.ecn_counts.map(|counts| EcnCounts {
                ect0: short(counts.ect0.get()),
                ect1: short(counts.ect1.get()),
                ce: short(counts.ce.get()),
            });
            Ack::from_packet_ranges(ack.packet_ranges(), short(ack.ack_delay.get()), ecn)
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
        Frame::Stream(f) => Frame::Stream(Stream {
            stream_id: s(f.stream_id),
            offset: f.offset.map(s),
            length_width: f.length_width.map(|_| length(f.data)),
            ..f
        }),
        Frame::Crypto(f) => Frame::Crypto(Crypto {
            offset: s(f.offset),
            length_width: length(f.data),
            ..f
        }),
        Frame::NewToken(f) => Frame::NewToken(NewToken {
            token_length_width: length(f.token),
            ..f
        }),
        Frame::ResetStream(f) => Frame::ResetStream(ResetStream {
            stream_id: s(f.stream_id),
            application_error_code: s(f.application_error_code),
            final_size: s(f.final_size),
        }),
        Frame::StopSending(f) => Frame::StopSending(StopSending {
            stream_id: s(f.stream_id),
            application_error_code: s(f.application_error_code),
        }),
        Frame::MaxData(f) => Frame::MaxData(MaxData {
            maximum_data: s(f.maximum_data),
        }),
        Frame::MaxStreamData(f) => Frame::MaxStreamData(MaxStreamData {
            stream_id: s(f.stream_id),
            maximum_stream_data: s(f.maximum_stream_data),
        }),
        Frame::MaxStreams(f) => Frame::MaxStreams(MaxStreams {
            maximum_streams: s(f.maximum_streams),
            ..f
        }),
        Frame::DataBlocked(f) => Frame::DataBlocked(DataBlocked {
            maximum_data: s(f.maximum_data),
        }),
        Frame::StreamDataBlocked(f) => Frame::StreamDataBlocked(StreamDataBlocked {
            stream_id: s(f.stream_id),
            maximum_stream_data: s(f.maximum_stream_data),
        }),
        Frame::StreamsBlocked(f) => Frame::StreamsBlocked(StreamsBlocked {
            maximum_streams: s(f.maximum_streams),
            ..f
        }),
        Frame::NewConnectionId(f) => Frame::NewConnectionId(NewConnectionId {
            sequence_number: s(f.sequence_number),
            retire_prior_to: s(f.retire_prior_to),
            ..f
        }),
        Frame::RetireConnectionId(f) => Frame::RetireConnectionId(RetireConnectionId {
            sequence_number: s(f.sequence_number),
        }),
        Frame::ConnectionClose(f) => Frame::ConnectionClose(ConnectionClose {
            error_code: match f.error_code {
                CloseErrorCode::Transport { code, frame_type } => CloseErrorCode::Transport {
                    code: s(code),
                    frame_type: s(frame_type),
                },
                CloseErrorCode::Application { code } => {
                    CloseErrorCode::Application { code: s(code) }
                }
            },
            reason_phrase_length_width: length(f.reason_phrase),
            ..f
        }),
        Frame::ResetStreamAt(f) => Frame::ResetStreamAt(ResetStreamAt {
            stream_id: s(f.stream_id),
            application_error_code: s(f.application_error_code),
            final_size: s(f.final_size),
            reliable_size: s(f.reliable_size),
        }),
        Frame::Datagram(f) => Frame::Datagram(Datagram {
            length_width: f.length_width.map(|_| length(f.data)),
            ..f
        }),
        ref other => other.clone(),
    }
}

#[test]
fn length_fields_must_hold_the_payload_length() {
    let payload = vec![0x5a; 16_384];
    for length in [0, 1, 63, 64, 16_383, 16_384] {
        let data = &payload[..length];
        for width in VarIntWidth::ALL {
            let fits = VarInt::try_from(length).is_ok_and(|value| width.fits(value));
            let frames = [
                Frame::Crypto(Crypto {
                    offset: short(VarInt::ZERO),
                    length_width: width,
                    data,
                }),
                Frame::Stream(Stream {
                    stream_id: short(sid(0)),
                    offset: None,
                    length_width: Some(width),
                    data,
                    fin: false,
                }),
                Frame::ConnectionClose(ConnectionClose {
                    error_code: CloseErrorCode::Application {
                        code: short(ApplicationErrorCode::new(VarInt::ZERO)),
                    },
                    reason_phrase_length_width: width,
                    reason_phrase: data,
                }),
                Frame::Datagram(Datagram {
                    length_width: Some(width),
                    data,
                }),
            ]
            .into_iter()
            .chain((length > 0).then_some(Frame::NewToken(NewToken {
                token_length_width: width,
                token: data,
            })));
            for frame in frames {
                if fits {
                    assert_round_trip(frame);
                    continue;
                }
                let error = LengthError { length, width };
                let invalid = frame.validate().unwrap_err();
                assert!(
                    std::error::Error::source(&invalid)
                        .is_some_and(|source| source.to_string() == error.to_string()),
                    "{invalid:?}"
                );
                let mut written = Vec::new();
                assert!(matches!(
                    written.sync_write_frame_unpin(frame),
                    Err(WriteFrameError::Invalid { .. })
                ));
                assert!(written.is_empty());
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
    assert_eq!(stream.offset, Some(short(VarInt::ZERO)));
    assert_eq!(stream.data_offset(), VarInt::ZERO);
    let Frame::Stream(plain) = without_off else {
        panic!("{without_off:?}")
    };
    assert_eq!(plain.offset, None);
    assert_eq!(plain.data_offset(), VarInt::ZERO);
    assert_ne!(stream, plain);
    assert_eq!(
        Stream {
            offset: None,
            ..stream
        },
        plain
    );
    for width in VarIntWidth::ALL {
        let frame = Stream {
            offset: Some(wide(VarInt::ZERO, width)),
            ..stream
        };
        assert_eq!(frame.type_value(), vi(0x0c));
        let encoding = assert_round_trip(Frame::Stream(frame));
        assert_eq!(encoding.len(), 2 + width.encoded_len() + 2);
    }
    // In a payload, each frame keeps its form.
    let payload = [0x0e, 0x04, 0x00, 0x01, b'a', 0x0a, 0x04, 0x01, b'b'];
    let frames: Vec<_> = Frames::new(&payload[..], Extensions::NONE)
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        frames,
        [
            Frame::Stream(Stream {
                stream_id: short(sid(4)),
                offset: Some(short(VarInt::ZERO)),
                length_width: Some(VarIntWidth::One),
                data: &b"a"[..],
                fin: false,
            }),
            Frame::Stream(Stream {
                stream_id: short(sid(4)),
                offset: None,
                length_width: Some(VarIntWidth::One),
                data: &b"b"[..],
                fin: false,
            }),
        ]
    );
}
