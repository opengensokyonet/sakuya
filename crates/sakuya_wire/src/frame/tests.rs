//! Tests that cover every frame type, and the helpers the tests of the frame
//! modules share.
use super::{
    Extensions, Frame, FrameType, Frames, MAX_STREAM_COUNT, UnknownFrameTypeError,
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
    stream_id::{Directionality, StreamId},
    transport_error::TransportErrorCode,
    var_int::{VarInt, codec::ReadVarIntHostExt as _},
};
use bytes::Bytes;
use core::num::NonZeroUsize;

pub(crate) fn vi(value: u64) -> VarInt {
    VarInt::try_from(value).unwrap()
}

pub(crate) fn sid(value: u64) -> StreamId {
    StreamId::from_var_int(vi(value))
}

/// Writes `frame` with [`write_frame`](super::codec::write_frame), checks
/// its length and type, reads it back from a byte slice and from `Bytes`,
/// and returns the encoding.
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

pub(crate) const TOKEN: [u8; 16] = *b"0123456789abcdef";

/// An ACK frame read from `encoding`.
pub(crate) fn read_ack(encoding: &[u8]) -> Frame<&[u8]> {
    let mut input = encoding;
    let frame = input.sync_read_frame_unpin(Extensions::NONE).unwrap();
    assert!(matches!(frame, Frame::Ack(_)), "{frame:?}");
    assert!(input.is_empty());
    frame
}

/// One frame of every type and form.
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
            stream_id: sid(4),
            application_error_code: ApplicationErrorCode::new(vi(0x100)),
            final_size: vi(70_000),
        }),
        Frame::StopSending(StopSending {
            stream_id: sid(3),
            application_error_code: ApplicationErrorCode::new(vi(7)),
        }),
        Frame::Crypto(Crypto {
            offset: vi(1000),
            data: b"client hello",
        }),
        Frame::Crypto(Crypto {
            offset: VarInt::ZERO,
            data: b"",
        }),
        Frame::NewToken(NewToken { token: b"token" }),
        Frame::MaxData(MaxData {
            maximum_data: vi(1 << 40),
        }),
        Frame::MaxStreamData(MaxStreamData {
            stream_id: sid(8),
            maximum_stream_data: vi(65_536),
        }),
        Frame::MaxStreams(MaxStreams {
            directionality: Directionality::Bidirectional,
            maximum_streams: vi(MAX_STREAM_COUNT),
        }),
        Frame::MaxStreams(MaxStreams {
            directionality: Directionality::Unidirectional,
            maximum_streams: vi(3),
        }),
        Frame::DataBlocked(DataBlocked {
            maximum_data: vi(16_384),
        }),
        Frame::StreamDataBlocked(StreamDataBlocked {
            stream_id: sid(2),
            maximum_stream_data: vi(63),
        }),
        Frame::StreamsBlocked(StreamsBlocked {
            directionality: Directionality::Bidirectional,
            maximum_streams: vi(100),
        }),
        Frame::StreamsBlocked(StreamsBlocked {
            directionality: Directionality::Unidirectional,
            maximum_streams: VarInt::ZERO,
        }),
        Frame::NewConnectionId(NewConnectionId {
            sequence_number: vi(2),
            retire_prior_to: vi(1),
            connection_id: NonEmptyCid::try_from(&[0xaa; 20][..]).unwrap(),
            stateless_reset_token: StatelessResetToken::new(TOKEN),
        }),
        Frame::NewConnectionId(NewConnectionId {
            sequence_number: vi(1),
            retire_prior_to: vi(1),
            connection_id: NonEmptyCid::try_from(&[0x01][..]).unwrap(),
            stateless_reset_token: StatelessResetToken::new(TOKEN),
        }),
        Frame::RetireConnectionId(RetireConnectionId {
            sequence_number: vi(9),
        }),
        Frame::PathChallenge(PathChallenge { data: *b"challeng" }),
        Frame::PathResponse(PathResponse { data: *b"response" }),
        Frame::ConnectionClose(ConnectionClose {
            error_code: CloseErrorCode::Transport {
                code: TransportErrorCode::PROTOCOL_VIOLATION,
                frame_type: vi(0x08),
            },
            reason_phrase: b"bad stream",
        }),
        Frame::ConnectionClose(ConnectionClose {
            error_code: CloseErrorCode::Application {
                code: ApplicationErrorCode::new(vi(0x42)),
            },
            reason_phrase: b"",
        }),
        Frame::HandshakeDone(HandshakeDone),
        Frame::ResetStreamAt(ResetStreamAt {
            stream_id: sid(0),
            application_error_code: ApplicationErrorCode::new(vi(1)),
            final_size: vi(800),
            reliable_size: vi(300),
        }),
        Frame::Datagram(Datagram {
            data: b"datagram",
            has_length: true,
        }),
        Frame::Datagram(Datagram {
            data: b"to the end",
            has_length: false,
        }),
    ];
    for bits in 0..8u64 {
        frames.push(Frame::Stream(Stream {
            stream_id: sid(4),
            offset: if bits & 0x04 != 0 {
                vi(1 << 20)
            } else {
                VarInt::ZERO
            },
            data: b"stream data",
            fin: bits & 0x01 != 0,
            has_length: bits & 0x02 != 0,
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
                stream_id: sid(1),
                offset: VarInt::ZERO,
                data: &[b'a', b'b', 0x01, 0x00][..],
                fin: true,
                has_length: false,
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

    // A longer encoding of type 0 is one PADDING frame of that length.
    let mut input = &[0x40, 0x00, 0x01][..];
    assert_eq!(
        input.sync_read_frame_unpin(Extensions::NONE).unwrap(),
        Frame::Padding(Padding {
            len: NonZeroUsize::new(2).unwrap()
        })
    );
    assert_eq!(input, [0x01]);
}

#[test]
fn unknown_and_disabled_types_are_rejected() {
    let cases: [(&[u8], Extensions); 6] = [
        (&[0x1f], Extensions::ALL),
        (&[0x21, 0x00], Extensions::ALL),
        (&[0x40, 0x32], Extensions::ALL),
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
