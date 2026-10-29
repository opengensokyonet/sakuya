// ACK ranges are written as arrays of inclusive ranges, some deliberately
// empty or reversed.
#![allow(clippy::single_range_in_vec_init, clippy::reversed_empty_ranges)]

use super::{
    Ack, ConnectionClose, Crypto, DataBlocked, Datagram, DecodeError, EcnCounts, EncodeError,
    Extensions, Frame, FrameType, Frames, HandshakeDone, InvalidFrameError, MAX_STREAM_COUNT,
    MaxData, MaxStreamData, MaxStreams, NewConnectionId, NewToken, Padding, PathChallenge,
    PathResponse, Ping, ResetStream, ResetStreamAt, RetireConnectionId, StopSending, Stream,
    StreamDataBlocked, StreamsBlocked,
    calls::{
        CryptoHeader, ReadCryptoHeaderExt as _, ReadCryptoHeaderHostExt as _, ReadFixedFrameError,
        ReadFixedFrameHostExt as _, ReadFrameTypeError, ReadFrameTypeExt as _,
        ReadFrameTypeHostExt as _, ReadStreamHeaderExt as _, StreamHeader, WriteFrameError,
        WriteFrameHostExt as _,
    },
};
use crate::{
    stream_id::{Directionality, StreamId},
    transport_error::TransportErrorCode,
    var_int::VarInt,
};
use bytes::BufMut;
use core::{num::NonZeroUsize, ops::RangeInclusive};
use nitori_call::{ReceiverAccess, call};
use nitori_io::prelude::*;
use std::{ops::ControlFlow, pin::pin};

fn vi(value: u64) -> VarInt {
    VarInt::try_from(value).unwrap()
}

fn sid(value: u64) -> StreamId {
    vi(value).into()
}

const TOKEN: [u8; 16] = *b"0123456789abcdef";

/// One frame of every type and form, except ACK, whose ranges cannot be
/// constructed directly.
fn sample_frames() -> Vec<Frame<'static>> {
    let mut frames = vec![
        Frame::Padding(Padding {
            len: NonZeroUsize::new(3).unwrap(),
        }),
        Frame::Ping(Ping),
        Frame::ResetStream(ResetStream {
            stream_id: sid(4),
            application_error_code: vi(0x100),
            final_size: vi(70_000),
        }),
        Frame::StopSending(StopSending {
            stream_id: sid(3),
            application_error_code: vi(7),
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
            connection_id: &[0xaa; 20],
            stateless_reset_token: &TOKEN,
        }),
        Frame::NewConnectionId(NewConnectionId {
            sequence_number: vi(1),
            retire_prior_to: vi(1),
            connection_id: &[0x01],
            stateless_reset_token: &TOKEN,
        }),
        Frame::RetireConnectionId(RetireConnectionId {
            sequence_number: vi(9),
        }),
        Frame::PathChallenge(PathChallenge { data: *b"challeng" }),
        Frame::PathResponse(PathResponse { data: *b"response" }),
        Frame::ConnectionClose(ConnectionClose {
            error_code: TransportErrorCode::PROTOCOL_VIOLATION.get(),
            frame_type: Some(vi(0x08)),
            reason_phrase: b"bad stream",
        }),
        Frame::ConnectionClose(ConnectionClose {
            error_code: vi(0x42),
            frame_type: None,
            reason_phrase: b"",
        }),
        Frame::HandshakeDone(HandshakeDone),
        Frame::ResetStreamAt(ResetStreamAt {
            stream_id: sid(0),
            application_error_code: vi(1),
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

/// Encodes `frame` through every entry point and checks that it decodes back.
fn assert_round_trip(frame: &Frame<'_>) -> Vec<u8> {
    let mut encoding = Vec::new();
    frame.encode(&mut encoding).unwrap();
    assert_eq!(encoding.len(), frame.encoded_len(), "{frame:?}");
    assert_eq!(
        VarInt::decode(&encoding).unwrap().0,
        frame.type_value(),
        "{frame:?}"
    );

    // A slice of exactly the encoded length takes the frame.
    let mut exact = vec![0; encoding.len()];
    let mut cursor = exact.as_mut_slice();
    frame.encode(&mut cursor).unwrap();
    assert!(cursor.is_empty());
    assert_eq!(exact, encoding);

    let (decoded, len) = Frame::decode(&encoding, Extensions::ALL).unwrap();
    assert_eq!((&decoded, len), (frame, encoding.len()), "{encoding:02x?}");

    // The operation writes the same bytes.
    let mut written = Vec::new();
    written.sync_write_frame_unpin(frame).unwrap();
    assert_eq!(written, encoding, "{frame:?}");
    encoding
}

#[test]
fn every_frame_round_trips() {
    for frame in sample_frames() {
        assert_round_trip(&frame);
    }
}

#[test]
fn encoding_fails_without_writing_when_room_is_short() {
    for frame in sample_frames() {
        let required = frame.encoded_len();
        let mut buffer = vec![0xee; required - 1];
        let mut cursor = buffer.as_mut_slice();
        assert_eq!(
            frame.encode(&mut cursor),
            Err(EncodeError::Capacity {
                required,
                available: required - 1
            })
        );
        assert_eq!(cursor.len(), required - 1);
        assert!(buffer.iter().all(|&byte| byte == 0xee), "{frame:?}");
    }
}

#[test]
fn stream_type_bits() {
    for frame_type in 0x08..=0x0fu8 {
        let mut encoding = vec![frame_type, 0x04];
        if frame_type & 0x04 != 0 {
            encoding.push(0x05);
        }
        if frame_type & 0x02 != 0 {
            encoding.push(0x02);
        }
        encoding.extend_from_slice(b"ab");
        let (frame, len) = Frame::decode(&encoding, Extensions::NONE).unwrap();
        assert_eq!(len, encoding.len());
        let Frame::Stream(stream) = frame else {
            panic!("{frame:?}")
        };
        let offset = if frame_type & 0x04 != 0 { 5 } else { 0 };
        assert_eq!(
            stream,
            Stream {
                stream_id: sid(4),
                offset: vi(offset),
                data: b"ab",
                fin: frame_type & 0x01 != 0,
                has_length: frame_type & 0x02 != 0,
            }
        );
        assert_eq!(stream.type_value(), vi(frame_type.into()));
        let mut reencoded = Vec::new();
        stream.encode(&mut reencoded).unwrap();
        assert_eq!(reencoded, encoding);
    }
}

#[test]
fn stream_without_length_takes_the_rest_of_the_payload() {
    // PING, then STREAM 0x09 (FIN, no OFF, no LEN) on stream 1.
    let payload = [0x01, 0x09, 0x01, b'a', b'b', 0x01, 0x00];
    let frames: Vec<_> = Frames::new(&payload, Extensions::NONE).collect();
    assert_eq!(
        frames,
        [
            Ok(Frame::Ping(Ping)),
            Ok(Frame::Stream(Stream {
                stream_id: sid(1),
                offset: VarInt::ZERO,
                data: &[b'a', b'b', 0x01, 0x00],
                fin: true,
                has_length: false,
            })),
        ]
    );
}

#[test]
fn padding_runs_are_one_value() {
    let payload = [0x00, 0x00, 0x00, 0x01, 0x00];
    let mut frames = Frames::new(&payload, Extensions::NONE);
    assert_eq!(
        frames.next(),
        Some(Ok(Frame::Padding(Padding {
            len: NonZeroUsize::new(3).unwrap()
        })))
    );
    assert_eq!(frames.offset(), 3);
    assert_eq!(frames.next(), Some(Ok(Frame::Ping(Ping))));
    assert_eq!(frames.remainder(), [0x00]);
    assert_eq!(
        frames.next(),
        Some(Ok(Frame::Padding(Padding {
            len: NonZeroUsize::MIN
        })))
    );
    assert_eq!(frames.next(), None);
    // A longer encoding of type 0 is one PADDING frame of that length.
    assert_eq!(
        Frame::decode(&[0x40, 0x00, 0x00], Extensions::NONE),
        Ok((
            Frame::Padding(Padding {
                len: NonZeroUsize::new(2).unwrap()
            }),
            2
        ))
    );
}

fn ranges<'a>(
    ranges: &'a [RangeInclusive<u64>],
) -> impl Iterator<Item = RangeInclusive<u64>> + Clone + 'a {
    ranges.iter().cloned()
}

#[test]
fn ack_with_several_ranges_and_ecn_counts() {
    // Largest 100, delay 5, two more ranges; ranges 97..=100, gap 1 then 90..=94,
    // gap 0 then 88..=88; ECN counts 1, 2, 3.
    let encoding = [
        0x03, 0x40, 100, 0x05, 0x02, 0x03, 0x01, 0x04, 0x00, 0x00, 0x01, 0x02, 0x03,
    ];
    let expected = [97..=100, 90..=94, 88..=88];
    let (frame, len) = Frame::decode(&encoding, Extensions::NONE).unwrap();
    assert_eq!(len, encoding.len());
    let Frame::Ack(ack) = &frame else {
        panic!("{frame:?}")
    };
    assert_eq!(ack.ack_delay, vi(5));
    assert_eq!(ack.largest_acknowledged(), Some(100));
    assert_eq!(ack.ranges.len(), 3);
    assert_eq!(ack.ranges.clone().collect::<Vec<_>>(), expected);
    assert_eq!(
        ack.ecn_counts,
        Some(EcnCounts {
            ect0: vi(1),
            ect1: vi(2),
            ce: vi(3),
        })
    );
    assert!(!frame.is_ack_eliciting());
    assert!(!frame.counts_in_flight());

    let built = Ack {
        ack_delay: vi(5),
        ranges: ranges(&expected),
        ecn_counts: ack.ecn_counts,
    };
    let mut encoded = Vec::new();
    built.encode(&mut encoded).unwrap();
    assert_eq!(encoded, encoding);
    assert_eq!(built.encoded_len(), encoding.len());
    assert_round_trip(&frame);
}

#[test]
fn ack_without_ecn_and_single_packet() {
    let built = Ack {
        ack_delay: VarInt::ZERO,
        ranges: ranges(&[0..=0]),
        ecn_counts: None,
    };
    let mut encoding = Vec::new();
    built.encode(&mut encoding).unwrap();
    assert_eq!(encoding, [0x02, 0x00, 0x00, 0x00, 0x00]);
    let (frame, _) = Frame::decode(&encoding, Extensions::NONE).unwrap();
    let Frame::Ack(ack) = &frame else {
        panic!("{frame:?}")
    };
    assert_eq!(ack.ranges.clone().collect::<Vec<_>>(), [0..=0]);
    assert_round_trip(&frame);

    // Ranges reaching the largest packet number.
    let max = VarInt::MAX.get();
    let wide = [max - 10..=max, 0..=max - 12];
    let built = Ack {
        ack_delay: vi(1),
        ranges: ranges(&wide),
        ecn_counts: None,
    };
    let mut encoding = Vec::new();
    built.encode(&mut encoding).unwrap();
    let (frame, _) = Frame::decode(&encoding, Extensions::NONE).unwrap();
    let Frame::Ack(ack) = &frame else {
        panic!("{frame:?}")
    };
    assert_eq!(
        ack.ranges.clone().collect::<Vec<_>>(),
        [max - 10..=max, 0..=max - 12]
    );
}

#[test]
fn ack_ranges_below_zero_are_rejected() {
    let cases: [(&[u8], u64); 3] = [
        // First ACK Range 6 below Largest Acknowledged 5.
        (&[0x02, 0x05, 0x00, 0x00, 0x06], 0),
        // 3..=5, then a gap of 2 reaches below 0.
        (&[0x02, 0x05, 0x00, 0x01, 0x02, 0x02, 0x00], 1),
        // 3..=5, gap 0 gives largest 1, length 2 reaches below 0.
        (&[0x02, 0x05, 0x00, 0x01, 0x02, 0x00, 0x02], 1),
    ];
    for (encoding, index) in cases {
        assert_eq!(
            Frame::decode(encoding, Extensions::NONE),
            Err(DecodeError::AckRange {
                offset: 0,
                frame_type: vi(2),
                index
            }),
            "{encoding:02x?}"
        );
    }
}

#[test]
fn ack_encoding_rejects_unordered_ranges() {
    let cases: [(&[RangeInclusive<u64>], InvalidFrameError); 6] = [
        (&[], InvalidFrameError::EmptyAck),
        (&[5..=3], InvalidFrameError::AckRange { index: 0 }),
        (&[1..=1, 5..=6], InvalidFrameError::AckRange { index: 1 }),
        // Adjacent ranges have no packet number between them.
        (&[5..=6, 3..=4], InvalidFrameError::AckRange { index: 1 }),
        (&[5..=6, 3..=5], InvalidFrameError::AckRange { index: 1 }),
        (
            &[VarInt::MAX.get()..=VarInt::MAX.get() + 1],
            InvalidFrameError::AckRange { index: 0 },
        ),
    ];
    for (ranges_in, error) in cases {
        let ack = Ack {
            ack_delay: VarInt::ZERO,
            ranges: ranges(ranges_in),
            ecn_counts: None,
        };
        assert_eq!(ack.validate(), Err(error), "{ranges_in:?}");
        let mut buffer = Vec::new();
        assert_eq!(
            ack.encode(&mut buffer),
            Err(EncodeError::Invalid { source: error })
        );
        assert!(buffer.is_empty());
    }
    // One packet number between ranges is enough.
    let ack = Ack {
        ack_delay: VarInt::ZERO,
        ranges: ranges(&[5..=6, 3..=3]),
        ecn_counts: None,
    };
    assert_eq!(ack.validate(), Ok(()));
}

#[test]
fn connection_close_types() {
    let transport = [0x1c, 0x07, 0x06, 0x03, b'b', b'a', b'd'];
    let (frame, _) = Frame::decode(&transport, Extensions::NONE).unwrap();
    let Frame::ConnectionClose(close) = frame else {
        panic!("{frame:?}")
    };
    assert_eq!(close.frame_type, Some(vi(0x06)));
    assert_eq!(close.reason_phrase, b"bad");
    assert_eq!(
        close.transport_error_code(),
        Some(TransportErrorCode::FRAME_ENCODING_ERROR)
    );
    assert!(!frame.is_ack_eliciting());

    let application = [0x1d, 0x41, 0x00, 0x00];
    let (frame, _) = Frame::decode(&application, Extensions::NONE).unwrap();
    let Frame::ConnectionClose(close) = frame else {
        panic!("{frame:?}")
    };
    assert_eq!((close.error_code, close.frame_type), (vi(0x100), None));
    assert_eq!(close.transport_error_code(), None);
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
        let error = Frame::decode(encoding, extensions).unwrap_err();
        let frame_type = VarInt::decode(encoding).unwrap().0;
        assert_eq!(
            error,
            DecodeError::UnknownType {
                offset: 0,
                frame_type
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR
        );
        assert_eq!(error.frame_type(), Some(frame_type));
    }
    assert!(Frame::decode(&[0x24, 0x00, 0x00, 0x00, 0x00], Extensions::ALL).is_ok());
    assert!(Frame::decode(&[0x30], Extensions::ALL).is_ok());
}

#[test]
fn truncated_frames_are_terminal() {
    let cases: [(&[u8], Option<u64>, usize); 7] = [
        // The type itself is cut short.
        (&[0x40], None, 2),
        (&[0x10], Some(0x10), 2),
        (&[0x10, 0x80, 0x00], Some(0x10), 5),
        // CRYPTO announcing 4 bytes with 2 present.
        (&[0x06, 0x00, 0x04, 0xaa, 0xbb], Some(0x06), 7),
        (&[0x1a, 1, 2, 3, 4, 5, 6, 7], Some(0x1a), 9),
        (&[0x18, 0x01, 0x00, 0x04, 1, 2, 3, 4, 0, 0], Some(0x18), 24),
        (&[0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02], Some(0x03), 8),
    ];
    for (encoding, frame_type, required) in cases {
        let error = Frame::decode(encoding, Extensions::NONE).unwrap_err();
        assert_eq!(
            error,
            DecodeError::Truncated {
                offset: 0,
                frame_type: frame_type.map(vi),
                required,
                available: encoding.len(),
            },
            "{encoding:02x?}"
        );
    }
    // In a payload, the offset names the frame that is cut short, and the
    // iteration ends with the error.
    let payload = [0x01, 0x01, 0x11, 0x04];
    let mut frames = Frames::new(&payload, Extensions::NONE);
    assert_eq!(frames.next(), Some(Ok(Frame::Ping(Ping))));
    assert_eq!(frames.next(), Some(Ok(Frame::Ping(Ping))));
    let error = frames.next().unwrap().unwrap_err();
    assert_eq!(error.offset(), 2);
    assert_eq!(
        error,
        DecodeError::Truncated {
            offset: 2,
            frame_type: Some(vi(0x11)),
            required: 5,
            available: 4
        }
    );
    assert_eq!(frames.next(), None);
}

#[test]
fn field_limits_are_checked_when_decoding() {
    let max = VarInt::MAX.get();
    let mut stream_end = vec![0x0e, 0x00];
    stream_end.extend_from_slice(&(max | 0xc000_0000_0000_0000).to_be_bytes());
    stream_end.extend_from_slice(&[0x01, 0xaa]);
    let mut stream_end_no_length = vec![0x0c, 0x00];
    stream_end_no_length.extend_from_slice(&(max | 0xc000_0000_0000_0000).to_be_bytes());
    stream_end_no_length.push(0xaa);
    let mut crypto_end = vec![0x06];
    crypto_end.extend_from_slice(&((max - 1) | 0xc000_0000_0000_0000).to_be_bytes());
    crypto_end.extend_from_slice(&[0x02, 0xaa, 0xbb]);
    let mut max_streams = vec![0x13];
    max_streams.extend_from_slice(&((MAX_STREAM_COUNT + 1) | 0xc000_0000_0000_0000).to_be_bytes());

    let cases: [(&[u8], DecodeError); 8] = [
        (
            &stream_end,
            DecodeError::DataEnd {
                offset: 0,
                frame_type: vi(0x0e),
                data_offset: vi(max),
                length: 1,
            },
        ),
        (
            &stream_end_no_length,
            DecodeError::DataEnd {
                offset: 0,
                frame_type: vi(0x0c),
                data_offset: vi(max),
                length: 1,
            },
        ),
        (
            &crypto_end,
            DecodeError::DataEnd {
                offset: 0,
                frame_type: vi(0x06),
                data_offset: vi(max - 1),
                length: 2,
            },
        ),
        (
            &max_streams,
            DecodeError::StreamCount {
                offset: 0,
                frame_type: vi(0x13),
                maximum_streams: vi(MAX_STREAM_COUNT + 1),
            },
        ),
        (
            &[0x18, 0x01, 0x00, 0x00],
            DecodeError::ConnectionIdLength {
                offset: 0,
                length: 0,
            },
        ),
        (
            &[0x18, 0x01, 0x00, 21],
            DecodeError::ConnectionIdLength {
                offset: 0,
                length: 21,
            },
        ),
        (&[0x07, 0x00], DecodeError::EmptyToken { offset: 0 }),
        (
            &[0x24, 0x00, 0x00, 0x05, 0x06],
            DecodeError::ReliableSize {
                offset: 0,
                final_size: vi(5),
                reliable_size: vi(6),
            },
        ),
    ];
    for (encoding, expected) in cases {
        let error = Frame::decode(encoding, Extensions::ALL).unwrap_err();
        assert_eq!(error, expected, "{encoding:02x?}");
        assert_eq!(
            error.frame_type(),
            Some(VarInt::decode(encoding).unwrap().0)
        );
    }

    let mut retire = vec![0x18, 0x01, 0x02, 0x01, 0xaa];
    retire.extend_from_slice(&TOKEN);
    assert_eq!(
        Frame::decode(&retire, Extensions::NONE),
        Err(DecodeError::RetirePriorTo {
            offset: 0,
            sequence_number: vi(1),
            retire_prior_to: vi(2),
        })
    );

    // The data may end exactly at 2^62 - 1.
    let mut at_limit = vec![0x0c, 0x00];
    at_limit.extend_from_slice(&((max - 1) | 0xc000_0000_0000_0000).to_be_bytes());
    at_limit.push(0xaa);
    assert!(Frame::decode(&at_limit, Extensions::NONE).is_ok());
}

#[test]
fn field_limits_are_checked_when_encoding() {
    let max = VarInt::MAX;
    let cases: [(Frame<'_>, InvalidFrameError); 7] = [
        (
            Frame::Stream(Stream {
                stream_id: sid(0),
                offset: max,
                data: b"x",
                fin: false,
                has_length: true,
            }),
            InvalidFrameError::DataEnd {
                frame_type: vi(0x0e),
                offset: max,
                length: 1,
            },
        ),
        (
            Frame::Crypto(Crypto {
                offset: max,
                data: b"x",
            }),
            InvalidFrameError::DataEnd {
                frame_type: vi(0x06),
                offset: max,
                length: 1,
            },
        ),
        (
            Frame::MaxStreams(MaxStreams {
                directionality: Directionality::Bidirectional,
                maximum_streams: vi(MAX_STREAM_COUNT + 1),
            }),
            InvalidFrameError::StreamCount {
                frame_type: vi(0x12),
                maximum_streams: vi(MAX_STREAM_COUNT + 1),
            },
        ),
        (
            Frame::NewConnectionId(NewConnectionId {
                sequence_number: vi(1),
                retire_prior_to: VarInt::ZERO,
                connection_id: &[],
                stateless_reset_token: &TOKEN,
            }),
            InvalidFrameError::ConnectionIdLength { length: 0 },
        ),
        (
            Frame::NewConnectionId(NewConnectionId {
                sequence_number: vi(1),
                retire_prior_to: vi(2),
                connection_id: &[1],
                stateless_reset_token: &TOKEN,
            }),
            InvalidFrameError::RetirePriorTo {
                sequence_number: vi(1),
                retire_prior_to: vi(2),
            },
        ),
        (
            Frame::NewToken(NewToken { token: b"" }),
            InvalidFrameError::EmptyToken,
        ),
        (
            Frame::ResetStreamAt(ResetStreamAt {
                stream_id: sid(0),
                application_error_code: VarInt::ZERO,
                final_size: vi(1),
                reliable_size: vi(2),
            }),
            InvalidFrameError::ReliableSize {
                final_size: vi(1),
                reliable_size: vi(2),
            },
        ),
    ];
    for (frame, error) in cases {
        assert_eq!(frame.validate(), Err(error));
        let mut buffer = Vec::new();
        assert_eq!(
            frame.encode(&mut buffer),
            Err(EncodeError::Invalid { source: error })
        );
        assert!(buffer.is_empty());
        let mut written = Vec::new();
        let failure = written.sync_write_frame_unpin(&frame).unwrap_err();
        assert!(matches!(failure, WriteFrameError::Invalid { source } if source == error));
        assert!(written.is_empty());
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
        assert_eq!(FrameType::of(frame.type_value()), Some(kind));
        assert_eq!(frame.is_ack_eliciting(), kind.is_ack_eliciting());
        assert_eq!(frame.counts_in_flight(), kind.counts_in_flight());
    }
    // Every value from 0x00 to 0x31 is either a known type or unknown.
    let known = (0..=0x31u32)
        .filter(|&value| FrameType::of(VarInt::from(value)).is_some())
        .count();
    assert_eq!(known, 0x1f + 1 + 2);
}

#[test]
fn max_data_len_fits_the_room_exactly() {
    let offsets = [VarInt::ZERO, vi(1), vi(1 << 20), vi(VarInt::MAX.get() - 3)];
    let rooms = (0..80).chain(16_370..16_400).chain([1 << 20]);
    for room in rooms {
        for offset in offsets {
            let crypto =
                |len: usize| Crypto { offset, data: &[] }.encoded_len() + len_field(len) - 1 + len;
            check_max(room, Crypto::max_data_len(offset, room), crypto, offset);
            for has_length in [false, true] {
                let stream = |len: usize| {
                    Stream {
                        stream_id: sid(1 << 10),
                        offset,
                        data: &[],
                        fin: false,
                        has_length,
                    }
                    .encoded_len()
                        + if has_length { len_field(len) - 1 } else { 0 }
                        + len
                };
                check_max(
                    room,
                    Stream::max_data_len(sid(1 << 10), offset, has_length, room),
                    stream,
                    offset,
                );
            }
        }
    }
}

fn len_field(len: usize) -> usize {
    VarInt::try_from(len).unwrap().encoded_len()
}

fn check_max(room: usize, max: Option<usize>, frame_len: impl Fn(usize) -> usize, offset: VarInt) {
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

#[test]
fn fixed_frames_read_through_operations() {
    for frame in sample_frames() {
        let mut encoding = Vec::new();
        frame.encode(&mut encoding).unwrap();
        let mut input = encoding.as_slice();
        let frame_type = input.sync_read_frame_type_unpin(Extensions::ALL).unwrap();
        assert_eq!(frame_type, frame.type_value());
        match input.sync_read_fixed_frame_unpin(frame_type) {
            Ok(read) => {
                // PADDING is read one byte at a time.
                let expected = match frame {
                    Frame::Padding(_) => Frame::Padding(Padding {
                        len: NonZeroUsize::MIN,
                    }),
                    _ => frame.clone(),
                };
                assert_eq!(read, expected);
                if !matches!(frame, Frame::Padding(_)) {
                    assert!(input.is_empty(), "{frame:?}");
                }
            }
            Err(ReadFixedFrameError::NotFixed {
                frame_type: rejected,
            }) => {
                assert_eq!(rejected, frame_type);
                assert!(matches!(
                    frame,
                    Frame::Crypto(_)
                        | Frame::NewToken(_)
                        | Frame::Stream(_)
                        | Frame::NewConnectionId(_)
                        | Frame::ConnectionClose(_)
                        | Frame::Datagram(_)
                ));
            }
            Err(error) => panic!("{frame:?}: {error:?}"),
        }
    }
}

#[test]
fn operations_reject_unknown_types_and_limits() {
    let mut input = &[0x30u8][..];
    assert!(matches!(
        input.sync_read_frame_type_unpin(Extensions::NONE),
        Err(ReadFrameTypeError::UnknownType { frame_type }) if frame_type == vi(0x30)
    ));
    let mut input = &[0x40u8][..];
    assert!(matches!(
        input.sync_read_frame_type_unpin(Extensions::NONE),
        Err(ReadFrameTypeError::Field { .. })
    ));
    let mut input = &[0x05u8, 0x06][..];
    assert!(matches!(
        input.sync_read_fixed_frame_unpin(vi(0x24)),
        Err(ReadFixedFrameError::Field { .. })
    ));
    let mut input = &[0x00u8, 0x00, 0x05, 0x06][..];
    assert!(matches!(
        input.sync_read_fixed_frame_unpin(vi(0x24)),
        Err(ReadFixedFrameError::ReliableSize { .. })
    ));
    let mut input = &[0x01u8, 0x02][..];
    assert!(matches!(
        input.sync_read_fixed_frame_unpin(vi(0x1a)),
        Err(ReadFixedFrameError::PathData { .. })
    ));
}

/// Reads a CRYPTO or STREAM frame, appending its data to `data`.
#[call(sync)]
async fn read_data_frame<F: ReadChunk, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    data: &mut Vec<u8>,
) -> Result<(Option<CryptoHeader>, Option<StreamHeader>, usize), String> {
    let chunk_maximum = NonZeroUsize::new(3).unwrap();
    let frame_type = io
        .read_frame_type(Extensions::NONE)
        .await
        .map_err(|_| "frame type")?;
    let mut chunks_read = 0;
    let (crypto, stream, length) = if frame_type == vi(0x06) {
        let header = io.read_crypto_header().await.map_err(|_| "crypto header")?;
        (Some(header), None, Some(header.length))
    } else {
        let header = io
            .read_stream_header(frame_type)
            .await
            .map_err(|_| "stream header")?;
        (None, Some(header), header.length)
    };
    match length {
        Some(length) => {
            let length = usize::try_from(length.get()).unwrap();
            let mut chunks = pin!(io.read_chunks_exact(length, chunk_maximum));
            loop {
                match chunks.as_mut().step().await {
                    ControlFlow::Continue(chunk) => {
                        chunks_read += 1;
                        data.put(chunk);
                    }
                    ControlFlow::Break(result) => break result.map_err(|_| "data")?,
                }
            }
        }
        None => {
            let mut chunks = pin!(io.read_chunks(usize::MAX, chunk_maximum));
            loop {
                match chunks.as_mut().step().await {
                    ControlFlow::Continue(chunk) => {
                        chunks_read += 1;
                        data.put(chunk);
                    }
                    ControlFlow::Break(result) => break result.map(|_| ()).map_err(|_| "data")?,
                }
            }
        }
    }
    Ok((crypto, stream, chunks_read))
}

#[test]
fn data_frames_read_header_then_chunks() {
    for frame in sample_frames() {
        let (Frame::Stream(_) | Frame::Crypto(_)) = frame else {
            continue;
        };
        let mut encoding = Vec::new();
        frame.encode(&mut encoding).unwrap();
        let mut input = encoding.as_slice();
        let mut data = Vec::new();
        let (crypto, stream, chunks) = input.sync_read_data_frame_unpin(&mut data).unwrap();
        assert!(input.is_empty());
        match frame {
            Frame::Crypto(expected) => {
                assert_eq!(
                    crypto,
                    Some(CryptoHeader {
                        offset: expected.offset,
                        length: vi(expected.data.len() as u64)
                    })
                );
                assert_eq!(data, expected.data);
                assert_eq!(chunks, expected.data.len().div_ceil(3));
            }
            Frame::Stream(expected) => {
                assert_eq!(
                    stream,
                    Some(StreamHeader {
                        stream_id: expected.stream_id,
                        offset: expected.offset,
                        length: expected.has_length.then(|| vi(expected.data.len() as u64)),
                        fin: expected.fin,
                    })
                );
                assert_eq!(data, expected.data);
                assert_eq!(chunks, expected.data.len().div_ceil(3));
            }
            _ => unreachable!(),
        }
    }
    // The Length field is missing.
    let mut input = &[0x00u8][..];
    assert!(input.sync_read_crypto_header_unpin().is_err());
}

#[test]
fn write_operation_reports_progress_when_the_sink_fills() {
    let frame = Frame::Crypto(Crypto {
        offset: vi(1),
        data: b"0123456789",
    });
    let mut buffer = [0u8; 5];
    let mut sink = buffer.as_mut_slice();
    let error = sink.sync_write_frame_unpin(&frame).unwrap_err();
    assert!(matches!(error, WriteFrameError::WriteZero { .. }));
    assert_eq!(error.completed(), 5);
    assert_eq!(buffer, [0x06, 0x01, 0x0a, b'0', b'1']);

    // Long padding runs and ACK frames are written piece by piece.
    let padding = Frame::Padding(Padding {
        len: NonZeroUsize::new(200).unwrap(),
    });
    let mut written = Vec::new();
    written.sync_write_frame_unpin(&padding).unwrap();
    assert_eq!(written, [0; 200]);
}
