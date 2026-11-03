//! The frames of RFC 9000 §19 at the edges of their fields, through the public
//! interface.
use core::convert::Infallible;
use sakuya_wire::{
    frame::{
        Extensions, Frame, FrameType,
        codec::{ReadFrameError, ReadFrameHostExt as _},
    },
    packet_number::PacketNumber,
    stream_id::Directionality,
    transport_error::TransportErrorCode,
    var_int::{VarInt, VarIntField, VarIntWidth, codec::WriteVarIntHostExt as _},
};

const MAX: u64 = (1 << 62) - 1;
const MAX_STREAMS: u64 = 1 << 60;

fn var(value: u64) -> Vec<u8> {
    let mut output = Vec::new();
    output
        .sync_write_var_int_unpin(VarInt::new(value).unwrap())
        .unwrap();
    output
}

fn frame(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn read(bytes: &[u8]) -> Result<(Frame<&[u8]>, usize), ReadFrameError<Infallible>> {
    let mut input = bytes;
    let frame = input.sync_read_frame_unpin(Extensions::NONE)?;
    Ok((frame, bytes.len() - input.len()))
}

/// Reads a whole frame.
fn accepts(bytes: &[u8]) -> Frame<&[u8]> {
    let (frame, consumed) = read(bytes).unwrap_or_else(|error| panic!("{bytes:02x?}: {error}"));
    assert_eq!(consumed, bytes.len(), "{bytes:02x?}");
    frame
}

/// The bytes fail as FRAME_ENCODING_ERROR, naming the frame's type, without
/// being a truncation.
fn rejects(bytes: &[u8]) {
    let error = read(bytes).expect_err("accepted");
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::FRAME_ENCODING_ERROR
    );
    assert_eq!(error.frame_type(), Some(VarInt::from(bytes[0])));
    assert!(!error.is_incomplete(), "{bytes:02x?}: {error}");
}

/// Every proper prefix of a frame fails as incomplete, with
/// FRAME_ENCODING_ERROR.
fn prefixes_are_incomplete(bytes: &[u8]) {
    for cut in 0..bytes.len() {
        let error = read(&bytes[..cut]).expect_err("a prefix was accepted");
        assert!(error.is_incomplete(), "{:02x?}: {error}", &bytes[..cut]);
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR
        );
    }
}

/// The packet number ranges of an ACK frame, smallest and largest, largest
/// range first.
fn ranges(frame: &Frame<&[u8]>) -> Vec<(u64, u64)> {
    let Frame::Ack(ack) = frame else {
        panic!("{frame:?}")
    };
    ack.packet_ranges()
        .map(|range| (range.start().get(), range.end().get()))
        .collect()
}

#[test]
fn every_single_byte_type_is_defined_or_unknown() {
    let defined = 0x00..=0x1e;
    for value in 0u8..=0x3f {
        let kind = FrameType::of(VarInt::from(value));
        let extension = matches!(value, 0x24 | 0x30 | 0x31);
        assert_eq!(
            kind.is_ok(),
            defined.contains(&value) || extension,
            "{value:#x}"
        );
        if defined.contains(&value) {
            continue;
        }
        // Without the extensions enabled, all of these are unknown.
        let error = read(&[value]).unwrap_err();
        assert!(
            matches!(error, ReadFrameError::UnknownType { .. }),
            "{value:#x}: {error}"
        );
        assert_eq!(error.frame_type(), Some(VarInt::from(value)));
    }
}

#[test]
fn frame_types_above_one_byte_are_unknown() {
    for bytes in [&[0x40, 0x40][..], &[0x7f, 0xff], &[0xff; 8]] {
        let error = read(bytes).unwrap_err();
        assert!(matches!(error, ReadFrameError::UnknownType { .. }));
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::FRAME_ENCODING_ERROR
        );
    }
}

/// RFC 9000 §12.4 lets a reader treat a longer encoding of the Frame Type as
/// a PROTOCOL_VIOLATION; this reader does, for defined types too.
#[test]
fn longer_encodings_of_a_type_are_protocol_violations() {
    let encodings: [&[u8]; 3] = [
        &[0x40, 0x01],
        &[0x80, 0, 0, 0x01],
        &[0xc0, 0, 0, 0, 0, 0, 0, 0x1e],
    ];
    for bytes in encodings {
        let error = read(bytes).unwrap_err();
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::PROTOCOL_VIOLATION,
            "{bytes:02x?}"
        );
        assert!(!error.is_incomplete(), "{bytes:02x?}");
    }
    // The type value of the failure is what the reader saw.
    let error = read(&[0x40, 0x07, 0x00]).unwrap_err();
    assert_eq!(error.frame_type(), Some(VarInt::from(7u8)));
}

/// RFC 9000 §19.3: ACK ranges at packet number zero and at the largest value.
#[test]
fn ack_ranges_reach_the_edges_of_the_packet_numbers() {
    // Largest 5, First ACK Range 5: down to exactly zero.
    let frame_bytes = [0x02, 5, 0, 0, 5];
    assert_eq!(ranges(&accepts(&frame_bytes)), [(0, 5)]);
    // First ACK Range one past the largest.
    rejects(&[0x02, 5, 0, 0, 6]);
    // Largest 5, first range 0, Gap 3: the next range ends at 5 - 3 - 2 = 0.
    assert_eq!(
        ranges(&accepts(&[0x02, 5, 0, 1, 0, 3, 0])),
        [(5, 5), (0, 0)]
    );
    // Gap 4 would end at -1.
    rejects(&[0x02, 5, 0, 1, 0, 4, 0]);
    // Range length 1 from an end at 0 would start at -1.
    rejects(&[0x02, 5, 0, 1, 0, 3, 1]);
    // The largest values.
    let largest = frame(&[&[0x02], &var(MAX), &var(MAX), &[0], &var(MAX)]);
    assert_eq!(ranges(&accepts(&largest)), [(0, MAX)]);
    let Frame::Ack(ack) = accepts(&largest) else {
        panic!()
    };
    assert_eq!(ack.largest_acknowledged().get(), PacketNumber::MAX);
    assert_eq!(ack.ack_delay().get(), VarInt::MAX);
    prefixes_are_incomplete(&largest);
}

#[test]
fn ack_range_count_is_not_trusted() {
    // A count of 2^62 - 1 with one pair present.
    let bytes = frame(&[&[0x02, 5, 0], &var(MAX), &[0, 0, 0]]);
    assert!(read(&bytes).unwrap_err().is_incomplete());
}

#[test]
fn ack_ecn_counts_follow_the_ranges() {
    let bytes = frame(&[&[0x03, 1, 0, 0, 0], &var(1), &var(2), &var(MAX)]);
    let Frame::Ack(ack) = accepts(&bytes) else {
        panic!()
    };
    let counts = ack.ecn_counts().unwrap();
    assert_eq!(
        (
            counts.ect0.get().get(),
            counts.ect1.get().get(),
            counts.ce.get().get()
        ),
        (1, 2, MAX)
    );
    prefixes_are_incomplete(&bytes);
    assert!(
        accepts(&[0x02, 1, 0, 0, 0]) != accepts(&[0x03, 1, 0, 0, 0, 0, 0, 0]),
        "the counts are present"
    );
}

#[test]
fn reset_stream_and_stop_sending_take_the_largest_values() {
    let bytes = frame(&[&[0x04], &var(MAX), &var(MAX), &var(MAX)]);
    let Frame::ResetStream(reset) = accepts(&bytes) else {
        panic!()
    };
    assert_eq!(reset.stream_id().get().get(), VarInt::MAX);
    assert_eq!(reset.final_size().get(), VarInt::MAX);
    prefixes_are_incomplete(&bytes);
    let bytes = frame(&[&[0x05], &var(MAX), &var(MAX)]);
    assert!(matches!(accepts(&bytes), Frame::StopSending(_)));
    prefixes_are_incomplete(&bytes);
}

/// RFC 9000 §19.6: the end of the data is at most 2^62 - 1.
#[test]
fn crypto_data_ends_at_the_largest_offset() {
    let bytes = frame(&[&[0x06], &var(MAX - 1), &[1, 0xaa]]);
    assert!(matches!(accepts(&bytes), Frame::Crypto(_)));
    let bytes = frame(&[&[0x06], &var(MAX), &[0]]);
    let Frame::Crypto(crypto) = accepts(&bytes) else {
        panic!()
    };
    assert_eq!(
        (crypto.offset().get(), *crypto.data()),
        (VarInt::MAX, &b""[..])
    );
    // The check needs only the fields, not the data.
    rejects(&frame(&[&[0x06], &var(MAX), &[1]]));
    rejects(&frame(&[&[0x06], &var(1), &var(MAX)]));
    assert!(read(&[0x06, 0, 4, 1, 2, 3]).unwrap_err().is_incomplete());
    prefixes_are_incomplete(&[0x06, 0, 3, 1, 2, 3]);
}

/// RFC 9000 §19.7: an empty token is a FRAME_ENCODING_ERROR.
#[test]
fn new_token_is_not_empty() {
    rejects(&[0x07, 0]);
    assert!(matches!(accepts(&[0x07, 1, 0xaa]), Frame::NewToken(_)));
    prefixes_are_incomplete(&[0x07, 2, 1, 2]);
}

/// RFC 9000 §19.8: the eight STREAM types and the fields their bits announce.
#[test]
fn stream_type_bits_announce_the_fields() {
    for type_value in 0x08u8..=0x0f {
        let (off, len, fin) = (
            type_value & 0x04 != 0,
            type_value & 0x02 != 0,
            type_value & 0x01 != 0,
        );
        let mut bytes = vec![type_value, 0x04];
        if off {
            bytes.push(0x09);
        }
        if len {
            bytes.push(2);
        }
        bytes.extend([0xaa, 0xbb]);
        let Frame::Stream(stream) = accepts(&bytes) else {
            panic!()
        };
        assert_eq!(stream.stream_id().get().get(), VarInt::from(4u8));
        assert_eq!(
            stream.offset().map(|offset| offset.get().get()),
            off.then_some(9)
        );
        assert_eq!(stream.data_offset().get(), if off { 9 } else { 0 });
        assert_eq!(*stream.data(), [0xaa, 0xbb]);
        assert_eq!((stream.fin(), stream.length_width().is_some()), (fin, len));
        assert_eq!(accepts(&bytes).type_value().get(), u64::from(type_value));
    }
}

#[test]
fn stream_data_ends_at_the_largest_offset() {
    // With and without a Length field.
    let at_limit = frame(&[&[0x0e], &var(0), &var(MAX - 1), &[1, 0xaa]]);
    assert!(matches!(accepts(&at_limit), Frame::Stream(_)));
    rejects(&frame(&[&[0x0e], &var(0), &var(MAX), &[1]]));
    let at_limit = frame(&[&[0x0c], &var(0), &var(MAX - 1), &[0xaa]]);
    assert!(matches!(accepts(&at_limit), Frame::Stream(_)));
    rejects(&frame(&[&[0x0c], &var(0), &var(MAX), &[0xaa]]));
    assert!(matches!(
        accepts(&frame(&[&[0x0c], &var(0), &var(MAX)])),
        Frame::Stream(_)
    ));
    // An Offset field with the value zero is kept, with its OFF bit.
    let Frame::Stream(stream) = accepts(&[0x0e, 0, 0, 1, 0xaa]) else {
        panic!()
    };
    assert_eq!(stream.offset(), Some(VarIntField::shortest(VarInt::ZERO)));
    assert_eq!(stream.data_offset(), VarInt::ZERO);
    assert_eq!(stream.type_value().get(), 0x0e);
    prefixes_are_incomplete(&[0x0e, 4, 9, 2, 0xaa, 0xbb]);
}

#[test]
fn integer_frames_take_the_largest_values() {
    for type_value in [0x10u8, 0x14, 0x19] {
        let bytes = frame(&[&[type_value], &var(MAX)]);
        accepts(&bytes);
        prefixes_are_incomplete(&bytes);
    }
    for type_value in [0x11u8, 0x15] {
        let bytes = frame(&[&[type_value], &var(MAX), &var(MAX)]);
        accepts(&bytes);
        prefixes_are_incomplete(&bytes);
    }
}

/// RFC 9000 §19.11, §19.14: stream counts are at most 2^60.
#[test]
fn stream_counts_stop_at_2_60() {
    for (type_value, directionality) in [
        (0x12u8, Directionality::Bidirectional),
        (0x13, Directionality::Unidirectional),
        (0x16, Directionality::Bidirectional),
        (0x17, Directionality::Unidirectional),
    ] {
        let bytes = frame(&[&[type_value], &var(MAX_STREAMS)]);
        match accepts(&bytes) {
            Frame::MaxStreams(frame) => assert_eq!(frame.directionality(), directionality),
            Frame::StreamsBlocked(frame) => assert_eq!(frame.directionality(), directionality),
            other => panic!("{other:?}"),
        }
        rejects(&frame(&[&[type_value], &var(MAX_STREAMS + 1)]));
        rejects(&frame(&[&[type_value], &var(MAX)]));
        prefixes_are_incomplete(&bytes);
    }
}

/// RFC 9000 §19.15.
#[test]
fn new_connection_id_lengths_and_retire_prior_to() {
    let token = [0x5a; 16];
    let with = |sequence: u64, retire: u64, cid: &[u8]| {
        frame(&[
            &[0x18],
            &var(sequence),
            &var(retire),
            &[cid.len() as u8],
            cid,
            &token,
        ])
    };
    for length in [1, 20] {
        let bytes = with(3, 3, &vec![0xcc; length]);
        let Frame::NewConnectionId(new_id) = accepts(&bytes) else {
            panic!()
        };
        assert_eq!(new_id.connection_id().as_bytes().len(), length);
        assert_eq!(new_id.stateless_reset_token().as_bytes(), &token);
        prefixes_are_incomplete(&bytes);
    }
    rejects(&with(3, 3, &[]));
    rejects(&with(3, 3, &[0xcc; 21]));
    // The largest length a byte states, with no bytes behind it.
    rejects(&[0x18, 0, 0, 255]);
    rejects(&with(3, 4, &[0xcc]));
    accepts(&with(MAX, MAX, &[0xcc]));
    rejects(&with(MAX - 1, MAX, &[0xcc]));
}

#[test]
fn path_frames_hold_exactly_eight_bytes() {
    for type_value in [0x1au8, 0x1b] {
        let bytes = [type_value, 1, 2, 3, 4, 5, 6, 7, 8];
        accepts(&bytes);
        prefixes_are_incomplete(&bytes);
        // A ninth byte is the next frame.
        let (_, consumed) = read(&[type_value, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert_eq!(consumed, 9);
    }
}

/// RFC 9000 §19.19: only type 0x1c carries a Frame Type field.
#[test]
fn connection_close_fields_follow_the_type() {
    let transport = frame(&[&[0x1c], &var(MAX), &var(MAX), &[2, b'n', b'o']]);
    accepts(&transport);
    prefixes_are_incomplete(&transport);
    let application = frame(&[&[0x1d], &var(MAX), &[2, b'n', b'o']]);
    accepts(&application);
    prefixes_are_incomplete(&application);
    // The reason phrase is not required to be UTF-8 here.
    accepts(&[0x1d, 0, 2, 0xff, 0xfe]);
    assert!(
        read(&frame(&[&[0x1d], &[0], &var(MAX)]))
            .unwrap_err()
            .is_incomplete()
    );
}

/// RFC 9000 §16: fields other than the Frame Type need not be shortest. They
/// read as the same values, and the frame keeps the widths it was read with.
#[test]
fn fields_may_use_longer_encodings() {
    let Frame::ResetStream(shortest) = accepts(&[0x04, 0x01, 0x02, 0x03]) else {
        panic!()
    };
    let longer = [
        0x04, 0x40, 0x01, 0x80, 0, 0, 0x02, 0xc0, 0, 0, 0, 0, 0, 0, 0x03,
    ];
    let Frame::ResetStream(reset) = accepts(&longer) else {
        panic!()
    };
    assert_eq!(
        (
            reset.stream_id().get(),
            reset.application_error_code().get(),
            reset.final_size().get()
        ),
        (
            shortest.stream_id().get(),
            shortest.application_error_code().get(),
            shortest.final_size().get()
        )
    );
    assert_eq!(
        (
            reset.stream_id().width(),
            reset.application_error_code().width(),
            reset.final_size().width()
        ),
        (VarIntWidth::Two, VarIntWidth::Four, VarIntWidth::Eight)
    );
    let (Frame::NewToken(longer), Frame::NewToken(shortest)) = (
        accepts(&[0x07, 0x40, 0x01, 0xaa]),
        accepts(&[0x07, 1, 0xaa]),
    ) else {
        panic!()
    };
    assert_eq!(longer.token(), shortest.token());
    assert_eq!(longer.token_length_width(), VarIntWidth::Two);
}
