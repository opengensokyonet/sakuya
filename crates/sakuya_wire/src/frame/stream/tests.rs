use super::{
    Stream,
    codec::{ReadStreamError, WriteStreamHostExt as _},
};
use crate::{
    frame::{
        DataEndError, Extensions, Frame, InvalidDataError,
        codec::{ReadFrameError, ReadFrameHostExt as _},
        tests::{assert_round_trip, check_max, edge_fields, length_field, short, sid, vi, wide},
    },
    stream_id::StreamId,
    var_int::{VarInt, VarIntField, VarIntWidth},
};

#[test]
fn type_bits() {
    for frame_type in 0x08..=0x0fu8 {
        let mut encoding = vec![frame_type, 0x04];
        if frame_type & 0x04 != 0 {
            encoding.push(0x05);
        }
        if frame_type & 0x02 != 0 {
            encoding.push(0x02);
        }
        encoding.extend_from_slice(b"ab");
        let mut input = encoding.as_slice();
        let frame = input.sync_read_frame_unpin(Extensions::NONE).unwrap();
        assert!(input.is_empty());
        let Frame::Stream(stream) = frame else {
            panic!("{frame:?}")
        };
        assert_eq!(
            stream,
            Stream::new(
                short(sid(4)),
                (frame_type & 0x04 != 0).then(|| short(vi(5))),
                (frame_type & 0x02 != 0).then_some(VarIntWidth::One),
                &b"ab"[..],
                frame_type & 0x01 != 0,
            )
            .unwrap()
        );
        assert_eq!(stream.type_value(), vi(frame_type.into()));
        let mut rewritten = Vec::new();
        rewritten.sync_write_stream_unpin(stream).unwrap();
        assert_eq!(rewritten, encoding);
        assert_round_trip(frame);
    }
}

#[test]
fn data_ending_beyond_2_62_is_rejected() {
    let max = VarInt::MAX.get();
    let mut with_length = vec![0x0e, 0x00];
    with_length.extend_from_slice(&(max | 0xc000_0000_0000_0000).to_be_bytes());
    with_length.extend_from_slice(&[0x01, 0xaa]);
    let mut without_length = vec![0x0c, 0x00];
    without_length.extend_from_slice(&(max | 0xc000_0000_0000_0000).to_be_bytes());
    without_length.push(0xaa);
    for (encoding, frame_type) in [(with_length, 0x0e), (without_length, 0x0c)] {
        let mut input = encoding.as_slice();
        let error = input.sync_read_frame_unpin(Extensions::NONE).unwrap_err();
        assert!(
            matches!(
                error,
                ReadFrameError::Stream {
                    source: ReadStreamError::DataEnd {
                        source: DataEndError { offset, length: 1 }
                    },
                    ..
                } if offset == VarInt::MAX
            ),
            "{error:?}"
        );
        assert_eq!(error.frame_type(), Some(vi(frame_type)));
    }

    // The data may end exactly at 2^62 - 1.
    let mut at_limit = vec![0x0c, 0x00];
    at_limit.extend_from_slice(&((max - 1) | 0xc000_0000_0000_0000).to_be_bytes());
    at_limit.push(0xaa);
    let mut input = at_limit.as_slice();
    assert!(input.sync_read_frame_unpin(Extensions::NONE).is_ok());

    // Construction rejects the same fields, with and without a Length
    // field.
    let expected = InvalidDataError::DataEnd {
        source: DataEndError {
            offset: VarInt::MAX,
            length: 1,
        },
    };
    for length_width in [Some(VarIntWidth::One), None] {
        let offset = Some(short(VarInt::MAX));
        assert_eq!(
            Stream::new(short(sid(0)), offset, length_width, &b"x"[..], false),
            Err(expected)
        );
    }
    let at_limit = Stream::new(
        short(sid(0)),
        Some(short(VarInt::MAX)),
        None,
        &b""[..],
        true,
    );
    assert!(at_limit.is_ok());
}

#[test]
fn max_data_len_fits_the_room_exactly() {
    let offsets = [
        None,
        Some(short(VarInt::ZERO)),
        Some(wide(VarInt::ZERO, VarIntWidth::Eight)),
        Some(short(vi(1))),
        Some(short(vi(1 << 20))),
        Some(short(vi(VarInt::MAX.get() - 3))),
    ];
    let stream_ids = [short(sid(1 << 10)), wide(sid(1 << 10), VarIntWidth::Eight)];
    let rooms = (0..80).chain(16_370..16_400).chain([1 << 20]);
    for room in rooms {
        for offset in offsets {
            for stream_id in stream_ids {
                for has_length in [false, true] {
                    let frame_len = |len: usize| {
                        let length_width = has_length.then_some(VarIntWidth::One);
                        Stream::new(stream_id, offset, length_width, &[][..], false)
                            .unwrap()
                            .encoded_len()
                            + if has_length { length_field(len) - 1 } else { 0 }
                            + len
                    };
                    let max = Stream::<&[u8]>::max_data_len(stream_id, offset, has_length, room);
                    check_max(
                        room,
                        max,
                        frame_len,
                        offset.map_or(VarInt::ZERO, |offset| offset.get()),
                    );
                    // The frame with that much data and the shortest Length
                    // field takes at most `room`.
                    if let Some(max) = max.filter(|&max| max <= 1 << 20) {
                        let data = vec![0; max];
                        let length_width = has_length
                            .then(|| VarIntWidth::shortest(VarInt::try_from(max).unwrap()));
                        let frame =
                            Stream::new(stream_id, offset, length_width, data.as_slice(), false)
                                .unwrap();
                        assert!(frame.encoded_len() <= room);
                    }
                }
            }
        }
    }
}

#[test]
fn stream_ids_and_offsets_keep_their_widths() {
    for field in edge_fields() {
        let stream_id =
            VarIntField::new(StreamId::from_var_int(field.get()), field.width()).unwrap();
        let frame = Stream::new(stream_id, Some(field), None, &b""[..], true).unwrap();
        let encoding = assert_round_trip(Frame::Stream(frame));
        assert_eq!(encoding.len(), 1 + 2 * field.encoded_len());
    }
}
