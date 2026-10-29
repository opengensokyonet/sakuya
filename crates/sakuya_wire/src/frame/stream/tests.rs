use super::{
    Stream,
    codec::{ReadStreamError, WriteStreamError, WriteStreamHostExt as _},
};
use crate::{
    frame::{
        DataEndError, Extensions, Frame,
        codec::{ReadFrameError, ReadFrameHostExt as _},
        tests::{assert_round_trip, check_max, length_field, sid, vi},
    },
    var_int::VarInt,
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
        let offset = if frame_type & 0x04 != 0 { 5 } else { 0 };
        assert_eq!(
            stream,
            Stream {
                stream_id: sid(4),
                offset: vi(offset),
                data: &b"ab"[..],
                fin: frame_type & 0x01 != 0,
                has_length: frame_type & 0x02 != 0,
            }
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

    let frame = Stream {
        stream_id: sid(0),
        offset: VarInt::MAX,
        data: &b"x"[..],
        fin: false,
        has_length: true,
    };
    let expected = DataEndError {
        offset: VarInt::MAX,
        length: 1,
    };
    assert_eq!(frame.validate(), Err(expected));
    let mut written = Vec::new();
    assert!(matches!(
        written.sync_write_stream_unpin(frame),
        Err(WriteStreamError::Invalid { source }) if source == expected
    ));
    assert!(written.is_empty());
}

#[test]
fn max_data_len_fits_the_room_exactly() {
    let offsets = [VarInt::ZERO, vi(1), vi(1 << 20), vi(VarInt::MAX.get() - 3)];
    let rooms = (0..80).chain(16_370..16_400).chain([1 << 20]);
    for room in rooms {
        for offset in offsets {
            for has_length in [false, true] {
                let frame_len = |len: usize| {
                    Stream {
                        stream_id: sid(1 << 10),
                        offset,
                        data: &[][..],
                        fin: false,
                        has_length,
                    }
                    .encoded_len()
                        + if has_length { length_field(len) - 1 } else { 0 }
                        + len
                };
                check_max(
                    room,
                    Stream::<&[u8]>::max_data_len(sid(1 << 10), offset, has_length, room),
                    frame_len,
                    offset,
                );
            }
        }
    }
}
