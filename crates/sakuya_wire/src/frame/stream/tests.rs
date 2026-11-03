use super::{
    Stream,
    codec::{
        ReadStreamError, WriteStreamHostExt as _, WriteStreamWithLengthHostExt as _,
        WriteStreamWithoutLengthHostExt as _,
    },
};
use crate::{
    frame::{
        DataEndError, Extensions, Frame, InvalidDataError, LengthError, NoLength,
        codec::{ReadFrameError, ReadFrameHostExt as _},
        tests::{
            assert_round_trip, check_max, edge_fields, length_field, short, sid, stream_frame, vi,
            wide,
        },
    },
    stream_id::StreamId,
    var_int::{VarInt, VarIntField, VarIntWidth},
};
use either::Either;

#[test]
fn type_bits() {
    for frame_type in 0x08..=0x0fu8 {
        let mut encoding = vec![frame_type, 0x04];
        let has_offset = frame_type & 0x04 != 0;
        let has_length = frame_type & 0x02 != 0;
        let fin = frame_type & 0x01 != 0;
        if has_offset {
            encoding.push(0x05);
        }
        if has_length {
            encoding.push(0x02);
        }
        encoding.extend_from_slice(b"ab");
        let mut input = encoding.as_slice();
        let frame = input.sync_read_frame_unpin(Extensions::NONE).unwrap();
        assert!(input.is_empty());
        let Frame::Stream(stream) = frame else {
            panic!("{frame:?}")
        };
        let offset = has_offset.then(|| short(vi(5)));
        let length = has_length.then_some(VarIntWidth::One);
        assert_eq!(
            stream,
            stream_frame(short(sid(4)), offset, length, &b"ab"[..], fin).unwrap()
        );
        assert_eq!(stream.type_value(), vi(frame_type.into()));
        let mut rewritten = Vec::new();
        rewritten.sync_write_stream_unpin(stream).unwrap();
        assert_eq!(rewritten, encoding);
        assert_round_trip(frame);

        // The frame of the kind the LEN bit states writes the same bytes,
        // and converts into the frame that was read.
        let mut written = Vec::new();
        let converted: Stream<&[u8]> = match stream.length() {
            Either::Left(NoLength) => {
                let frame =
                    Stream::<_, NoLength>::new(short(sid(4)), offset, NoLength, &b"ab"[..], fin)
                        .unwrap();
                assert_eq!(frame.type_value(), vi(frame_type.into()));
                assert_eq!(frame.encoded_len(), encoding.len());
                written
                    .sync_write_stream_without_length_unpin(frame)
                    .unwrap();
                frame.into()
            }
            Either::Right(width) => {
                let frame =
                    Stream::<_, VarIntWidth>::new(short(sid(4)), offset, width, &b"ab"[..], fin)
                        .unwrap();
                assert_eq!(frame.type_value(), vi(frame_type.into()));
                assert_eq!(frame.encoded_len(), encoding.len());
                written.sync_write_stream_with_length_unpin(frame).unwrap();
                frame.into()
            }
        };
        assert_eq!(written, encoding);
        assert_eq!(converted, stream);
    }
}

#[test]
fn read_length_fields_are_kept() {
    // Both values of the LEN bit, with a Length field of every width.
    let without = assert_round_trip(Frame::Stream(
        stream_frame(short(sid(4)), None, None, &b"hi"[..], false).unwrap(),
    ));
    assert_eq!(without, [0x08, 0x04, b'h', b'i']);
    let mut input = without.as_slice();
    let Frame::Stream(stream) = input.sync_read_frame_unpin(Extensions::NONE).unwrap() else {
        panic!()
    };
    assert_eq!(stream.length(), Either::Left(NoLength));
    for width in VarIntWidth::ALL {
        let frame = stream_frame(short(sid(4)), None, Some(width), &b"hi"[..], false).unwrap();
        let encoding = assert_round_trip(Frame::Stream(frame));
        assert_eq!(encoding.len(), 2 + width.encoded_len() + 2);
        let mut input = encoding.as_slice();
        let Frame::Stream(stream) = input.sync_read_frame_unpin(Extensions::NONE).unwrap() else {
            panic!()
        };
        assert_eq!(stream.length(), Either::Right(width));
    }
}

#[test]
fn each_kind_of_length_field_checks_its_limits() {
    let data = [0; 64];
    let narrow = LengthError::check(64, VarIntWidth::One).unwrap_err();
    // A Length field must hold the length of the data.
    assert_eq!(
        Stream::<_, VarIntWidth>::new(short(sid(0)), None, VarIntWidth::One, &data[..], false),
        Err(InvalidDataError::Length { source: narrow })
    );
    assert_eq!(
        Stream::<_>::new(
            short(sid(0)),
            None,
            Either::Right(VarIntWidth::One),
            &data[..],
            false
        ),
        Err(InvalidDataError::Length { source: narrow })
    );
    let with_length =
        Stream::<_, VarIntWidth>::new(short(sid(0)), None, VarIntWidth::Two, &data[..], false);
    assert_eq!(with_length.unwrap().length(), VarIntWidth::Two);
    // Without a Length field, any length up to the end bound is accepted.
    let without_length =
        Stream::<_, NoLength>::new(short(sid(0)), None, NoLength, &data[..], false).unwrap();
    assert_eq!(without_length.length(), NoLength);
    let either = Stream::<_>::new(
        short(sid(0)),
        None,
        Either::Left(NoLength),
        &data[..],
        false,
    );
    assert_eq!(either, Ok(without_length.into()));
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
                        source
                    },
                    frame_type: rejected,
                } if source == DataEndError::check(VarInt::MAX, 1).unwrap_err()
                    && rejected.get() == vi(frame_type)
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

    // Construction rejects the same fields, for every kind of Length field.
    let error = DataEndError::check(VarInt::MAX, 1).unwrap_err();
    assert_eq!((error.offset(), error.length()), (VarInt::MAX, 1));
    // Data that ends exactly at the bound passes the check.
    assert_eq!(DataEndError::check(VarInt::MAX, 0), Ok(()));
    let offset = Some(short(VarInt::MAX));
    let data = &b"x"[..];
    assert_eq!(
        Stream::<_, NoLength>::new(short(sid(0)), offset, NoLength, data, false),
        Err(error)
    );
    assert_eq!(
        Stream::<_, VarIntWidth>::new(short(sid(0)), offset, VarIntWidth::One, data, false),
        Err(InvalidDataError::DataEnd { source: error })
    );
    for length_width in [Some(VarIntWidth::One), None] {
        assert_eq!(
            stream_frame(short(sid(0)), offset, length_width, data, false),
            Err(InvalidDataError::DataEnd { source: error })
        );
    }
    let at_limit = Stream::<_, NoLength>::new(short(sid(0)), offset, NoLength, &b""[..], true);
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
                let start = offset.map_or(VarInt::ZERO, |offset| offset.get());
                let empty = Stream::<_, NoLength>::new(stream_id, offset, NoLength, &[][..], false)
                    .unwrap()
                    .encoded_len();

                // With a Length field.
                let max = Stream::<&[u8], VarIntWidth>::max_data_len(stream_id, offset, room);
                check_max(room, max, |len| empty + length_field(len) + len, start);
                // The frame with that much data and the shortest Length
                // field takes at most `room`.
                if let Some(max) = max.filter(|&max| max <= 1 << 20) {
                    let data = vec![0; max];
                    let width = VarIntWidth::shortest(VarInt::try_from(max).unwrap());
                    let frame = Stream::<_, VarIntWidth>::new(
                        stream_id,
                        offset,
                        width,
                        data.as_slice(),
                        false,
                    )
                    .unwrap();
                    assert!(frame.encoded_len() <= room);
                }

                // Without a Length field.
                let max = Stream::<&[u8], NoLength>::max_data_len(stream_id, offset, room);
                check_max(room, max, |len| empty + len, start);
            }
        }
    }
}

#[test]
fn stream_ids_and_offsets_keep_their_widths() {
    for field in edge_fields() {
        let stream_id =
            VarIntField::new(StreamId::from_var_int(field.get()), field.width()).unwrap();
        let frame = stream_frame(stream_id, Some(field), None, &b""[..], true).unwrap();
        let encoding = assert_round_trip(Frame::Stream(frame));
        assert_eq!(encoding.len(), 1 + 2 * field.encoded_len());
    }
}
