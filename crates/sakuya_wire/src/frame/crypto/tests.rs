use super::{
    Crypto,
    codec::{ReadCryptoError, WriteCryptoHostExt as _},
};
use crate::{
    frame::{
        DataEndError, Extensions, Frame, InvalidDataError, LengthError,
        codec::{ReadFrameError, ReadFrameHostExt as _},
        tests::{assert_round_trip, check_max, length_field, short, vi, wide},
    },
    var_int::{VarInt, VarIntWidth},
};

#[test]
fn round_trips() {
    let encoding = assert_round_trip(Frame::Crypto(
        Crypto::new(short(vi(1)), VarIntWidth::One, &b"hello"[..]).unwrap(),
    ));
    assert_eq!(encoding, [0x06, 0x01, 0x05, b'h', b'e', b'l', b'l', b'o']);
    let encoding = assert_round_trip(Frame::Crypto(
        Crypto::new(
            wide(vi(1), VarIntWidth::Four),
            VarIntWidth::Two,
            &b"hello"[..],
        )
        .unwrap(),
    ));
    assert_eq!(
        encoding,
        [
            0x06, 0x80, 0, 0, 0x01, 0x40, 0x05, b'h', b'e', b'l', b'l', b'o'
        ]
    );
}

#[test]
fn data_ending_beyond_2_62_is_rejected() {
    let max = VarInt::MAX.get();
    let mut encoding = vec![0x06];
    encoding.extend_from_slice(&((max - 1) | 0xc000_0000_0000_0000).to_be_bytes());
    encoding.extend_from_slice(&[0x02, 0xaa, 0xbb]);
    let expected = DataEndError::check(vi(max - 1), 2).unwrap_err();
    let mut input = encoding.as_slice();
    assert!(matches!(
        input.sync_read_frame_unpin(Extensions::NONE),
        Err(ReadFrameError::Crypto {
            source: ReadCryptoError::DataEnd { source },
            ..
        }) if source == expected
    ));

    // Construction rejects the same fields.
    let expected = InvalidDataError::DataEnd {
        source: DataEndError::check(VarInt::MAX, 1).unwrap_err(),
    };
    assert_eq!(
        Crypto::new(short(VarInt::MAX), VarIntWidth::One, &b"x"[..]),
        Err(expected)
    );
}

#[test]
fn narrow_length_fields_are_rejected() {
    let data = [0; 64];
    let expected = InvalidDataError::Length {
        source: LengthError::check(64, VarIntWidth::One).unwrap_err(),
    };
    assert_eq!(
        Crypto::new(short(VarInt::ZERO), VarIntWidth::One, &data[..]),
        Err(expected)
    );
    assert_eq!(
        expected.to_string(),
        "field of 64 bytes is longer than a 1-byte Length field can state"
    );
}

#[test]
fn write_reports_progress_when_the_sink_fills() {
    let frame = Crypto::new(short(vi(1)), VarIntWidth::One, &b"0123456789"[..]).unwrap();
    let mut buffer = [0u8; 5];
    let mut sink = buffer.as_mut_slice();
    let error = sink.sync_write_crypto_unpin(frame).unwrap_err();
    assert_eq!(error.completed(), 5);
    assert_eq!(buffer, [0x06, 0x01, 0x0a, b'0', b'1']);
}

#[test]
fn max_data_len_fits_the_room_exactly() {
    let offsets = [
        short(VarInt::ZERO),
        wide(VarInt::ZERO, VarIntWidth::Four),
        short(vi(1)),
        short(vi(1 << 20)),
        short(vi(VarInt::MAX.get() - 3)),
    ];
    let rooms = (0..80).chain(16_370..16_400).chain([1 << 20]);
    for room in rooms {
        for offset in offsets {
            let frame_len = |len: usize| {
                Crypto::new(offset, VarIntWidth::One, &[][..])
                    .unwrap()
                    .encoded_len()
                    + length_field(len)
                    - 1
                    + len
            };
            let max = Crypto::<&[u8]>::max_data_len(offset, room);
            check_max(room, max, frame_len, offset.get());
            if let Some(max) = max.filter(|&max| max <= 1 << 20) {
                let data = vec![0; max];
                let length_width = VarIntWidth::shortest(VarInt::try_from(max).unwrap());
                let frame = Crypto::new(offset, length_width, data.as_slice()).unwrap();
                assert!(frame.encoded_len() <= room);
            }
        }
    }
}
