use super::{CryptoFrame, codec::ReadCryptoFrameError};
use crate::frame::codec::ReadFieldsError;
use crate::frame::set::codec::ReadFrameError;
use crate::frame::tests::ReadOneFrame as _;
use crate::frame::{DataEndError, InvalidDataError, LengthError};
use crate::frame::{
    Frame,
    tests::{assert_round_trip, check_max, length_field, short, vi, wide},
};
use sakuya_var_int::{VarInt, VarIntWidth};
use sakuya_wire::parts::{Coproduct, PartsError};

#[test]
fn round_trips() {
    let encoding = assert_round_trip(Frame::Crypto(
        CryptoFrame::new(short(vi(1)), VarIntWidth::One, &b"hello"[..]).unwrap(),
    ));
    assert_eq!(encoding, [0x06, 0x01, 0x05, b'h', b'e', b'l', b'l', b'o']);
    let encoding = assert_round_trip(Frame::Crypto(
        CryptoFrame::new(
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
        input.read_one_frame(),
        Err(ReadFrameError::Fields { source: PartsError(Coproduct::Inl(ReadFieldsError::Crypto {
            source: ReadCryptoFrameError::DataEnd { source },
            ..
        })) }) if source == expected
    ));

    // Construction rejects the same fields.
    let expected = InvalidDataError::DataEnd {
        source: DataEndError::check(VarInt::MAX, 1).unwrap_err(),
    };
    assert_eq!(
        CryptoFrame::new(short(VarInt::MAX), VarIntWidth::One, &b"x"[..]),
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
        CryptoFrame::new(short(VarInt::ZERO), VarIntWidth::One, &data[..]),
        Err(expected)
    );
    assert_eq!(
        expected.to_string(),
        "field of 64 bytes is longer than a 1-byte Length field can state"
    );
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
                CryptoFrame::new(offset, VarIntWidth::One, &[][..])
                    .unwrap()
                    .encoded_len()
                    + length_field(len)
                    - 1
                    + len
            };
            let max = CryptoFrame::<&[u8]>::max_data_len(offset, room);
            check_max(room, max, frame_len, offset.get());
            if let Some(max) = max.filter(|&max| max <= 1 << 20) {
                let data = vec![0; max];
                let length_width = VarIntWidth::shortest(VarInt::try_from(max).unwrap());
                let frame = CryptoFrame::new(offset, length_width, data.as_slice()).unwrap();
                assert!(frame.encoded_len() <= room);
            }
        }
    }
}
