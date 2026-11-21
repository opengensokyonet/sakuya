//! Variable-length integer fields of the value types of version 1.
use bytes::Bytes;
use core::fmt::Debug;
use sakuya_wire_v1::var_int::{
    VarInt, VarIntField, VarIntWidth,
    codec::{ReadVarIntFieldError, read_var_int, read_var_int_field, write_var_int_field},
};
use sakuya_wire_v1::{
    application_error::ApplicationErrorCode, packet_number::PacketNumber,
    stream_count::StreamCount, stream_id::StreamId, transport_error::TransportErrorCode,
};

/// The examples of RFC 9000 Appendix A.1.
const RFC_EXAMPLES: [(&[u8], u64); 4] = [
    (
        &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
        151_288_809_941_952_652,
    ),
    (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
    (&[0x7b, 0xbd], 15_293),
    (&[0x25], 37),
];

/// Values at the edges of each encoded length, with their shortest encodings.
const BOUNDARIES: [(&[u8], u64); 8] = [
    (&[0x00], 0),
    (&[0x3f], 63),
    (&[0x40, 0x40], 64),
    (&[0x7f, 0xff], 16_383),
    (&[0x80, 0x00, 0x40, 0x00], 16_384),
    (&[0xbf, 0xff, 0xff, 0xff], (1 << 30) - 1),
    (&[0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00], 1 << 30),
    (&[0xff; 8], (1 << 62) - 1),
];

fn var_int(value: u64) -> VarInt {
    VarInt::try_from(value).unwrap()
}

/// Values at the edges of each width, and the largest stream count.
const EDGES: [u64; 9] = [
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

/// Every width that holds `value`.
fn widths_for(value: VarInt) -> impl Iterator<Item = VarIntWidth> {
    VarIntWidth::ALL
        .into_iter()
        .filter(move |width| width.fits(value))
}

#[test]
fn fields_check_their_width() {
    for value in EDGES.map(var_int) {
        let shortest = VarIntField::shortest(value);
        assert_eq!(shortest.width(), VarIntWidth::shortest(value));
        assert_eq!(shortest.get(), value);
        for width in VarIntWidth::ALL {
            let field = VarIntField::new(value, width);
            if width.fits(value) {
                let field = field.unwrap();
                assert_eq!((field.get(), field.width()), (value, width));
                assert_eq!(field.encoded_len(), width.encoded_len());
                assert_eq!(field.to_var_int(), value);
                assert_eq!(field.into_inner(), value);
                assert_eq!(field == shortest, width == shortest.width());
            } else {
                let error = field.unwrap_err();
                assert_eq!((error.value(), error.width()), (value, width));
            }
        }
    }
    let error = VarIntField::new(var_int(64), VarIntWidth::One).unwrap_err();
    assert_eq!(
        error.to_string(),
        "64 does not fit a 1-byte variable-length integer encoding"
    );
    // A domain type is checked by its value as a variable-length integer.
    let stream_id = StreamId::from_var_int(var_int(16_384));
    assert!(VarIntField::new(stream_id, VarIntWidth::Two).is_err());
    assert_eq!(
        VarIntField::new(stream_id, VarIntWidth::Four).map(|field| field.get()),
        Ok(stream_id)
    );
}

/// Checks `T::try_from(VarInt::from(x)) == Ok(x)` for the values of `T`
/// that `values` produces.
fn assert_conversions_agree<T>(values: impl IntoIterator<Item = T>)
where
    T: Copy + PartialEq + Debug + Into<VarInt> + TryFrom<VarInt, Error: Debug + PartialEq>,
{
    for value in values {
        assert_eq!(T::try_from(value.into()), Ok(value), "{value:?}");
    }
}

#[test]
fn field_types_convert_back_and_forth() {
    let values = || EDGES.map(var_int);
    assert_conversions_agree(values());
    assert_conversions_agree(values().map(StreamId::from_var_int));
    assert_conversions_agree(values().map(PacketNumber::from_var_int));
    assert_conversions_agree(values().map(ApplicationErrorCode::new));
    assert_conversions_agree(values().map(TransportErrorCode::from));
    assert_conversions_agree(
        values()
            .into_iter()
            .filter_map(|value| StreamCount::try_from(value).ok()),
    );
    assert_conversions_agree((0..=u8::MAX).map(Small));
}

/// Writes `field`, checks the length of the encoding, and reads it back from
/// a byte slice and from `Bytes`.
fn assert_field_round_trip<T>(field: VarIntField<T>) -> Vec<u8>
where
    T: Copy + PartialEq + Debug + Into<VarInt> + TryFrom<VarInt, Error: Debug>,
{
    let mut encoding = Vec::new();
    write_var_int_field(&mut encoding, field);
    assert_eq!(encoding.len(), field.encoded_len(), "{field:?}");
    let mut input = encoding.as_slice();
    let read: VarIntField<T> = read_var_int_field(&mut input).unwrap();
    assert_eq!(read, field);
    assert!(input.is_empty());
    let mut input = Bytes::from(encoding.clone());
    let read: VarIntField<T> = read_var_int_field(&mut input).unwrap();
    assert_eq!(read, field);
    // The variable-length integer reader decodes the same value.
    assert_eq!(
        read_var_int(&mut encoding.as_slice()).unwrap(),
        field.to_var_int()
    );
    encoding
}

#[test]
fn fields_round_trip_at_every_width() {
    for value in EDGES.map(var_int) {
        for width in widths_for(value) {
            let field = VarIntField::new(value, width).unwrap();
            let encoding = assert_field_round_trip(field);
            assert_eq!(VarIntWidth::of_first_byte(encoding[0]), width);
            let stream_id = VarIntField::new(StreamId::from_var_int(value), width).unwrap();
            assert_eq!(assert_field_round_trip(stream_id), encoding);
        }
    }
    // The examples of RFC 9000 Appendix A.1, including 0x4025 for 37.
    for (encoding, value) in RFC_EXAMPLES
        .into_iter()
        .chain(BOUNDARIES)
        .chain([(&[0x40, 0x25][..], 37)])
    {
        let mut input = encoding;
        let field: VarIntField<VarInt> = read_var_int_field(&mut input).unwrap();
        assert_eq!(field.get(), var_int(value));
        assert_eq!(field.encoded_len(), encoding.len());
        let mut rewritten = Vec::new();
        write_var_int_field(&mut rewritten, field);
        assert_eq!(rewritten, encoding);
    }
}

/// A type that holds only the values that fit a byte, standing in for a
/// type defined outside this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Small(u8);

impl From<Small> for VarInt {
    fn from(value: Small) -> Self {
        Self::from(value.0)
    }
}

impl TryFrom<VarInt> for Small {
    type Error = core::num::TryFromIntError;

    fn try_from(value: VarInt) -> Result<Self, Self::Error> {
        u8::try_from(value.get()).map(Self)
    }
}

#[test]
fn stream_count_fields_stop_at_2_60() {
    let field = VarIntField::shortest(StreamCount::MAX);
    assert_eq!(field.width(), VarIntWidth::Eight);
    let mut above = assert_field_round_trip(field);
    above[7] += 1;
    let mut input = above.as_slice();
    let error = read_var_int_field::<StreamCount>(&mut input).unwrap_err();
    assert!(matches!(
        error,
        ReadVarIntFieldError::Value {
            source,
            ..
        } if source.value() == (1 << 60) + 1
    ));
}
