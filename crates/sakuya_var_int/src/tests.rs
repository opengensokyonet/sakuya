use super::{
    VarInt, VarIntField, VarIntWidth,
    codec::{
        ReadVarIntFieldError, read_var_int, read_var_int_field, write_var_int, write_var_int_field,
    },
};
use bytes::Bytes;
use core::{convert::Infallible, fmt::Debug};
use nitori_io::error::IncompleteError;

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

#[test]
fn reads_rfc_examples_and_boundaries() {
    for (encoding, value) in RFC_EXAMPLES.into_iter().chain(BOUNDARIES) {
        let mut input = encoding;
        assert_eq!(
            read_var_int(&mut input).unwrap(),
            var_int(value),
            "{encoding:02x?}"
        );
        assert!(input.is_empty());
        let mut input = Bytes::copy_from_slice(encoding);
        assert_eq!(read_var_int(&mut input).unwrap(), var_int(value));
        assert!(input.is_empty());
    }
}

#[test]
fn writes_rfc_examples_and_boundaries_shortest() {
    for (encoding, value) in RFC_EXAMPLES.into_iter().chain(BOUNDARIES) {
        let value = var_int(value);
        assert_eq!(value.encoded_len(), encoding.len(), "{value}");
    }
}

#[test]
fn reads_longer_than_necessary_encodings() {
    // RFC 9000 Appendix A.1: 0x4025 also decodes to 37.
    let mut input = &[0x40, 0x25][..];
    assert_eq!(read_var_int(&mut input).unwrap(), var_int(37));
    let mut input = &[0xc0, 0, 0, 0, 0, 0, 0, 0x25][..];
    assert_eq!(read_var_int(&mut input).unwrap(), var_int(37));
    assert!(input.is_empty());
}

#[test]
fn reports_each_truncated_length() {
    let cases: [(&[u8], usize); 4] = [
        (&[0x40], 2),
        (&[0x9d, 0x7f, 0x3e], 4),
        (&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8], 8),
        (&[0x7b], 2),
    ];
    for (encoding, encoded_len) in cases {
        let mut input = encoding;
        let error = read_var_int(&mut input).unwrap_err();
        assert_eq!(
            (error.expected(), error.completed()),
            (encoded_len, encoding.len()),
            "{encoding:02x?}"
        );
        assert!(input.is_empty());
    }
}

#[test]
fn constructors_check_the_range() {
    assert_eq!(VarInt::MAX.get(), (1 << 62) - 1);
    assert_eq!(VarInt::try_from((1u64 << 62) - 1), Ok(VarInt::MAX));
    let error = VarInt::try_from(1u64 << 62).unwrap_err();
    assert_eq!(error.value(), 1 << 62);
    assert_eq!(VarInt::new(1 << 62), Err(error));
    assert_eq!(VarInt::new(u64::MAX).unwrap_err().value(), u64::MAX);
    assert!(VarInt::try_from(usize::MAX).is_err());
    assert_eq!(VarInt::try_from(1200usize), Ok(var_int(1200)));
    assert_eq!(VarInt::from(u32::MAX).get(), u64::from(u32::MAX));
    assert_eq!(VarInt::from(u16::MAX).get(), u64::from(u16::MAX));
    assert_eq!(VarInt::from(u8::MAX).get(), u64::from(u8::MAX));
    assert_eq!(u64::from(var_int(37)), 37);
    assert_eq!(VarInt::default(), VarInt::ZERO);
}

#[test]
fn arithmetic_stays_in_range() {
    let one = var_int(1);
    assert_eq!(VarInt::MAX.checked_add(one), None);
    assert_eq!(var_int(2).checked_add(one), Some(var_int(3)));
    assert_eq!(VarInt::ZERO.checked_sub(one), None);
    assert_eq!(var_int(3).checked_sub(one), Some(var_int(2)));
    assert_eq!(var_int(1 << 31).checked_mul(var_int(1 << 31)), None);
    assert_eq!(var_int(1 << 60).checked_mul(var_int(4)), None);
    assert_eq!(
        var_int(1 << 60).checked_mul(var_int(3)),
        Some(var_int(3 << 60))
    );
    assert_eq!(
        var_int(1 << 30).checked_mul(var_int(2)),
        Some(var_int(1 << 31))
    );
    assert_eq!(VarInt::MAX.checked_mul(VarInt::MAX), None);
    assert_eq!(VarInt::MAX.saturating_add(one), VarInt::MAX);
    assert_eq!(var_int(2).saturating_add(one), var_int(3));
    assert_eq!(VarInt::ZERO.saturating_sub(one), VarInt::ZERO);
    assert!(var_int(63) < var_int(64));
}

#[test]
fn encoded_len_of_first_byte() {
    assert_eq!(VarInt::encoded_len_of(0x25), 1);
    assert_eq!(VarInt::encoded_len_of(0x7b), 2);
    assert_eq!(VarInt::encoded_len_of(0x9d), 4);
    assert_eq!(VarInt::encoded_len_of(0xc2), 8);
}

#[test]
fn formats_as_the_number() {
    assert_eq!(var_int(15_293).to_string(), "15293");
    assert_eq!(format!("{:?}", var_int(37)), "VarInt(37)");
}

#[test]
fn reads_exactly_one_encoding() {
    for (encoding, value) in RFC_EXAMPLES.into_iter().chain(BOUNDARIES) {
        let input = [encoding, &[0x25]].concat();
        let mut source = input.as_slice();
        assert_eq!(read_var_int(&mut source).unwrap(), var_int(value));
        assert_eq!(source, [0x25]);
    }
}

#[test]
fn reports_an_ended_source() {
    let mut source = &[][..];
    let error = read_var_int(&mut source).unwrap_err();
    assert_eq!((error.expected(), error.completed()), (1, 0));

    let mut source = &[0x9d, 0x7f][..];
    let error = read_var_int(&mut source).unwrap_err();
    assert_eq!((error.expected(), error.completed()), (4, 2));
    assert!(source.is_empty());
}

#[test]
fn writes_the_shortest_encoding() {
    for (encoding, value) in RFC_EXAMPLES.into_iter().chain(BOUNDARIES) {
        let mut output = Vec::new();
        write_var_int(&mut output, var_int(value));
        assert_eq!(output, encoding);
    }
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

#[test]
fn widths_hold_their_ranges() {
    let cases = [
        (VarIntWidth::One, 1, 63),
        (VarIntWidth::Two, 2, 16_383),
        (VarIntWidth::Four, 4, (1 << 30) - 1),
        (VarIntWidth::Eight, 8, (1 << 62) - 1),
    ];
    for (width, encoded_len, max) in cases {
        assert_eq!(width.encoded_len(), encoded_len);
        assert_eq!(width.max_value(), var_int(max));
        assert!(width.fits(var_int(max)));
        if max < VarInt::MAX.get() {
            assert!(!width.fits(var_int(max + 1)));
            assert!(VarIntWidth::shortest(var_int(max + 1)) > width);
        }
        assert_eq!(VarIntWidth::shortest(var_int(max)), width);
    }
    assert_eq!(VarIntWidth::ALL.map(VarIntWidth::encoded_len), [1, 2, 4, 8]);
    for byte in 0..=u8::MAX {
        assert_eq!(
            VarIntWidth::of_first_byte(byte).encoded_len(),
            VarInt::encoded_len_of(byte)
        );
    }
    for value in EDGES {
        assert_eq!(
            VarIntWidth::shortest(var_int(value)).encoded_len(),
            var_int(value).encoded_len()
        );
    }
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
fn field_reads_report_values_the_type_rejects() {
    let field = VarIntField::new(Small(200), VarIntWidth::Four).unwrap();
    assert_eq!(assert_field_round_trip(field), [0x80, 0x00, 0x00, 200]);

    let mut input = &[0x41, 0x00, 0x25][..];
    let error = read_var_int_field::<Small>(&mut input).unwrap_err();
    assert!(
        matches!(error, ReadVarIntFieldError::Value { value, .. } if value == var_int(256)),
        "{error:?}"
    );
    assert_eq!(
        error.to_string(),
        "variable-length integer 256 is outside the range of the field"
    );
    // The encoding is consumed; the next byte is not.
    assert_eq!(input, [0x25]);

    let mut input = &[0x80, 0x00][..];
    let error = read_var_int_field::<Small>(&mut input).unwrap_err();
    assert!(matches!(error, ReadVarIntFieldError::VarInt { .. }));
    let mut input = &[0x80, 0x00][..];
    let error: ReadVarIntFieldError<Infallible> =
        read_var_int_field::<VarInt>(&mut input).unwrap_err();
    let error = IncompleteError::from(error);
    assert_eq!((error.expected(), error.completed()), (4, 2));
}

mod stream;
