use super::{
    OutOfRangeError, VarInt,
    codec::{ReadVarIntError, ReadVarIntHostExt as _, WriteVarIntError, WriteVarIntHostExt as _},
};
use bytes::Bytes;
use nitori_io::bridge::Std;
use std::io;

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
            input.sync_read_var_int_unpin().unwrap(),
            var_int(value),
            "{encoding:02x?}"
        );
        assert!(input.is_empty());
        let mut input = Bytes::copy_from_slice(encoding);
        assert_eq!(input.sync_read_var_int_unpin().unwrap(), var_int(value));
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
    assert_eq!(input.sync_read_var_int_unpin().unwrap(), var_int(37));
    let mut input = &[0xc0, 0, 0, 0, 0, 0, 0, 0x25][..];
    assert_eq!(input.sync_read_var_int_unpin().unwrap(), var_int(37));
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
        let error = input.sync_read_var_int_unpin().unwrap_err();
        let ReadVarIntError::Incomplete { source: incomplete } = &error else {
            panic!("expected Incomplete, got {error:?}");
        };
        assert_eq!(
            (incomplete.expected, incomplete.completed),
            (encoded_len, encoding.len()),
            "{encoding:02x?}"
        );
        assert!(error.is_incomplete());
    }
}

#[test]
fn write_into_a_full_slice_reports_progress() {
    let mut storage = [0xaa; 3];
    let mut output = &mut storage[..];
    let error = output
        .sync_write_var_int_unpin(var_int(494_878_333))
        .unwrap_err();
    assert!(matches!(error, WriteVarIntError::WriteZero { .. }));
    assert_eq!(error.completed(), 3);
    assert_eq!(storage, [0x9d, 0x7f, 0x3e]);

    let mut storage = [0; 2];
    let mut output = &mut storage[..];
    output.sync_write_var_int_unpin(var_int(15_293)).unwrap();
    assert!(output.is_empty());
    assert_eq!(storage, [0x7b, 0xbd]);
}

#[test]
fn constructors_check_the_range() {
    assert_eq!(VarInt::MAX.get(), (1 << 62) - 1);
    assert_eq!(VarInt::try_from((1u64 << 62) - 1), Ok(VarInt::MAX));
    assert_eq!(
        VarInt::try_from(1u64 << 62),
        Err(OutOfRangeError { value: 1 << 62 })
    );
    assert_eq!(
        VarInt::new(u64::MAX),
        Err(OutOfRangeError { value: u64::MAX })
    );
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
fn read_operation_reads_exactly_one_encoding() {
    for (encoding, value) in RFC_EXAMPLES.into_iter().chain(BOUNDARIES) {
        let input = [encoding, &[0x25]].concat();
        let mut source = input.as_slice();
        assert_eq!(source.sync_read_var_int_unpin().unwrap(), var_int(value));
        assert_eq!(source, [0x25]);
    }
}

/// A source that yields one byte per read and fails once it is exhausted.
struct Trickle<'a> {
    bytes: &'a [u8],
}

impl io::Read for Trickle<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Some((&first, rest)) = self.bytes.split_first() else {
            return Err(io::Error::other("source failed"));
        };
        if buffer.is_empty() {
            return Ok(0);
        }
        buffer[0] = first;
        self.bytes = rest;
        Ok(1)
    }
}

#[test]
fn read_operation_accumulates_short_reads() {
    let (encoding, value) = RFC_EXAMPLES[0];
    let mut source = Std::new(Trickle { bytes: encoding });
    assert_eq!(source.sync_read_var_int_unpin().unwrap(), var_int(value));
}

#[test]
fn read_operation_reports_an_ended_source() {
    let mut source = &[][..];
    let error = source.sync_read_var_int_unpin().unwrap_err();
    let ReadVarIntError::Incomplete { source: incomplete } = &error else {
        panic!("expected Incomplete, got {error:?}");
    };
    assert_eq!((incomplete.expected, incomplete.completed), (1, 0));
    assert_eq!(error.completed(), 0);

    let mut source = &[0x9d, 0x7f][..];
    let error = source.sync_read_var_int_unpin().unwrap_err();
    let ReadVarIntError::Incomplete { source: incomplete } = &error else {
        panic!("expected Incomplete, got {error:?}");
    };
    assert_eq!((incomplete.expected, incomplete.completed), (4, 2));
    assert!(error.host_error().is_none());
    assert!(source.is_empty());
}

#[test]
fn read_operation_keeps_the_receiver_error() {
    let mut source = Std::new(Trickle {
        bytes: &[0xc2, 0x19, 0x7c],
    });
    let error = source.sync_read_var_int_unpin().unwrap_err();
    assert!(matches!(
        error,
        ReadVarIntError::Receiver { completed: 3, .. }
    ));
    assert_eq!(error.completed(), 3);
    assert_eq!(error.host_error().unwrap().to_string(), "source failed");

    let mut source = Std::new(Trickle { bytes: &[] });
    let error = source.sync_read_var_int_unpin().unwrap_err();
    assert!(matches!(
        error,
        ReadVarIntError::Receiver { completed: 0, .. }
    ));
}

#[test]
fn write_operation_writes_the_shortest_encoding() {
    for (encoding, value) in RFC_EXAMPLES.into_iter().chain(BOUNDARIES) {
        let mut output = Vec::new();
        output.sync_write_var_int_unpin(var_int(value)).unwrap();
        assert_eq!(output, encoding);
    }
}

/// A sink that accepts up to `room` bytes, one per write, then fails or stops
/// accepting.
struct Narrow {
    accepted: Vec<u8>,
    room: usize,
    fail: bool,
}

impl io::Write for Narrow {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.accepted.len() == self.room {
            return if self.fail {
                Err(io::Error::other("sink failed"))
            } else {
                Ok(0)
            };
        }
        let Some(&first) = input.first() else {
            return Ok(0);
        };
        self.accepted.push(first);
        Ok(1)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn write_operation_accumulates_short_writes() {
    let (encoding, value) = RFC_EXAMPLES[1];
    let mut sink = Std::new(Narrow {
        accepted: Vec::new(),
        room: usize::MAX,
        fail: false,
    });
    sink.sync_write_var_int_unpin(var_int(value)).unwrap();
    assert_eq!(sink.into_inner().accepted, encoding);
}

#[test]
fn write_operation_reports_failures_with_progress() {
    let value = var_int(RFC_EXAMPLES[0].1);
    let mut sink = Std::new(Narrow {
        accepted: Vec::new(),
        room: 5,
        fail: true,
    });
    let error = sink.sync_write_var_int_unpin(value).unwrap_err();
    assert!(matches!(
        error,
        WriteVarIntError::Receiver { completed: 5, .. }
    ));
    assert_eq!(error.host_error().unwrap().to_string(), "sink failed");

    let mut sink = Std::new(Narrow {
        accepted: Vec::new(),
        room: 2,
        fail: false,
    });
    let error = sink.sync_write_var_int_unpin(value).unwrap_err();
    assert!(matches!(error, WriteVarIntError::WriteZero { .. }));
    assert_eq!(error.completed(), 2);
    assert!(error.host_error().is_none());
}
