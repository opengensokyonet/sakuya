//! Variable-length integers against quinn-proto and s2n-quic-core.
use proptest::prelude::*;
use sakuya_wire::var_int::{VarInt, VarIntWidth};
use wire_differential::{
    cases,
    generate::{var_int, var_int_as},
    var_int::*,
};

fn check(bytes: &[u8]) {
    let ours = read_sakuya(bytes);
    assert_eq!(ours, read_sakuya_field(bytes), "{bytes:02x?}");
    assert_eq!(ours, read_quinn(bytes), "{bytes:02x?}");
    assert_eq!(ours, read_s2n(bytes), "{bytes:02x?}");
}

#[test]
fn every_encoding_of_at_most_two_bytes() {
    check(&[]);
    for first in 0..=255u8 {
        check(&[first]);
        for second in 0..=255u8 {
            check(&[first, second]);
        }
    }
}

proptest! {
    #![proptest_config(cases::config(100_000))]

    #[test]
    fn reads_agree_on_any_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..10)) {
        check(&bytes);
    }

    #[test]
    fn writes_agree(value in var_int()) {
        let ours = write_sakuya(value);
        prop_assert_eq!(&ours, &write_quinn(value));
        prop_assert_eq!(&ours, &write_s2n(value));
        prop_assert_eq!(read_sakuya(&ours), Some((value, ours.len())));
    }

    /// An encoding of any width that holds the value reads to the same value
    /// everywhere.
    #[test]
    fn wider_encodings_agree(value in var_int(), extra in 0usize..4) {
        let shortest = VarIntWidth::shortest(VarInt::new(value).unwrap()) as usize;
        let width = VarIntWidth::ALL[(shortest + extra).min(3)];
        let bytes = write_sakuya_as(value, width);
        prop_assert_eq!(bytes.len(), width.encoded_len());
        prop_assert_eq!(&bytes, &var_int_as(value, width.encoded_len()));
        check(&bytes);
        prop_assert_eq!(read_sakuya(&bytes), Some((value, bytes.len())));
    }
}
