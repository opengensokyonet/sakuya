use super::{StreamDataInput, StreamDataInputError};
use bytes::Bytes;
use sakuya_var_int::VarInt;

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

#[test]
fn input_rejects_inconsistent_shapes() {
    assert_eq!(
        StreamDataInput::new(v(10), v(5), false, Bytes::new()),
        Err(StreamDataInputError::EndBeforeOffset {
            offset: v(10),
            end: v(5),
        })
    );
    assert_eq!(
        StreamDataInput::new(v(0), v(2), false, Bytes::from_static(b"abc")),
        Err(StreamDataInputError::PayloadBeyondEnd {
            offset: v(0),
            end: v(2),
            payload_len: 3,
        })
    );
    // A payload that would end beyond the largest offset passes any end.
    assert!(matches!(
        StreamDataInput::new(VarInt::MAX, VarInt::MAX, false, Bytes::from_static(b"a")),
        Err(StreamDataInputError::PayloadBeyondEnd { .. })
    ));
    let trimmed = StreamDataInput::new(v(0), v(10), true, Bytes::from_static(b"abc")).unwrap();
    assert_eq!(trimmed.payload_end(), v(3));
    assert_eq!(trimmed.into_parts().1, v(10));
}
