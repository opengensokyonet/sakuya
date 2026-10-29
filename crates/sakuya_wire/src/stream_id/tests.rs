use super::{
    Directionality, Initiator, StreamId, StreamIndexError,
    codec::{ReadStreamIdHostExt as _, WriteStreamIdHostExt as _},
};
use crate::var_int::VarInt;

fn stream_id(value: u32) -> StreamId {
    StreamId::from(VarInt::from(value))
}

#[test]
fn reads_the_type_bits() {
    // RFC 9000 §2.1, Table 1.
    let types = [
        (0x00, Initiator::Client, Directionality::Bidirectional),
        (0x01, Initiator::Server, Directionality::Bidirectional),
        (0x02, Initiator::Client, Directionality::Unidirectional),
        (0x03, Initiator::Server, Directionality::Unidirectional),
    ];
    for (bits, initiator, directionality) in types {
        for index in [0, 1, 1000] {
            let id = stream_id(index << 2 | bits);
            assert_eq!(id.initiator(), initiator, "{id}");
            assert_eq!(id.directionality(), directionality, "{id}");
            assert_eq!(id.index(), u64::from(index), "{id}");
            assert_eq!(
                StreamId::new(initiator, directionality, u64::from(index)),
                Ok(id)
            );
        }
    }
}

#[test]
fn composes_up_to_the_largest_index() {
    assert_eq!(StreamId::MAX_INDEX, (1 << 60) - 1);
    let last = StreamId::new(
        Initiator::Server,
        Directionality::Unidirectional,
        StreamId::MAX_INDEX,
    )
    .unwrap();
    assert_eq!(last.get(), VarInt::MAX);
    assert_eq!(last.index(), StreamId::MAX_INDEX);
    assert_eq!(
        StreamId::new(
            Initiator::Client,
            Directionality::Bidirectional,
            StreamId::MAX_INDEX + 1
        ),
        Err(StreamIndexError {
            index: StreamId::MAX_INDEX + 1
        })
    );
}

#[test]
fn converts_and_formats_as_the_number() {
    let id = stream_id(0x0d);
    assert_eq!(VarInt::from(id), VarInt::from(0x0du8));
    assert_eq!(id.get(), VarInt::from(0x0du8));
    assert_eq!(id.to_string(), "13");
    assert!(stream_id(4) < stream_id(5));
    assert_eq!(StreamId::default(), stream_id(0));
    assert_eq!(StreamId::from_var_int(VarInt::from(9u8)), stream_id(9));
}

#[test]
fn reads_and_writes_as_a_variable_length_integer() {
    for value in [0, 63, 64, 1 << 20] {
        let id = stream_id(value);
        let mut output = Vec::new();
        output.sync_write_stream_id_unpin(id).unwrap();
        assert_eq!(output.len(), id.get().encoded_len());
        let mut input = output.as_slice();
        assert_eq!(input.sync_read_stream_id_unpin().unwrap(), id);
        assert!(input.is_empty());
    }
    let mut input = &[0x40][..];
    assert!(
        input
            .sync_read_stream_id_unpin()
            .unwrap_err()
            .is_incomplete()
    );
}
