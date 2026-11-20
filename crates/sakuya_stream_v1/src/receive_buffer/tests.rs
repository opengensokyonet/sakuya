use super::{
    StreamDataInput, StreamDataInputError, StreamReceiveBuffer,
    fragmented::FragmentedStreamReceiveBuffer,
};
use bytes::Bytes;
use sakuya_wire::var_int::VarInt;

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

/// `len` bytes whose values are their stream offsets modulo 251.
fn data(offset: u32, len: u32) -> Bytes {
    (offset..offset + len)
        .map(|at| u8::try_from(at % 251).unwrap())
        .collect()
}

fn frame(offset: u32, len: u32, fin: bool) -> StreamDataInput {
    StreamDataInput::new(v(offset), v(offset + len), fin, data(offset, len)).unwrap()
}

fn read_all(buffer: &mut FragmentedStreamReceiveBuffer, limit: VarInt) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = buffer.read_chunk(limit) {
        assert!(!chunk.is_empty());
        out.extend_from_slice(&chunk);
    }
    out
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

/// [100, 200) with FIN, then [0, 100): data becomes contiguous only with the
/// second frame; everything is delivered once 200 is read.
#[test]
fn out_of_order_fin_then_fill() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(100, 100, true));
    assert_eq!(buffer.final_size(), Some(v(200)));
    assert_eq!(buffer.accounted_end(), v(200));
    assert!(buffer.read_chunk(VarInt::MAX).is_none());

    buffer.receive_data(frame(0, 100, false));
    assert_eq!(read_all(&mut buffer, VarInt::MAX), data(0, 200));
    assert_eq!(buffer.delivered_end(), v(200));
    assert_eq!(buffer.held_len(), 0);
}

/// The accounted end follows the highest end, not the stored bytes.
#[test]
fn accounted_end_follows_highest_end() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(100, 10, false));
    assert_eq!(buffer.accounted_end(), v(110));
    buffer.receive_data(frame(0, 100, false));
    assert_eq!(buffer.accounted_end(), v(110));
    buffer.receive_final_size(v(300));
    assert_eq!(buffer.accounted_end(), v(300));
    assert_eq!(buffer.final_size(), Some(v(300)));
    // A final size adds no readable data.
    assert_eq!(read_all(&mut buffer, VarInt::MAX), data(0, 110));
    assert!(buffer.read_chunk(VarInt::MAX).is_none());
}

/// [512, 768) then [0, 256): the readable end is 256 while the accounted end
/// is 768, and it stays 768 after reading.
#[test]
fn readable_end_differs_from_accounted_end() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(512, 256, false));
    buffer.receive_data(frame(0, 256, false));
    assert_eq!(read_all(&mut buffer, VarInt::MAX), data(0, 256));
    assert_eq!(buffer.delivered_end(), v(256));
    assert_eq!(buffer.accounted_end(), v(768));
}

/// Releasing the undelivered tail keeps 768 as the accounted end; a reset
/// with final size 1024 then accounts up to 1024 while data stops at 768.
#[test]
fn release_keeps_history_and_reset_extends_accounting() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(0, 768, false));
    buffer.release_from(v(256));
    assert_eq!(buffer.held_len(), 256);
    assert_eq!(buffer.accounted_end(), v(768));
    buffer.receive_final_size(v(1024));
    assert_eq!(buffer.accounted_end(), v(1024));
    assert_eq!(read_all(&mut buffer, VarInt::MAX), data(0, 256));
}

#[test]
fn shorter_duplicate_does_not_replace_longer_data() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(0, 100, false));
    let other = Bytes::from(vec![0xee; 50]);
    buffer.receive_data(StreamDataInput::new(v(0), v(50), false, other).unwrap());
    assert_eq!(buffer.held_len(), 100);
    assert_eq!(read_all(&mut buffer, VarInt::MAX), data(0, 100));
}

#[test]
fn overlapping_inputs_store_only_uncovered_pieces() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(10, 10, false));
    buffer.receive_data(frame(30, 10, false));
    // Covers both fragments and the gaps around them, with different bytes.
    let other = Bytes::from(vec![0xee; 50]);
    buffer.receive_data(StreamDataInput::new(v(0), v(50), false, other).unwrap());
    assert_eq!(buffer.held_len(), 50);
    let read = read_all(&mut buffer, VarInt::MAX);
    assert_eq!(&read[..10], &[0xee; 10]);
    assert_eq!(&read[10..20], &data(10, 10)[..]);
    assert_eq!(&read[20..30], &[0xee; 10]);
    assert_eq!(&read[30..40], &data(30, 10)[..]);
    assert_eq!(&read[40..], &[0xee; 10]);
}

/// With an empty map the read position still filters old duplicates.
#[test]
fn delivered_data_is_not_stored_again() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(0, 100, false));
    assert_eq!(read_all(&mut buffer, VarInt::MAX).len(), 100);
    buffer.receive_data(frame(0, 100, false));
    buffer.receive_data(frame(50, 60, false));
    assert_eq!(buffer.held_len(), 10);
    assert_eq!(read_all(&mut buffer, VarInt::MAX), data(100, 10));
}

#[test]
fn reads_stop_at_the_limit() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(0, 100, false));
    let chunk = buffer.read_chunk(v(30)).unwrap();
    assert_eq!(chunk, data(0, 30));
    assert!(buffer.read_chunk(v(30)).is_none());

    let mut target = [0u8; 50];
    let mut slice = &mut target[..];
    assert_eq!(buffer.read_into(v(60), &mut slice), 30);
    assert_eq!(&target[..30], &data(30, 30)[..]);
    assert_eq!(buffer.delivered_end(), v(60));

    let mut small = [0u8; 7];
    let mut slice = &mut small[..];
    assert_eq!(buffer.read_into(VarInt::MAX, &mut slice), 7);
    assert_eq!(&small[..], &data(60, 7)[..]);
    let mut rest = Vec::new();
    assert_eq!(buffer.read_into(VarInt::MAX, &mut rest), 33);
    assert_eq!(rest, data(67, 33));
}

#[test]
fn read_into_spans_fragments() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(0, 10, false));
    buffer.receive_data(frame(10, 10, false));
    buffer.receive_data(frame(30, 10, false));
    let mut out = Vec::new();
    assert_eq!(buffer.read_into(VarInt::MAX, &mut out), 20);
    assert_eq!(out, data(0, 20));
}

#[test]
fn release_truncates_a_straddling_fragment() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(0, 100, false));
    buffer.receive_data(frame(150, 100, false));
    buffer.release_from(v(50));
    assert_eq!(buffer.held_len(), 50);
    // Later data above the release point is the stream receive component's
    // business to trim; the buffer itself keeps accepting it.
    assert_eq!(read_all(&mut buffer, VarInt::MAX), data(0, 50));
}

#[test]
fn destroy_keeps_scalars_and_ignores_payload() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(0, 100, false));
    buffer.destroy();
    assert!(buffer.is_destroyed());
    assert_eq!(buffer.held_len(), 0);
    buffer.receive_data(frame(100, 100, true));
    assert_eq!(buffer.held_len(), 0);
    assert_eq!(buffer.accounted_end(), v(200));
    assert_eq!(buffer.final_size(), Some(v(200)));
}

#[test]
fn first_final_size_is_kept() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    buffer.receive_data(frame(0, 10, true));
    buffer.receive_final_size(v(20));
    assert_eq!(buffer.final_size(), Some(v(10)));
    assert_eq!(buffer.accounted_end(), v(20));
}

#[test]
fn trimmed_payload_still_accounts_the_whole_frame() {
    let mut buffer = FragmentedStreamReceiveBuffer::new();
    let input = StreamDataInput::new(v(0), v(100), true, data(0, 40)).unwrap();
    buffer.receive_data(input);
    assert_eq!(buffer.accounted_end(), v(100));
    assert_eq!(buffer.final_size(), Some(v(100)));
    assert_eq!(buffer.held_len(), 40);
}
