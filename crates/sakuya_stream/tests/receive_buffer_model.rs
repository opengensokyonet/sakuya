//! A byte-array model of [`FragmentedStreamReceiveBuffer`] under generated inputs:
//! out-of-order, overlapping and duplicated frames, trimmed payloads, reads
//! bounded by a limit, releases and destruction.

use bytes::{BufMut, Bytes, BytesMut};
use proptest::prelude::*;
use sakuya_stream::receive_buffer::fragmented::FragmentedStreamReceiveBuffer;
use sakuya_stream::receive_buffer::{StreamDataInput, StreamReceiveBuffer};
use sakuya_wire::var_int::VarInt;

const SPAN: usize = 256;

fn v(value: usize) -> VarInt {
    VarInt::new(value as u64).unwrap()
}

fn byte_at(offset: usize) -> u8 {
    u8::try_from(offset % 251).unwrap()
}

fn content(offset: usize, len: usize) -> Bytes {
    (offset..offset + len).map(byte_at).collect()
}

#[derive(Clone, Debug)]
enum Op {
    /// A frame `[offset, offset + len)` of which only `kept` bytes are handed
    /// over, as the acceptance limit would trim it.
    Data {
        offset: usize,
        len: usize,
        kept: usize,
        fin: bool,
    },
    FinalSize(usize),
    ReadChunk {
        limit: usize,
    },
    ReadInto {
        limit: usize,
        room: usize,
    },
    Release(usize),
    Destroy,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        10 => (0..SPAN, 0..64usize, 0..64usize, prop::bool::weighted(0.1))
            .prop_map(|(offset, len, kept, fin)| Op::Data { offset, len, kept: kept.min(len), fin }),
        1 => (0..SPAN + 64).prop_map(Op::FinalSize),
        4 => (0..SPAN + 64).prop_map(|limit| Op::ReadChunk { limit }),
        4 => (0..SPAN + 64, 0..48usize).prop_map(|(limit, room)| Op::ReadInto { limit, room }),
        1 => (0..SPAN + 64).prop_map(Op::Release),
        1 => Just(Op::Destroy).prop_filter("rare", |_| true),
    ]
}

#[derive(Debug)]
struct Model {
    held: Vec<bool>,
    delivered: usize,
    accounted: usize,
    final_size: Option<usize>,
    destroyed: bool,
}

impl Model {
    fn new() -> Self {
        let bytes = SPAN + 128;
        Self {
            held: vec![false; bytes],
            delivered: 0,
            accounted: 0,
            final_size: None,
            destroyed: false,
        }
    }

    fn run(&self, limit: usize) -> usize {
        (self.delivered..limit.min(self.held.len()))
            .take_while(|&at| self.held[at])
            .count()
    }

    fn held_len(&self) -> usize {
        self.held.iter().filter(|held| **held).count()
    }
}

fn check(buffer: &FragmentedStreamReceiveBuffer, model: &Model) {
    assert_eq!(buffer.delivered_end(), v(model.delivered));
    assert_eq!(buffer.accounted_end(), v(model.accounted));
    assert_eq!(buffer.final_size(), model.final_size.map(v));
    assert_eq!(buffer.held_len(), model.held_len());
    assert_eq!(buffer.is_destroyed(), model.destroyed);
}

fn step(buffer: &mut FragmentedStreamReceiveBuffer, model: &mut Model, op: &Op) {
    match *op {
        Op::Data {
            offset,
            len,
            kept,
            fin,
        } => {
            let end = offset + len;
            let input =
                StreamDataInput::new(v(offset), v(end), fin, content(offset, kept)).unwrap();
            buffer.receive_data(input);
            model.accounted = model.accounted.max(end);
            if fin && model.final_size.is_none() {
                model.final_size = Some(end);
            }
            if !model.destroyed {
                for at in offset.max(model.delivered)..offset + kept {
                    model.held[at] = true;
                }
            }
        }
        Op::FinalSize(size) => {
            buffer.receive_final_size(v(size));
            model.accounted = model.accounted.max(size);
            model.final_size.get_or_insert(size);
        }
        Op::ReadChunk { limit } => {
            let run = model.run(limit);
            let chunk = buffer.read_chunk(v(limit));
            match chunk {
                Some(chunk) => {
                    assert!(!chunk.is_empty(), "a chunk is never empty");
                    assert!(chunk.len() <= run, "chunk passes the run or the limit");
                    assert_eq!(chunk, content(model.delivered, chunk.len()));
                    for at in model.delivered..model.delivered + chunk.len() {
                        model.held[at] = false;
                    }
                    model.delivered += chunk.len();
                }
                None => assert_eq!(run, 0, "a chunk was available"),
            }
        }
        Op::ReadInto { limit, room } => {
            let run = model.run(limit);
            let mut target = BytesMut::with_capacity(room).limit(room);
            let copied = buffer.read_into(v(limit), &mut target);
            assert_eq!(
                copied,
                run.min(room),
                "reads stop only at room, gap or limit"
            );
            let bytes = target.into_inner().freeze();
            assert_eq!(bytes.len(), copied);
            assert_eq!(bytes, content(model.delivered, copied));
            for at in model.delivered..model.delivered + copied {
                model.held[at] = false;
            }
            model.delivered += copied;
        }
        Op::Release(end) => {
            buffer.release_from(v(end));
            let from = end.max(model.delivered);
            if from < model.held.len() {
                model.held[from..].fill(false);
            }
        }
        Op::Destroy => {
            buffer.destroy();
            model.held.fill(false);
            model.destroyed = true;
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 4000, ..ProptestConfig::default() })]

    #[test]
    fn fragmented_buffer_follows_the_model(ops in prop::collection::vec(op(), 0..80)) {
        let mut buffer = FragmentedStreamReceiveBuffer::new();
        let mut model = Model::new();
        for op in &ops {
            let accounted = model.accounted;
            let delivered = model.delivered;
            step(&mut buffer, &mut model, op);
            check(&buffer, &model);
            prop_assert!(model.accounted >= accounted, "accounted end fell");
            prop_assert!(model.delivered >= delivered, "delivery moved back");
        }
    }

    /// Whatever the order and overlap of the frames, reading afterwards
    /// returns every byte of the stream exactly once and in order.
    #[test]
    fn any_arrival_order_reassembles_the_stream(
        len in 1usize..200,
        cuts in prop::collection::vec(0usize..200, 0..30),
        order in prop::collection::vec(any::<prop::sample::Index>(), 0..60),
        chunked in any::<bool>(),
    ) {
        let mut cuts: Vec<_> = cuts.into_iter().map(|cut| cut % (len + 1)).collect();
        cuts.push(0);
        cuts.push(len);
        cuts.sort_unstable();
        cuts.dedup();
        let pieces: Vec<_> = cuts.windows(2).map(|w| (w[0], w[1])).collect();
        let mut buffer = FragmentedStreamReceiveBuffer::new();
        // Duplicates in a random order, then every piece once in reverse, so
        // that the whole stream has arrived.
        let repeats = order.iter().map(|index| pieces[index.index(pieces.len())]);
        for (start, end) in repeats.chain(pieces.iter().rev().copied()) {
            let input = StreamDataInput::new(
                v(start), v(end), end == len, content(start, end - start),
            ).unwrap();
            buffer.receive_data(input);
        }
        prop_assert_eq!(buffer.final_size(), Some(v(len)));
        prop_assert_eq!(buffer.held_len(), len);
        let mut read = Vec::new();
        if chunked {
            while let Some(chunk) = buffer.read_chunk(VarInt::MAX) {
                read.extend_from_slice(&chunk);
            }
        } else {
            let mut target = BytesMut::new().limit(len + 1);
            buffer.read_into(VarInt::MAX, &mut target);
            read.extend_from_slice(&target.into_inner());
        }
        prop_assert_eq!(Bytes::from(read), content(0, len));
        prop_assert_eq!(buffer.delivered_end(), v(len));
        prop_assert_eq!(buffer.held_len(), 0);
    }
}
