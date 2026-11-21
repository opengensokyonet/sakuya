//! A byte-array model of the selection and feedback of
//! [`OffsetMapStreamSendBuffer`] under generated inputs: appends with
//! different urgencies and destinations, partial selections, overlapping
//! acknowledgements and losses, unfulfilled intents and resets.
//!
//! Each byte of the model carries its own copy of the destination it was
//! written with, as each piece of the buffer carries a copy of its marker.
//! The model states which bytes wait for which destination, in what order,
//! which ones a reset or an acknowledgement removed, and which ones are left
//! without a destination; where the buffer cuts its pieces is its own.

use bytes::Bytes;
use proptest::prelude::*;
use sakuya_stream_v1::connection_send_credit::{
    AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
};
use sakuya_stream_v1::send_buffer::covered_bytes::CoveredBytes;
use sakuya_stream_v1::send_buffer::offset_map::OffsetMapStreamSendBuffer;
use sakuya_stream_v1::send_buffer::{ResetRetention, StreamSendBuffer};
use sakuya_stream_v1::send_options::SendOptions;
use sakuya_stream_v1::send_options::destination::{
    DestinationFallback, SendDestination, StreamSendDestination, Unfulfilled,
};
use sakuya_stream_v1::send_options::urgency::Urgency;
use sakuya_wire_v1::stream_id::StreamId;
use sakuya_wire_v1::var_int::VarInt;
use std::collections::BTreeSet;
use std::ops::Range;

const SPAN: usize = 400;

fn v(value: usize) -> VarInt {
    VarInt::new(value as u64).unwrap()
}

fn byte_at(offset: usize) -> u8 {
    u8::try_from(offset % 251).unwrap()
}

/// Where a route sends at one time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Path {
    Direct,
    Relay,
    Any,
}

/// A destination that falls back through `fallbacks`, one per failure, and
/// is exhausted once none is left; any active link path never falls back.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Route {
    current: Path,
    fallbacks: Vec<Path>,
}

impl Route {
    fn fall_back(&mut self) -> DestinationFallback {
        if self.current == Path::Any {
            return DestinationFallback::Degraded;
        }
        if self.fallbacks.is_empty() {
            return DestinationFallback::Exhausted;
        }
        self.current = self.fallbacks.remove(0);
        DestinationFallback::Degraded
    }
}

impl SendDestination for Route {
    type Current = Path;

    fn current(&self) -> Path {
        self.current
    }

    fn on_unfulfilled(&mut self, _: Unfulfilled) -> DestinationFallback {
        self.fall_back()
    }
}

impl StreamSendDestination for Route {
    fn on_lost(&mut self) -> DestinationFallback {
        self.fall_back()
    }
}

type Options = SendOptions<Urgency, Route>;
type Buffer = OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, Options>;

fn route() -> impl Strategy<Value = Route> {
    prop_oneof![
        Just(Route {
            current: Path::Any,
            fallbacks: vec![]
        }),
        Just(Route {
            current: Path::Direct,
            fallbacks: vec![]
        }),
        Just(Route {
            current: Path::Direct,
            fallbacks: vec![Path::Any]
        }),
        Just(Route {
            current: Path::Direct,
            fallbacks: vec![Path::Relay, Path::Any]
        }),
        Just(Route {
            current: Path::Relay,
            fallbacks: vec![Path::Direct]
        }),
    ]
}

fn path() -> impl Strategy<Value = Path> {
    prop_oneof![Just(Path::Direct), Just(Path::Relay), Just(Path::Any)]
}

#[derive(Clone, Debug)]
enum Op {
    Append {
        len: usize,
        urgency: u8,
        route: Route,
    },
    Select {
        path: Path,
        max_len: usize,
    },
    Acknowledge {
        start: usize,
        len: usize,
    },
    Lose {
        start: usize,
        len: usize,
    },
    Unfulfilled {
        path: Path,
    },
    Reset {
        reliable: usize,
    },
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (1..48usize, 0..=7u8, route())
            .prop_map(|(len, urgency, route)| Op::Append { len, urgency, route }),
        6 => (path(), 0..64usize).prop_map(|(path, max_len)| Op::Select { path, max_len }),
        2 => (0..SPAN, 0..80usize).prop_map(|(start, len)| Op::Acknowledge { start, len }),
        3 => (0..SPAN, 0..80usize).prop_map(|(start, len)| Op::Lose { start, len }),
        1 => path().prop_map(|path| Op::Unfulfilled { path }),
        1 => (0..SPAN).prop_map(|reliable| Op::Reset { reliable }),
    ]
}

/// Where a byte of the model is.
#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    /// Waiting to be sent.
    Waiting,
    /// Selected, neither acknowledged nor lost.
    Selected,
    /// Without a destination.
    Exhausted,
    /// Acknowledged, or abandoned by a reset.
    Gone,
}

#[derive(Clone, Debug)]
struct Byte {
    urgency: Urgency,
    route: Route,
    state: State,
}

#[derive(Debug, Default)]
struct Model {
    bytes: Vec<Byte>,
    /// The final size and reliable size of the reset applied last.
    reset: Option<(usize, usize)>,
}

impl Model {
    fn waiting(&self, path: Path) -> BTreeSet<usize> {
        (0..self.bytes.len())
            .filter(|&at| {
                self.bytes[at].state == State::Waiting && self.bytes[at].route.current == path
            })
            .collect()
    }

    fn destinations(&self) -> BTreeSet<Path> {
        self.bytes
            .iter()
            .filter(|byte| byte.state == State::Waiting)
            .map(|byte| byte.route.current)
            .collect()
    }

    /// The first byte `next` must give for `path`.
    fn next(&self, path: Path) -> Option<usize> {
        self.waiting(path)
            .into_iter()
            .min_by_key(|&at| (self.bytes[at].urgency, at))
    }

    /// The bytes from `start` that a segment may span: waiting for the same
    /// destination with the same urgency, without a gap.
    fn run_from(&self, start: usize) -> usize {
        let first = &self.bytes[start];
        self.bytes[start..]
            .iter()
            .take_while(|byte| {
                byte.state == State::Waiting
                    && byte.urgency == first.urgency
                    && byte.route.current == first.route.current
            })
            .count()
    }

    fn snapshot(&self) -> [BTreeSet<usize>; 3] {
        [Path::Direct, Path::Relay, Path::Any].map(|path| self.waiting(path))
    }

    /// Lets the bytes in `bytes` fall back; returns the ones exhausted.
    fn fall_back(&mut self, bytes: impl Iterator<Item = usize>, loss: bool) -> Vec<usize> {
        let mut exhausted = Vec::new();
        for at in bytes {
            let byte = &mut self.bytes[at];
            let fallback = if loss {
                byte.route.on_lost()
            } else {
                byte.route.on_unfulfilled(Unfulfilled::Rejected)
            };
            byte.state = match fallback {
                DestinationFallback::Degraded => State::Waiting,
                DestinationFallback::Exhausted => {
                    exhausted.push(at);
                    State::Exhausted
                }
            };
        }
        exhausted
    }
}

fn paths_changed(before: &[BTreeSet<usize>; 3], after: &[BTreeSet<usize>; 3]) -> BTreeSet<Path> {
    [Path::Direct, Path::Relay, Path::Any]
        .into_iter()
        .zip(before.iter().zip(after))
        .filter(|(_, (before, after))| before != after)
        .map(|(path, _)| path)
        .collect()
}

/// The bytes of `ranges`, which must be sorted and not adjacent.
fn bytes_of(ranges: &[Range<VarInt>]) -> Vec<usize> {
    for pair in ranges.windows(2) {
        assert!(pair[0].end < pair[1].start, "ranges sorted and joined");
    }
    ranges
        .iter()
        .flat_map(|range| range.start.get() as usize..range.end.get() as usize)
        .collect()
}

fn range(start: usize, len: usize) -> Range<VarInt> {
    v(start)..v(start + len)
}

fn check(model: &Model, buffer: &Buffer) {
    let destinations: BTreeSet<Path> = buffer.destinations().into_iter().collect();
    assert_eq!(destinations, model.destinations());
    assert_eq!(
        buffer.destinations().len(),
        destinations.len(),
        "each destination once"
    );
    for path in [Path::Direct, Path::Relay, Path::Any] {
        let next = buffer.next(&path);
        assert_eq!(
            next.as_ref().map(|segment| segment.offset.get() as usize),
            model.next(path)
        );
        if let Some(segment) = next {
            let start = segment.offset.get() as usize;
            assert!(segment.len >= 1 && segment.len <= model.run_from(start));
            assert_eq!(segment.marker.parameters(), &model.bytes[start].urgency);
            assert_eq!(segment.marker.destination(), &model.bytes[start].route);
        }
    }
    let mut kept = vec![false; model.bytes.len()];
    for (offset, bytes) in buffer.retained() {
        let start = offset.get() as usize;
        for (index, &byte) in bytes.iter().enumerate() {
            assert!(!kept[start + index], "pieces do not overlap");
            kept[start + index] = true;
            assert_eq!(byte, byte_at(start + index));
        }
    }
    for (at, byte) in model.bytes.iter().enumerate() {
        assert_eq!(kept[at], byte.state != State::Gone, "byte {at} kept");
    }
    assert_eq!(buffer.written_end(), v(model.bytes.len()));
}

fn step(
    op: &Op,
    model: &mut Model,
    buffer: &mut Buffer,
    connection: &AtomicConnectionSendFlowController,
) {
    match op.clone() {
        Op::Append {
            len,
            urgency,
            route,
        } => {
            if model.reset.is_some() || model.bytes.len() + len > SPAN {
                return;
            }
            let start = model.bytes.len();
            let bytes: Bytes = (start..start + len).map(byte_at).collect();
            let urgency = Urgency::new(urgency).unwrap();
            let reservation = connection
                .reserve(StreamId::from_var_int(VarInt::ZERO), v(len))
                .unwrap();
            let data =
                CoveredBytes::new(bytes, reservation, SendOptions::new(urgency, route.clone()))
                    .unwrap();
            buffer.append(data).unwrap();
            model.bytes.extend((0..len).map(|_| Byte {
                urgency,
                route: route.clone(),
                state: State::Waiting,
            }));
        }
        Op::Select { path, max_len } => {
            let expected = model.next(path);
            let selected = buffer.select(&path, max_len);
            let (Some(start), true) = (expected, max_len > 0) else {
                assert!(selected.is_none());
                return;
            };
            let selected = selected.expect("data waits for the destination");
            assert_eq!(selected.offset.get() as usize, start);
            let len = selected.bytes.len();
            assert!(len >= 1 && len <= max_len && len <= model.run_from(start));
            for (index, &byte) in selected.bytes.iter().enumerate() {
                assert_eq!(byte, byte_at(start + index));
                model.bytes[start + index].state = State::Selected;
            }
        }
        Op::Acknowledge { start, len } => {
            let before = model.snapshot();
            let changed: Vec<Path> = buffer.on_acknowledged(range(start, len));
            let end = (start + len).min(model.bytes.len());
            for byte in &mut model.bytes[start.min(end)..end] {
                byte.state = State::Gone;
            }
            let changed_set: BTreeSet<Path> = changed.iter().copied().collect();
            assert_eq!(changed.len(), changed_set.len(), "each destination once");
            assert_eq!(changed_set, paths_changed(&before, &model.snapshot()));
        }
        Op::Lose { start, len } => {
            let before = model.snapshot();
            let changes = buffer.on_lost(range(start, len));
            let end = (start + len).min(model.bytes.len());
            let lost: Vec<usize> = (start.min(end)..end)
                .filter(|&at| model.bytes[at].state == State::Selected)
                .collect();
            let exhausted = model.fall_back(lost.into_iter(), true);
            assert_eq!(bytes_of(&changes.exhausted), exhausted);
            let changed: BTreeSet<Path> = changes.pending_changed.iter().copied().collect();
            assert!(changed.is_superset(&paths_changed(&before, &model.snapshot())));
        }
        Op::Unfulfilled { path } => {
            let before = model.snapshot();
            let waiting = model.waiting(path);
            let changes = buffer.on_unfulfilled(&path, Unfulfilled::Rejected);
            let exhausted = model.fall_back(waiting.into_iter(), false);
            assert_eq!(bytes_of(&changes.exhausted), exhausted);
            let changed: BTreeSet<Path> = changes.pending_changed.iter().copied().collect();
            assert!(changed.is_superset(&paths_changed(&before, &model.snapshot())));
        }
        Op::Reset { reliable } => {
            let written = model.bytes.len();
            let (final_size, reliable) = match model.reset {
                None => (written, reliable.min(written)),
                Some((final_size, previous)) => (final_size, reliable.min(previous)),
            };
            buffer
                .apply_reset(ResetRetention {
                    final_size: v(final_size),
                    reliable_size: v(reliable),
                })
                .unwrap();
            for byte in &mut model.bytes[reliable..] {
                byte.state = State::Gone;
            }
            model.reset = Some((final_size, reliable));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn selection_and_feedback_follow_the_model(ops in prop::collection::vec(op(), 0..80)) {
        let connection = AtomicConnectionSendFlowController::new(v(SPAN));
        let mut buffer = Buffer::new();
        let mut model = Model::default();
        for op in &ops {
            step(op, &mut model, &mut buffer, &connection);
            check(&model, &buffer);
        }
    }
}
