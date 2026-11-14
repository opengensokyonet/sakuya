//! Proptest strategies for frames and payloads: valid frames in the neutral
//! model, the widths sakuya writes them in, encodings that break one rule,
//! and byte strings made for the frame readers.
use super::{
    Frame,
    sakuya::{self, Layout},
};
use crate::generate::{VAR_MAX, cid, var_int, var_int_as, width};
use proptest::{collection::vec, option, prelude::*, sample::select};
use sakuya_wire::var_int::VarIntWidth;

fn data() -> impl Strategy<Value = Vec<u8>> + Clone {
    prop_oneof![
        3 => vec(any::<u8>(), 0..8),
        1 => vec(any::<u8>(), 60..70),
    ]
}

/// An offset and data that end at most at 2^62 − 1.
fn bounded_data() -> impl Strategy<Value = (u64, Vec<u8>)> + Clone {
    (var_int(), data()).prop_map(|(offset, data)| (offset.min(VAR_MAX - data.len() as u64), data))
}

/// ACK ranges that the encoding can state, derived from a largest value and
/// gaps and lengths that stop at packet number zero.
fn ack_ranges() -> impl Strategy<Value = Vec<(u64, u64)>> + Clone {
    (var_int(), var_int(), vec((var_int(), var_int()), 0..6)).prop_map(|(largest, first, rest)| {
        let first = first.min(largest);
        let mut ranges = vec![(largest - first, largest)];
        let mut smallest = largest - first;
        for (gap, length) in rest {
            let Some(end) = smallest.checked_sub(gap).and_then(|v| v.checked_sub(2)) else {
                break;
            };
            let start = end.saturating_sub(length);
            ranges.push((start, end));
            smallest = start;
        }
        ranges
    })
}

/// A stream count up to 2^60, often at the bound.
fn stream_count() -> impl Strategy<Value = u64> + Clone {
    prop_oneof![
        1 => Just(1u64 << 60),
        4 => var_int().prop_map(|count| count.min(1 << 60)),
    ]
}

/// A valid frame of RFC 9000, RFC 9221 or RESET_STREAM_AT, with a Length
/// field where it can have one.
pub fn frame() -> BoxedStrategy<Frame> {
    prop_oneof![
        Just(Frame::Padding),
        Just(Frame::Ping),
        (
            var_int(),
            ack_ranges(),
            option::of((var_int(), var_int(), var_int()))
        )
            .prop_map(|(delay, ranges, ecn)| Frame::Ack { delay, ranges, ecn }),
        (var_int(), var_int(), var_int()).prop_map(|(id, code, final_size)| Frame::ResetStream {
            id,
            code,
            final_size
        }),
        (var_int(), var_int()).prop_map(|(id, code)| Frame::StopSending { id, code }),
        bounded_data().prop_map(|(offset, data)| Frame::Crypto { offset, data }),
        vec(any::<u8>(), 1..24).prop_map(|token| Frame::NewToken { token }),
        (
            var_int(),
            prop_oneof![1 => Just((0, Vec::new())), 4 => bounded_data()],
            any::<bool>()
        )
            .prop_map(|(id, (offset, data), fin)| Frame::Stream {
                id,
                offset,
                fin,
                has_length: true,
                data,
            }),
        var_int().prop_map(Frame::MaxData),
        (var_int(), var_int()).prop_map(|(id, limit)| Frame::MaxStreamData { id, limit }),
        (any::<bool>(), stream_count()).prop_map(|(uni, count)| Frame::MaxStreams { uni, count }),
        var_int().prop_map(Frame::DataBlocked),
        (var_int(), var_int()).prop_map(|(id, limit)| Frame::StreamDataBlocked { id, limit }),
        (any::<bool>(), stream_count())
            .prop_map(|(uni, count)| Frame::StreamsBlocked { uni, count }),
        (var_int(), var_int(), cid(), any::<[u8; 16]>()).prop_map(
            |(sequence, retire, cid, token)| Frame::NewConnectionId {
                sequence,
                retire_prior_to: retire.min(sequence),
                cid,
                token,
            }
        ),
        var_int().prop_map(Frame::RetireConnectionId),
        any::<[u8; 8]>().prop_map(Frame::PathChallenge),
        any::<[u8; 8]>().prop_map(Frame::PathResponse),
        (var_int(), var_int(), data()).prop_map(|(code, frame_type, reason)| {
            Frame::TransportClose {
                code,
                frame_type,
                reason,
            }
        }),
        (var_int(), data()).prop_map(|(code, reason)| Frame::ApplicationClose { code, reason }),
        Just(Frame::HandshakeDone),
        data().prop_map(|data| Frame::Datagram {
            has_length: true,
            data
        }),
        (var_int(), var_int(), var_int(), var_int()).prop_map(
            |(id, code, final_size, reliable_size)| Frame::ResetStreamAt {
                id,
                code,
                final_size,
                reliable_size: reliable_size.min(final_size),
            }
        ),
    ]
    .boxed()
}

/// Valid frames for one payload, with runs of PADDING; a STREAM or DATAGRAM
/// frame at the end may lack its Length field.
pub fn frames() -> BoxedStrategy<Vec<Frame>> {
    let item = prop_oneof![
        6 => frame().prop_map(|frame| vec![frame]),
        1 => (1usize..8).prop_map(|count| vec![Frame::Padding; count]),
    ];
    (vec(item, 1..6), any::<bool>())
        .prop_map(|(items, open_end)| {
            let mut frames: Vec<Frame> = items.into_iter().flatten().collect();
            if open_end
                && let Some(Frame::Stream { has_length, .. } | Frame::Datagram { has_length, .. }) =
                    frames.last_mut()
            {
                *has_length = false;
            }
            frames
        })
        .boxed()
}

/// The widths sakuya writes variable-length integers in: mostly the
/// shortest, otherwise a sequence of widths used in turn.
pub fn layout() -> BoxedStrategy<Layout> {
    let widths = vec(select(VarIntWidth::ALL.to_vec()), 1..6);
    prop_oneof![
        1 => Just(Layout::shortest()),
        2 => (widths, any::<bool>())
            .prop_map(|(widths, explicit_zero_offset)| Layout::new(widths, explicit_zero_offset)),
    ]
    .boxed()
}

/// Frames that sakuya wrote in the widths of a layout, with the frames.
pub fn encoded() -> BoxedStrategy<(Vec<Frame>, Vec<u8>)> {
    (frames(), layout())
        .prop_map(|(frames, mut layout)| {
            let bytes = sakuya::write(&frames, &mut layout).expect("valid frames build");
            (frames, bytes)
        })
        .boxed()
}

/// An encoding that breaks one rule of a frame, and the transport error
/// code the rule calls for.
#[derive(Clone, Debug)]
pub struct Violation {
    pub bytes: Vec<u8>,
    /// The Frame Type value of the encoding.
    pub frame_type: u64,
    /// The rule, as the RFC states it.
    pub rule: &'static str,
    pub code: u64,
}

const FRAME_ENCODING_ERROR: u64 = 0x07;
const PROTOCOL_VIOLATION: u64 = 0x0a;

fn violation(frame_type: u64, rule: &'static str, fields: Vec<Vec<u8>>) -> Violation {
    let mut bytes = var_int_as(frame_type, 1);
    bytes.extend(fields.into_iter().flatten());
    Violation {
        bytes,
        frame_type,
        rule,
        code: FRAME_ENCODING_ERROR,
    }
}

/// The encoding of a value at a width that holds it.
fn field() -> impl Strategy<Value = Vec<u8>> + Clone {
    (var_int(), width()).prop_map(|(value, width)| var_int_as(value, width))
}

/// An encoding of a frame that breaks exactly one rule that the encoding
/// alone decides.
pub fn violation_of_a_rule() -> BoxedStrategy<Violation> {
    let beyond = |limit: u64| (limit + 1)..=VAR_MAX;
    prop_oneof![
        width().prop_map(|w| violation(
            0x07,
            "RFC 9000 §19.7: the token MUST NOT be empty",
            vec![var_int_as(0, w)]
        )),
        (0u64..VAR_MAX, width(), cid(), any::<[u8; 16]>()).prop_flat_map(
            |(sequence, w, cid, token)| ((sequence + 1)..=VAR_MAX).prop_map(move |retire| {
                violation(
                    0x18,
                    "RFC 9000 §19.15: Retire Prior To MUST NOT exceed Sequence Number",
                    vec![
                        var_int_as(sequence, w),
                        var_int_as(retire, 1),
                        vec![cid.len() as u8],
                        cid.clone(),
                        token.to_vec(),
                    ],
                )
            })
        ),
        (
            var_int(),
            prop_oneof![Just(0usize), 21usize..=255],
            any::<[u8; 16]>()
        )
            .prop_map(|(sequence, length, token)| violation(
                0x18,
                "RFC 9000 §19.15: a connection ID length below 1 or above 20 is invalid",
                vec![
                    var_int_as(sequence, 1),
                    var_int_as(0, 1),
                    vec![length as u8],
                    vec![0xc1; length],
                    token.to_vec(),
                ],
            )),
        (
            select(vec![0x12u64, 0x13, 0x16, 0x17]),
            beyond(1 << 60),
            width()
        )
            .prop_map(|(ty, count, w)| violation(
                ty,
                "RFC 9000 §19.11, §19.14: a stream count cannot exceed 2^60",
                vec![var_int_as(count, w)]
            )),
        (any::<bool>(), any::<bool>(), field(), 0u64..8, 1usize..20).prop_map(
            |(length, fin, id, room, extra)| {
                let data = vec![0xd7; room as usize + extra];
                let mut fields = vec![id, var_int_as(VAR_MAX - room, 8)];
                if length {
                    fields.push(var_int_as(data.len() as u64, 1));
                }
                fields.push(data);
                let ty = 0x0c | u64::from(length) << 1 | u64::from(fin);
                violation(
                    ty,
                    "RFC 9000 §19.8: the end of stream data cannot exceed 2^62-1",
                    fields,
                )
            }
        ),
        (0u64..8, 1usize..20).prop_map(|(room, extra)| {
            let data = vec![0xc7; room as usize + extra];
            violation(
                0x06,
                "RFC 9000 §19.6: the end of crypto data cannot exceed 2^62-1",
                vec![
                    var_int_as(VAR_MAX - room, 8),
                    var_int_as(data.len() as u64, 1),
                    data,
                ],
            )
        }),
        (0u64..1000, 1u64..1000, any::<bool>()).prop_map(|(largest, excess, in_gap)| {
            let fields = if in_gap {
                // The first range ends at `largest - first`; the gap below it
                // reaches below zero.
                vec![
                    var_int_as(largest, 1),
                    var_int_as(0, 1),
                    var_int_as(1, 1),
                    var_int_as(0, 1),
                    var_int_as(largest + excess, 1),
                    var_int_as(0, 1),
                ]
            } else {
                vec![
                    var_int_as(largest, 1),
                    var_int_as(0, 1),
                    var_int_as(0, 1),
                    var_int_as(largest + excess, 1),
                ]
            };
            violation(
                0x02,
                "RFC 9000 §19.3.1: no computed packet number may be negative",
                fields,
            )
        }),
        (field(), field(), 0u64..VAR_MAX).prop_flat_map(|(id, code, final_size)| {
            ((final_size + 1)..=VAR_MAX).prop_map(move |reliable| {
                violation(
                    0x24,
                    "draft-ietf-quic-reliable-stream-reset-11 §4: Reliable Size MUST NOT exceed \
                     Final Size",
                    vec![
                        id.clone(),
                        code.clone(),
                        var_int_as(final_size, 8),
                        var_int_as(reliable, 1),
                    ],
                )
            })
        }),
        (
            prop_oneof![
                Just(0x1fu64),
                0x20u64..=0x23,
                0x25u64..=0x2f,
                0x32u64..=0x3f,
                0x40u64..=0x3fff,
                var_int().prop_filter("unclaimed", |value| *value > 0x31),
            ],
            vec(any::<u8>(), 0..8)
        )
            .prop_map(|(ty, tail)| {
                let mut bytes = var_int_as(ty, 1);
                bytes.extend(tail);
                Violation {
                    bytes,
                    frame_type: ty,
                    rule: "RFC 9000 §12.4: a frame of unknown type is a FRAME_ENCODING_ERROR",
                    code: FRAME_ENCODING_ERROR,
                }
            }),
        (
            0u64..0x4000,
            select(vec![2usize, 4, 8]),
            vec(any::<u8>(), 0..8)
        )
            .prop_filter("longer than necessary", |(ty, width, _)| {
                var_int_as(*ty, 1).len() < *width
            })
            .prop_map(|(ty, width, tail)| {
                let mut bytes = var_int_as(ty, width);
                bytes.extend(tail);
                Violation {
                    bytes,
                    frame_type: ty,
                    rule: "RFC 9000 §12.4: a frame type MUST use the shortest encoding; an \
                           endpoint MAY treat a longer one as a PROTOCOL_VIOLATION",
                    code: PROTOCOL_VIOLATION,
                }
            }),
    ]
    .boxed()
}

/// The Frame Type values the payloads start fields with: those of RFC 9000,
/// of the extensions of sakuya, of the extensions of the references, and a
/// few no one defines.
fn type_value() -> impl Strategy<Value = u64> + Clone {
    prop_oneof![
        8 => 0x00u64..=0x1e,
        3 => select(vec![0x24u64, 0x30, 0x31]),
        2 => select(vec![0x1fu64, 0xaf, 0xdc0000, 0xdc0002]),
        1 => select(vec![0x20u64, 0x2f, 0x3f, 0x40, 0x4000]),
    ]
}

/// A byte string made for the frame readers: frames that sakuya wrote,
/// those frames damaged, a Frame Type followed by integers at random widths,
/// an encoding that breaks a rule, and plain random bytes.
pub fn payload() -> BoxedStrategy<Vec<u8>> {
    let encoded = encoded().prop_map(|(_, bytes)| bytes).boxed();
    let damaged = (
        encoded.clone(),
        vec((any::<prop::sample::Index>(), any::<u8>()), 1..4),
        any::<prop::sample::Index>(),
    )
        .prop_map(|(mut bytes, edits, cut)| {
            if bytes.is_empty() {
                return bytes;
            }
            for (index, value) in edits {
                let at = index.index(bytes.len());
                bytes[at] = value;
            }
            let keep = cut.index(bytes.len() + 1);
            bytes.truncate(keep.max(1));
            bytes
        });
    let fields = (
        type_value(),
        prop_oneof![6 => Just(1usize), 1 => select(vec![2usize, 4, 8])],
        vec(field(), 0..9),
        vec(any::<u8>(), 0..24),
    )
        .prop_map(|(ty, type_width, fields, tail)| {
            let mut bytes = var_int_as(ty, type_width);
            bytes.extend(fields.into_iter().flatten());
            bytes.extend(tail);
            bytes
        });
    let broken = (encoded.clone(), violation_of_a_rule()).prop_map(|(mut bytes, violation)| {
        // Frames without a Length field take the rest of the payload; the
        // violation goes before them.
        let mut payload = violation.bytes;
        payload.append(&mut bytes);
        payload
    });
    prop_oneof![
        2 => encoded,
        3 => damaged,
        4 => fields,
        1 => broken,
        1 => vec(any::<u8>(), 0..48),
    ]
    .boxed()
}
