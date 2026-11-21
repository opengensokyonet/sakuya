use super::{
    IdentifiedStream, InitialMaxStreams, LocalStreamNotOpenedError, MaxStreamsExceededError,
    MaxStreamsReachedError, ReceiveOnlyStreamError, ReceivingPartFrameError,
    ReceivingPartFrameType, ReclaimError, SendOnlyStreamError, SendingPartFrameError,
    SendingPartFrameType, StreamIdLedger,
};
use proptest::prelude::*;
use sakuya_wire_v1::role::Role;
use sakuya_wire_v1::stream_count::StreamCount;
use sakuya_wire_v1::stream_id::{Directionality, Initiator, StreamId};
use sakuya_wire_v1::transport_error::TransportErrorCode;
use sakuya_wire_v1::var_int::VarInt;
use std::collections::{BTreeMap, BTreeSet};

const BIDI: Directionality = Directionality::Bidirectional;
const UNI: Directionality = Directionality::Unidirectional;

fn n(value: u64) -> StreamCount {
    StreamCount::new(value).unwrap()
}

fn limits(bidirectional: u64, unidirectional: u64) -> InitialMaxStreams {
    InitialMaxStreams {
        bidirectional: n(bidirectional),
        unidirectional: n(unidirectional),
    }
}

fn id(initiator: Initiator, directionality: Directionality, index: u64) -> StreamId {
    StreamId::new(initiator, directionality, index).unwrap()
}

/// A client ledger: it may open 2 bidirectional and 1 unidirectional
/// streams; the server may open 3 bidirectional and 2 unidirectional.
fn client() -> StreamIdLedger {
    StreamIdLedger::new(Role::Client, limits(2, 1), limits(3, 2))
}

fn stream_frame(ledger: &mut StreamIdLedger, stream_id: StreamId) -> IdentifiedStream {
    ledger
        .on_receiving_part_frame(stream_id, ReceivingPartFrameType::Stream)
        .unwrap()
}

#[test]
fn local_streams_open_in_order_up_to_the_limit() {
    let mut ledger = client();
    assert_eq!(ledger.open_local(BIDI), Ok(id(Initiator::Client, BIDI, 0)));
    assert_eq!(ledger.open_local(BIDI), Ok(id(Initiator::Client, BIDI, 1)));
    assert_eq!(
        ledger.open_local(BIDI),
        Err(MaxStreamsReachedError {
            directionality: BIDI,
            limit: n(2),
        })
    );
    assert_eq!(ledger.local_opened(BIDI), 2);
    assert_eq!(ledger.open_local(UNI), Ok(id(Initiator::Client, UNI, 0)));

    let mut server = StreamIdLedger::new(Role::Server, limits(1, 0), limits(0, 0));
    assert_eq!(server.open_local(BIDI), Ok(id(Initiator::Server, BIDI, 0)));
    assert!(server.open_local(UNI).is_err());
}

#[test]
fn max_streams_only_grows() {
    let mut ledger = client();
    assert!(!ledger.on_max_streams(BIDI, n(2)));
    assert!(!ledger.on_max_streams(BIDI, n(1)));
    assert_eq!(ledger.local_limit(BIDI), n(2));
    assert!(ledger.on_max_streams(BIDI, n(4)));
    assert!(!ledger.on_max_streams(BIDI, n(3)));
    assert_eq!(ledger.local_limit(BIDI), n(4));
    assert_eq!(ledger.local_limit(UNI), n(1));
}

/// Blocked at 2: one `STREAMS_BLOCKED` at 2; after it is sent, blocking at 2
/// again wants nothing; `MAX_STREAMS` to 3 clears it, and blocking at 3
/// wants a frame at 3.
#[test]
fn streams_blocked_once_for_each_limit() {
    let mut ledger = client();
    ledger.open_local(BIDI).unwrap();
    ledger.open_local(BIDI).unwrap();
    assert_eq!(ledger.streams_blocked(BIDI), None);
    assert!(ledger.open_local(BIDI).is_err());
    assert_eq!(ledger.streams_blocked(BIDI), Some(n(2)));
    assert_eq!(ledger.streams_blocked(UNI), None);
    ledger.on_streams_blocked_sent(BIDI, n(2));
    assert_eq!(ledger.streams_blocked(BIDI), None);
    assert!(ledger.open_local(BIDI).is_err());
    assert_eq!(ledger.streams_blocked(BIDI), None);

    ledger.on_max_streams(BIDI, n(3));
    assert_eq!(ledger.streams_blocked(BIDI), None);
    ledger.open_local(BIDI).unwrap();
    assert!(ledger.open_local(BIDI).is_err());
    assert_eq!(ledger.streams_blocked(BIDI), Some(n(3)));
    // A limit growth before the frame is sent clears it.
    ledger.on_max_streams(BIDI, n(4));
    assert_eq!(ledger.streams_blocked(BIDI), None);
}

/// A lost `STREAMS_BLOCKED` at 2 is wanted again while 2 is the limit.
#[test]
fn a_lost_streams_blocked_is_wanted_again() {
    let mut ledger = client();
    ledger.open_local(BIDI).unwrap();
    ledger.open_local(BIDI).unwrap();
    assert!(ledger.open_local(BIDI).is_err());
    ledger.on_streams_blocked_sent(BIDI, n(2));
    ledger.on_streams_blocked_lost(BIDI, n(2));
    assert_eq!(ledger.streams_blocked(BIDI), Some(n(2)));
    ledger.on_streams_blocked_sent(BIDI, n(2));
    ledger.on_max_streams(BIDI, n(3));
    ledger.on_streams_blocked_lost(BIDI, n(2));
    assert_eq!(ledger.streams_blocked(BIDI), None);
}

/// The design's example: the peer has opened its bidirectional stream with
/// index 0, then a frame names index 2. Indices 1 and 2 open together; only
/// 2 is created now, 1 when its first frame arrives.
#[test]
fn a_peer_stream_opens_the_lower_ones_and_creates_only_itself() {
    let mut ledger = client();
    let server = |index| id(Initiator::Server, BIDI, index);
    assert_eq!(
        stream_frame(&mut ledger, server(0)),
        IdentifiedStream::Created
    );
    assert_eq!(
        stream_frame(&mut ledger, server(0)),
        IdentifiedStream::Existing
    );
    assert_eq!(
        stream_frame(&mut ledger, server(2)),
        IdentifiedStream::Created
    );
    assert_eq!(ledger.peer_opened(BIDI), 3);
    assert_eq!(
        stream_frame(&mut ledger, server(2)),
        IdentifiedStream::Existing
    );
    assert_eq!(
        ledger.on_sending_part_frame(server(1), SendingPartFrameType::MaxStreamData),
        Ok(IdentifiedStream::Created)
    );
    assert_eq!(
        stream_frame(&mut ledger, server(1)),
        IdentifiedStream::Existing
    );
    // Another type is counted on its own.
    assert_eq!(ledger.peer_opened(UNI), 0);
}

#[test]
fn local_streams_are_existing_once_opened() {
    let mut ledger = client();
    let stream = ledger.open_local(BIDI).unwrap();
    assert_eq!(
        stream_frame(&mut ledger, stream),
        IdentifiedStream::Existing
    );
    assert_eq!(
        ledger.on_sending_part_frame(stream, SendingPartFrameType::StopSending),
        Ok(IdentifiedStream::Existing)
    );
    let uni = ledger.open_local(UNI).unwrap();
    assert_eq!(
        ledger.on_sending_part_frame(uni, SendingPartFrameType::MaxStreamData),
        Ok(IdentifiedStream::Existing)
    );
}

/// A frame for a stream of this endpoint that it has not opened, of either
/// part, is `STREAM_STATE_ERROR`.
#[test]
fn local_stream_not_opened() {
    let mut ledger = client();
    let unopened = id(Initiator::Client, BIDI, 0);
    let error = ledger
        .on_receiving_part_frame(unopened, ReceivingPartFrameType::ResetStream)
        .unwrap_err();
    assert_eq!(
        error,
        ReceivingPartFrameError::LocalStreamNotOpened {
            source: LocalStreamNotOpenedError {
                stream_id: unopened
            },
        }
    );
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::STREAM_STATE_ERROR
    );
    let error = ledger
        .on_sending_part_frame(unopened, SendingPartFrameType::StopSending)
        .unwrap_err();
    assert_eq!(
        error,
        SendingPartFrameError::LocalStreamNotOpened {
            source: LocalStreamNotOpenedError {
                stream_id: unopened
            },
        }
    );
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::STREAM_STATE_ERROR
    );
    ledger.open_local(BIDI).unwrap();
    let next = id(Initiator::Client, BIDI, 1);
    assert!(
        ledger
            .on_receiving_part_frame(next, ReceivingPartFrameType::StreamDataBlocked)
            .is_err()
    );
}

/// Frames for the receiving part on a unidirectional stream of this endpoint,
/// and frames for the sending part on one of the peer, are
/// `STREAM_STATE_ERROR`, whether the stream is open or not.
#[test]
fn frames_for_the_part_a_unidirectional_stream_lacks() {
    let mut ledger = client();
    let local_uni = ledger.open_local(UNI).unwrap();
    for frame_type in [
        ReceivingPartFrameType::Stream,
        ReceivingPartFrameType::ResetStream,
        ReceivingPartFrameType::StreamDataBlocked,
        // RESET_STREAM_AT, a reset frame of an extension
        ReceivingPartFrameType::Extension(VarInt::from_u32(0x24)),
    ] {
        let error = ledger
            .on_receiving_part_frame(local_uni, frame_type)
            .unwrap_err();
        assert_eq!(
            error,
            ReceivingPartFrameError::SendOnlyStream {
                source: SendOnlyStreamError {
                    stream_id: local_uni,
                    frame_type,
                },
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::STREAM_STATE_ERROR
        );
    }
    let peer_uni = id(Initiator::Server, UNI, 0);
    for frame_type in [
        SendingPartFrameType::StopSending,
        SendingPartFrameType::MaxStreamData,
    ] {
        let error = ledger
            .on_sending_part_frame(peer_uni, frame_type)
            .unwrap_err();
        assert_eq!(
            error,
            SendingPartFrameError::ReceiveOnlyStream {
                source: ReceiveOnlyStreamError {
                    stream_id: peer_uni,
                    frame_type,
                },
            }
        );
        assert_eq!(
            error.transport_error_code(),
            TransportErrorCode::STREAM_STATE_ERROR
        );
    }
    // The rejected frames opened nothing.
    assert_eq!(ledger.peer_opened(UNI), 0);
    // The parts that exist take their frames.
    assert_eq!(
        stream_frame(&mut ledger, peer_uni),
        IdentifiedStream::Created
    );
    assert_eq!(
        ledger.on_sending_part_frame(local_uni, SendingPartFrameType::StopSending),
        Ok(IdentifiedStream::Existing)
    );
}

/// A stream of the peer at or beyond the granted limit is
/// `STREAM_LIMIT_ERROR`, and opens nothing.
#[test]
fn peer_stream_beyond_the_limit() {
    let mut ledger = client();
    let beyond = id(Initiator::Server, UNI, 2);
    let error = ledger
        .on_receiving_part_frame(beyond, ReceivingPartFrameType::Stream)
        .unwrap_err();
    assert_eq!(
        error,
        ReceivingPartFrameError::MaxStreamsExceeded {
            source: MaxStreamsExceededError {
                stream_id: beyond,
                limit: n(2),
            },
        }
    );
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::STREAM_LIMIT_ERROR
    );
    assert_eq!(ledger.peer_opened(UNI), 0);
    let bidi_beyond = id(Initiator::Server, BIDI, 3);
    let error = ledger
        .on_sending_part_frame(bidi_beyond, SendingPartFrameType::StopSending)
        .unwrap_err();
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::STREAM_LIMIT_ERROR
    );
    assert_eq!(
        stream_frame(&mut ledger, id(Initiator::Server, UNI, 1)),
        IdentifiedStream::Created
    );
}

/// A reclaimed stream reports late frames as reclaimed and is never created
/// again; a reclaimed stream of the peer lets the granted limit grow by one.
#[test]
fn reclaimed_streams_ignore_late_frames_and_grant_one_more() {
    let mut ledger = client();
    let server = |index| id(Initiator::Server, BIDI, index);
    stream_frame(&mut ledger, server(1));
    assert_eq!(
        ledger.reclaim(server(0)),
        Err(ReclaimError::NotCreated {
            stream_id: server(0),
        })
    );
    assert_eq!(
        ledger.reclaim(server(2)),
        Err(ReclaimError::NotOpened {
            stream_id: server(2),
        })
    );
    assert_eq!(ledger.max_streams(BIDI), None);
    ledger.reclaim(server(1)).unwrap();
    assert!(ledger.is_reclaimed(server(1)));
    assert_eq!(
        ledger.reclaim(server(1)),
        Err(ReclaimError::AlreadyReclaimed {
            stream_id: server(1),
        })
    );
    assert_eq!(
        stream_frame(&mut ledger, server(1)),
        IdentifiedStream::Reclaimed
    );
    assert_eq!(
        ledger.on_sending_part_frame(server(1), SendingPartFrameType::StopSending),
        Ok(IdentifiedStream::Reclaimed)
    );
    // The limit to grant grows by one; it applies once it may be visible.
    assert_eq!(ledger.max_streams(BIDI), Some(n(4)));
    assert_eq!(ledger.max_streams(BIDI), Some(n(4)));
    assert!(
        ledger
            .on_receiving_part_frame(server(3), ReceivingPartFrameType::Stream)
            .is_err()
    );
    assert!(ledger.raise_peer_limit(BIDI, n(4)));
    assert!(!ledger.raise_peer_limit(BIDI, n(3)));
    assert_eq!(ledger.peer_limit(BIDI), n(4));
    assert_eq!(ledger.max_streams(BIDI), None);
    assert_eq!(
        stream_frame(&mut ledger, server(3)),
        IdentifiedStream::Created
    );
    // The uncreated stream 0 still creates on its first frame.
    assert_eq!(
        stream_frame(&mut ledger, server(0)),
        IdentifiedStream::Created
    );
}

#[test]
fn reclaiming_local_streams_grants_nothing() {
    let mut ledger = client();
    let stream = ledger.open_local(BIDI).unwrap();
    assert_eq!(
        ledger.reclaim(id(Initiator::Client, BIDI, 1)),
        Err(ReclaimError::NotOpened {
            stream_id: id(Initiator::Client, BIDI, 1),
        })
    );
    ledger.reclaim(stream).unwrap();
    assert_eq!(
        stream_frame(&mut ledger, stream),
        IdentifiedStream::Reclaimed
    );
    assert_eq!(ledger.max_streams(BIDI), None);
    // Reclaiming does not give this endpoint credit back either.
    ledger.open_local(BIDI).unwrap();
    assert!(ledger.open_local(BIDI).is_err());
}

/// One operation of the property test.
#[derive(Clone, Debug)]
enum Op {
    OpenLocal(Directionality),
    ReceivingPartFrame(StreamId),
    SendingPartFrame(StreamId),
    Reclaim(StreamId),
    MaxStreams(Directionality, u64),
    RaisePeerLimit(Directionality),
}

fn directionality() -> impl Strategy<Value = Directionality> {
    prop_oneof![Just(BIDI), Just(UNI)]
}

fn stream_id() -> impl Strategy<Value = StreamId> {
    (
        prop_oneof![Just(Initiator::Client), Just(Initiator::Server)],
        directionality(),
        0u64..12,
    )
        .prop_map(|(initiator, directionality, index)| id(initiator, directionality, index))
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => directionality().prop_map(Op::OpenLocal),
        4 => stream_id().prop_map(Op::ReceivingPartFrame),
        2 => stream_id().prop_map(Op::SendingPartFrame),
        3 => stream_id().prop_map(Op::Reclaim),
        1 => (directionality(), 0u64..12).prop_map(|(d, maximum)| Op::MaxStreams(d, maximum)),
        1 => directionality().prop_map(Op::RaisePeerLimit),
    ]
}

/// What a stream is in the reference model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Uncreated,
    Live,
    Reclaimed,
}

proptest! {
    /// Against a reference model: open, live and reclaimed streams never
    /// overlap, each stream is created at most once and never after it was
    /// reclaimed, the limit for this endpoint only grows, and the limit to
    /// grant the peer is the initial one plus the reclaimed streams.
    #[test]
    fn ledger_matches_the_reference_model(
        role in prop_oneof![Just(Role::Client), Just(Role::Server)],
        initial in (0u64..6, 0u64..6, 0u64..6, 0u64..6),
        ops in prop::collection::vec(op(), 0..80),
    ) {
        let granted_by_peer = limits(initial.0, initial.1);
        let granted_to_peer = limits(initial.2, initial.3);
        let mut ledger = StreamIdLedger::new(role, granted_by_peer, granted_to_peer);
        let local_initiator = match role {
            Role::Client => Initiator::Client,
            Role::Server => Initiator::Server,
        };
        let mut phases: BTreeMap<StreamId, Phase> = BTreeMap::new();
        let mut created: BTreeSet<StreamId> = BTreeSet::new();
        let mut reclaimed_peer = [0u64; 2];
        let slot = |d: Directionality| usize::from(d == UNI);
        for op in ops {
            let before = [ledger.local_limit(BIDI), ledger.local_limit(UNI)];
            match op {
                Op::OpenLocal(d) => {
                    let opened = ledger.local_opened(d);
                    match ledger.open_local(d) {
                        Ok(stream) => {
                            prop_assert!(opened < before[slot(d)].get());
                            prop_assert_eq!(stream, id(local_initiator, d, opened));
                            prop_assert_eq!(phases.insert(stream, Phase::Live), None);
                        }
                        Err(error) => {
                            prop_assert_eq!(opened, before[slot(d)].get());
                            prop_assert_eq!(error.limit(), before[slot(d)]);
                            prop_assert_eq!(ledger.local_opened(d), opened);
                        }
                    }
                }
                Op::ReceivingPartFrame(stream) | Op::SendingPartFrame(stream) => {
                    let receiving = matches!(op, Op::ReceivingPartFrame(_));
                    let local = stream.initiator() == local_initiator;
                    let uni = stream.directionality() == UNI;
                    let d = stream.directionality();
                    let outcome = if receiving {
                        ledger
                            .on_receiving_part_frame(stream, ReceivingPartFrameType::Stream)
                            .map_err(|error| error.transport_error_code())
                    } else {
                        ledger
                            .on_sending_part_frame(stream, SendingPartFrameType::StopSending)
                            .map_err(|error| error.transport_error_code())
                    };
                    let peer_limit = ledger.peer_limit(d).get();
                    let expected = if uni && local == receiving {
                        Err(TransportErrorCode::STREAM_STATE_ERROR)
                    } else if local {
                        match phases.get(&stream) {
                            None => Err(TransportErrorCode::STREAM_STATE_ERROR),
                            Some(Phase::Live) => Ok(IdentifiedStream::Existing),
                            Some(Phase::Reclaimed) => Ok(IdentifiedStream::Reclaimed),
                            Some(Phase::Uncreated) => unreachable!(),
                        }
                    } else if stream.index() >= peer_limit {
                        Err(TransportErrorCode::STREAM_LIMIT_ERROR)
                    } else {
                        match phases.get(&stream) {
                            None | Some(Phase::Uncreated) => Ok(IdentifiedStream::Created),
                            Some(Phase::Live) => Ok(IdentifiedStream::Existing),
                            Some(Phase::Reclaimed) => Ok(IdentifiedStream::Reclaimed),
                        }
                    };
                    prop_assert_eq!(outcome, expected);
                    if outcome == Ok(IdentifiedStream::Created) {
                        prop_assert!(created.insert(stream), "created twice: {stream}");
                        for lower in 0..stream.index() {
                            phases
                                .entry(id(stream.initiator(), d, lower))
                                .or_insert(Phase::Uncreated);
                        }
                        phases.insert(stream, Phase::Live);
                    }
                }
                Op::Reclaim(stream) => {
                    let result = ledger.reclaim(stream);
                    match phases.get(&stream) {
                        Some(Phase::Live) => {
                            prop_assert_eq!(result, Ok(()));
                            phases.insert(stream, Phase::Reclaimed);
                            if stream.initiator() != local_initiator {
                                reclaimed_peer[slot(stream.directionality())] += 1;
                            }
                        }
                        Some(Phase::Uncreated) => prop_assert_eq!(
                            result,
                            Err(ReclaimError::NotCreated { stream_id: stream })
                        ),
                        Some(Phase::Reclaimed) => prop_assert_eq!(
                            result,
                            Err(ReclaimError::AlreadyReclaimed { stream_id: stream })
                        ),
                        None => prop_assert_eq!(
                            result,
                            Err(ReclaimError::NotOpened { stream_id: stream })
                        ),
                    }
                }
                Op::MaxStreams(d, maximum) => {
                    let grew = ledger.on_max_streams(d, n(maximum));
                    prop_assert_eq!(grew, n(maximum) > before[slot(d)]);
                }
                Op::RaisePeerLimit(d) => {
                    if let Some(target) = ledger.max_streams(d) {
                        prop_assert!(target > ledger.peer_limit(d));
                        prop_assert!(ledger.raise_peer_limit(d, target));
                    }
                }
            }
            for d in [BIDI, UNI] {
                // The limit for this endpoint only grows.
                prop_assert!(ledger.local_limit(d) >= before[slot(d)]);
                // The target is the initial limit plus the reclaimed streams.
                let initial = if d == BIDI { initial.2 } else { initial.3 };
                let target = initial + reclaimed_peer[slot(d)];
                let expected = (target > ledger.peer_limit(d).get()).then(|| n(target));
                prop_assert_eq!(ledger.max_streams(d), expected);
            }
            // Live and reclaimed streams are disjoint, and the ledger agrees
            // on which are reclaimed.
            for (&stream, &phase) in &phases {
                prop_assert_eq!(ledger.is_reclaimed(stream), phase == Phase::Reclaimed);
            }
        }
    }
}
