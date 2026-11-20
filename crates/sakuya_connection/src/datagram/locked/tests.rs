//! The queues alone, and with the ranked strategy's intake and planner and
//! the DATAGRAM frame source: the bounds of each queue, the layer's end,
//! the limits the peer sets, and a withdrawal racing the supply.
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    num::NonZeroUsize,
    pin::pin,
    task::{Context, Poll, Waker},
};
use sakuya_wire::v1::frame::write::InFlightClass;
use std::{rc::Rc, sync::Barrier};

use frunk_core::indices::Here;
use sakuya_stream::connection::CloseReason;
use sakuya_wire::{
    datagram::MaxDatagramFrameSize,
    frame::NoLength,
    parts::{CNil, Coproduct},
    var_int::VarInt,
};

use super::*;
use crate::v1::events::PartEventSum;
use crate::v1::send_planning::SendStrategyPublisher;
use crate::{
    datagram::{
        application::DatagramWriter,
        send::{
            DatagramSettlement, DatagramState, WithdrawReport,
            tests::{SummaryWriter, TestSide, TestSources, TestTypes, Written, datagram_summary},
        },
    },
    frame_source::FrameSource,
    send_strategy::{
        DatagramFillPlan, DatagramLimits, FrameSourceCursor, InHead, LinkPathRoleKind,
        LinkPathSendPlanner, Observe, PacketOverheads, PlannedDatagram, PlannedPacket,
        SendStrategy,
        ranked::{
            CellIntentTicket, RankedLinkPathSendPlanner, RankedSendIntake, RankedSendPublisher,
            RankedSendStrategy,
        },
    },
    v1::application_handles::credential::HandleCredential,
    write::{ClassOfSource, NotLast, OpenPacket, Supplied},
};

pub(in crate::datagram) type Core = RankedSendStrategy<TestTypes>;
pub(in crate::datagram) type Planner = RankedLinkPathSendPlanner<TestTypes>;
/// The publisher the queues are lent, and ignore.
type Publisher = RankedSendPublisher<TestTypes>;
/// The ticket the queues keep for a datagram's intent.
type Ticket = CellIntentTicket<()>;
/// The handle of the strategy's intake the queues publish through.
type Publish = PlacedIntakeHandle<
    RankedSendIntake<TestTypes>,
    DatagramIntent<Urgency>,
    AnyActiveLinkPath,
    Ticket,
>;
/// The queues that give their events through `E`.
type QueuesOf<E> = LockedDatagramQueues<(), Ticket, TestSide, Publish, E>;
type Queues = QueuesOf<NoEvents>;
/// What sends and receives on queues that give their events through `E`,
/// as the handle of their layer does once it is lent the queues: the
/// queues' handle.
struct HandleOf<E> {
    queues: LockedDatagramQueuesHandle<(), Ticket, TestSide, Publish, E>,
}
type Handle = HandleOf<NoEvents>;
type WriterOf<E> = DatagramWriter<
    LockedDatagramSendShare<(), Ticket, TestSide, Publish, E>,
    sakuya_stream::send_options::NoSendOptions,
>;
type Writer = WriterOf<NoEvents>;

/// The queues `queues` as the driver lends them: queues over the test
/// strategy types, so that their methods know them.
fn lent<E: SharedEvents>(
    queues: &mut QueuesOf<E>,
) -> &mut impl DatagramQueues<
    (),
    TestTypes,
    Handle = LockedDatagramQueuesHandle<(), Ticket, TestSide, Publish, E>,
    Remains = LockedDatagramQueuesRemains<Bytes>,
    Received = Bytes,
> {
    queues
}

/// The capability's operations, on the queues' handle.
impl<E: SharedEvents> HandleOf<E> {
    fn datagram_writer(&self) -> WriterOf<E> {
        DatagramWriter::new(LockedDatagramSendShare {
            queue: SendQueueReach::Queues(Arc::clone(&self.queues.shared)),
        })
    }

    fn recv_datagram(
        &self,
    ) -> impl core::future::Future<Output = Result<Bytes, LayerEndedError<()>>> + '_ {
        poll_fn(move |cx| self.queues.shared.poll_receive(cx))
    }

    fn dropped_datagrams(&self) -> u64 {
        self.queues.dropped_datagrams()
    }
}

pub(in crate::datagram) fn bounds(
    datagrams: usize,
    bytes: usize,
    overflow: DatagramOverflow,
) -> DatagramQueueBounds {
    DatagramQueueBounds {
        datagrams: NonZeroUsize::new(datagrams).expect("not zero"),
        bytes,
        overflow,
    }
}

fn queues(peer: u32, config: LockedDatagramQueuesConfig) -> (Queues, Core, Handle) {
    queues_with(peer, config, NoEvents)
}

/// As [`queues`], with queues that give their events through `events`.
fn queues_with<E: SharedEvents + Clone + 'static>(
    peer: u32,
    config: LockedDatagramQueuesConfig,
    events: E,
) -> (QueuesOf<E>, Core, HandleOf<E>)
where
    E::PartEvents: PartEventSum<DatagramEvent, Here>,
{
    let mut core = Core::new();
    let _ = core.send_keys_available(sakuya_wire::v1::encryption_level::EncryptionLevel::OneRtt);
    let mut queues = <QueuesOf<E> as DatagramQueues<(), TestTypes>>::new(
        DatagramQueuesFacts {
            peer: MaxDatagramFrameSize::new(VarInt::from_u32(peer)),
        },
        config,
        DatagramEvents::new::<Here>(events),
        PlacedIntakeHandle::new::<InHead<Here>>(core.intake()),
    );
    let handle = HandleOf {
        queues: lent(&mut queues).handle(),
    };
    (queues, core, handle)
}

fn receiving(receive: DatagramQueueBounds) -> (Queues, Core, Handle) {
    queues(
        1200,
        LockedDatagramQueuesConfig {
            receive,
            ..LockedDatagramQueuesConfig::default()
        },
    )
}

fn sending(peer: u32, send: DatagramQueueBounds) -> (Queues, Core, Handle, Writer) {
    let (queues, core, handle) = queues(
        peer,
        LockedDatagramQueuesConfig {
            send,
            ..LockedDatagramQueuesConfig::default()
        },
    );
    let writer = handle.datagram_writer();
    (queues, core, handle, writer)
}

pub(in crate::datagram) fn frame(data: &'static [u8]) -> DatagramFrame<Bytes> {
    DatagramFrame::<_, NoLength>::without_length(Bytes::from_static(data)).into()
}

fn poll_now<F: core::future::Future>(future: F) -> Poll<F::Output> {
    pin!(future).poll(&mut Context::from_waker(Waker::noop()))
}

fn recv<E: SharedEvents>(handle: &HandleOf<E>) -> Poll<Result<Bytes, LayerEndedError<()>>> {
    poll_now(handle.recv_datagram())
}

fn received<E: SharedEvents>(handle: &HandleOf<E>) -> Vec<Bytes> {
    let mut all = Vec::new();
    while let Poll::Ready(Ok(datagram)) = recv(handle) {
        all.push(datagram);
    }
    all
}

pub(in crate::datagram) fn idle() -> LayerEnd<()> {
    LayerEnd::ConnectionClosed(CloseReason::IdleTimeout)
}

// ---- receiving ----

/// A full receive queue that refuses new datagrams drops each new one and
/// counts it; the ones kept are read in order.
#[test]
fn a_full_receive_queue_drops_the_new_datagram() {
    let (mut queues, _core, handle) = receiving(bounds(2, 1000, DatagramOverflow::RejectNew));
    for data in [&b"one"[..], b"two", b"three"] {
        lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(data));
    }
    assert_eq!(handle.dropped_datagrams(), 1);
    assert_eq!(received(&handle), [&b"one"[..], b"two"]);
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"four"));
    assert_eq!(received(&handle), [&b"four"[..]]);
    assert_eq!(handle.dropped_datagrams(), 1, "the count only grows");
}

/// A full receive queue that drops the oldest keeps the newest ones.
#[test]
fn a_full_receive_queue_drops_the_oldest_datagram() {
    let (mut queues, _core, handle) = receiving(bounds(2, 1000, DatagramOverflow::DropOldest));
    for data in [&b"one"[..], b"two", b"three"] {
        lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(data));
    }
    assert_eq!(handle.dropped_datagrams(), 1);
    assert_eq!(received(&handle), [&b"two"[..], b"three"]);
}

/// The bytes of payload are bounded as well; a datagram larger than the
/// whole queue is dropped without dropping the others.
#[test]
fn the_receive_queue_is_bounded_by_bytes() {
    let (mut queues, _core, handle) = receiving(bounds(8, 10, DatagramOverflow::DropOldest));
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"sixsix"));
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"fivef"));
    assert_eq!(handle.dropped_datagrams(), 1, "the first made room");
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"eleven-byte"));
    assert_eq!(handle.dropped_datagrams(), 2);
    assert_eq!(received(&handle), [&b"fivef"[..]]);
    let (mut queues, _core, handle) = receiving(bounds(8, 10, DatagramOverflow::RejectNew));
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"sixsix"));
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"fivef"));
    assert_eq!(received(&handle), [&b"sixsix"[..]]);
}

/// Once the layer ended, what was received is still read; then the end.
#[test]
fn what_was_received_is_read_before_the_layers_end() {
    let (mut queues, _core, handle) = receiving(DatagramQueueBounds::default());
    assert!(recv(&handle).is_pending());
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"kept"));
    lent(&mut queues).layer_ended(&mut Publisher::default(), idle());
    assert_eq!(recv(&handle), Poll::Ready(Ok(Bytes::from_static(b"kept"))));
    assert!(matches!(
        recv(&handle),
        Poll::Ready(Err(error)) if matches!(error.end(), LayerEnd::ConnectionClosed(_))
    ));
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"late"));
    assert!(matches!(recv(&handle), Poll::Ready(Err(_))));
}

// ---- sending ----

/// Above what one 1200-byte datagram holds in any packet, the guaranteed
/// size stays there; the peer's limit is the peer's, a Length of 4
/// bytes taken from 65535.
#[test]
fn the_guaranteed_size_is_what_any_link_path_in_use_carries() {
    let (_queues, _core, _handle, writer) = sending(65535, DatagramQueueBounds::default());
    assert_eq!(
        writer.datagram_limits(),
        DatagramFrameLimits {
            guaranteed: 1128,
            peer: 65530
        }
    );
    // one of the guaranteed size, as a DATAGRAM frame with a Length field
    // in a 0-RTT packet with connection IDs of 20 bytes, fills 1200 bytes
    let frame = super::super::frame_len_with_length(1128);
    assert_eq!(1 + 4 + 1 + 20 + 1 + 20 + 2 + 4 + frame + 16, 1200);
}

/// The peer's `max_datagram_frame_size` of this handshake replaces the one
/// the queues were made on: what is sent from then on is held to it, also
/// through a writer apart from the connection.
#[test]
fn the_peers_size_of_this_handshake_holds_what_is_sent_after() {
    let (mut queues, _core, _handle, writer) = sending(100, DatagramQueueBounds::default());
    lent(&mut queues)
        .peer_transport_parameters_known(MaxDatagramFrameSize::new(VarInt::from_u32(1200)));
    assert_eq!(
        writer.datagram_limits(),
        DatagramFrameLimits {
            guaranteed: 1128,
            peer: 1197
        }
    );
    writer
        .send(Bytes::from(vec![0; 500]))
        .expect("within the new limit")
        .release();
}

/// A peer without a `max_datagram_frame_size` other than 0 takes nothing.
#[test]
fn nothing_is_sent_to_a_peer_that_did_not_announce_support() {
    let (_queues, _core, _handle, writer) = sending(0, DatagramQueueBounds::default());
    assert!(matches!(
        writer.send(Bytes::from_static(b"no")),
        Err(SendDatagramError::NotSupportedByPeer)
    ));
    assert_eq!(
        writer.datagram_limits(),
        DatagramFrameLimits {
            guaranteed: 0,
            peer: 0
        }
    );
}

/// The limit is the peer's, counted with a Length field, in bytes of
/// payload: 100 takes 97 bytes (1 + 2 + 97).
#[test]
fn a_datagram_over_the_peers_limit_is_too_large() {
    let (_queues, _core, _handle, writer) = sending(100, DatagramQueueBounds::default());
    assert_eq!(
        writer.datagram_limits(),
        DatagramFrameLimits {
            guaranteed: 97,
            peer: 97
        }
    );
    writer
        .send(Bytes::from(vec![0; 97]))
        .expect("within the limit")
        .release();
    assert!(matches!(
        writer.send(Bytes::from(vec![0; 98])),
        Err(SendDatagramError::TooLarge { limit: 97 })
    ));
}

/// A full send queue that refuses new datagrams fails the send; one that
/// drops the oldest withdraws it, and its ticket says so.
#[test]
fn a_full_send_queue_refuses_or_drops_the_oldest() {
    let (_queues, _core, _handle, writer) =
        sending(1200, bounds(2, 1000, DatagramOverflow::RejectNew));
    let first = writer.send(Bytes::from_static(b"one")).unwrap();
    let second = writer.send(Bytes::from_static(b"two")).unwrap();
    assert!(matches!(
        writer.send(Bytes::from_static(b"three")),
        Err(SendDatagramError::QueueFull)
    ));
    // a withdrawn one leaves room
    assert_eq!(first.withdraw(), WithdrawReport::Withdrawn);
    let third = writer.send(Bytes::from_static(b"three")).unwrap();
    assert_eq!(second.state(), DatagramState::Waiting);
    drop((second, third));

    let (_queues, _core, _handle, writer) =
        sending(1200, bounds(2, 1000, DatagramOverflow::DropOldest));
    let mut first = writer.send(Bytes::from_static(b"one")).unwrap();
    let second = writer.send(Bytes::from_static(b"two")).unwrap();
    let third = writer.send(Bytes::from_static(b"three")).unwrap();
    assert_eq!(
        first.state(),
        DatagramState::Withdrawn(DatagramWithdrawCause::DroppedOldest)
    );
    assert_eq!(
        poll_now(first.settled()),
        Poll::Ready(DatagramSettlement::Withdrawn(
            DatagramWithdrawCause::DroppedOldest
        ))
    );
    assert_eq!(first.withdraw(), WithdrawReport::Withdrawn);
    assert_eq!(second.state(), DatagramState::Waiting);
    assert_eq!(third.state(), DatagramState::Waiting);
    // larger than the whole queue: refused, the others kept
    let (_queues, _core, _handle, writer) =
        sending(1200, bounds(4, 8, DatagramOverflow::DropOldest));
    let kept = writer.send(Bytes::from_static(b"four")).unwrap();
    assert!(matches!(
        writer.send(Bytes::from_static(b"ninebytes")),
        Err(SendDatagramError::QueueFull)
    ));
    assert_eq!(kept.state(), DatagramState::Waiting);
    kept.release();
}

/// Once the layer ended, sending fails with the end, and the datagrams
/// still waiting are withdrawn.
#[test]
fn the_layers_end_withdraws_what_waits_and_fails_sends() {
    let (mut queues, _core, _handle, writer) = sending(1200, DatagramQueueBounds::default());
    let waiting = writer.send(Bytes::from_static(b"waiting")).unwrap();
    lent(&mut queues).layer_ended(&mut Publisher::default(), idle());
    assert_eq!(
        waiting.state(),
        DatagramState::Withdrawn(DatagramWithdrawCause::LayerEnded)
    );
    assert!(matches!(
        writer.send(Bytes::from_static(b"late")),
        Err(SendDatagramError::LayerEnded { .. })
    ));
    waiting.release();
}

// ---- with the strategy ----

pub(in crate::datagram) fn limits() -> DatagramLimits {
    DatagramLimits {
        link_ceiling: Some(1500),
        peer_max_udp_payload: 65527,
        pmtu_conclusion: 1200,
        anti_amplification_credit: None,
        congestion_window_left: 12_000,
        pacing_allowance: usize::MAX,
        pacing_release_pending: false,
        probe_permits: 0,
    }
}

fn planner(core: &mut Core) -> Planner {
    let mut planner = core.add_link_path(1, LinkPathRoleKind::Active);
    let _ = planner.observe(limits());
    let _ = planner.observe(PacketOverheads {
        one_rtt: Some(30),
        ..PacketOverheads::default()
    });
    planner
}

/// Fill the next datagram's items into one packet through `queues`, as the
/// DATAGRAM frame source does, calling `before` before each; what was
/// written, or `None` when nothing is planned.
fn supply_next(
    queues: &mut Queues,
    planner: &mut Planner,
    core: &mut Core,
    mut before: impl FnMut(),
) -> Option<Written> {
    let driver = crate::send_strategy::DriverContent::default();
    let Poll::Ready(PlannedDatagram::Fill(mut plan)) = planner.poll_plan(
        core,
        &mut Publisher::default(),
        &driver,
        &mut Context::from_waker(Waker::noop()),
    ) else {
        return None;
    };
    let out = Rc::new(RefCell::new(Written::default()));
    let mut packet = OpenPacket::<_, ClassOfSource, NotLast>::new(SummaryWriter::new(1500, &out));
    while let Some(planned) = plan.next_packet() {
        let PlannedPacket::OneRtt(mut cursor) = planned else {
            panic!("only 1-RTT packets are planned")
        };
        while let Some(item) = FrameSourceCursor::<TestSources>::next(&mut cursor) {
            before();
            let supplied = item.supply(packet, |intent, open| {
                lent(queues)
                    .supply_datagram::<_, _, _, _, InHead<Here>>(
                        &mut Publisher::default(),
                        intent.key(),
                        open.into_source_class::<InFlightClass>(),
                    )
                    .into_class_of_source()
            });
            let Supplied::Open(open) = supplied else {
                panic!("a packet in a position other than the last stays open")
            };
            packet = open;
        }
    }
    drop(plan);
    drop(packet);
    Some(
        Rc::into_inner(out)
            .expect("the packet is dropped")
            .into_inner(),
    )
}

#[test]
fn pacing_can_release_a_single_datagram_smaller_than_the_path_maximum() {
    let (_queues, mut core, _handle, writer) = sending(1200, DatagramQueueBounds::default());
    let mut planner = planner(&mut core);
    let ticket = writer
        .with_send_options(Urgency::default(), AnyActiveLinkPath)
        .send(Bytes::from_static(b"ping"))
        .expect("taken");
    let driver = crate::send_strategy::DriverContent::default();
    let mut cx = Context::from_waker(Waker::noop());

    // A 30-byte packet overhead, a one-byte frame type, and four bytes of
    // payload. The only frame can omit its Length.
    let _ = planner.observe(DatagramLimits {
        pacing_allowance: 34,
        pacing_release_pending: true,
        ..limits()
    });
    let mut published = Publisher::default();
    assert!(
        planner
            .poll_plan(&mut core, &mut published, &driver, &mut cx)
            .is_pending()
    );
    assert_eq!(ticket.state(), DatagramState::Waiting);
    let _ = planner.observe(DatagramLimits {
        pacing_allowance: 35,
        pacing_release_pending: true,
        ..limits()
    });
    assert!(matches!(
        planner.poll_plan(&mut core, &mut published, &driver, &mut cx),
        Poll::Ready(PlannedDatagram::Fill(_))
    ));
}

/// Sent through the strategy, a datagram is written by the frame source,
/// and its acknowledgment settles its ticket; a datagram is planned once
/// only, and its queue counts it as gone once written.
#[test]
fn a_datagram_sent_through_the_strategy_is_written_and_acknowledged() {
    let (mut queues, mut core, _handle, writer) =
        sending(1200, bounds(1, 1000, DatagramOverflow::RejectNew));
    let mut planner = planner(&mut core);
    let mut ticket = writer
        .borrow_with_send_options(Urgency::default(), AnyActiveLinkPath)
        .send(Bytes::from_static(b"ping"))
        .expect("taken");
    let mut written = supply_next(&mut queues, &mut planner, &mut core, || {}).expect("planned");
    assert_eq!(written.bytes, [0x31, 0x04, b'p', b'i', b'n', b'g']);
    assert_eq!(ticket.state(), DatagramState::Sent);
    // the queue counted it as gone at once
    writer
        .send(Bytes::from_static(b"next"))
        .expect("room for one more")
        .release();
    lent(&mut queues).on_frame_lost(datagram_summary(written.summaries[0]));
    assert_eq!(ticket.state(), DatagramState::Lost);
    lent(&mut queues).on_frame_delivered(datagram_summary(written.summaries.remove(0)));
    assert_eq!(
        poll_now(ticket.settled()),
        Poll::Ready(DatagramSettlement::Acknowledged)
    );
    ticket.release();
}

/// Withdrawn on another thread just as the driver supplies it, a datagram
/// is either withdrawn and never written, or written and reported consumed.
/// The two threads meet once the datagram is planned; the withdrawal is
/// delayed by a different number of spins each time, so it falls on either
/// side of the claim and of the write.
#[test]
fn a_withdrawal_racing_the_supply_takes_place_or_reports_the_datagram_consumed() {
    let (mut queues, mut core, _handle, writer) = sending(1200, DatagramQueueBounds::default());
    let mut planner = planner(&mut core);
    let (mut withdrawn, mut consumed) = (0, 0);
    for round in 0..400 {
        let ticket = writer.send(Bytes::from_static(b"raced")).unwrap();
        let barrier = Barrier::new(2);
        let (written, report) = std::thread::scope(|scope| {
            let barrier = &barrier;
            let withdrawing = scope.spawn(move || {
                barrier.wait();
                for _ in 0..round % 40 {
                    core::hint::spin_loop();
                }
                ticket.withdraw()
            });
            let written = supply_next(&mut queues, &mut planner, &mut core, || {
                barrier.wait();
            });
            (written, withdrawing.join().unwrap())
        });
        let written = written.expect("the datagram is planned before it is withdrawn");
        match report {
            WithdrawReport::Withdrawn => {
                withdrawn += 1;
                assert!(written.bytes.is_empty());
            }
            WithdrawReport::Consumed => {
                consumed += 1;
                assert_eq!(written.bytes, [0x31, 0x05, b'r', b'a', b'c', b'e', b'd']);
            }
        }
        assert!(supply_next(&mut queues, &mut planner, &mut core, || {}).is_none());
    }
    assert_eq!(withdrawn + consumed, 400);
}

/// An intent the strategy gave out but that was not fulfilled is published
/// again at once, through the queues the DATAGRAM frame source finds in its
/// lineage: the next plan carries the datagram, with no send in between.
#[test]
fn an_unfulfilled_datagram_is_published_again_at_once() {
    let (mut queues, mut core, _handle, writer) =
        sending(1200, bounds(1, 1000, DatagramOverflow::RejectNew));
    let mut planner = planner(&mut core);
    let mut publisher = SendStrategyPublisher::new(Publisher::default());
    let ticket = writer.send(Bytes::from_static(b"again")).expect("taken");
    let driver = crate::send_strategy::DriverContent::default();
    let Poll::Ready(PlannedDatagram::Fill(mut plan)) = planner.poll_plan(
        &mut core,
        &mut Publisher::default(),
        &driver,
        &mut Context::from_waker(Waker::noop()),
    ) else {
        panic!("the datagram is planned")
    };
    let Some(PlannedPacket::OneRtt(mut cursor)) = plan.next_packet() else {
        panic!("a 1-RTT packet is planned")
    };
    let item = FrameSourceCursor::<TestSources>::next(&mut cursor).expect("the datagram's item");
    let out = Rc::new(RefCell::new(Written::default()));
    let packet = OpenPacket::<_, ClassOfSource, NotLast>::new(SummaryWriter::new(1500, &out));
    let taken = crate::take::TakenPositions::default();
    let mut lineage = crate::take::Lineage::new(
        frunk_core::hlist![
            &mut publisher,
            Some(crate::take::ComponentMut::new(
                &mut queues,
                crate::take::Sink::Nowhere,
                1
            ))
        ],
        &taken,
    );
    let _ = item.supply(packet, |intent, open| {
        // not written: the intent is not fulfilled instead
        crate::datagram::send::LineageDatagramFrameSource::<_, Queues, (), TestTypes, _, _, _>::new(
            &mut lineage,
        )
        .unfulfilled(
            intent,
            sakuya_stream::send_options::destination::Unfulfilled::Ended,
        );
        Supplied::Open(open)
    });
    drop(plan);
    assert_eq!(ticket.state(), DatagramState::Waiting);
    let written = supply_next(&mut queues, &mut planner, &mut core, || {}).expect("planned again");
    assert_eq!(written.bytes, [0x31, 0x05, b'a', b'g', b'a', b'i', b'n']);
    assert_eq!(ticket.state(), DatagramState::Sent);
    ticket.release();
}

/// The driver's panic only marks the end: who waits to receive and the
/// ticket of a datagram waiting are woken, every receive and send reports
/// the end, also before what was received, and the ticket settles as
/// withdrawn as the layer ended; the queues neither withdraw the datagram
/// nor end, and the strategy still holds its intent.
#[test]
fn the_drivers_panic_ends_the_waits_and_withdraws_nothing() {
    let (mut queues, mut core, handle, writer) = sending(1200, DatagramQueueBounds::default());
    let receive_wakes = Arc::new(CountingWake::default());
    let receive_waker = Waker::from(Arc::clone(&receive_wakes));
    let mut receive = pin!(handle.recv_datagram());
    assert!(
        receive
            .as_mut()
            .poll(&mut Context::from_waker(&receive_waker))
            .is_pending()
    );
    let mut ticket = writer.send(Bytes::from_static(b"waiting")).expect("taken");
    let settle_wakes = Arc::new(CountingWake::default());
    let settle_waker = Waker::from(Arc::clone(&settle_wakes));
    {
        let mut settled = pin!(ticket.settled());
        assert!(
            settled
                .as_mut()
                .poll(&mut Context::from_waker(&settle_waker))
                .is_pending()
        );
    }

    handle.queues.shared.driver_panicked(idle());
    assert_eq!(receive_wakes.count(), 1, "the receive is woken");
    assert_eq!(settle_wakes.count(), 1, "the ticket's wait is woken");
    // a datagram received now is not read
    lock(&queues.shared.state)
        .received
        .push_back(Bytes::from_static(b"late"));
    assert!(matches!(
        receive.as_mut().poll(&mut Context::from_waker(&receive_waker)),
        Poll::Ready(Err(error)) if *error.end() == idle()
    ));
    assert_eq!(
        poll_now(ticket.settled()),
        Poll::Ready(DatagramSettlement::Withdrawn(
            DatagramWithdrawCause::LayerEnded
        ))
    );
    assert_eq!(
        ticket.state(),
        DatagramState::Withdrawn(DatagramWithdrawCause::LayerEnded)
    );
    assert!(matches!(
        writer.send(Bytes::from_static(b"late")),
        Err(SendDatagramError::LayerEnded { source }) if *source.end() == idle()
    ));
    assert_eq!(ticket.withdraw(), WithdrawReport::Withdrawn);
    // the mark changed nothing: the queues did not end, the datagram
    // still waits in the send queue, and the strategy still plans it
    {
        let state = lock(&queues.shared.state);
        assert!(state.end.is_none());
        assert_eq!(state.waiting.len(), 1);
        assert!(state.waiting.values().all(|cell| cell.is_waiting()));
    }
    let mut planner = planner(&mut core);
    assert!(
        supply_next(&mut queues, &mut planner, &mut core, || {}).is_some(),
        "the strategy's ticket was left alone"
    );
}

/// A waker's wakes, counted.
#[derive(Default)]
pub(in crate::datagram) struct CountingWake(std::sync::atomic::AtomicUsize);

impl std::task::Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl CountingWake {
    pub(in crate::datagram) fn count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

// ---- the events of the datagrams ----

/// One event of the datagrams, as [`Recording`] keeps it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::datagram) enum RecordedDatagram {
    Moved(usize, DataLocation, DataLocation),
    Dropped(usize, DatagramDropped),
}

/// A handle that records the events of the datagrams; its clones share the
/// record.
#[derive(Debug, Clone, Default)]
pub(in crate::datagram) struct Recording(Arc<Mutex<Vec<RecordedDatagram>>>);

impl Recording {
    /// The events since the last call.
    pub(in crate::datagram) fn taken(&self) -> Vec<RecordedDatagram> {
        core::mem::take(&mut *lock(&self.0))
    }
}

impl SharedEvents for Recording {
    const ENABLED: bool = true;
    fn enabled(&self) -> bool {
        true
    }
    fn stream_state(
        &self,
        _: sakuya_wire::v1::stream_id::StreamId,
        _: crate::v1::events::StreamStateChange,
        _: crate::v1::events::EventInitiator,
    ) {
        panic!("the datagram queues give no events of streams");
    }
    fn stream_data_moved(&self, _: &crate::v1::events::StreamDataMoved) {
        panic!("the datagram queues give no events of streams");
    }
    type PartEvents = Coproduct<DatagramEvent, CNil>;
    fn part_event(&self, event: Self::PartEvents) {
        let recorded = match event {
            Coproduct::Inl(DatagramEvent::DataMoved { length, from, to }) => {
                RecordedDatagram::Moved(length, from, to)
            }
            Coproduct::Inl(DatagramEvent::Dropped { length, dropped }) => {
                RecordedDatagram::Dropped(length, dropped)
            }
            Coproduct::Inr(never) => match never {},
        };
        lock(&self.0).push(recorded);
    }
}

/// A datagram the send queue takes moves to the transport; one a full
/// send queue that drops the oldest drops is dropped as the send queue's,
/// with its own length; one refused gives nothing, as the send fails.
#[test]
fn the_send_queue_gives_what_it_takes_and_what_it_drops() {
    use DataLocation::{Application, Transport};

    let events = Recording::default();
    let (_queues, _core, handle) = queues_with(
        1200,
        LockedDatagramQueuesConfig {
            send: bounds(1, 1000, DatagramOverflow::DropOldest),
            ..LockedDatagramQueuesConfig::default()
        },
        events.clone(),
    );
    let writer = handle.datagram_writer();
    let first = writer.send(Bytes::from_static(b"one")).expect("taken");
    assert_eq!(
        events.taken(),
        [RecordedDatagram::Moved(3, Application, Transport)]
    );
    let second = writer.send(Bytes::from_static(b"second")).expect("taken");
    assert_eq!(
        events.taken(),
        [
            RecordedDatagram::Dropped(3, DatagramDropped::SendQueueFull),
            RecordedDatagram::Moved(6, Application, Transport),
        ]
    );
    drop((first, second));

    let (_queues, _core, handle) = queues_with(
        1200,
        LockedDatagramQueuesConfig {
            send: bounds(1, 1000, DatagramOverflow::RejectNew),
            ..LockedDatagramQueuesConfig::default()
        },
        events.clone(),
    );
    let writer = handle.datagram_writer();
    let kept = writer.send(Bytes::from_static(b"one")).expect("taken");
    events.taken();
    assert!(matches!(
        writer.send(Bytes::from_static(b"two")),
        Err(SendDatagramError::QueueFull)
    ));
    assert_eq!(events.taken(), [], "the refused send tells the application");
    drop(kept);
}

/// A full receive queue drops a new datagram, or the oldest, or one larger
/// than the whole queue, each as the receive queue's with its own length;
/// a datagram taken gives nothing until a read moves it to the application.
#[test]
fn the_receive_queue_gives_what_it_drops_and_what_is_read() {
    use DataLocation::{Application, Transport};
    use DatagramDropped::ReceiveQueueFull;

    let events = Recording::default();
    let (mut queues, _core, handle) = queues_with(
        1200,
        LockedDatagramQueuesConfig {
            receive: bounds(1, 10, DatagramOverflow::RejectNew),
            ..LockedDatagramQueuesConfig::default()
        },
        events.clone(),
    );
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"one"));
    assert_eq!(events.taken(), [], "network to transport is the frame's");
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"two!"));
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"eleven-byte"));
    assert_eq!(
        events.taken(),
        [
            RecordedDatagram::Dropped(4, ReceiveQueueFull),
            RecordedDatagram::Dropped(11, ReceiveQueueFull),
        ]
    );
    assert_eq!(received(&handle), [&b"one"[..]]);
    assert_eq!(
        events.taken(),
        [RecordedDatagram::Moved(3, Transport, Application)]
    );

    let (mut queues, _core, handle) = queues_with(
        1200,
        LockedDatagramQueuesConfig {
            receive: bounds(1, 10, DatagramOverflow::DropOldest),
            ..LockedDatagramQueuesConfig::default()
        },
        events.clone(),
    );
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"one"));
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"two!"));
    assert_eq!(
        events.taken(),
        [RecordedDatagram::Dropped(3, ReceiveQueueFull)]
    );
    assert_eq!(received(&handle), [&b"two!"[..]]);
    assert_eq!(
        events.taken(),
        [RecordedDatagram::Moved(4, Transport, Application)]
    );
}

// ---- through the shared connection, and too large for now ----

/// A held datagram, as the capability through the shared connection names
/// it: the queues keep it by its key until its credential comes back.
#[test]
fn a_datagram_held_through_the_shared_connection_is_kept_until_its_credential_comes_back() {
    let (mut queues, mut core, _handle) = queues(1200, LockedDatagramQueuesConfig::default());
    let mut publisher = Publisher::default();
    let credential = HandleCredential::new();
    let urgency = Urgency::default();
    let key = lent(&mut queues)
        .send_held::<_, _>(
            &mut publisher,
            Bytes::from_static(b"held"),
            &urgency,
            &AnyActiveLinkPath,
        )
        .expect("taken");
    let held = HeldDatagram::new(key, &credential);
    assert_eq!(
        lent(&mut queues).ticket_state::<_>(&publisher, held),
        DatagramState::Waiting
    );
    let mut planner = planner(&mut core);
    let mut written = supply_next(&mut queues, &mut planner, &mut core, || {}).expect("planned");
    assert_eq!(written.bytes, [0x31, 0x04, b'h', b'e', b'l', b'd']);
    assert_eq!(
        lent(&mut queues).ticket_state::<_>(&publisher, held),
        DatagramState::Sent
    );
    let mut cx = Context::from_waker(Waker::noop());
    assert!(
        lent(&mut queues)
            .poll_ticket_settled(held, &mut cx)
            .is_pending()
    );
    lent(&mut queues).on_frame_delivered(datagram_summary(written.summaries.remove(0)));
    assert_eq!(
        lent(&mut queues).poll_ticket_settled(held, &mut cx),
        Poll::Ready(DatagramSettlement::Acknowledged)
    );
    assert_eq!(
        lent(&mut queues).withdraw_held::<_, _>(&mut publisher, held),
        WithdrawReport::Consumed
    );

    // one withdrawn before it is written is never written
    let key = lent(&mut queues)
        .send_held::<_, _>(
            &mut publisher,
            Bytes::from_static(b"gone"),
            &urgency,
            &AnyActiveLinkPath,
        )
        .expect("taken");
    assert_eq!(
        lent(&mut queues)
            .withdraw_held::<_, _>(&mut publisher, HeldDatagram::new(key, &credential)),
        WithdrawReport::Withdrawn
    );
    assert!(supply_next(&mut queues, &mut planner, &mut core, || {}).is_none());
    // one released is still sent
    let key = lent(&mut queues)
        .send_held::<_, _>(
            &mut publisher,
            Bytes::from_static(b"let go"),
            &urgency,
            &AnyActiveLinkPath,
        )
        .expect("taken");
    lent(&mut queues).release_held(HeldDatagram::new(key, &credential));
    let written = supply_next(&mut queues, &mut planner, &mut core, || {}).expect("planned");
    assert_eq!(written.bytes.len(), 8);
}

/// Once the credential came back, the queues know nothing of the datagram:
/// an operation that names it reports it withdrawn as the layer ended
/// (and is a broken invariant, which a debug build asserts).
#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "is gone"))]
fn a_held_datagram_whose_credential_came_back_is_not_known() {
    let (mut queues, _core, _handle) = queues(1200, LockedDatagramQueuesConfig::default());
    let mut publisher = Publisher::default();
    let credential = HandleCredential::new();
    let key = lent(&mut queues)
        .send_held::<_, _>(
            &mut publisher,
            Bytes::from_static(b"held"),
            &Urgency::default(),
            &AnyActiveLinkPath,
        )
        .expect("taken");
    let held = HeldDatagram::new(key, &credential);
    lent(&mut queues).release_held(held);
    assert_eq!(
        lent(&mut queues).ticket_state::<_>(&publisher, held),
        DatagramState::Withdrawn(DatagramWithdrawCause::LayerEnded)
    );
}

/// Once the layer ended, what was in flight is lost, and what the held
/// tickets read stays in what the queues leave.
#[test]
fn the_layers_end_loses_what_is_in_flight_and_leaves_the_held_tickets() {
    let (mut queues, mut core, _handle, writer) = sending(1200, DatagramQueueBounds::default());
    let mut publisher = Publisher::default();
    let credential = HandleCredential::new();
    let mut detached = writer.send(Bytes::from_static(b"apart")).expect("taken");
    let key = lent(&mut queues)
        .send_held::<_, _>(
            &mut publisher,
            Bytes::from_static(b"held"),
            &Urgency::default(),
            &AnyActiveLinkPath,
        )
        .expect("taken");
    let mut planner = planner(&mut core);
    supply_next(&mut queues, &mut planner, &mut core, || {}).expect("planned");
    assert_eq!(detached.state(), DatagramState::Sent);
    let waiting = lent(&mut queues)
        .send_held::<_, _>(
            &mut publisher,
            Bytes::from_static(b"waits"),
            &Urgency::default(),
            &AnyActiveLinkPath,
        )
        .expect("taken");
    lent(&mut queues).layer_ended(&mut publisher, idle());
    assert_eq!(
        poll_now(detached.settled()),
        Poll::Ready(DatagramSettlement::Lost)
    );
    let mut remains = lent(&mut queues).remains();
    assert_eq!(remains.ticket_state(key), Some(DatagramState::Lost));
    assert_eq!(
        remains.ticket_settlement(waiting),
        Some(DatagramSettlement::Withdrawn(
            DatagramWithdrawCause::LayerEnded
        ))
    );
    assert_eq!(remains.take_ticket(key), Some(WithdrawReport::Consumed));
    assert_eq!(remains.take_ticket(key), None, "forgotten");
    assert_eq!(
        remains.take_ticket(waiting),
        Some(WithdrawReport::Withdrawn)
    );
    let _ = credential;
    detached.release();
}

/// A planner of an active link path `id` whose datagrams carry 1200 bytes,
/// of which a 1-RTT packet takes 30 beyond its frames.
pub(in crate::datagram) fn active(core: &mut Core, id: u8) -> Planner {
    let mut planner = core.add_link_path(id, LinkPathRoleKind::Active);
    let _ = planner.observe(limits());
    let _ = planner.observe(PacketOverheads {
        one_rtt: Some(30),
        ..PacketOverheads::default()
    });
    planner
}

/// Plan once with `planner`, writing nothing of what it plans.
fn plan_once(planner: &mut Planner, core: &mut Core) {
    let driver = crate::send_strategy::DriverContent::default();
    let _ = planner.poll_plan(
        core,
        &mut Publisher::default(),
        &driver,
        &mut Context::from_waker(Waker::noop()),
    );
}

/// A datagram larger than what every active link path carries waits as too
/// large: the intake's ticket says so, the datagram's ticket reads it, and
/// its wait goes on; once a link path can carry it, it waits as before.
#[test]
fn a_datagram_too_large_for_every_active_link_path_waits_as_too_large() {
    let (_queues, mut core, _handle, writer) = sending(65535, DatagramQueueBounds::default());
    let mut first = active(&mut core, 1);
    let mut second = active(&mut core, 2);
    let mut ticket = writer
        .send(Bytes::from(vec![0; 1200]))
        .expect("within the peer's limit");
    plan_once(&mut first, &mut core);
    assert_eq!(
        ticket.state(),
        DatagramState::Waiting,
        "the second link path has not planned"
    );
    plan_once(&mut second, &mut core);
    assert_eq!(ticket.state(), DatagramState::WaitingTooLarge);
    assert!(poll_now(ticket.settled()).is_pending(), "it still waits");
    let _ = second.observe(DatagramLimits {
        pmtu_conclusion: 1400,
        ..limits()
    });
    plan_once(&mut second, &mut core);
    assert_eq!(ticket.state(), DatagramState::Waiting);
    assert_eq!(ticket.withdraw(), WithdrawReport::Withdrawn);
}
