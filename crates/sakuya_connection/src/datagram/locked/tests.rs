//! The queues alone, and with the ranked strategy's intake and planner and
//! the DATAGRAM frame source: the bounds of each queue, the layer's end,
//! the limits the peer sets, and a withdrawal racing the supply.
use core::{
    cell::RefCell,
    pin::pin,
    task::{Context, Poll, Waker},
};
use std::{rc::Rc, sync::Barrier};

use frunk_core::indices::Here;
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream::connection::CloseReason;
use sakuya_wire::{
    datagram::MaxDatagramFrameSize,
    frame::NoLength,
    parts::{CNil, Coproduct},
    var_int::VarInt,
};

use super::*;
use crate::{
    datagram::{
        application::DatagramWriter,
        send::{
            DatagramFrameSource, DatagramSettlement, DatagramState, WithdrawReport,
            tests::{SummaryWriter, Written, datagram_summary},
        },
    },
    frame_source::{FrameSource, Nowhere},
    send_strategy::{
        DatagramFillPlan, DatagramLimits, FrameSourceCursor, FrameSourceSet, InHead,
        LinkPathRoleKind, LinkPathSendPlanner, MinimumLengths, Observe, PacketOverheads,
        PlannedDatagram, PlannedPacket, SendIntent, SendStrategy, SendStrategyTypes,
        ranked::{IntentTicket, RankedLinkPathSendPlanner, RankedSendIntake, RankedSendStrategy},
    },
    write::{ClassOfSource, FlightClass, InFlightClass, NotLast, OpenPacket, Supplied},
};

/// The side of these tests: it reads the bytes and the level.
#[derive(Debug)]
enum TestSide {}

impl DatagramSide for TestSide {
    type Received = Bytes;

    fn received(level: EncryptionLevel, data: Bytes) -> Bytes {
        assert_eq!(level, EncryptionLevel::OneRtt);
        data
    }
}

type Intents = Coproduct<Coproduct<DatagramIntent<Urgency>, CNil>, CNil>;

fn inner(intent: &Intents) -> &DatagramIntent<Urgency> {
    match intent {
        Coproduct::Inl(Coproduct::Inl(intent)) => intent,
        Coproduct::Inl(Coproduct::Inr(never)) | Coproduct::Inr(never) => match *never {},
    }
}

/// Every kind of packet carries the datagrams.
#[derive(Debug)]
enum TestSources {}

impl FrameSourceSet for TestSources {
    type Intents = Intents;
    type FrameSourceId = super::super::send::FrameSourceId;
    type Item<'a> = &'a DatagramIntent<Urgency>;

    fn item(intent: &Intents) -> Option<&DatagramIntent<Urgency>> {
        Some(inner(intent))
    }

    fn source(_: &&DatagramIntent<Urgency>) -> super::super::send::FrameSourceId {
        super::super::send::FrameSourceId::Datagram
    }
}

#[derive(Debug)]
enum TestTypes {}

impl SendStrategyTypes for TestTypes {
    type SendIntents = Intents;
    type FrameSourceId = super::super::send::FrameSourceId;
    type LinkPathIdentifier = u8;
    type CloseCause = ();
    type InitialFrameSources = TestSources;
    type HandshakeFrameSources = TestSources;
    type ZeroRttFrameSources = TestSources;
    type OneRttFrameSources = TestSources;
    type ProbeFrameSources = TestSources;
    type SettlingFrameSources = TestSources;

    fn frame_source(intent: &Intents) -> super::super::send::FrameSourceId {
        inner(intent).frame_source()
    }

    fn min_lengths(intent: &Intents) -> MinimumLengths {
        inner(intent).min_lengths()
    }

    fn flight_class(_: &Intents) -> FlightClass {
        FlightClass::InFlight
    }
}

type Core = RankedSendStrategy<TestTypes>;
type Planner = RankedLinkPathSendPlanner<TestTypes>;
type Queues = LockedDatagramQueues<(), IntentTicket<()>, TestSide>;
/// The handle of a layer whose one share is the queues' handle.
type Handle = EstablishedLayerHandle<
    frunk_core::HList![LockedDatagramQueuesHandle<(), IntentTicket<()>, TestSide>],
    RankedSendIntake<TestTypes>,
    (),
    (),
>;
type Writer = DatagramWriter<
    <Handle as Datagrams<(Here, InHead<Here>)>>::SendShare,
    sakuya_stream::send_options::NoSendOptions,
>;

fn bounds(datagrams: usize, bytes: usize, overflow: DatagramOverflow) -> DatagramQueueBounds {
    DatagramQueueBounds {
        datagrams: NonZeroUsize::new(datagrams).expect("not zero"),
        bytes,
        overflow,
    }
}

fn queues(peer: u32, config: LockedDatagramQueuesConfig) -> (Queues, Core, Handle) {
    let queues = Queues::new(
        DatagramQueuesFacts {
            peer: MaxDatagramFrameSize::new(VarInt::from_u32(peer)),
        },
        config,
    );
    let mut core = Core::new();
    core.send_keys_available(sakuya_wire::v1::encryption_level::EncryptionLevel::OneRtt);
    let handle =
        EstablishedLayerHandle::new(frunk_core::hlist![queues.handle()], core.intake(), ());
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
    let writer = Datagrams::<(Here, InHead<Here>)>::datagram_writer(&handle);
    (queues, core, handle, writer)
}

fn frame(data: &'static [u8]) -> DatagramFrame<Bytes> {
    DatagramFrame::<_, NoLength>::without_length(Bytes::from_static(data)).into()
}

fn poll_now<F: core::future::Future>(future: F) -> Poll<F::Output> {
    pin!(future).poll(&mut Context::from_waker(Waker::noop()))
}

fn recv(handle: &Handle) -> Poll<Result<Bytes, LayerEndedError<()>>> {
    poll_now(Datagrams::<(Here, InHead<Here>)>::recv_datagram(handle))
}

fn received(handle: &Handle) -> Vec<Bytes> {
    let mut all = Vec::new();
    while let Poll::Ready(Ok(datagram)) = recv(handle) {
        all.push(datagram);
    }
    all
}

fn idle() -> LayerEnd<()> {
    LayerEnd::ConnectionClosed(CloseReason::IdleTimeout)
}

// ---- receiving ----

/// A full receive queue that refuses new datagrams drops each new one and
/// counts it; the ones kept are read in order.
#[test]
fn a_full_receive_queue_drops_the_new_datagram() {
    let (mut queues, _core, handle) = receiving(bounds(2, 1000, DatagramOverflow::RejectNew));
    for data in [&b"one"[..], b"two", b"three"] {
        queues.on_datagram_frame(EncryptionLevel::OneRtt, frame(data));
    }
    assert_eq!(handle.dropped_datagrams(), 1);
    assert_eq!(received(&handle), [&b"one"[..], b"two"]);
    queues.on_datagram_frame(EncryptionLevel::OneRtt, frame(b"four"));
    assert_eq!(received(&handle), [&b"four"[..]]);
    assert_eq!(handle.dropped_datagrams(), 1, "the count only grows");
}

/// A full receive queue that drops the oldest keeps the newest ones.
#[test]
fn a_full_receive_queue_drops_the_oldest_datagram() {
    let (mut queues, _core, handle) = receiving(bounds(2, 1000, DatagramOverflow::DropOldest));
    for data in [&b"one"[..], b"two", b"three"] {
        queues.on_datagram_frame(EncryptionLevel::OneRtt, frame(data));
    }
    assert_eq!(handle.dropped_datagrams(), 1);
    assert_eq!(received(&handle), [&b"two"[..], b"three"]);
}

/// The bytes of payload are bounded as well; a datagram larger than the
/// whole queue is dropped without dropping the others.
#[test]
fn the_receive_queue_is_bounded_by_bytes() {
    let (mut queues, _core, handle) = receiving(bounds(8, 10, DatagramOverflow::DropOldest));
    queues.on_datagram_frame(EncryptionLevel::OneRtt, frame(b"sixsix"));
    queues.on_datagram_frame(EncryptionLevel::OneRtt, frame(b"fivef"));
    assert_eq!(handle.dropped_datagrams(), 1, "the first made room");
    queues.on_datagram_frame(EncryptionLevel::OneRtt, frame(b"eleven-byte"));
    assert_eq!(handle.dropped_datagrams(), 2);
    assert_eq!(received(&handle), [&b"fivef"[..]]);
    let (mut queues, _core, handle) = receiving(bounds(8, 10, DatagramOverflow::RejectNew));
    queues.on_datagram_frame(EncryptionLevel::OneRtt, frame(b"sixsix"));
    queues.on_datagram_frame(EncryptionLevel::OneRtt, frame(b"fivef"));
    assert_eq!(received(&handle), [&b"sixsix"[..]]);
}

/// Once the layer ended, what was received is still read; then the end.
#[test]
fn what_was_received_is_read_before_the_layers_end() {
    let (mut queues, _core, handle) = receiving(DatagramQueueBounds::default());
    assert!(recv(&handle).is_pending());
    queues.on_datagram_frame(EncryptionLevel::OneRtt, frame(b"kept"));
    queues.layer_ended(idle());
    assert_eq!(recv(&handle), Poll::Ready(Ok(Bytes::from_static(b"kept"))));
    assert!(matches!(
        recv(&handle),
        Poll::Ready(Err(error)) if matches!(error.end(), LayerEnd::ConnectionClosed(_))
    ));
    queues.on_datagram_frame(EncryptionLevel::OneRtt, frame(b"late"));
    assert!(matches!(recv(&handle), Poll::Ready(Err(_))));
}

// ---- sending ----

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
            everywhere: 0,
            somewhere: 0
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
            everywhere: 97,
            somewhere: 97
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
    queues.layer_ended(idle());
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

fn limits() -> DatagramLimits {
    DatagramLimits {
        link_ceiling: Some(1500),
        peer_max_udp_payload: 65527,
        pmtu_conclusion: 1200,
        anti_amplification_credit: None,
        congestion_window_left: 12_000,
        pacing_allowance: usize::MAX,
        probe_permits: 0,
    }
}

fn planner(core: &mut Core) -> Planner {
    let mut planner = core.add_link_path(1, LinkPathRoleKind::Active);
    planner.observe(limits());
    planner.observe(PacketOverheads {
        one_rtt: Some(30),
        ..PacketOverheads::default()
    });
    planner
}

/// Fill the next datagram's items into one packet through the DATAGRAM
/// frame source, calling `before` before each; what was written, or `None`
/// when nothing is planned.
fn supply_next(
    planner: &mut Planner,
    core: &mut Core,
    mut before: impl FnMut(),
) -> Option<Written> {
    let Poll::Ready(PlannedDatagram::Fill(mut plan)) =
        planner.poll_plan(core, &mut Context::from_waker(Waker::noop()))
    else {
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
                DatagramFrameSource
                    .supply::<_, _, InHead<Here>>(intent, open.into_source_class::<InFlightClass>())
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

/// Sent through the strategy, a datagram is written by the frame source,
/// and its acknowledgment settles its ticket; a datagram is planned once
/// only, and its queue counts it as gone once written.
#[test]
fn a_datagram_sent_through_the_strategy_is_written_and_acknowledged() {
    let (_queues, mut core, _handle, writer) =
        sending(1200, bounds(1, 1000, DatagramOverflow::RejectNew));
    let mut planner = planner(&mut core);
    let mut ticket = writer
        .with_send_options(Urgency::default(), AnyActiveLinkPath)
        .send(Bytes::from_static(b"ping"))
        .expect("taken");
    let mut written = supply_next(&mut planner, &mut core, || {}).expect("planned");
    assert_eq!(written.bytes, [0x31, 0x04, b'p', b'i', b'n', b'g']);
    assert_eq!(ticket.state(), DatagramState::Sent);
    assert!(supply_next(&mut planner, &mut core, || {}).is_none());
    DatagramFrameSource.delivered::<_, Nowhere>(
        &mut (),
        PacketNumberSpaceKind::ApplicationData,
        datagram_summary(written.summaries.remove(0)),
    );
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
    let (_queues, mut core, _handle, writer) = sending(1200, DatagramQueueBounds::default());
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
            let written = supply_next(&mut planner, &mut core, || {
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
        assert!(supply_next(&mut planner, &mut core, || {}).is_none());
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
    let publish = core
        .intake()
        .handle::<DatagramIntent<Urgency>, InHead<Here>>();
    let ticket = writer.send(Bytes::from_static(b"again")).expect("taken");
    let Poll::Ready(PlannedDatagram::Fill(mut plan)) =
        planner.poll_plan(&mut core, &mut Context::from_waker(Waker::noop()))
    else {
        panic!("the datagram is planned")
    };
    let Some(PlannedPacket::OneRtt(mut cursor)) = plan.next_packet() else {
        panic!("a 1-RTT packet is planned")
    };
    let item = FrameSourceCursor::<TestSources>::next(&mut cursor).expect("the datagram's item");
    let out = Rc::new(RefCell::new(Written::default()));
    let packet = OpenPacket::<_, ClassOfSource, NotLast>::new(SummaryWriter::new(1500, &out));
    let mut taken = crate::take::TakenPositions::default();
    let mut lineage = crate::take::Lineage::new(frunk_core::hlist![Some(&mut queues)], &mut taken);
    let _ = item.supply(packet, |intent, open| {
        // not written: the intent is not fulfilled instead
        crate::datagram::send::LineageDatagramFrameSource::<_, Queues, (), _, Here>::new(
            &mut lineage,
            publish.clone(),
        )
        .unfulfilled(
            intent,
            sakuya_stream::send_options::destination::Unfulfilled::Ended,
        );
        Supplied::Open(open)
    });
    drop(plan);
    assert_eq!(ticket.state(), DatagramState::Waiting);
    let written = supply_next(&mut planner, &mut core, || {}).expect("planned again");
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
    let (queues, mut core, handle, writer) = sending(1200, DatagramQueueBounds::default());
    let receive_wakes = Arc::new(CountingWake::default());
    let receive_waker = Waker::from(Arc::clone(&receive_wakes));
    let mut receive = pin!(Datagrams::<(Here, InHead<Here>)>::recv_datagram(&handle));
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

    handle.shares.driver_panicked(idle());
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
        assert!(state.waiting[0].is_waiting());
    }
    let mut planner = planner(&mut core);
    assert!(
        supply_next(&mut planner, &mut core, || {}).is_some(),
        "the strategy's ticket was left alone"
    );
}

/// A waker's wakes, counted.
#[derive(Default)]
struct CountingWake(std::sync::atomic::AtomicUsize);

impl std::task::Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl CountingWake {
    fn count(&self) -> usize {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}
