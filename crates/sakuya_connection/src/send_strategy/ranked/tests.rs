use core::task::{Context, Poll, Waker};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::Wake;

use sakuya_recovery::packet_number_space::PacketNumberSpaceKind::{
    self, ApplicationData, Handshake, Initial,
};
use sakuya_stream::connection::CloseReason;
use sakuya_wire::{
    parts::{HCons, HNil},
    v1::encryption_level::EncryptionLevel,
};

use super::*;
use crate::{
    frame_source::{
        FrameSourcePart, HandshakePacket, InitialPacket, OneRttPacket, OneRttProbePacket,
        PartsFrameSources, SettlingResponsePacket, ZeroRttPacket,
    },
    send_strategy::SendIntentsOf,
    send_strategy::{InjectSendIntent, SendIntentHandle},
    v1::{
        Part,
        send::{AckIntent, FrameSourceId, ProbePingIntent, SendItem},
        streams::send::{StreamIntent, shortest_stream_frame},
    },
};

type Parts = HCons<Part, HNil>;

#[derive(Debug)]
enum TestTypes {}

impl SendStrategyTypes for TestTypes {
    type SendIntents = <Parts as SendIntentsOf>::SendIntents;
    type FrameSourceId = <Parts as SendIntentsOf>::FrameSourceIds;
    type LinkPathIdentifier = u8;
    type CloseCause = ();
    type InitialFrameSources = PartsFrameSources<InitialPacket, Parts>;
    type HandshakeFrameSources = PartsFrameSources<HandshakePacket, Parts>;
    type ZeroRttFrameSources = PartsFrameSources<ZeroRttPacket, Parts>;
    type OneRttFrameSources = PartsFrameSources<OneRttPacket, Parts>;
    type ProbeFrameSources = PartsFrameSources<OneRttProbePacket, Parts>;
    type SettlingFrameSources = PartsFrameSources<SettlingResponsePacket, Parts>;

    fn frame_source(intent: &Self::SendIntents) -> Self::FrameSourceId {
        Parts::frame_source(intent)
    }

    fn min_lengths(intent: &Self::SendIntents) -> MinimumLengths {
        Parts::min_lengths(intent)
    }

    fn flight_class(intent: &Self::SendIntents) -> FlightClass {
        Parts::flight_class(intent)
    }
}

type Core = RankedSendStrategy<TestTypes>;
type Planner = RankedLinkPathSendPlanner<TestTypes>;

struct CountingWaker(AtomicUsize);

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn waker() -> (Arc<CountingWaker>, Waker) {
    let count = Arc::new(CountingWaker(AtomicUsize::new(0)));
    (Arc::clone(&count), Waker::from(count))
}

fn limits(window: usize) -> DatagramLimits {
    DatagramLimits {
        link_ceiling: Some(1500),
        peer_max_udp_payload: 65527,
        pmtu_conclusion: 1200,
        anti_amplification_credit: None,
        congestion_window_left: window,
        pacing_allowance: usize::MAX,
        probe_permits: 0,
    }
}

fn overheads() -> PacketOverheads {
    PacketOverheads {
        initial: Some(40),
        handshake: Some(40),
        zero_rtt: Some(40),
        one_rtt: Some(30),
        expands_every_initial: false,
    }
}

fn setup(levels: &[EncryptionLevel], window: usize) -> (Core, Planner) {
    let mut core = Core::new();
    for &level in levels {
        core.send_keys_available(level);
    }
    let mut planner = core.add_link_path(1, LinkPathRoleKind::Active);
    planner.observe(limits(window));
    planner.observe(overheads());
    (core, planner)
}

type Intents = <Parts as SendIntentsOf>::SendIntents;

/// The driver's content of an ACK frame due in `space`.
fn ack(space: PacketNumberSpaceKind) -> Intents {
    <Intents as InjectSendIntent<_, _>>::inject(AckIntent::new(space, 5))
}

/// The driver's content of the PING of a probe of `space`.
fn ping(space: PacketNumberSpaceKind) -> Intents {
    <Intents as InjectSendIntent<_, _>>::inject(ProbePingIntent::new(space))
}

/// The driver's content of `intents`, with no close packet.
fn driver(intents: impl IntoIterator<Item = Intents>) -> DriverContent<Intents> {
    DriverContent {
        intents: intents.into_iter().collect(),
        close: None,
    }
}

/// The driver's content of a sealed close packet, `received` datagrams
/// after it was sealed.
fn sealed(received: u64) -> DriverContent<Intents> {
    DriverContent {
        intents: Vec::new(),
        close: Some(CloseResendFacts {
            datagrams_received: received,
        }),
    }
}

const ALL: [EncryptionLevel; 3] = [
    EncryptionLevel::Initial,
    EncryptionLevel::Handshake,
    EncryptionLevel::OneRtt,
];

/// The kinds of the packets of the plan and, in each, the frame sources of
/// the items, as the cursors give them, each item reported as `written`.
fn walk(
    plan: &mut RankedPlan<'_, TestTypes>,
    written: usize,
) -> Vec<(PlannedPacketKind, Vec<FrameSourceId>)> {
    fn items<S: FrameSourceSet>(
        cursor: &mut impl FrameSourceCursor<S, Feedback = RankedFeedback>,
        written: usize,
        into: &mut Vec<FrameSourceId>,
    ) where
        for<'a> S::Item<'a>: Head,
    {
        while let Some(PlannedItem { item, feedback, .. }) = cursor.next() {
            into.push(item.head());
            feedback.supplied(written);
        }
    }
    let mut packets = Vec::new();
    while let Some(packet) = plan.next_packet() {
        let kind = packet.kind();
        let mut planned = Vec::new();
        match packet {
            PlannedPacket::Initial(mut cursor) => items(&mut cursor, written, &mut planned),
            PlannedPacket::Handshake(mut cursor) => items(&mut cursor, written, &mut planned),
            PlannedPacket::ZeroRtt(mut cursor) => items(&mut cursor, written, &mut planned),
            PlannedPacket::OneRtt(mut cursor) => items(&mut cursor, written, &mut planned),
            PlannedPacket::OneRttProbe(mut cursor) => items(&mut cursor, written, &mut planned),
            PlannedPacket::SettlingResponse(mut cursor) => {
                items(&mut cursor, written, &mut planned);
            }
        }
        packets.push((kind, planned));
    }
    packets
}

trait Head {
    fn head(self) -> FrameSourceId;
}

impl Head for frunk_core::coproduct::Coproduct<SendItem, sakuya_wire::parts::CNil> {
    fn head(self) -> FrameSourceId {
        match self {
            frunk_core::coproduct::Coproduct::Inl(item) => {
                <Part as FrameSourcePart<InitialPacket>>::source(&item)
            }
            frunk_core::coproduct::Coproduct::Inr(never) => match never {},
        }
    }
}

fn ready<'a>(
    planner: &'a mut Planner,
    core: &'a mut Core,
    driver: &'a DriverContent<Intents>,
    waker: &Waker,
) -> RankedPlan<'a, TestTypes> {
    match planner.poll_plan(core, driver, &mut Context::from_waker(waker)) {
        Poll::Ready(PlannedDatagram::Fill(plan)) => plan,
        Poll::Ready(PlannedDatagram::ResendClose) => panic!("no close packet is planned"),
        Poll::Pending => panic!("a plan was expected"),
    }
}

fn pending(planner: &mut Planner, core: &mut Core, driver: &DriverContent<Intents>, waker: &Waker) {
    assert!(matches!(
        planner.poll_plan(core, driver, &mut Context::from_waker(waker)),
        Poll::Pending
    ));
}

#[test]
fn acknowledgments_go_in_increasing_levels_and_lower_levels_yield() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    // Ranked after the acknowledgments, the Handshake PING is of a lower
    // level than the 1-RTT ACK: it yields to the next datagram.
    let content = driver([
        ack(ApplicationData),
        ack(Initial),
        ack(Handshake),
        ping(Handshake),
    ]);
    let (_, waker) = waker();
    let mut plan = ready(&mut planner, &mut core, &content, &waker);
    let leading = plan.leading_content().unwrap();
    assert_eq!(leading.packet, PlannedPacketKind::Initial);
    assert_eq!(
        leading.source,
        frunk_core::coproduct::Coproduct::Inl(FrameSourceId::Ack(Initial))
    );
    assert_eq!(
        walk(&mut plan, 10),
        [
            (
                PlannedPacketKind::Initial,
                vec![FrameSourceId::Ack(Initial)]
            ),
            (
                PlannedPacketKind::Handshake,
                vec![FrameSourceId::Ack(Handshake)]
            ),
            (
                PlannedPacketKind::OneRtt,
                vec![FrameSourceId::Ack(ApplicationData)]
            ),
        ]
    );
    drop(plan);
    // The acknowledgments were written, and the driver no longer has them;
    // the PING is planned next.
    let content = driver([ping(Handshake)]);
    let mut plan = ready(&mut planner, &mut core, &content, &waker);
    assert_eq!(
        walk(&mut plan, 1),
        [(
            PlannedPacketKind::Handshake,
            vec![FrameSourceId::ProbePing(Handshake)]
        )]
    );
}

/// The planner keeps nothing of the driver's content: what the next
/// request does not have is not planned.
#[test]
fn the_drivers_content_is_planned_as_each_request_gives_it() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let content = driver([ack(Initial)]);
    let (_, waker) = waker();
    let mut plan = ready(&mut planner, &mut core, &content, &waker);
    assert_eq!(
        walk(&mut plan, 10),
        [(
            PlannedPacketKind::Initial,
            vec![FrameSourceId::Ack(Initial)]
        )]
    );
    drop(plan);
    let mut plan = ready(&mut planner, &mut core, &content, &waker);
    assert_eq!(
        walk(&mut plan, 0).len(),
        1,
        "planned again while it is there"
    );
    drop(plan);
    pending(&mut planner, &mut core, &DriverContent::new(), &waker);
}

/// An intent that stays after writing is not consumed by a supply that
/// wrote part of it: its source resized it, and it is planned again by the
/// room it needs then; the other intents are consumed as before.
#[test]
fn an_intent_that_stays_after_writing_is_planned_again() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let handle = core
        .intake()
        .handle::<StreamIntent<sakuya_stream::send_options::urgency::Urgency>, _>();
    let stream_id =
        sakuya_wire::v1::stream_id::StreamId::from(sakuya_wire::var_int::VarInt::from_u32(1));
    let mut stream = handle.publish_to(
        StreamIntent::Stream {
            stream_id,
            parameters: sakuya_stream::send_options::urgency::Urgency::default(),
            min: shortest_stream_frame(stream_id, sakuya_wire::var_int::VarInt::ZERO, true),
        },
        AnyActiveLinkPath,
    );
    let max_data = handle.publish_to(StreamIntent::MaxData { len: 2 }, AnyActiveLinkPath);
    let (_, waker) = waker();
    let none = DriverContent::new();
    let mut plan = ready(&mut planner, &mut core, &none, &waker);
    assert_eq!(
        walk(&mut plan, 10),
        [(
            PlannedPacketKind::OneRtt,
            vec![FrameSourceId::MaxData, FrameSourceId::Stream]
        )]
    );
    drop(plan);
    assert_eq!(max_data.state(), IntentState::Consumed);
    assert_eq!(stream.state(), IntentState::Waiting);
    // what is left needs more room: the next byte has an Offset field
    stream.resize(MinimumLengths {
        with_length: 5,
        as_last: 4,
    });
    let mut plan = ready(&mut planner, &mut core, &none, &waker);
    assert_eq!(
        walk(&mut plan, 10),
        [(PlannedPacketKind::OneRtt, vec![FrameSourceId::Stream])]
    );
    drop(plan);
    assert_eq!(stream.state(), IntentState::Waiting);
    // withdrawn once nothing is left: nothing more is planned
    let _ = stream.withdraw();
    pending(&mut planner, &mut core, &none, &waker);
}

/// An item dropped without being supplied wrote nothing: the plan goes on
/// to the next item, and whether the datagram ends is the filling's, as
/// the item tells whether it holds its place.
#[test]
fn an_item_dropped_without_being_supplied_leaves_the_plan_going_on() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let content = driver([ack(ApplicationData), ping(ApplicationData), ack(Handshake)]);
    let (_, waker) = waker();
    let mut plan = ready(&mut planner, &mut core, &content, &waker);
    let Some(PlannedPacket::Handshake(mut cursor)) = plan.next_packet() else {
        panic!("a Handshake packet first")
    };
    let item = cursor.next().unwrap();
    assert!(item.holds_place(), "an ACK holds its place");
    assert!(item.last_in_packet());
    // Not supplied: the item is not used again.
    assert!(cursor.next().is_none());
    let Some(PlannedPacket::OneRtt(mut cursor)) = plan.next_packet() else {
        panic!("then a 1-RTT packet")
    };
    // Not supplied: the item goes out of scope here.
    let _ = cursor.next().unwrap();
    let ping = cursor.next().expect("the item after it");
    assert_eq!(ping.item.head(), FrameSourceId::ProbePing(ApplicationData));
}

#[test]
fn content_that_does_not_fit_holds_its_place_until_the_window_opens() {
    // A server's Initial ACK needs no window; the PING of 1-RTT does.
    let (mut core, mut planner) = setup(&ALL, 0);
    let content = driver([ping(ApplicationData)]);
    let (wakes, waker) = waker();
    pending(&mut planner, &mut core, &content, &waker);
    // A window still too small for the packet does not wake the planner.
    planner.observe(limits(20));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    planner.observe(limits(31));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    let mut plan = ready(&mut planner, &mut core, &content, &waker);
    assert_eq!(
        walk(&mut plan, 1),
        [(
            PlannedPacketKind::OneRtt,
            vec![FrameSourceId::ProbePing(ApplicationData)]
        )]
    );
}

#[test]
fn a_client_initial_needs_room_for_the_whole_expanded_datagram() {
    let (mut core, mut planner) = setup(&ALL, 1199);
    planner.observe(PacketOverheads {
        expands_every_initial: true,
        ..overheads()
    });
    let content = driver([ack(Initial)]);
    let (wakes, waker) = waker();
    pending(&mut planner, &mut core, &content, &waker);
    planner.observe(limits(1200));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    let mut plan = ready(&mut planner, &mut core, &content, &waker);
    assert_eq!(
        walk(&mut plan, 10),
        [(
            PlannedPacketKind::Initial,
            vec![FrameSourceId::Ack(Initial)]
        )]
    );
}

#[test]
fn keys_wake_a_waiting_planner() {
    let (mut core, mut planner) = setup(&[EncryptionLevel::Initial], 12_000);
    let content = driver([ack(Handshake)]);
    let (wakes, waker) = waker();
    // Without Handshake keys there is nothing to plan.
    pending(&mut planner, &mut core, &content, &waker);
    core.send_keys_available(EncryptionLevel::Handshake);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    let mut plan = ready(&mut planner, &mut core, &content, &waker);
    assert_eq!(
        walk(&mut plan, 10),
        [(
            PlannedPacketKind::Handshake,
            vec![FrameSourceId::Ack(Handshake)]
        )]
    );
}

#[test]
fn a_confirmed_handshake_stops_initial_and_handshake_content() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let content = driver([ack(Initial), ack(Handshake)]);
    core.handshake_confirmed();
    let (_, waker) = waker();
    pending(&mut planner, &mut core, &content, &waker);
}

/// The planner holds no intents of its own: a role change and its end hand
/// nothing back, and a link path that is not active plans none of the
/// driver's content its packets cannot carry.
#[test]
fn a_planner_holds_nothing_to_end() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let mut ended = Vec::new();
    planner.role_changed(&mut core, LinkPathRoleKind::Candidate, &mut ended);
    assert!(ended.is_empty());
    let (_, waker) = waker();
    pending(
        &mut planner,
        &mut core,
        &driver([ack(ApplicationData), ping(ApplicationData)]),
        &waker,
    );
    planner.ended(&mut core, &mut ended);
    assert!(ended.is_empty());
}

#[test]
fn closing_ends_waiting_intents_and_later_ones_with_the_reason() {
    let (mut core, _planner) = setup(&ALL, 12_000);
    let handle = core
        .intake()
        .handle::<StreamIntent<sakuya_stream::send_options::urgency::Urgency>, _>();
    let waiting = handle.publish_to(StreamIntent::MaxData { len: 2 }, AnyActiveLinkPath);
    core.no_more_active_link_paths(CloseReason::IdleTimeout);
    let later = handle.publish_to(StreamIntent::MaxData { len: 3 }, AnyActiveLinkPath);
    for ticket in [waiting, later] {
        let IntentState::Ended(error) = ticket.state() else {
            panic!("the intent ended")
        };
        assert_eq!(error, ConnectionClosedError::new(CloseReason::IdleTimeout));
    }
}

#[test]
fn content_of_a_packet_the_link_path_cannot_send_holds_no_place() {
    // The Initial keys went: the link path sends no Initial packet, and the
    // core was never told otherwise.
    let (mut core, mut planner) = setup(&ALL, 12_000);
    planner.observe(PacketOverheads {
        initial: None,
        ..overheads()
    });
    let content = driver([ack(Initial), ack(Handshake)]);
    let (wakes, waker) = waker();
    let mut plan = ready(&mut planner, &mut core, &content, &waker);
    assert_eq!(
        walk(&mut plan, 10),
        [(
            PlannedPacketKind::Handshake,
            vec![FrameSourceId::Ack(Handshake)]
        )]
    );
    drop(plan);
    // With only the Initial ACK left, nothing is planned and no room is
    // waited for: a larger datagram does not wake the planner.
    pending(&mut planner, &mut core, &driver([ack(Initial)]), &waker);
    assert_eq!(planner.thresholds.ack_only, None);
    assert_eq!(planner.thresholds.in_flight, None);
    planner.observe(DatagramLimits {
        link_ceiling: Some(65527),
        pmtu_conclusion: 65527,
        ..limits(usize::MAX)
    });
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
}

/// Whether the planner gives the close packet to send again now, with
/// `content` the driver's.
fn resends(
    planner: &mut Planner,
    core: &mut Core,
    content: &DriverContent<Intents>,
    waker: &Waker,
) -> bool {
    match planner.poll_plan(core, content, &mut Context::from_waker(waker)) {
        Poll::Ready(PlannedDatagram::ResendClose) => true,
        Poll::Ready(PlannedDatagram::Fill(_)) => panic!("a closing link path fills nothing"),
        Poll::Pending => false,
    }
}

#[test]
fn a_closing_link_path_resends_once_sealed_and_for_powers_of_two_of_datagrams() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    planner.role_changed(&mut core, LinkPathRoleKind::Closing, &mut Vec::new());
    let (_, waker) = waker();
    assert!(
        !resends(&mut planner, &mut core, &DriverContent::new(), &waker),
        "nothing sealed"
    );
    assert!(resends(&mut planner, &mut core, &sealed(0), &waker));
    assert!(
        !resends(&mut planner, &mut core, &sealed(0), &waker),
        "once"
    );
    let mut answered = Vec::new();
    for datagram in 1..=17 {
        if resends(&mut planner, &mut core, &sealed(datagram), &waker) {
            answered.push(datagram);
        }
    }
    assert_eq!(answered, [1, 2, 4, 8, 16]);
    // two datagrams before the call asks again are one resend
    let mut answered = Vec::new();
    for datagram in [18, 20, 31, 33, 40] {
        if resends(&mut planner, &mut core, &sealed(datagram), &waker) {
            answered.push(datagram);
        }
    }
    assert_eq!(answered, [33]);
}

#[test]
fn a_close_packet_with_fewer_datagrams_than_at_the_last_resend_goes_as_one_just_sealed() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    planner.role_changed(&mut core, LinkPathRoleKind::Closing, &mut Vec::new());
    let (_, waker) = waker();
    assert!(resends(&mut planner, &mut core, &sealed(5), &waker));
    assert!(!resends(&mut planner, &mut core, &sealed(6), &waker));
    assert!(resends(&mut planner, &mut core, &sealed(0), &waker));
    assert!(resends(&mut planner, &mut core, &sealed(1), &waker));
}

#[test]
fn a_close_packet_sealed_before_the_closing_role_waits_for_it() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let (count, waker) = waker();
    pending(&mut planner, &mut core, &sealed(0), &waker);
    planner.role_changed(&mut core, LinkPathRoleKind::Closing, &mut Vec::new());
    assert_eq!(count.0.load(Ordering::SeqCst), 1, "woken by the role");
    assert!(resends(&mut planner, &mut core, &sealed(0), &waker));
}

#[test]
fn a_draining_link_path_resends_nothing() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    planner.role_changed(&mut core, LinkPathRoleKind::Closing, &mut Vec::new());
    planner.role_changed(&mut core, LinkPathRoleKind::Draining, &mut Vec::new());
    let (_, waker) = waker();
    assert!(!resends(&mut planner, &mut core, &sealed(1), &waker));
}

mod intake;
