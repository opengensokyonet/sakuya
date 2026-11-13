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
        HandshakePacket, InitialPacket, OneRttPacket, OneRttProbePacket, PartsFrameSources,
        SettlingResponsePacket, ZeroRttPacket,
    },
    send_strategy::SendIntentsOf,
    v1::{
        Part,
        send::{AckIntent, FrameSourceId, ProbePingIntent, SendItem},
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

fn ack(core: &mut Core, space: PacketNumberSpaceKind) -> IntentTicket<()> {
    core.publish_to(AckIntent::new(space), AnyActiveLinkPath)
}

const ALL: [EncryptionLevel; 3] = [
    EncryptionLevel::Initial,
    EncryptionLevel::Handshake,
    EncryptionLevel::OneRtt,
];

/// The kinds of the packets of the plan and, in each, the items, as the
/// cursors give them, each item reported as `written`.
fn walk(
    plan: &mut RankedPlan<'_, TestTypes>,
    written: usize,
) -> Vec<(PlannedPacketKind, Vec<SendItem>)> {
    fn items<S: FrameSourceSet>(
        cursor: &mut impl FrameSourceCursor<S, Feedback = RankedFeedback>,
        written: usize,
        into: &mut Vec<SendItem>,
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
    fn head(self) -> SendItem;
}

impl Head for frunk_core::coproduct::Coproduct<SendItem, sakuya_wire::parts::CNil> {
    fn head(self) -> SendItem {
        match self {
            frunk_core::coproduct::Coproduct::Inl(item) => item,
            frunk_core::coproduct::Coproduct::Inr(never) => match never {},
        }
    }
}

fn ready<'a>(
    planner: &'a mut Planner,
    core: &'a mut Core,
    waker: &Waker,
) -> RankedPlan<'a, TestTypes> {
    match planner.poll_plan(core, &mut Context::from_waker(waker)) {
        Poll::Ready(PlannedDatagram::Fill(plan)) => plan,
        Poll::Ready(PlannedDatagram::ResendClose) => panic!("no close packet is planned"),
        Poll::Pending => panic!("a plan was expected"),
    }
}

fn pending(planner: &mut Planner, core: &mut Core, waker: &Waker) {
    assert!(matches!(
        planner.poll_plan(core, &mut Context::from_waker(waker)),
        Poll::Pending
    ));
}

#[test]
fn acknowledgments_go_in_increasing_levels_and_lower_levels_yield() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let _acks = [
        ack(&mut core, ApplicationData),
        ack(&mut core, Initial),
        ack(&mut core, Handshake),
    ];
    // Ranked after the acknowledgments, the Handshake PING is of a lower
    // level than the 1-RTT ACK: it yields to the next datagram.
    let _ping = planner.publish(ProbePingIntent::new(Handshake)).unwrap();
    let (_, waker) = waker();
    let mut plan = ready(&mut planner, &mut core, &waker);
    let leading = plan.leading_content().unwrap();
    assert_eq!(leading.packet, PlannedPacketKind::Initial);
    assert_eq!(
        leading.source,
        frunk_core::coproduct::Coproduct::Inl(FrameSourceId::Ack(Initial))
    );
    assert_eq!(
        walk(&mut plan, 10),
        [
            (PlannedPacketKind::Initial, vec![SendItem::Ack(Initial)]),
            (PlannedPacketKind::Handshake, vec![SendItem::Ack(Handshake)]),
            (
                PlannedPacketKind::OneRtt,
                vec![SendItem::Ack(ApplicationData)]
            ),
        ]
    );
    drop(plan);
    // The acknowledgments were consumed; the PING is planned next.
    let mut plan = ready(&mut planner, &mut core, &waker);
    assert_eq!(
        walk(&mut plan, 1),
        [(
            PlannedPacketKind::Handshake,
            vec![SendItem::ProbePing(Handshake)]
        )]
    );
}

#[test]
fn consumed_and_withdrawn_intents_leave_the_plan() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let consumed = ack(&mut core, Initial);
    let withdrawn = ack(&mut core, Handshake);
    drop(withdrawn);
    let (_, waker) = waker();
    let mut plan = ready(&mut planner, &mut core, &waker);
    assert_eq!(
        walk(&mut plan, 10),
        [(PlannedPacketKind::Initial, vec![SendItem::Ack(Initial)])]
    );
    drop(plan);
    assert_eq!(consumed.state(), IntentState::Consumed);
    pending(&mut planner, &mut core, &waker);
}

#[test]
fn an_item_dropped_without_being_supplied_ends_the_datagram() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let initial = ack(&mut core, Initial);
    let _handshake = ack(&mut core, Handshake);
    let (_, waker) = waker();
    let mut plan = ready(&mut planner, &mut core, &waker);
    let Some(PlannedPacket::Initial(mut cursor)) = plan.next_packet() else {
        panic!("an Initial packet first")
    };
    // Not supplied: the item goes out of scope here.
    let _ = cursor.next().unwrap();
    assert!(cursor.next().is_none());
    assert!(plan.next_packet().is_none());
    assert!(plan.peek_next_packet().is_none());
    drop(plan);
    assert_eq!(initial.state(), IntentState::Waiting);
}

#[test]
fn content_that_does_not_fit_holds_its_place_until_the_window_opens() {
    // A server's Initial ACK needs no window; the PING of 1-RTT does.
    let (mut core, mut planner) = setup(&ALL, 0);
    let _ping = planner
        .publish(ProbePingIntent::new(ApplicationData))
        .unwrap();
    let (wakes, waker) = waker();
    pending(&mut planner, &mut core, &waker);
    // A window still too small for the packet does not wake the planner.
    planner.observe(limits(20));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    planner.observe(limits(31));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    let mut plan = ready(&mut planner, &mut core, &waker);
    assert_eq!(
        walk(&mut plan, 1),
        [(
            PlannedPacketKind::OneRtt,
            vec![SendItem::ProbePing(ApplicationData)]
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
    let _ack = ack(&mut core, Initial);
    let (wakes, waker) = waker();
    pending(&mut planner, &mut core, &waker);
    planner.observe(limits(1200));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    let mut plan = ready(&mut planner, &mut core, &waker);
    assert_eq!(
        walk(&mut plan, 10),
        [(PlannedPacketKind::Initial, vec![SendItem::Ack(Initial)])]
    );
}

#[test]
fn publishing_and_keys_wake_a_waiting_planner() {
    let (mut core, mut planner) = setup(&[EncryptionLevel::Initial], 12_000);
    let (wakes, waker) = waker();
    pending(&mut planner, &mut core, &waker);
    let _ack = ack(&mut core, Handshake);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    // Without Handshake keys there is nothing to plan.
    pending(&mut planner, &mut core, &waker);
    core.send_keys_available(EncryptionLevel::Handshake);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
    let mut plan = ready(&mut planner, &mut core, &waker);
    assert_eq!(
        walk(&mut plan, 10),
        [(PlannedPacketKind::Handshake, vec![SendItem::Ack(Handshake)])]
    );
}

#[test]
fn a_confirmed_handshake_stops_initial_and_handshake_content() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let _acks = [ack(&mut core, Initial), ack(&mut core, Handshake)];
    core.handshake_confirmed();
    let (_, waker) = waker();
    pending(&mut planner, &mut core, &waker);
}

#[test]
fn a_planner_out_of_the_active_role_refuses_and_ends_its_intents() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let ping = planner
        .publish(ProbePingIntent::new(ApplicationData))
        .unwrap();
    planner.role_changed(&mut core, LinkPathRoleKind::Closing);
    assert!(!ping.is_waiting());
    let refused = planner
        .publish(ProbePingIntent::new(ApplicationData))
        .unwrap_err();
    assert_eq!(
        refused.error(),
        &LinkPathPublishError::from(RoleNotAcceptingError::new(LinkPathRoleKind::Closing))
    );
    assert_eq!(refused.into_intent(), ProbePingIntent::new(ApplicationData));
}

#[test]
fn closing_ends_waiting_intents_and_later_ones_with_the_reason() {
    let (mut core, _planner) = setup(&ALL, 12_000);
    let waiting = ack(&mut core, Initial);
    core.no_more_active_link_paths(CloseReason::IdleTimeout);
    let later = ack(&mut core, Handshake);
    for ticket in [waiting, later] {
        let IntentState::Ended(error) = ticket.state() else {
            panic!("the intent ended")
        };
        assert_eq!(error, ConnectionClosedError::new(CloseReason::IdleTimeout));
    }
}
