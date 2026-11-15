//! The intake, its tickets, and the order of application data, with intents
//! of a test part whose rank and urgency each intent gives.
use core::task::{Context, Poll, Waker};
use std::sync::atomic::Ordering;

use sakuya_stream::{
    connection::{CloseReason, ConnectionClosedError},
    send_options::urgency::Urgency,
};
use sakuya_wire::{
    parts::{CNil, Coproduct},
    v1::encryption_level::EncryptionLevel,
};

use super::{super::*, waker};
use crate::{
    send_strategy::{
        InHead, IntentTicketResize, IntentTicketWithdraw, SendIntentHandle, SendIntentIntake,
    },
    write::InFlightClass,
};

/// An intent of the test part: `id` names it, and it needs `min` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TestIntent {
    id: u32,
    priority: SendPriority,
    holds_place: bool,
    urgency: Urgency,
    min: usize,
}

fn data(id: u32, urgency: u8) -> TestIntent {
    TestIntent {
        id,
        priority: SendPriority::ApplicationData,
        holds_place: false,
        urgency: Urgency::new(urgency).unwrap(),
        min: 10,
    }
}

fn control(id: u32) -> TestIntent {
    TestIntent {
        id,
        priority: SendPriority::Control,
        holds_place: true,
        urgency: Urgency::default(),
        min: 10,
    }
}

fn sized(intent: TestIntent, min: usize) -> TestIntent {
    TestIntent { min, ..intent }
}

fn lengths(min: usize) -> MinimumLengths {
    MinimumLengths {
        with_length: min,
        as_last: min,
    }
}

impl SendIntent for TestIntent {
    type FrameSourceId = u32;
    type Class = InFlightClass;

    fn frame_source(&self) -> u32 {
        self.id
    }

    fn min_lengths(&self) -> MinimumLengths {
        lengths(self.min)
    }
}

impl RankedIntent for TestIntent {
    fn rank(&self) -> SendRank {
        SendRank {
            priority: self.priority,
            holds_place: self.holds_place,
        }
    }

    fn urgency(&self) -> Urgency {
        self.urgency
    }
}

impl RankedCoreIntent for TestIntent {
    type Outcome<C> = IntentTicket<C>;
}

type Intents = Coproduct<Coproduct<TestIntent, CNil>, CNil>;

fn inner(intent: &Intents) -> &TestIntent {
    match intent {
        Coproduct::Inl(Coproduct::Inl(intent)) => intent,
        Coproduct::Inl(Coproduct::Inr(never)) | Coproduct::Inr(never) => match *never {},
    }
}

/// Every kind of packet carries the test intents.
#[derive(Debug)]
enum TestSources {}

impl FrameSourceSet for TestSources {
    type Intents = Intents;
    type FrameSourceId = u32;
    type Item<'a> = TestIntent;

    fn item(intent: &Intents) -> Option<TestIntent> {
        Some(*inner(intent))
    }

    fn source(item: &TestIntent) -> u32 {
        item.id
    }
}

#[derive(Debug)]
enum TestTypes {}

impl SendStrategyTypes for TestTypes {
    type SendIntents = Intents;
    type FrameSourceId = u32;
    type LinkPathIdentifier = u8;
    type CloseCause = ();
    type InitialFrameSources = TestSources;
    type HandshakeFrameSources = TestSources;
    type ZeroRttFrameSources = TestSources;
    type OneRttFrameSources = TestSources;
    type ProbeFrameSources = TestSources;
    type SettlingFrameSources = TestSources;

    fn frame_source(intent: &Intents) -> u32 {
        inner(intent).id
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
type Handle = <RankedSendIntake<TestTypes> as SendIntentIntake<AnyActiveLinkPath>>::Handle<
    TestIntent,
    InHead<frunk_core::indices::Here>,
>;

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

/// A core with 1-RTT keys only, so every intent goes into 1-RTT packets,
/// its planner of an active link path that has `window` bytes, each 1-RTT
/// packet taking 30 beyond its frames, and the intake's handle.
fn setup(window: usize) -> (Core, Planner, Handle) {
    let mut core = Core::new();
    core.send_keys_available(EncryptionLevel::OneRtt);
    let mut planner = core.add_link_path(1, LinkPathRoleKind::Active);
    planner.observe(limits(window));
    planner.observe(PacketOverheads {
        one_rtt: Some(30),
        ..PacketOverheads::default()
    });
    let handle = core.intake().handle::<TestIntent, _>();
    (core, planner, handle)
}

fn publish(handle: &Handle, intent: TestIntent) -> IntentTicket<()> {
    handle.publish_to(intent, AnyActiveLinkPath)
}

/// The ids of the items of the next datagram, the first `take` of them
/// supplied with `written` bytes each; `None` when nothing is planned.
fn next_datagram(
    planner: &mut Planner,
    core: &mut Core,
    waker: &Waker,
    take: usize,
    written: usize,
) -> Option<Vec<u32>> {
    let Poll::Ready(PlannedDatagram::Fill(mut plan)) =
        planner.poll_plan(core, &mut Context::from_waker(waker))
    else {
        return None;
    };
    let mut ids = Vec::new();
    while let Some(packet) = plan.next_packet() {
        let PlannedPacket::OneRtt(mut cursor) = packet else {
            panic!("only 1-RTT packets are planned")
        };
        while ids.len() < take
            && let Some(PlannedItem { item, feedback, .. }) =
                FrameSourceCursor::<TestSources>::next(&mut cursor)
        {
            ids.push(item.id);
            feedback.supplied(written);
        }
        if ids.len() == take {
            break;
        }
    }
    Some(ids)
}

fn all(planner: &mut Planner, core: &mut Core, waker: &Waker) -> Option<Vec<u32>> {
    next_datagram(planner, core, waker, usize::MAX, 0)
}

fn wakes(count: &super::CountingWaker) -> usize {
    count.0.load(Ordering::SeqCst)
}

#[test]
fn what_the_intake_publishes_is_planned() {
    let (mut core, mut planner, handle) = setup(12_000);
    let ticket = publish(&handle, data(1, 3));
    let (_, waker) = waker();
    assert_eq!(
        next_datagram(&mut planner, &mut core, &waker, usize::MAX, 10),
        Some(vec![1])
    );
    assert_eq!(ticket.state(), IntentState::Consumed);
    assert_eq!(all(&mut planner, &mut core, &waker), None);
}

#[test]
fn a_publish_from_another_thread_wakes_the_waiting_planner() {
    let (mut core, mut planner, handle) = setup(12_000);
    let (count, waker) = waker();
    assert_eq!(all(&mut planner, &mut core, &waker), None);
    let ticket = std::thread::spawn(move || publish(&handle, data(1, 3)))
        .join()
        .unwrap();
    assert_eq!(wakes(&count), 1);
    assert_eq!(all(&mut planner, &mut core, &waker), Some(vec![1]));
    drop(ticket);
}

#[test]
fn a_publish_while_the_planner_plans_keeps_it_from_waiting() {
    let (mut core, mut planner, handle) = setup(12_000);
    let (count, waker) = waker();
    // published after the planner began and before it waits: it plans
    // again instead of waiting
    let seen = planner.begin(&mut core);
    let _ticket = publish(&handle, data(1, 3));
    assert!(!planner.wait(seen, &waker));
    assert_eq!(wakes(&count), 0, "nobody was waiting to be woken");
    assert_eq!(all(&mut planner, &mut core, &waker), Some(vec![1]));
}

#[test]
fn a_publish_after_the_planner_waits_wakes_it() {
    let (mut core, mut planner, handle) = setup(12_000);
    let (count, waker) = waker();
    let seen = planner.begin(&mut core);
    assert!(planner.wait(seen, &waker));
    let _ticket = publish(&handle, data(1, 3));
    assert_eq!(wakes(&count), 1);
    // woken once: the waker was taken
    let _again = publish(&handle, data(2, 3));
    assert_eq!(wakes(&count), 1);
    assert_eq!(all(&mut planner, &mut core, &waker), Some(vec![1, 2]));
}

#[test]
fn content_that_does_not_fit_the_room_wakes_when_the_room_grows() {
    let (mut core, mut planner, handle) = setup(100);
    let (count, waker) = waker();
    assert_eq!(all(&mut planner, &mut core, &waker), None);
    let _ticket = publish(&handle, sized(data(1, 3), 500));
    assert_eq!(wakes(&count), 0, "it does not fit 100 bytes");
    planner.observe(limits(400));
    assert_eq!(wakes(&count), 0, "nor 400");
    planner.observe(limits(1000));
    assert_eq!(wakes(&count), 1);
    assert_eq!(all(&mut planner, &mut core, &waker), Some(vec![1]));
}

#[test]
fn a_waiting_planner_wakes_for_content_that_fits_its_room_as_last_told() {
    let (mut core, mut planner, handle) = setup(0);
    let (count, waker) = waker();
    assert_eq!(all(&mut planner, &mut core, &waker), None);
    // nothing waits for room: the larger window wakes nothing, but it is
    // the room content published now is compared with
    planner.observe(limits(1000));
    assert_eq!(wakes(&count), 0);
    let _ticket = publish(&handle, data(1, 3));
    assert_eq!(wakes(&count), 1);
}

#[test]
fn content_another_planner_took_in_still_wakes_the_waiting_one() {
    let (mut core, mut first, handle) = setup(100);
    let mut second = core.add_link_path(2, LinkPathRoleKind::Active);
    second.observe(limits(0));
    second.observe(PacketOverheads {
        one_rtt: Some(30),
        ..PacketOverheads::default()
    });
    let (count, waker) = waker();
    assert_eq!(all(&mut second, &mut core, &waker), None);
    let _ticket = publish(&handle, sized(data(1, 3), 500));
    // the first link path takes it in, and has no room for it either
    let (_, other) = super::waker();
    assert_eq!(all(&mut first, &mut core, &other), None);
    second.observe(limits(1000));
    assert_eq!(wakes(&count), 1);
    assert_eq!(all(&mut second, &mut core, &waker), Some(vec![1]));
}

#[test]
fn resizing_wakes_once_the_intent_fits() {
    let (mut core, mut planner, handle) = setup(500);
    let mut ticket = publish(&handle, sized(data(1, 3), 1000));
    let (count, waker) = waker();
    assert_eq!(all(&mut planner, &mut core, &waker), None);
    ticket.resize(lengths(800));
    assert_eq!(wakes(&count), 0, "800 bytes do not fit 500");
    ticket.resize(lengths(100));
    assert_eq!(wakes(&count), 1);
    let Poll::Ready(PlannedDatagram::Fill(plan)) =
        planner.poll_plan(&mut core, &mut Context::from_waker(&waker))
    else {
        panic!("a plan was expected")
    };
    // the plan reads the least room as resized
    assert_eq!(plan.leading_content().unwrap().min, lengths(100));
}

#[test]
fn withdrawn_and_dropped_tickets_leave_the_plan() {
    let (mut core, mut planner, handle) = setup(12_000);
    let withdrawn = publish(&handle, data(1, 3));
    let dropped = publish(&handle, data(2, 3));
    let _kept = publish(&handle, data(3, 3));
    assert_eq!(withdrawn.withdraw(), IntentState::Withdrawn);
    drop(dropped);
    let (_, waker) = waker();
    assert_eq!(
        next_datagram(&mut planner, &mut core, &waker, usize::MAX, 10),
        Some(vec![3])
    );
    // once taken in by the core, too
    let later = publish(&handle, data(4, 3));
    let consumed = publish(&handle, data(5, 3));
    planner.begin(&mut core);
    assert!(lock(&core.published).is_empty());
    assert_eq!(later.withdraw(), IntentState::Withdrawn);
    assert_eq!(
        next_datagram(&mut planner, &mut core, &waker, usize::MAX, 10),
        Some(vec![5])
    );
    assert_eq!(consumed.withdraw(), IntentState::Consumed);
}

#[test]
fn withdrawing_what_holds_its_place_wakes_the_planner() {
    let (mut core, mut planner, handle) = setup(100);
    let blocking = publish(&handle, sized(control(1), 500));
    let _data = publish(&handle, data(2, 3));
    let (count, waker) = waker();
    assert_eq!(all(&mut planner, &mut core, &waker), None);
    drop(blocking);
    assert_eq!(wakes(&count), 1);
    assert_eq!(all(&mut planner, &mut core, &waker), Some(vec![2]));
}

#[test]
fn what_the_intake_publishes_after_the_close_ends_with_its_reason() {
    let (mut core, _planner, handle) = setup(12_000);
    let unplanned = publish(&handle, data(1, 3));
    core.no_more_active_link_paths(CloseReason::IdleTimeout);
    let later = publish(&handle, data(2, 3));
    drop(core);
    let after_the_core = publish(&handle, data(3, 3));
    for ticket in [unplanned, later, after_the_core] {
        assert_eq!(
            ticket.withdraw(),
            IntentState::Ended(ConnectionClosedError::new(CloseReason::IdleTimeout))
        );
    }
}

#[test]
fn application_data_goes_by_urgency_after_the_other_ranks() {
    let (mut core, mut planner, handle) = setup(12_000);
    let _tickets = [
        publish(&handle, data(1, 5)),
        publish(&handle, data(2, 0)),
        publish(&handle, data(3, 7)),
        publish(&handle, control(4)),
        publish(&handle, data(5, 3)),
        publish(
            &handle,
            TestIntent {
                priority: SendPriority::Acknowledgment,
                ..control(6)
            },
        ),
    ];
    let (_, waker) = waker();
    assert_eq!(
        all(&mut planner, &mut core, &waker),
        Some(vec![6, 4, 2, 5, 1, 3])
    );
}

#[test]
fn application_data_of_one_urgency_takes_turns() {
    let (mut core, mut planner, handle) = setup(12_000);
    let _tickets = [
        publish(&handle, data(1, 3)),
        publish(&handle, data(2, 3)),
        publish(&handle, data(3, 3)),
        publish(&handle, data(9, 1)),
    ];
    let (_, waker) = waker();
    // the more urgent one first, then the first of urgency 3 has its turn
    assert_eq!(
        next_datagram(&mut planner, &mut core, &waker, 2, 0),
        Some(vec![9, 1])
    );
    assert_eq!(all(&mut planner, &mut core, &waker), Some(vec![9, 2, 3, 1]));
    assert_eq!(
        next_datagram(&mut planner, &mut core, &waker, 2, 0),
        Some(vec![9, 2])
    );
    assert_eq!(all(&mut planner, &mut core, &waker), Some(vec![9, 3, 1, 2]));
}

#[test]
fn application_data_that_does_not_fit_is_passed_over() {
    let (mut core, mut planner, handle) = setup(200);
    let _tickets = [
        publish(&handle, sized(data(1, 0), 500)),
        publish(&handle, data(2, 7)),
    ];
    let (_, waker) = waker();
    assert_eq!(all(&mut planner, &mut core, &waker), Some(vec![2]));
    // what holds its place in another rank still keeps what follows out
    let (mut core, mut planner, handle) = setup(200);
    let _tickets = [
        publish(&handle, sized(control(1), 500)),
        publish(&handle, data(2, 7)),
    ];
    assert_eq!(all(&mut planner, &mut core, &waker), None);
}
