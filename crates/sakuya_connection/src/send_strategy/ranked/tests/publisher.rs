//! The publisher: what it marks and keeps for the planners that wait with
//! it, the consumption of its tickets' intents, and the intents too large
//! for every active link path.
use sakuya_stream_v1::send_options::urgency::Urgency;
use sakuya_wire::var_int::VarInt;
use sakuya_wire_v1::stream_id::StreamId;

use super::*;

/// A STREAM intent of `number` that needs `as_last` bytes in the last
/// position, and one more with a Length field: it stays after writing.
fn stream_needing(number: u32, as_last: usize) -> StreamIntent<Urgency> {
    StreamIntent::Stream {
        stream_id: StreamId::from(VarInt::from_u32(number)),
        parameters: Urgency::default(),
        min: MinimumLengths {
            with_length: as_last + 1,
            as_last,
        },
    }
}

/// A MAX_DATA intent: it is consumed once written.
fn max_data() -> StreamIntent<Urgency> {
    StreamIntent::MaxData { len: 2 }
}

fn publish(published: &mut Publisher, intent: StreamIntent<Urgency>) -> KeyIntentTicket {
    published.publish_to(intent, AnyActiveLinkPath)
}

/// A planner that waits with the publisher, after a plan of nothing.
fn waiting(window: usize) -> (Core, Planner, Publisher) {
    let (mut core, mut planner) = setup(&ALL, window);
    let mut published = Publisher::default();
    let (_, waker) = waker();
    pending_with(
        &mut planner,
        &mut core,
        &mut published,
        &DriverContent::new(),
        &waker,
    );
    (core, planner, published)
}

/// What the core holds of the intent of `ticket`: whether it waits, or
/// `None` once it left.
fn keyed_waiting(core: &Core, ticket: &KeyIntentTicket) -> Option<bool> {
    core.keyed
        .iter()
        .find(|entry| entry.state.key == ticket.key)
        .map(|entry| entry.state.waiting)
}

#[test]
fn content_that_fits_marks_the_waiting_planner() {
    let (_core, mut planner, mut published) = waiting(12_000);
    let _ticket = publish(&mut published, max_data());
    assert_eq!(published.take_plan_change(), PlanChange::Possible);
    assert_eq!(published.take_plan_change(), PlanChange::None, "taken");
    assert_eq!(
        planner.intents_changed(&mut published),
        PlanChange::Possible
    );
    assert_eq!(
        planner.intents_changed(&mut published),
        PlanChange::None,
        "the mark is taken"
    );
}

#[test]
fn content_that_does_not_fit_is_a_threshold_a_larger_room_reaches() {
    let (_core, mut planner, mut published) = waiting(100);
    let _ticket = publish(&mut published, stream_needing(1, 500));
    assert_eq!(published.take_plan_change(), PlanChange::None);
    assert_eq!(planner.intents_changed(&mut published), PlanChange::None);
    // the publisher compares with the room as the planner left it
    assert_eq!(planner.observe(limits(400)), PlanChange::None);
    assert_eq!(planner.intents_changed(&mut published), PlanChange::None);
    assert_eq!(planner.observe(limits(1000)), PlanChange::None);
    assert_eq!(
        planner.intents_changed(&mut published),
        PlanChange::Possible
    );
}

#[test]
fn a_resize_that_fits_marks_the_waiting_planner() {
    let (_core, mut planner, mut published) = waiting(100);
    let mut ticket = publish(&mut published, stream_needing(1, 500));
    assert_eq!(published.take_plan_change(), PlanChange::None);
    published.resize(
        &mut ticket,
        MinimumLengths {
            with_length: 51,
            as_last: 50,
        },
    );
    assert_eq!(published.take_plan_change(), PlanChange::Possible);
    assert_eq!(
        planner.intents_changed(&mut published),
        PlanChange::Possible
    );
}

/// A withdrawal marks a planner that left content that did not fit; one
/// of an intent the core has not taken in yet is only forgotten.
#[test]
fn a_withdrawal_marks_a_planner_that_left_content_that_did_not_fit() {
    let (mut core, mut planner) = setup(&ALL, 100);
    let mut published = Publisher::default();
    let blocking = publish(&mut published, stream_needing(1, 500));
    let (_, waker) = waker();
    let none = DriverContent::new();
    pending_with(&mut planner, &mut core, &mut published, &none, &waker);
    let _ = published.take_plan_change();
    published.withdraw(blocking);
    assert_eq!(published.take_plan_change(), PlanChange::Possible);
    assert_eq!(
        planner.intents_changed(&mut published),
        PlanChange::Possible
    );

    let (_core, mut planner, mut published) = waiting(12_000);
    let unplanned = publish(&mut published, stream_needing(1, 1300));
    assert_eq!(published.take_plan_change(), PlanChange::None);
    published.withdraw(unplanned);
    assert_eq!(published.take_plan_change(), PlanChange::None);
    assert_eq!(planner.intents_changed(&mut published), PlanChange::None);
}

/// The intent of a key's ticket is consumed by the plan that wrote it,
/// unless it stays after writing.
#[test]
fn a_written_intent_is_consumed_unless_it_stays() {
    let (mut core, mut planner) = setup(&ALL, 12_000);
    let mut published = Publisher::default();
    let stays = publish(&mut published, stream_needing(1, 10));
    let consumed = publish(&mut published, max_data());
    let (_, waker) = waker();
    let none = DriverContent::new();
    let mut plan = ready_with(&mut planner, &mut core, &mut published, &none, &waker);
    assert_eq!(
        walk(&mut plan, 10),
        [(
            PlannedPacketKind::OneRtt,
            vec![FrameSourceId::MaxData, FrameSourceId::Stream]
        )]
    );
    drop(plan);
    assert_eq!(keyed_waiting(&core, &consumed), Some(false));
    assert_eq!(keyed_waiting(&core, &stays), Some(true));
    // the next plan forgets what was consumed and plans what stays
    let mut plan = ready_with(&mut planner, &mut core, &mut published, &none, &waker);
    assert_eq!(
        walk(&mut plan, 10),
        [(PlannedPacketKind::OneRtt, vec![FrameSourceId::Stream])]
    );
    drop(plan);
    assert_eq!(keyed_waiting(&core, &consumed), None);
    published.release_written(consumed);
    published.withdraw(stays);
}

/// An active link path's planner with the limits `limits`.
fn active(core: &mut Core, id: u8, limits: DatagramLimits) -> Planner {
    let mut planner = core.add_link_path(id, LinkPathRoleKind::Active);
    let _ = planner.observe(limits);
    let _ = planner.observe(overheads());
    planner
}

/// Plan once with `planner`, whatever it plans.
fn plan_once(planner: &mut Planner, core: &mut Core, published: &mut Publisher) {
    let (_, waker) = waker();
    let driver = DriverContent::new();
    if let Poll::Ready(PlannedDatagram::Fill(mut plan)) =
        planner.poll_plan(core, published, &driver, &mut Context::from_waker(&waker))
    {
        drop(walk(&mut plan, 0));
    }
}

/// Larger than every datagram of every active link path, an intent waits
/// as too large; a link path that can carry it, or a new active one, ends
/// that.
#[test]
fn an_intent_too_large_for_every_active_link_path_waits_as_too_large() {
    let mut core = Core::new();
    for level in ALL {
        let _ = core.send_keys_available(level);
    }
    // 1200 bytes and a 1-RTT packet taking 30 beyond its frames
    let mut first = active(&mut core, 1, limits(12_000));
    let mut second = active(&mut core, 2, limits(12_000));
    let mut published = Publisher::default();
    let ticket = publish(&mut published, stream_needing(1, 1171));
    plan_once(&mut first, &mut core, &mut published);
    assert!(
        !published.waits_too_large(&ticket),
        "the second link path has not planned"
    );
    plan_once(&mut second, &mut core, &mut published);
    assert!(published.waits_too_large(&ticket));
    // a new active link path may carry it
    let mut third = active(&mut core, 3, limits(12_000));
    plan_once(&mut first, &mut core, &mut published);
    assert!(!published.waits_too_large(&ticket));
    plan_once(&mut third, &mut core, &mut published);
    assert!(published.waits_too_large(&ticket));
    // a link path that grows carries it
    let _ = second.observe(DatagramLimits {
        pmtu_conclusion: 1400,
        ..limits(12_000)
    });
    plan_once(&mut second, &mut core, &mut published);
    assert!(!published.waits_too_large(&ticket));
    published.withdraw(ticket);
}

/// Only the size of a link path's datagrams counts, not what its windows
/// allow now, and a link path that does not carry 1200 bytes finds nothing
/// too large.
#[test]
fn too_large_counts_the_datagram_size_alone() {
    let mut core = Core::new();
    for level in ALL {
        let _ = core.send_keys_available(level);
    }
    let mut planner = active(&mut core, 1, limits(100));
    let mut published = Publisher::default();
    let ticket = publish(&mut published, stream_needing(1, 500));
    plan_once(&mut planner, &mut core, &mut published);
    assert!(
        !published.waits_too_large(&ticket),
        "it fits once the window opens"
    );
    let _ = planner.observe(DatagramLimits {
        pmtu_conclusion: 1100,
        ..limits(12_000)
    });
    let large = publish(&mut published, stream_needing(2, 1171));
    plan_once(&mut planner, &mut core, &mut published);
    assert!(!published.waits_too_large(&large));
    published.withdraw(ticket);
    published.withdraw(large);
}

/// Without an active link path nothing is reported too large.
#[test]
fn nothing_is_too_large_without_an_active_link_path() {
    let mut core = Core::new();
    let _ = core.send_keys_available(EncryptionLevel::OneRtt);
    let mut planner = active(&mut core, 1, limits(12_000));
    let mut published = Publisher::default();
    let ticket = publish(&mut published, stream_needing(1, 1171));
    plan_once(&mut planner, &mut core, &mut published);
    assert!(published.waits_too_large(&ticket));
    let _ = planner.role_changed(&mut core, LinkPathRoleKind::Candidate, &mut Vec::new());
    let at = core
        .keyed
        .iter()
        .position(|entry| entry.state.key == ticket.key)
        .expect("taken in");
    core.found_too_large(planner.serial, &[Held::Keyed(at)], &mut published);
    assert!(!published.waits_too_large(&ticket));
    published.withdraw(ticket);
}
