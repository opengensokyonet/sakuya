//! The queues held directly: the bounds of each queue, writing by the key,
//! what comes of a datagram written, the intents not fulfilled, the
//! datagrams held through the shared connection, the layer's end and the
//! driver's panic, and the DATAGRAM frame source in a lineage.
use alloc::sync::Arc;
use core::{
    cell::RefCell,
    task::{Context, Poll, Waker},
};
use std::rc::Rc;

use frunk_core::indices::Here;
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_wire::var_int::VarInt;
use sakuya_wire_datagram::MaxDatagramFrameSize;

use super::*;
use crate::{
    locked::tests::{
        Core, CountingWake, Planner, RecordedDatagram, Recording, active, bounds, frame, idle,
        limits,
    },
    send::{
        LineageDatagramFrameSource,
        tests::{Nowhere, SummaryWriter, TestSide, TestTypes, Written, datagram_summary, inner},
    },
};
use sakuya_connection::v1::events::PartEventSum;
use sakuya_connection::{
    frame_source::FrameSource,
    send_strategy::{
        DatagramLimits, InHead, LinkPathSendPlanner, Observe, SendStrategy,
        ranked::{KeyIntentTicket, PublisherChange, RankedSendPublisher},
    },
    v1::send_planning::SendStrategyPublisher,
    write::{Last, NotLast},
};

type Ticket = KeyIntentTicket;
type QueuesOf<E> = OwnedDatagramQueues<(), Ticket, TestSide, E>;
type Queues = QueuesOf<NoEvents>;
/// The publisher the queues are lent, kept across calls as the connection
/// keeps it.
type Publisher = RankedSendPublisher<TestTypes>;

/// The queues `queues` as the driver and the capability lend them: queues
/// over the test strategy types, so that their methods know them.
fn lent<E: SharedEvents>(
    queues: &mut QueuesOf<E>,
) -> &mut impl DatagramQueues<
    (),
    TestTypes,
    Handle = (),
    Remains = OwnedDatagramQueuesRemains<Bytes>,
    Received = Bytes,
> {
    queues
}

fn queues_with<E: SharedEvents>(
    peer: u32,
    config: OwnedDatagramQueuesConfig,
    events: E,
) -> QueuesOf<E>
where
    E::PartEvents: PartEventSum<DatagramEvent, Here>,
{
    <QueuesOf<E> as DatagramQueues<(), TestTypes>>::new(
        DatagramQueuesFacts {
            peer: MaxDatagramFrameSize::new(VarInt::from_u32(peer)),
        },
        config,
        DatagramEvents::new::<Here>(events),
        (),
    )
}

fn receiving(receive: DatagramQueueBounds) -> Queues {
    queues_with(
        1200,
        OwnedDatagramQueuesConfig {
            receive,
            ..OwnedDatagramQueuesConfig::default()
        },
        NoEvents,
    )
}

fn sending(peer: u32, send: DatagramQueueBounds) -> Queues {
    queues_with(
        peer,
        OwnedDatagramQueuesConfig {
            send,
            ..OwnedDatagramQueuesConfig::default()
        },
        NoEvents,
    )
}

/// Send `payload` through `queues`, lent `publisher`.
fn send<E: SharedEvents>(
    queues: &mut QueuesOf<E>,
    publisher: &mut Publisher,
    payload: &'static [u8],
) -> Result<DatagramKey, SendDatagramError<()>> {
    lent(queues).send_held::<_, _>(
        publisher,
        Bytes::from_static(payload),
        &Urgency::default(),
        &AnyActiveLinkPath,
    )
}

fn recv<E: SharedEvents>(queues: &mut QueuesOf<E>) -> Poll<Result<Bytes, LayerEndedError<()>>> {
    lent(queues).poll_receive(&mut Context::from_waker(Waker::noop()))
}

fn received<E: SharedEvents>(queues: &mut QueuesOf<E>) -> Vec<Bytes> {
    let mut all = Vec::new();
    while let Poll::Ready(Ok(datagram)) = recv(queues) {
        all.push(datagram);
    }
    all
}

/// Supply the datagram of `key` into an open packet of `room` bytes in
/// position `P`; what the packet holds afterwards and whether it closed.
fn supply<P: PacketPosition>(
    queues: &mut Queues,
    publisher: &mut Publisher,
    key: DatagramKey,
    room: usize,
) -> (Written, bool) {
    let out = Rc::new(RefCell::new(Written::default()));
    let packet = OpenPacket::<_, InFlightClass, P>::new(SummaryWriter::new(room, &out));
    let closed = matches!(
        lent(queues).supply_datagram::<_, _, _, _, InHead<Here>>(publisher, key, packet),
        Supplied::Closed(_)
    );
    (
        Rc::into_inner(out)
            .expect("the packet is dropped")
            .into_inner(),
        closed,
    )
}

/// What the publisher took since the last call, by the keys of its
/// tickets: the datagram's key of each intent published, and each key
/// withdrawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    Published(u64, DatagramKey),
    Withdrawn(u64),
}

fn seen(publisher: &mut Publisher) -> Vec<Seen> {
    publisher
        .take_changes()
        .into_iter()
        .map(|change| match change {
            PublisherChange::Published { key, intent } => {
                Seen::Published(key, inner(&intent).key())
            }
            PublisherChange::Withdrawn { key } => Seen::Withdrawn(key),
            PublisherChange::Resized { .. } => panic!("a datagram intent is not resized"),
        })
        .collect()
}

fn held(key: DatagramKey) -> DatagramTicketCredential {
    DatagramTicketCredential::new(key)
}

fn state(
    queues: &mut Queues,
    publisher: &Publisher,
    held: &DatagramTicketCredential,
) -> DatagramState {
    lent(queues).ticket_state::<_>(publisher, held)
}

fn settled(queues: &mut Queues, held: &DatagramTicketCredential) -> Poll<DatagramSettlement> {
    lent(queues).poll_ticket_settled(held, &mut Context::from_waker(Waker::noop()))
}

// ---- receiving ----

/// A full receive queue that refuses new datagrams drops each new one and
/// counts it; one that drops the oldest keeps the newest ones; the bytes
/// are bounded too, and one larger than the whole queue is dropped alone.
#[test]
fn a_full_receive_queue_drops_as_it_is_configured() {
    let mut queues = receiving(bounds(2, 1000, DatagramOverflow::RejectNew));
    for data in [&b"one"[..], b"two", b"three"] {
        lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(data));
    }
    assert_eq!(lent(&mut queues).dropped_datagrams(), 1);
    assert_eq!(received(&mut queues), [&b"one"[..], b"two"]);

    let mut queues = receiving(bounds(2, 1000, DatagramOverflow::DropOldest));
    for data in [&b"one"[..], b"two", b"three"] {
        lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(data));
    }
    assert_eq!(lent(&mut queues).dropped_datagrams(), 1);
    assert_eq!(received(&mut queues), [&b"two"[..], b"three"]);

    let mut queues = receiving(bounds(8, 10, DatagramOverflow::DropOldest));
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"sixsix"));
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"fivef"));
    assert_eq!(
        lent(&mut queues).dropped_datagrams(),
        1,
        "the first made room"
    );
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"eleven-byte"));
    assert_eq!(lent(&mut queues).dropped_datagrams(), 2);
    assert_eq!(received(&mut queues), [&b"fivef"[..]]);
}

/// The receive queue gives what it drops and what is read.
#[test]
fn the_receive_queue_gives_what_it_drops_and_what_is_read() {
    let events = Recording::default();
    let mut queues = queues_with(
        1200,
        OwnedDatagramQueuesConfig {
            receive: bounds(1, 10, DatagramOverflow::DropOldest),
            ..OwnedDatagramQueuesConfig::default()
        },
        events.clone(),
    );
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"one"));
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"two!"));
    assert_eq!(
        events.taken(),
        [RecordedDatagram::Dropped(
            3,
            DatagramDropped::ReceiveQueueFull
        )]
    );
    assert_eq!(received(&mut queues), [&b"two!"[..]]);
    assert_eq!(
        events.taken(),
        [RecordedDatagram::Moved(
            4,
            DataLocation::Transport,
            DataLocation::Application
        )]
    );
}

/// Once the layer ended, what was received is still read; then the end,
/// and nothing more is taken.
#[test]
fn what_was_received_is_read_before_the_layers_end() {
    let mut queues = receiving(DatagramQueueBounds::default());
    let wakes = Arc::new(CountingWake::default());
    let waker = Waker::from(Arc::clone(&wakes));
    assert!(
        lent(&mut queues)
            .poll_receive(&mut Context::from_waker(&waker))
            .is_pending()
    );
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"kept"));
    assert_eq!(wakes.count(), 1);
    lent(&mut queues).layer_ended(&mut Publisher::default(), idle());
    assert_eq!(
        recv(&mut queues),
        Poll::Ready(Ok(Bytes::from_static(b"kept")))
    );
    assert!(matches!(recv(&mut queues), Poll::Ready(Err(error)) if *error.end() == idle()));
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"late"));
    assert!(matches!(recv(&mut queues), Poll::Ready(Err(_))));
}

// ---- sending ----

/// The peer's `max_datagram_frame_size` of this handshake replaces the one
/// the queues were made on, as a client's early layer is made on the
/// remembered one: what is sent from then on is held to it.
#[test]
fn the_peers_size_of_this_handshake_holds_what_is_sent_after() {
    let mut publisher = Publisher::default();
    let mut queues = sending(100, DatagramQueueBounds::default());
    lent(&mut queues)
        .peer_transport_parameters_known(MaxDatagramFrameSize::new(VarInt::from_u32(1200)));
    assert_eq!(
        lent(&mut queues).limits(),
        DatagramFrameLimits {
            guaranteed: 1128,
            peer: 1197
        }
    );
    send(&mut queues, &mut publisher, &[0; 500]).expect("within the new limit");
}

/// A peer that takes nothing, a datagram over the peer's limit, a full
/// send queue that refuses, and one larger than the whole queue: nothing is
/// taken, and nothing published.
#[test]
fn a_send_is_refused_as_the_peer_and_the_queue_say() {
    let mut publisher = Publisher::default();
    let mut queues = sending(0, DatagramQueueBounds::default());
    assert_eq!(
        send(&mut queues, &mut publisher, b"no"),
        Err(SendDatagramError::NotSupportedByPeer)
    );
    assert_eq!(
        lent(&mut queues).limits(),
        DatagramFrameLimits {
            guaranteed: 0,
            peer: 0
        }
    );
    let mut queues = sending(100, DatagramQueueBounds::default());
    assert_eq!(
        lent(&mut queues).limits(),
        DatagramFrameLimits {
            guaranteed: 97,
            peer: 97
        }
    );
    assert_eq!(
        lent(&mut queues).send_held::<_, _>(
            &mut publisher,
            Bytes::from(vec![0; 98]),
            &Urgency::default(),
            &AnyActiveLinkPath,
        ),
        Err(SendDatagramError::TooLarge { limit: 97 })
    );
    let mut queues = sending(1200, bounds(1, 8, DatagramOverflow::RejectNew));
    assert_eq!(
        send(&mut queues, &mut publisher, b"ninebytes"),
        Err(SendDatagramError::QueueFull)
    );
    let first = send(&mut queues, &mut publisher, b"one").expect("taken");
    assert_eq!(
        send(&mut queues, &mut publisher, b"two"),
        Err(SendDatagramError::QueueFull)
    );
    assert_eq!(seen(&mut publisher), [Seen::Published(0, first)]);
}

/// A full send queue that drops the oldest withdraws it, with its intent;
/// its ticket says so, and the drop is given as the send queue's.
#[test]
fn a_full_send_queue_that_drops_the_oldest_withdraws_it() {
    let events = Recording::default();
    let mut queues = queues_with(
        1200,
        OwnedDatagramQueuesConfig {
            send: bounds(2, 1000, DatagramOverflow::DropOldest),
            ..OwnedDatagramQueuesConfig::default()
        },
        events.clone(),
    );
    let mut publisher = Publisher::default();
    let first = send(&mut queues, &mut publisher, b"one").expect("taken");
    let second = send(&mut queues, &mut publisher, b"two").expect("taken");
    assert_eq!(
        seen(&mut publisher),
        [Seen::Published(0, first), Seen::Published(1, second)]
    );
    let third = send(&mut queues, &mut publisher, b"three").expect("taken");
    assert_eq!(
        seen(&mut publisher),
        [Seen::Withdrawn(0), Seen::Published(2, third)]
    );
    assert_eq!(
        events.taken(),
        [
            RecordedDatagram::Moved(3, DataLocation::Application, DataLocation::Transport),
            RecordedDatagram::Moved(3, DataLocation::Application, DataLocation::Transport),
            RecordedDatagram::Dropped(3, DatagramDropped::SendQueueFull),
            RecordedDatagram::Moved(5, DataLocation::Application, DataLocation::Transport),
        ]
    );
    let first = &held(first);
    assert_eq!(
        lent(&mut queues).ticket_state::<_>(&publisher, first),
        DatagramState::Withdrawn(DatagramWithdrawCause::DroppedOldest)
    );
    assert_eq!(
        lent(&mut queues).poll_ticket_settled(first, &mut Context::from_waker(Waker::noop())),
        Poll::Ready(DatagramSettlement::Withdrawn(
            DatagramWithdrawCause::DroppedOldest
        ))
    );
    assert_eq!(
        lent(&mut queues).withdraw_held::<_, _>(&mut publisher, first),
        WithdrawReport::Withdrawn
    );
    assert_eq!(seen(&mut publisher), [], "withdrawn once");
}

// ---- writing by the key ----

/// The datagram of a key is written as the last frame without a Length
/// field, otherwise with one; its summary is the key, its ticket goes as
/// written, and it is written once only.
#[test]
fn a_datagram_is_written_by_its_key_once() {
    let mut publisher = Publisher::default();
    let mut queues = sending(1200, bounds(1, 1000, DatagramOverflow::RejectNew));
    let last = send(&mut queues, &mut publisher, b"last").expect("taken");
    let (written, closed) = supply::<Last>(&mut queues, &mut publisher, last, 100);
    assert!(closed);
    assert_eq!(written.bytes, [0x30, b'l', b'a', b's', b't']);
    assert_eq!(
        written
            .summaries
            .into_iter()
            .map(datagram_summary)
            .collect::<Vec<_>>(),
        [DatagramSummary { key: last }]
    );
    assert_eq!(
        state(&mut queues, &publisher, &held(last)),
        DatagramState::Sent
    );
    let (written, _) = supply::<NotLast>(&mut queues, &mut publisher, last, 100);
    assert!(written.bytes.is_empty(), "written once only");
    // it left the send queue at once, and its ticket went as written
    let more = send(&mut queues, &mut publisher, b"more").expect("room");
    assert_eq!(
        seen(&mut publisher),
        [Seen::Published(0, last), Seen::Published(1, more)]
    );
    let (written, _) = supply::<NotLast>(&mut queues, &mut publisher, more, 5);
    assert!(written.bytes.is_empty(), "it does not fit");
    assert_eq!(
        state(&mut queues, &publisher, &held(more)),
        DatagramState::Waiting
    );
    let (written, closed) = supply::<NotLast>(&mut queues, &mut publisher, more, 100);
    assert!(!closed);
    assert_eq!(written.bytes, [0x31, 0x04, b'm', b'o', b'r', b'e']);
    assert_eq!(seen(&mut publisher), [], "nothing withdrawn");
}

/// A datagram withdrawn by its holder, or a key not there, writes nothing.
#[test]
fn a_datagram_withdrawn_or_not_there_is_not_written() {
    let mut publisher = Publisher::default();
    let mut queues = sending(1200, DatagramQueueBounds::default());
    let gone = send(&mut queues, &mut publisher, b"gone").expect("taken");
    let _ = seen(&mut publisher);
    assert_eq!(
        lent(&mut queues).withdraw_held::<_, _>(&mut publisher, &held(gone)),
        WithdrawReport::Withdrawn
    );
    assert_eq!(seen(&mut publisher), [Seen::Withdrawn(0)]);
    let (written, _) = supply::<NotLast>(&mut queues, &mut publisher, gone, 100);
    assert!(written.bytes.is_empty());
    let (written, _) =
        supply::<NotLast>(&mut queues, &mut publisher, DatagramKey::FIRST.next(), 100);
    assert!(written.bytes.is_empty());
}

/// The acknowledgment and the loss settle the datagram's ticket; a late
/// acknowledgment of a lost datagram counts; a summary of a datagram the
/// queues forgot is ignored.
#[test]
fn what_comes_of_a_datagram_written_settles_its_ticket() {
    let mut publisher = Publisher::default();
    let mut queues = sending(1200, DatagramQueueBounds::default());
    let acknowledged = send(&mut queues, &mut publisher, b"ack").expect("taken");
    let lost = send(&mut queues, &mut publisher, b"lost").expect("taken");
    for key in [acknowledged, lost] {
        supply::<NotLast>(&mut queues, &mut publisher, key, 100);
        assert!(settled(&mut queues, &held(key)).is_pending());
    }
    lent(&mut queues).on_frame_delivered(DatagramSummary { key: acknowledged });
    assert_eq!(
        settled(&mut queues, &held(acknowledged)),
        Poll::Ready(DatagramSettlement::Acknowledged)
    );
    lent(&mut queues).on_frame_lost(DatagramSummary { key: lost });
    assert_eq!(
        settled(&mut queues, &held(lost)),
        Poll::Ready(DatagramSettlement::Lost)
    );
    lent(&mut queues).on_frame_delivered(DatagramSummary { key: lost });
    assert_eq!(
        state(&mut queues, &publisher, &held(lost)),
        DatagramState::Acknowledged
    );
    lent(&mut queues).release_held(&held(acknowledged));
    lent(&mut queues).on_frame_lost(DatagramSummary { key: acknowledged });
    assert!(!queues.datagrams.contains_key(&acknowledged), "forgotten");
}

/// A datagram whose ticket was released is still sent, and the queues keep
/// it only until its packet is acknowledged or lost.
#[test]
fn a_released_datagram_is_sent_and_then_forgotten() {
    let mut publisher = Publisher::default();
    let mut queues = sending(1200, DatagramQueueBounds::default());
    let key = send(&mut queues, &mut publisher, b"let go").expect("taken");
    lent(&mut queues).release_held(&held(key));
    let (written, _) = supply::<NotLast>(&mut queues, &mut publisher, key, 100);
    assert_eq!(written.bytes.len(), 8, "still sent");
    assert!(
        queues.datagrams.contains_key(&key),
        "until its fate is known"
    );
    lent(&mut queues).on_frame_delivered(DatagramSummary { key });
    assert!(queues.datagrams.is_empty());
}

/// Once the credential came back, the queues know nothing of the datagram:
/// an operation that names it reports it withdrawn as the layer ended
/// (and is a broken invariant, which a debug build asserts).
#[test]
#[cfg_attr(debug_assertions, should_panic(expected = "is gone"))]
fn a_held_datagram_whose_credential_came_back_is_not_known() {
    let mut publisher = Publisher::default();
    let mut queues = sending(1200, DatagramQueueBounds::default());
    let key = send(&mut queues, &mut publisher, b"held").expect("taken");
    lent(&mut queues).release_held(&held(key));
    assert_eq!(
        state(&mut queues, &publisher, &held(key)),
        DatagramState::Withdrawn(DatagramWithdrawCause::LayerEnded)
    );
}

/// A datagram written before its holder withdraws it reports consumed.
#[test]
fn withdrawing_reports_whether_the_datagram_was_written() {
    let mut publisher = Publisher::default();
    let mut queues = sending(1200, DatagramQueueBounds::default());
    let key = send(&mut queues, &mut publisher, b"late").expect("taken");
    supply::<NotLast>(&mut queues, &mut publisher, key, 100);
    let _ = seen(&mut publisher);
    assert_eq!(
        lent(&mut queues).withdraw_held::<_, _>(&mut publisher, &held(key)),
        WithdrawReport::Consumed
    );
    assert_eq!(seen(&mut publisher), [], "nothing to withdraw");
}

// ---- intents not fulfilled ----

/// An intent not fulfilled is published again at once while its
/// destination degrades: the ended ticket goes, a new one takes its place,
/// and the datagram's ticket stays.
#[test]
fn an_unfulfilled_datagram_is_published_again_at_once() {
    let mut publisher = Publisher::default();
    let mut queues = sending(1200, DatagramQueueBounds::default());
    let key = send(&mut queues, &mut publisher, b"again").expect("taken");
    assert_eq!(seen(&mut publisher), [Seen::Published(0, key)]);
    lent(&mut queues).on_intent_unfulfilled::<_, _>(&mut publisher, key, Unfulfilled::Ended);
    assert_eq!(
        seen(&mut publisher),
        [Seen::Withdrawn(0), Seen::Published(1, key)]
    );
    assert_eq!(
        state(&mut queues, &publisher, &held(key)),
        DatagramState::Waiting
    );
    let (written, _) = supply::<NotLast>(&mut queues, &mut publisher, key, 100);
    assert_eq!(written.bytes.len(), 7);
    lent(&mut queues).on_intent_unfulfilled::<_, _>(&mut publisher, key, Unfulfilled::Ended);
    assert_eq!(seen(&mut publisher), [], "nothing for a datagram written");
}

/// A destination with nothing left to fall back to withdraws the datagram.
#[test]
fn an_unfulfilled_datagram_whose_destination_has_nothing_left_is_withdrawn() {
    let mut publisher = Publisher::default();
    let mut placed = placed::<_, InHead<Here>>(&mut publisher);
    let key = DatagramKey::FIRST;
    let ticket = placed.publish_to(
        DatagramIntent::new(key, 9, Urgency::default()),
        AnyActiveLinkPath,
    );
    let mut datagram = OwnedDatagram {
        payload: Bytes::from_static(b"exhausted"),
        parameters: Urgency::default(),
        destination: Nowhere,
        ticket: Some(ticket),
        progress: ProgressState::new(),
        held: true,
    };
    assert!(!datagram.unfulfilled(key, Unfulfilled::Rejected, &mut placed));
    assert!(datagram.ticket.is_none());
    assert_eq!(
        datagram.progress.state(false),
        Some(DatagramState::Withdrawn(
            DatagramWithdrawCause::DestinationExhausted
        ))
    );
    assert_eq!(seen(&mut publisher), [], "the pending intent is forgotten");
}

// ---- too large for now ----

/// Plan once with `planner`, lent `publisher`, writing nothing.
fn plan_once(planner: &mut Planner, core: &mut Core, publisher: &mut Publisher) {
    let driver = sakuya_connection::send_strategy::DriverContent::default();
    let _ = planner.poll_plan(
        core,
        publisher,
        &driver,
        &mut Context::from_waker(Waker::noop()),
    );
}

/// A datagram larger than what every active link path carries waits as too
/// large, as the publisher says of its key ticket; its wait goes on, and
/// once a link path can carry it, it waits as before.
#[test]
fn a_datagram_too_large_for_every_active_link_path_waits_as_too_large() {
    let mut core = Core::new();
    let _ = core.send_keys_available(EncryptionLevel::OneRtt);
    let mut first = active(&mut core, 1);
    let mut second = active(&mut core, 2);
    let mut publisher = Publisher::default();
    let mut queues = sending(65535, DatagramQueueBounds::default());
    let key = lent(&mut queues)
        .send_held::<_, _>(
            &mut publisher,
            Bytes::from(vec![0; 1200]),
            &Urgency::default(),
            &AnyActiveLinkPath,
        )
        .expect("within the peer's limit");
    let held = &held(key);
    plan_once(&mut first, &mut core, &mut publisher);
    assert_eq!(
        state(&mut queues, &publisher, held),
        DatagramState::Waiting,
        "the second link path has not planned"
    );
    plan_once(&mut second, &mut core, &mut publisher);
    assert_eq!(
        state(&mut queues, &publisher, held),
        DatagramState::WaitingTooLarge
    );
    assert!(settled(&mut queues, held).is_pending(), "it still waits");
    let _ = second.observe(DatagramLimits {
        pmtu_conclusion: 1400,
        ..limits()
    });
    plan_once(&mut second, &mut core, &mut publisher);
    assert_eq!(state(&mut queues, &publisher, held), DatagramState::Waiting);
    assert_eq!(
        lent(&mut queues).withdraw_held::<_, _>(&mut publisher, held),
        WithdrawReport::Withdrawn
    );
}

// ---- the end ----

/// The layer's end withdraws what waits as the layer ended, its intent
/// withdrawn through the publisher, loses what is in flight, and fails the
/// sends; what the held tickets read stays in what the queues leave.
#[test]
fn the_layers_end_withdraws_what_waits_and_leaves_what_the_tickets_read() {
    let mut publisher = Publisher::default();
    let mut queues = sending(1200, DatagramQueueBounds::default());
    let waiting = send(&mut queues, &mut publisher, b"waiting").expect("taken");
    let sent = send(&mut queues, &mut publisher, b"sent").expect("taken");
    let acknowledged = send(&mut queues, &mut publisher, b"acked").expect("taken");
    let released = send(&mut queues, &mut publisher, b"released").expect("taken");
    for key in [sent, acknowledged, released] {
        supply::<NotLast>(&mut queues, &mut publisher, key, 100);
    }
    lent(&mut queues).on_frame_delivered(DatagramSummary { key: acknowledged });
    lent(&mut queues).release_held(&held(released));
    let wakes = Arc::new(CountingWake::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    assert!(
        lent(&mut queues)
            .poll_ticket_settled(&held(waiting), &mut cx)
            .is_pending()
    );
    let _ = seen(&mut publisher);
    lent(&mut queues).layer_ended(&mut publisher, idle());
    assert_eq!(wakes.count(), 1, "the ticket's wait is woken");
    assert_eq!(
        seen(&mut publisher),
        [Seen::Withdrawn(0)],
        "only what waits is withdrawn"
    );
    assert!(matches!(
        send(&mut queues, &mut publisher, b"late"),
        Err(SendDatagramError::LayerEnded { source }) if *source.end() == idle()
    ));
    let mut remains = lent(&mut queues).remains();
    assert_eq!(
        remains.ticket_state(waiting),
        Some(DatagramState::Withdrawn(DatagramWithdrawCause::LayerEnded))
    );
    assert_eq!(
        remains.ticket_settlement(sent),
        Some(DatagramSettlement::Lost)
    );
    assert_eq!(
        remains.ticket_settlement(acknowledged),
        Some(DatagramSettlement::Acknowledged)
    );
    assert_eq!(remains.ticket_state(released), None, "not held");
    assert_eq!(remains.take_ticket(sent), Some(WithdrawReport::Consumed));
    assert_eq!(remains.take_ticket(sent), None, "forgotten");
    assert_eq!(
        remains.take_ticket(waiting),
        Some(WithdrawReport::Withdrawn)
    );
}

/// The driver's panic only marks the end: who waits is woken, every
/// receive and send reports the end, also before what was received, and
/// the tickets read what waits as withdrawn as the layer ended, what is in
/// flight as lost; nothing is withdrawn, and a holder's withdrawal changes
/// nothing.
#[test]
fn the_drivers_panic_ends_the_waits_and_withdraws_nothing() {
    let mut publisher = Publisher::default();
    let mut queues = sending(1200, DatagramQueueBounds::default());
    let waiting = send(&mut queues, &mut publisher, b"waiting").expect("taken");
    let sent = send(&mut queues, &mut publisher, b"sent").expect("taken");
    supply::<NotLast>(&mut queues, &mut publisher, sent, 100);
    lent(&mut queues).on_datagram_frame(EncryptionLevel::OneRtt, frame(b"unread"));
    let wakes = Arc::new(CountingWake::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    for key in [waiting, sent] {
        assert!(
            lent(&mut queues)
                .poll_ticket_settled(&held(key), &mut cx)
                .is_pending()
        );
    }
    let _ = seen(&mut publisher);
    lent(&mut queues).driver_panicked(idle());
    assert_eq!(wakes.count(), 2, "both waits are woken");
    assert!(matches!(recv(&mut queues), Poll::Ready(Err(error)) if *error.end() == idle()));
    assert!(matches!(
        send(&mut queues, &mut publisher, b"late"),
        Err(SendDatagramError::LayerEnded { .. })
    ));
    assert_eq!(
        settled(&mut queues, &held(waiting)),
        Poll::Ready(DatagramSettlement::Withdrawn(
            DatagramWithdrawCause::LayerEnded
        ))
    );
    assert_eq!(
        state(&mut queues, &publisher, &held(sent)),
        DatagramState::Lost
    );
    assert_eq!(
        lent(&mut queues).withdraw_held::<_, _>(&mut publisher, &held(waiting)),
        WithdrawReport::Withdrawn
    );
    assert_eq!(
        seen(&mut publisher),
        [],
        "the strategy's tickets are left alone"
    );
    let mut remains = lent(&mut queues).remains();
    assert_eq!(remains.pop_received(), Some(Bytes::from_static(b"unread")));
    assert_eq!(remains.ticket_state(sent), Some(DatagramState::Lost));
    assert_eq!(remains.ticket_state(waiting), None, "handed back");
}

// ---- the frame source ----

/// The DATAGRAM frame source in a lineage writes through the queues, takes
/// back what comes of the frame through them, and has them publish again
/// an intent not fulfilled; without the established layer it writes
/// nothing and takes nothing back.
#[test]
fn the_frame_source_in_a_lineage_goes_through_the_queues() {
    let mut queues = sending(1200, DatagramQueueBounds::default());
    let mut publisher = SendStrategyPublisher::new(Publisher::default());
    let again = send(&mut queues, publisher.publisher_mut(), b"again").expect("taken");
    let written_key = send(&mut queues, publisher.publisher_mut(), b"written").expect("taken");
    let _ = seen(publisher.publisher_mut());
    let taken = sakuya_connection::take::TakenPositions::default();
    let out = Rc::new(RefCell::new(Written::default()));
    {
        let mut lineage = sakuya_connection::take::Lineage::new(
            frunk_core::hlist![
                &mut publisher,
                Some(sakuya_connection::take::ComponentMut::new(
                    &mut queues,
                    sakuya_connection::take::Sink::Nowhere,
                    1
                ))
            ],
            &taken,
        );
        let mut source =
            LineageDatagramFrameSource::<_, Queues, (), TestTypes, _, _, _>::new(&mut lineage);
        source.unfulfilled(
            &DatagramIntent::new(again, 5, Urgency::default()),
            Unfulfilled::Ended,
        );
        let packet = OpenPacket::<_, InFlightClass, NotLast>::new(SummaryWriter::new(100, &out));
        let _ = source.supply::<_, _, InHead<Here>>(
            &DatagramIntent::new(written_key, 7, Urgency::default()),
            packet,
        );
        let summary = datagram_summary(out.borrow().summaries[0]);
        source.lost(PacketNumberSpaceKind::ApplicationData, &summary);
        source.delivered(PacketNumberSpaceKind::ApplicationData, summary);
    }
    assert_eq!(out.borrow().bytes.len(), 9);
    assert_eq!(
        seen(publisher.publisher_mut()),
        [Seen::Withdrawn(0), Seen::Published(2, again)]
    );
    assert_eq!(
        state(&mut queues, publisher.publisher(), &held(written_key)),
        DatagramState::Acknowledged
    );

    let out = Rc::new(RefCell::new(Written::default()));
    {
        let mut lineage = sakuya_connection::take::Lineage::new(
            frunk_core::hlist![
                &mut publisher,
                None::<sakuya_connection::take::ComponentMut<'_, Queues>>
            ],
            &taken,
        );
        let mut source =
            LineageDatagramFrameSource::<_, Queues, (), TestTypes, _, _, _>::new(&mut lineage);
        let packet = OpenPacket::<_, InFlightClass, NotLast>::new(SummaryWriter::new(100, &out));
        let _ = source.supply::<_, _, InHead<Here>>(
            &DatagramIntent::new(again, 5, Urgency::default()),
            packet,
        );
        source.unfulfilled(
            &DatagramIntent::new(again, 5, Urgency::default()),
            Unfulfilled::Ended,
        );
    }
    assert!(out.borrow().bytes.is_empty());
    assert_eq!(seen(publisher.publisher_mut()), []);
}

/// The queues are `Send` where what they hold is.
#[test]
fn the_queues_are_send() {
    fn send<X: Send>() {}
    send::<Queues>();
}
