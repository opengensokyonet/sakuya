//! What writing an ACK frame does to the state of the logical path it is
//! written for.

use frunk_core::hlist;
use sakuya_recovery::ack_obligation::Rfc9000AckObligation;

use super::*;
use crate::take::TakenPositions;

type Instant = core::time::Duration;

fn pn(number: u64) -> PacketNumber {
    PacketNumber::new(number).unwrap()
}

/// The components an ACK frame is written from, of a logical path whose
/// peer last updated its keys with packet 9 of the Application Data space.
struct Components {
    journals: PacketNumberSpaces<ReceiveJournals<Instant>>,
    obligations: PacketNumberSpaces<Rfc9000AckObligation<Instant>>,
    numbers: KeyPhaseNumbers,
}

impl Components {
    fn new() -> Self {
        let mut numbers = KeyPhaseNumbers::new();
        numbers.promoted(1, pn(9));
        Self {
            journals: PacketNumberSpaces {
                initial: None,
                handshake: Some(ReceiveJournals::new()),
                application_data: ReceiveJournals::new(),
            },
            obligations: PacketNumberSpaces {
                initial: None,
                handshake: Some(Rfc9000AckObligation::new(None)),
                application_data: Rfc9000AckObligation::new(Some(Instant::from_millis(25))),
            },
            numbers,
        }
    }

    /// Write an ACK frame up to `largest` in `space`, through the state
    /// the frame source of a sending call is given.
    fn ack_written(&mut self, space: PacketNumberSpaceKind, largest: u64) {
        let mut taken = TakenPositions::default();
        let mut lineage = Lineage::new(
            hlist![&mut self.journals, &mut self.obligations, &mut self.numbers],
            &mut taken,
        );
        let mut state =
            LineageAckFrameState::<_, Instant, Rfc9000AckObligation<Instant>, _, _, _>::new(
                &mut lineage,
            );
        state.ack_written(space, pn(largest));
    }
}

#[test]
fn an_ack_frame_of_the_application_data_space_acknowledges_the_key_update() {
    let mut components = Components::new();
    components.ack_written(PacketNumberSpaceKind::ApplicationData, 8);
    assert_eq!(components.numbers.trigger(1), Some((pn(9), false)));
    components.ack_written(PacketNumberSpaceKind::ApplicationData, 9);
    assert_eq!(components.numbers.trigger(1), Some((pn(9), true)));
}

#[test]
fn an_ack_frame_of_another_space_leaves_the_key_update_unacknowledged() {
    let mut components = Components::new();
    // the Handshake space numbers its packets on its own: its ACK frame
    // goes in a Handshake packet and says nothing of packet 9 of the
    // Application Data space
    components.ack_written(PacketNumberSpaceKind::Handshake, 12);
    assert_eq!(components.numbers.trigger(1), Some((pn(9), false)));
}

// ---- the ACK frame written ----

/// The receive journals of the Application Data space, which the ACK frame
/// source writes from.
struct Received(ReceiveJournals<Instant>);

impl AckFrameState<Instant> for Received {
    fn journals(&self, space: PacketNumberSpaceKind) -> Option<&ReceiveJournals<Instant>> {
        (space == PacketNumberSpaceKind::ApplicationData).then_some(&self.0)
    }

    fn ack_written(&mut self, _: PacketNumberSpaceKind, _: PacketNumber) -> AckDue<Instant> {
        AckDue::NotDue
    }
}

/// The receive journals of the packets `numbers`, each arrived at 10 ms.
fn received(numbers: impl IntoIterator<Item = u64>) -> Received {
    let mut journals = ReceiveJournals::new();
    for number in numbers {
        let admission = journals.admit(pn(number)).unwrap();
        journals.record(admission, Instant::from_millis(10), None);
    }
    Received(journals)
}

/// The ACK frame the ACK frame source writes at 12 ms from `received`
/// into a 1-RTT packet, in a datagram of at most `max_len` bytes, read back
/// as the peer reads it; and the room the packet had for it.
fn ack_frame_written(received: Received, max_len: usize) -> (AckFrame, usize) {
    use core::num::NonZeroUsize;

    use bytes::BytesMut;
    use sakuya_recovery::send_journals::{DequeSendJournals, SendJournals as _};
    use sakuya_wire::{
        parts::HList,
        v1::{
            frame::{FrameRun, set::Frames},
            role::Role,
        },
    };

    use crate::{
        v1::{
            aead_usage::AeadUsage,
            datagram_batch::tests::{Accounts, Batch, one_rtt_keys},
            receive::open_one_rtt,
        },
        write::AckOnlyClass,
    };

    let (sender, receiver) = one_rtt_keys();
    let mut journals = DequeSendJournals::<u64, FeedbackSummary<Instant>, ()>::new();
    let mut usage = AeadUsage::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    let mut source = AckFrameSource::new(received, Instant::from_millis(12));
    let room;
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, max_len, max_len, false);
        let packet = datagram
            .start_one_rtt_packet(
                journals.start_attempt(()),
                sender.send().unwrap(),
                &mut usage,
                None,
            )
            .unwrap();
        let open = packet.open::<AckOnlyClass>();
        room = open.remaining();
        let _ = source.supply(PacketNumberSpaceKind::ApplicationData, open);
    }
    let mut packet = BytesMut::from(batch.datagrams().next().unwrap());
    let (opened, _) =
        open_one_rtt(receiver.receive().unwrap(), None, &mut packet, 9, None).unwrap();
    let payload = &packet[opened.payload.clone()];
    let mut frames = Frames::new(payload, PhantomData::<HList![sakuya_wire::v1::Part]>);
    let Some(FrameRun::Ack(frame)) = frames.next().map(|run| run.unwrap().extract()) else {
        panic!("the packet starts with an ACK frame: {payload:?}")
    };
    (frame, room)
}

/// The ranges `frame` acknowledges, from the largest packet number down.
fn ranges_of(frame: &AckFrame) -> Vec<(u64, u64)> {
    frame
        .packet_ranges()
        .map(|range| (range.start().get(), range.end().get()))
        .collect()
}

#[test]
fn an_ack_frame_without_room_for_every_range_leaves_out_the_smallest() {
    // 100 ranges of one packet each: 0, 2, … 198
    let numbers: Vec<u64> = (0..100).map(|n| 2 * n).collect();
    // a 1-RTT packet takes 26 bytes beyond its frames here
    let (frame, room) = ack_frame_written(received(numbers.iter().copied()), 26 + 50);
    assert_eq!(room, 50);
    let ranges = ranges_of(&frame);
    let kept = ranges.len();
    assert!(kept < numbers.len(), "{ranges:?}");
    // the largest ranges are kept, the smallest packet numbers go
    // (RFC 9000 §13.2.3)
    let expected: Vec<(u64, u64)> = numbers.iter().rev().take(kept).map(|&n| (n, n)).collect();
    assert_eq!(ranges, expected);
    assert!(frame.encoded_len() <= room);
    // one range more would not have fit
    let longer = AckFrame::from_packet_ranges(
        numbers.iter().rev().take(kept + 1).map(|&n| pn(n)..=pn(n)),
        frame.ack_delay(),
        None,
    )
    .unwrap();
    assert!(longer.encoded_len() > room);
    // 2 ms after the largest arrived, at the exponent 3
    assert_eq!(frame.ack_delay().get(), VarInt::from_u32(2000 >> 3));
}

#[test]
fn an_ack_frame_without_room_for_its_ack_delay_is_the_shortest() {
    // with its ACK Delay of 2 ms, the first range alone takes 7 bytes;
    // the shortest frame, without a delay, 6
    let (frame, room) = ack_frame_written(received([196, 198]), 26 + 6);
    assert_eq!(room, 6);
    assert_eq!(frame.encoded_len(), 6);
    assert_eq!(ranges_of(&frame), [(198, 198)]);
    assert_eq!(frame.ack_delay().get(), VarInt::ZERO);
}
