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
