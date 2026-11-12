use super::{PacketNumberSpaceKind, PacketNumberSpaceSet};

#[test]
fn a_set_iterates_in_space_order() {
    let set: PacketNumberSpaceSet = [
        PacketNumberSpaceKind::ApplicationData,
        PacketNumberSpaceKind::Initial,
    ]
    .into_iter()
    .collect();
    assert!(set.contains(PacketNumberSpaceKind::Initial));
    assert!(!set.contains(PacketNumberSpaceKind::Handshake));
    assert_eq!(
        set.iter().collect::<Vec<_>>(),
        [
            PacketNumberSpaceKind::Initial,
            PacketNumberSpaceKind::ApplicationData
        ]
    );
}

#[test]
fn inserting_twice_keeps_one() {
    let mut set = PacketNumberSpaceSet::EMPTY;
    assert!(set.is_empty());
    set.insert(PacketNumberSpaceKind::Handshake);
    set.insert(PacketNumberSpaceKind::Handshake);
    assert_eq!(set.iter().count(), 1);
}

mod spaces {
    use super::super::{PacketNumberSpaceKind, PacketNumberSpaces};

    fn all() -> PacketNumberSpaces<u32> {
        PacketNumberSpaces {
            initial: Some(1),
            handshake: Some(2),
            application_data: 3,
        }
    }

    #[test]
    fn get_finds_the_value_of_each_space() {
        let spaces = all();
        assert_eq!(spaces.get(PacketNumberSpaceKind::Initial), Some(&1));
        assert_eq!(spaces.get(PacketNumberSpaceKind::Handshake), Some(&2));
        assert_eq!(spaces.get(PacketNumberSpaceKind::ApplicationData), Some(&3));
    }

    #[test]
    fn a_discarded_space_has_no_value() {
        let spaces = PacketNumberSpaces {
            initial: None,
            handshake: Some(2),
            application_data: 3,
        };
        assert_eq!(spaces.get(PacketNumberSpaceKind::Initial), None);
        let mut spaces = spaces;
        assert_eq!(spaces.get_mut(PacketNumberSpaceKind::Initial), None);
    }

    #[test]
    fn get_mut_changes_the_value_in_place() {
        let mut spaces = all();
        *spaces.get_mut(PacketNumberSpaceKind::Handshake).unwrap() = 20;
        *spaces
            .get_mut(PacketNumberSpaceKind::ApplicationData)
            .unwrap() = 30;
        assert_eq!(spaces.handshake, Some(20));
        assert_eq!(spaces.application_data, 30);
    }

    #[test]
    fn iteration_follows_the_order_of_the_spaces() {
        let spaces = all();
        assert_eq!(
            spaces.iter().collect::<Vec<_>>(),
            [
                (PacketNumberSpaceKind::Initial, &1),
                (PacketNumberSpaceKind::Handshake, &2),
                (PacketNumberSpaceKind::ApplicationData, &3),
            ]
        );
    }

    #[test]
    fn iteration_skips_discarded_spaces() {
        let spaces = PacketNumberSpaces {
            initial: None,
            handshake: None,
            application_data: 3,
        };
        assert_eq!(
            spaces.iter().collect::<Vec<_>>(),
            [(PacketNumberSpaceKind::ApplicationData, &3)]
        );
        let spaces = PacketNumberSpaces {
            initial: None,
            handshake: Some(2),
            application_data: 3,
        };
        assert_eq!(spaces.iter().count(), 2);
    }

    #[test]
    fn mutable_iteration_changes_each_value() {
        let mut spaces = PacketNumberSpaces {
            initial: None,
            handshake: Some(2),
            application_data: 3,
        };
        for (_, value) in spaces.iter_mut() {
            *value *= 10;
        }
        assert_eq!(spaces.handshake, Some(20));
        assert_eq!(spaces.application_data, 30);
        let kinds: Vec<_> = spaces.iter_mut().map(|(kind, _)| kind).collect();
        assert_eq!(
            kinds,
            [
                PacketNumberSpaceKind::Handshake,
                PacketNumberSpaceKind::ApplicationData
            ]
        );
    }

    #[test]
    fn map_keeps_which_spaces_there_are_and_tells_the_space() {
        let spaces = PacketNumberSpaces {
            initial: None,
            handshake: Some(2),
            application_data: 3,
        };
        let mapped = spaces.map(|kind, value| format!("{kind:?}{value}"));
        assert_eq!(mapped.initial, None);
        assert_eq!(mapped.handshake.as_deref(), Some("Handshake2"));
        assert_eq!(mapped.application_data, "ApplicationData3");
    }
}

mod state {
    use super::super::PacketNumberSpaceState;
    use sakuya_link::EcnMarking;
    use sakuya_wire::v1::packet_number::PacketNumber;

    fn pn(value: u64) -> PacketNumber {
        PacketNumber::new(value).unwrap()
    }

    #[test]
    fn nothing_is_acknowledged_at_first() {
        let state = PacketNumberSpaceState::new();
        assert_eq!(state.largest_acked(), None);
        assert_eq!(state.smallest_acked(), None);
    }

    #[test]
    fn the_first_acknowledgment_sets_both_bounds() {
        let mut state = PacketNumberSpaceState::new();
        state.on_ack(pn(4), pn(9));
        assert_eq!(state.smallest_acked(), Some(pn(4)));
        assert_eq!(state.largest_acked(), Some(pn(9)));
    }

    #[test]
    fn the_bounds_only_move_outward() {
        let mut state = PacketNumberSpaceState::new();
        state.on_ack(pn(4), pn(9));
        // inside: no change
        state.on_ack(pn(5), pn(7));
        assert_eq!(state.smallest_acked(), Some(pn(4)));
        assert_eq!(state.largest_acked(), Some(pn(9)));
        // outside on both ends
        state.on_ack(pn(2), pn(12));
        assert_eq!(state.smallest_acked(), Some(pn(2)));
        assert_eq!(state.largest_acked(), Some(pn(12)));
    }

    #[test]
    fn a_loss_may_be_ignored_when_nothing_was_acknowledged() {
        let state = PacketNumberSpaceState::new();
        assert!(state.loss_may_ignore_congestion(pn(100)));
    }

    #[test]
    fn a_loss_may_be_ignored_below_every_acknowledged_packet() {
        let mut state = PacketNumberSpaceState::new();
        state.on_ack(pn(5), pn(9));
        assert!(state.loss_may_ignore_congestion(pn(4)));
        assert!(!state.loss_may_ignore_congestion(pn(5)));
        assert!(!state.loss_may_ignore_congestion(pn(7)));
    }

    #[test]
    fn marked_packets_are_counted_by_codepoint() {
        let mut state = PacketNumberSpaceState::new();
        state.marked_sent(EcnMarking::Ect0);
        state.marked_sent(EcnMarking::Ect0);
        state.marked_sent(EcnMarking::Ect1);
        state.marked_sent(EcnMarking::NotEct);
        assert_eq!(state.ect0_sent(), 2);
        assert_eq!(state.ect1_sent(), 1);
    }
}
