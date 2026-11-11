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
