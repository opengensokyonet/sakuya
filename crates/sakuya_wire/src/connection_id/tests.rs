use super::{ConnectionId, ConnectionIdLengthError, NonEmptyCid, NonEmptyCidError};
use std::collections::{BTreeSet, HashSet};

const RFC_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

#[test]
fn accepts_lengths_up_to_twenty_bytes() {
    for length in [0, 1, 8, 20] {
        let bytes: Vec<u8> = (0..length).map(|byte| byte as u8 + 1).collect();
        let id = ConnectionId::try_from(bytes.as_slice()).unwrap();
        assert_eq!(id.as_bytes(), bytes);
        assert_eq!(id.len(), length);
        assert_eq!(id.is_empty(), length == 0);
        assert_eq!(AsRef::<[u8]>::as_ref(&id), bytes);
    }
}

#[test]
fn rejects_longer_slices() {
    assert_eq!(
        ConnectionId::try_from(&[0; 21][..]),
        Err(ConnectionIdLengthError { length: 21 })
    );
    assert_eq!(
        ConnectionId::new(&[0; 255]),
        Err(ConnectionIdLengthError { length: 255 })
    );
}

#[test]
fn compares_and_hashes_as_bytes() {
    let short = ConnectionId::new(&[1]).unwrap();
    let long = ConnectionId::new(&[1, 0]).unwrap();
    assert_ne!(short, long);
    assert!(ConnectionId::EMPTY < short);
    assert!(short < long);
    assert!(long < ConnectionId::new(&[2]).unwrap());
    assert_eq!(ConnectionId::default(), ConnectionId::EMPTY);

    let set: HashSet<ConnectionId> = [short, long, ConnectionId::EMPTY].into();
    assert!(set.contains(&[1, 0][..]));
    assert!(set.contains(&[][..]));
    assert!(!set.contains(&[0][..]));
    let ordered: BTreeSet<ConnectionId> = set.into_iter().collect();
    assert!(ordered.contains(&[1][..]));
}

#[test]
fn formats_as_hexadecimal() {
    let id = ConnectionId::new(&RFC_DCID).unwrap();
    assert_eq!(id.to_string(), "8394c8f03e515708");
    assert_eq!(format!("{id:?}"), "ConnectionId(8394c8f03e515708)");
    assert_eq!(format!("{:?}", ConnectionId::EMPTY), "ConnectionId()");
    let id = NonEmptyCid::new(id).unwrap();
    assert_eq!(id.to_string(), "8394c8f03e515708");
    assert_eq!(format!("{id:?}"), "NonEmptyCid(8394c8f03e515708)");
}

#[test]
fn non_empty_cid_rejects_the_empty_id() {
    assert_eq!(NonEmptyCid::new(ConnectionId::EMPTY), None);
    assert_eq!(
        NonEmptyCid::try_from(ConnectionId::EMPTY),
        Err(NonEmptyCidError::Empty)
    );
    assert_eq!(NonEmptyCid::try_from(&[][..]), Err(NonEmptyCidError::Empty));
    assert_eq!(
        NonEmptyCid::try_from(&[0; 21][..]),
        Err(NonEmptyCidError::Length {
            source: ConnectionIdLengthError { length: 21 }
        })
    );
}

#[test]
fn non_empty_cid_keeps_the_connection_id() {
    let id = ConnectionId::new(&RFC_DCID).unwrap();
    let non_empty = NonEmptyCid::try_from(&RFC_DCID[..]).unwrap();
    assert_eq!(non_empty.get(), id);
    assert_eq!(ConnectionId::from(non_empty), id);
    assert_eq!(AsRef::<ConnectionId>::as_ref(&non_empty), &id);
    assert_eq!(non_empty.as_bytes(), RFC_DCID);
    assert_eq!(NonEmptyCid::try_from(id), Ok(non_empty));

    let set: HashSet<NonEmptyCid> = [non_empty].into();
    assert!(set.contains(&RFC_DCID[..]));
    let single = NonEmptyCid::try_from(&[0x00][..]).unwrap();
    assert!(single < non_empty);
}
