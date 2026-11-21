use super::RawConnectionId;
use std::collections::HashSet;

const RFC_DCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

#[test]
fn raw_connection_ids_take_up_to_255_bytes() {
    for length in [0, 20, 21, 255] {
        let bytes = vec![0x5a; length];
        let raw = RawConnectionId::new(&bytes).unwrap();
        assert_eq!((raw.as_bytes(), raw.len()), (&bytes[..], length));
        assert_eq!(raw.is_empty(), length == 0);
    }
    let error = RawConnectionId::try_from(&[0; 256][..]).unwrap_err();
    assert_eq!(error.length(), 256);
    assert_eq!(RawConnectionId::new(&[0; 300]).unwrap_err().length(), 300);
    assert_eq!(
        error.to_string(),
        "connection ID of 256 bytes exceeds the long header maximum of 255 bytes"
    );
    let raw = RawConnectionId::new(&RFC_DCID).unwrap();
    assert_eq!(raw.as_bytes(), RFC_DCID);
    assert_eq!(format!("{raw:?}"), "RawConnectionId(8394c8f03e515708)");
    assert_eq!(raw.to_string(), "8394c8f03e515708");
    assert_eq!(RawConnectionId::default(), RawConnectionId::EMPTY);
    let set: HashSet<RawConnectionId> = [raw].into();
    assert!(set.contains(&RFC_DCID[..]));
}
