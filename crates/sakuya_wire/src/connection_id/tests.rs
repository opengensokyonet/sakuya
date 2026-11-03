use super::{
    ConnectionId, ConnectionIdLength, EmptyCidError, NonEmptyCid, NonEmptyCidError,
    RawConnectionId, StatelessResetToken,
    codec::{
        ReadConnectionIdError, ReadConnectionIdHostExt as _, ReadRawConnectionIdHostExt as _,
        WriteConnectionIdHostExt as _,
    },
};
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
    let error = ConnectionId::try_from(&[0; 21][..]).unwrap_err();
    assert_eq!(error.length(), 21);
    assert_eq!(ConnectionIdLength::new(21), Err(error));
    assert_eq!(ConnectionId::new(&[0; 255]).unwrap_err().length(), 255);
}

#[test]
fn lengths_range_from_zero_to_twenty_bytes() {
    for length in [0, 1, 8, 20] {
        let typed = ConnectionIdLength::new(length).unwrap();
        assert_eq!(typed.get(), length);
        assert_eq!(usize::from(typed), length);
        assert_eq!(usize::from(u8::from(typed)), length);
        assert_eq!(typed.is_zero(), length == 0);
        assert_eq!(ConnectionIdLength::try_from(length), Ok(typed));
    }
    assert_eq!(ConnectionIdLength::new(0), Ok(ConnectionIdLength::ZERO));
    assert_eq!(ConnectionIdLength::new(21).unwrap_err().length(), 21);
    assert_eq!(ConnectionIdLength::new(256).unwrap_err().length(), 256);
    assert_eq!(
        ConnectionIdLength::new(21).unwrap_err().to_string(),
        "connection ID of 21 bytes exceeds the QUIC version 1 maximum of 20 bytes"
    );
    let id = ConnectionId::new(&RFC_DCID).unwrap();
    assert_eq!(id.length(), ConnectionIdLength::new(8).unwrap());
    assert_eq!(ConnectionId::EMPTY.length(), ConnectionIdLength::ZERO);
    assert_eq!(format!("{:?}", id.length()), "ConnectionIdLength(8)");
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
    assert_eq!(NonEmptyCid::new(ConnectionId::EMPTY), Err(EmptyCidError));
    assert_eq!(
        NonEmptyCid::try_from(ConnectionId::EMPTY),
        Err(EmptyCidError)
    );
    assert_eq!(
        NonEmptyCid::try_from(&[][..]),
        Err(NonEmptyCidError::Empty {
            source: EmptyCidError
        })
    );
    assert_eq!(
        NonEmptyCid::try_from(&[0; 21][..]),
        Err(NonEmptyCidError::Length {
            source: ConnectionIdLength::new(21).unwrap_err()
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

#[test]
fn raw_connection_ids_take_up_to_255_bytes() {
    for length in [0, 20, 21, 255] {
        let bytes = vec![0x5a; length];
        let raw = RawConnectionId::new(&bytes).unwrap();
        assert_eq!((raw.as_bytes(), raw.len()), (&bytes[..], length));
        assert_eq!(raw.is_empty(), length == 0);
        assert_eq!(
            ConnectionId::try_from(raw),
            if length <= 20 {
                Ok(ConnectionId::new(&bytes).unwrap())
            } else {
                Err(ConnectionIdLength::new(length).unwrap_err())
            }
        );
    }
    let error = RawConnectionId::try_from(&[0; 256][..]).unwrap_err();
    assert_eq!(error.length(), 256);
    assert_eq!(RawConnectionId::new(&[0; 300]).unwrap_err().length(), 300);
    assert_eq!(
        error.to_string(),
        "connection ID of 256 bytes exceeds the long header maximum of 255 bytes"
    );
    let id = ConnectionId::new(&RFC_DCID).unwrap();
    let raw = RawConnectionId::from(id);
    assert_eq!(raw.as_bytes(), RFC_DCID);
    assert_eq!(format!("{raw:?}"), "RawConnectionId(8394c8f03e515708)");
    assert_eq!(raw.to_string(), "8394c8f03e515708");
    assert_eq!(RawConnectionId::default(), RawConnectionId::EMPTY);
    let set: HashSet<RawConnectionId> = [raw].into();
    assert!(set.contains(&RFC_DCID[..]));
}

#[test]
fn stateless_reset_token_keeps_its_bytes() {
    let token = StatelessResetToken::new([0x11; 16]);
    assert_eq!(token.as_bytes(), &[0x11; 16]);
    assert_eq!(<[u8; 16]>::from(token), [0x11; 16]);
    assert_eq!(StatelessResetToken::from([0x11; 16]), token);
    assert_eq!(
        format!("{token:?}"),
        "StatelessResetToken(11111111111111111111111111111111)"
    );
}

#[test]
fn stateless_reset_tokens_compare_every_byte() {
    let token = StatelessResetToken::new([0x11; 16]);
    for position in 0..StatelessResetToken::LEN {
        for flipped in [0x01, 0x80] {
            let mut bytes = [0x11; 16];
            bytes[position] ^= flipped;
            assert_ne!(StatelessResetToken::new(bytes), token, "{position}");
        }
    }
    let set: HashSet<StatelessResetToken> = [token].into();
    assert!(set.contains(&StatelessResetToken::new([0x11; 16])));
}

#[test]
fn length_prefixed_connection_ids_round_trip() {
    for length in [0, 1, 8, 20] {
        let id = ConnectionId::new(&vec![0xaa; length]).unwrap();
        let mut output = Vec::new();
        output.sync_write_connection_id_unpin(id).unwrap();
        assert_eq!(output.len(), 1 + length);
        assert_eq!(output[0] as usize, length);
        let mut input = output.as_slice();
        assert_eq!(input.sync_read_connection_id_unpin().unwrap(), id);
        let mut input = output.as_slice();
        assert_eq!(
            input.sync_read_raw_connection_id_unpin().unwrap(),
            RawConnectionId::from(id)
        );
    }
}

#[test]
fn length_prefixed_connection_id_limits() {
    // A version 1 connection ID is rejected at its length byte.
    let mut input = &[21, 0xaa, 0xbb][..];
    let error = input.sync_read_connection_id_unpin().unwrap_err();
    assert!(matches!(
        error,
        ReadConnectionIdError::Length { source } if source.length() == 21
    ));
    assert_eq!(input, [0xaa, 0xbb]);

    let mut long = vec![255];
    long.extend([7; 255]);
    let mut input = long.as_slice();
    assert_eq!(
        input.sync_read_raw_connection_id_unpin().unwrap().len(),
        255
    );

    for encoding in [&[][..], &[4, 1, 2][..]] {
        let mut input = encoding;
        assert!(
            input
                .sync_read_connection_id_unpin()
                .unwrap_err()
                .is_incomplete()
        );
        let mut input = encoding;
        assert!(
            input
                .sync_read_raw_connection_id_unpin()
                .unwrap_err()
                .is_incomplete()
        );
    }
}
