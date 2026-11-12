use bytes::Bytes;
use sakuya_tls::{engine::CryptoLevel, message::MessageLimits};
use sakuya_wire::var_int::VarInt;

use super::{
    BoundedCryptoBuffer, CryptoCapacityError, CryptoFrameError, CryptoLevelMoveError,
    CryptoReceiver, FragmentedCryptoReceiveBuffer,
};

fn v(n: u64) -> VarInt {
    VarInt::new(n).unwrap()
}

fn bounded(capacity: usize) -> BoundedCryptoBuffer<FragmentedCryptoReceiveBuffer> {
    BoundedCryptoBuffer {
        buffer: FragmentedCryptoReceiveBuffer::new(),
        capacity,
    }
}

fn server() -> CryptoReceiver<FragmentedCryptoReceiveBuffer> {
    CryptoReceiver::server(
        MessageLimits::default(),
        false,
        bounded(20_000),
        bounded(4096),
    )
    .unwrap()
}

fn client() -> CryptoReceiver<FragmentedCryptoReceiveBuffer> {
    CryptoReceiver::client(
        MessageLimits::default(),
        bounded(20_000),
        bounded(70_000),
        bounded(20_000),
    )
    .unwrap()
}

fn read_all(receiver: &mut CryptoReceiver<FragmentedCryptoReceiveBuffer>) -> Vec<u8> {
    let mut out = Vec::new();
    receiver.read_into(&mut out);
    out
}

#[test]
fn open_stores_and_reads_in_order() {
    let mut r = server();
    r.receive_frame(CryptoLevel::Initial, v(0), Bytes::from_static(b"abc"))
        .unwrap();
    assert_eq!(read_all(&mut r), b"abc");
    assert_eq!(read_all(&mut r), b"");
}

#[test]
fn out_of_order_data_waits_for_the_gap() {
    let mut r = server();
    r.receive_frame(CryptoLevel::Initial, v(3), Bytes::from_static(b"def"))
        .unwrap();
    assert_eq!(read_all(&mut r), b"");
    r.receive_frame(CryptoLevel::Initial, v(0), Bytes::from_static(b"abc"))
        .unwrap();
    assert_eq!(read_all(&mut r), b"abcdef");
}

#[test]
fn open_frame_past_capacity_exceeds_buffer() {
    let mut r = server();
    let level = CryptoLevel::Handshake;
    // Capacity is 4096 past the read position, 0.
    r.receive_frame(level, v(0), Bytes::from(vec![0; 4096]))
        .unwrap();
    assert_eq!(
        r.receive_frame(level, v(4095), Bytes::from_static(b"ab")),
        Err(CryptoFrameError::BufferExceeded { level })
    );
    assert_eq!(
        r.receive_frame(level, v(VarInt::MAX.get()), Bytes::from_static(b"a")),
        Err(CryptoFrameError::BufferExceeded { level })
    );
}

#[test]
fn capacity_window_moves_with_the_read_position() {
    let mut r = server();
    r.move_input_to(CryptoLevel::Handshake).unwrap();
    let level = CryptoLevel::Handshake;
    r.receive_frame(level, v(0), Bytes::from(vec![0; 4096]))
        .unwrap();
    assert!(
        r.receive_frame(level, v(4096), Bytes::from_static(b"x"))
            .is_err()
    );
    assert_eq!(read_all(&mut r).len(), 4096);
    r.receive_frame(level, v(4096), Bytes::from_static(b"x"))
        .unwrap();
}

#[test]
fn left_level_ignores_retransmission_and_rejects_beyond() {
    let mut r = server();
    let level = CryptoLevel::Initial;
    r.receive_frame(level, v(0), Bytes::from_static(b"abcdef"))
        .unwrap();
    assert_eq!(read_all(&mut r), b"abcdef");
    r.move_input_to(CryptoLevel::Handshake).unwrap();
    assert_eq!(r.reading(), CryptoLevel::Handshake);
    r.receive_frame(level, v(0), Bytes::from_static(b"abc"))
        .unwrap();
    r.receive_frame(level, v(2), Bytes::from_static(b"cdef"))
        .unwrap();
    r.receive_frame(level, v(6), Bytes::new()).unwrap();
    assert_eq!(
        r.receive_frame(level, v(4), Bytes::from_static(b"efg")),
        Err(CryptoFrameError::BeyondReceivedEnd { level })
    );
    assert_eq!(
        r.receive_frame(level, v(7), Bytes::new()),
        Err(CryptoFrameError::BeyondReceivedEnd { level })
    );
}

#[test]
fn refused_level_errors_on_data_and_ignores_empty() {
    let mut r = server();
    r.receive_frame(CryptoLevel::OneRtt, v(0), Bytes::new())
        .unwrap();
    assert_eq!(
        r.receive_frame(CryptoLevel::OneRtt, v(0), Bytes::from_static(b"x")),
        Err(CryptoFrameError::Refused)
    );
}

#[test]
fn later_level_data_waits_until_the_engine_moves() {
    let mut r = client();
    r.receive_frame(CryptoLevel::Handshake, v(0), Bytes::from_static(b"hs"))
        .unwrap();
    assert_eq!(read_all(&mut r), b"");
    r.move_input_to(CryptoLevel::Handshake).unwrap();
    assert_eq!(read_all(&mut r), b"hs");
}

#[test]
fn move_with_unread_bytes_fails_and_changes_nothing() {
    let mut r = server();
    r.receive_frame(CryptoLevel::Initial, v(0), Bytes::from_static(b"abc"))
        .unwrap();
    assert_eq!(
        r.move_input_to(CryptoLevel::Handshake),
        Err(CryptoLevelMoveError::UnreadBytes {
            level: CryptoLevel::Initial
        })
    );
    assert_eq!(r.reading(), CryptoLevel::Initial);
    assert_eq!(read_all(&mut r), b"abc");
    r.move_input_to(CryptoLevel::Handshake).unwrap();
}

#[test]
fn move_with_data_stored_ahead_of_a_gap_fails() {
    let mut r = server();
    r.receive_frame(CryptoLevel::Initial, v(5), Bytes::from_static(b"zz"))
        .unwrap();
    assert_eq!(
        r.move_input_to(CryptoLevel::Handshake),
        Err(CryptoLevelMoveError::UnreadBytes {
            level: CryptoLevel::Initial
        })
    );
}

#[test]
fn move_backward_or_in_place_is_not_forward() {
    let mut r = server();
    assert_eq!(
        r.move_input_to(CryptoLevel::Initial),
        Err(CryptoLevelMoveError::NotForward {
            from: CryptoLevel::Initial,
            to: CryptoLevel::Initial
        })
    );
    r.move_input_to(CryptoLevel::Handshake).unwrap();
    assert_eq!(
        r.move_input_to(CryptoLevel::Initial),
        Err(CryptoLevelMoveError::NotForward {
            from: CryptoLevel::Handshake,
            to: CryptoLevel::Initial
        })
    );
    assert_eq!(r.reading(), CryptoLevel::Handshake);
}

#[test]
fn skipping_a_level_leaves_it_unchanged() {
    let mut r = client();
    r.move_input_to(CryptoLevel::OneRtt).unwrap();
    // Handshake stayed open.
    r.receive_frame(CryptoLevel::Handshake, v(0), Bytes::from_static(b"x"))
        .unwrap();
    assert_eq!(read_all(&mut r), b"");
}

#[test]
fn reading_a_refused_level_returns_zero() {
    let mut r = server();
    r.move_input_to(CryptoLevel::OneRtt).unwrap();
    assert_eq!(read_all(&mut r), b"");
}

#[test]
fn capacity_at_the_minimum_passes_and_below_fails() {
    let limits = MessageLimits::default();
    // Server Initial: ClientHello, 16 KiB plus the 4-byte header.
    let minimum = 16 * 1024 + 4;
    assert!(CryptoReceiver::server(limits, false, bounded(minimum), bounded(4096)).is_ok());
    assert_eq!(
        CryptoReceiver::server(limits, false, bounded(minimum - 1), bounded(4096)).unwrap_err(),
        CryptoCapacityError {
            level: CryptoLevel::Initial,
            capacity: minimum - 1,
            minimum
        }
    );
}

#[test]
fn handshake_minimum_depends_on_client_certificate() {
    let limits = MessageLimits::default();
    // Without a client certificate only Finished counts: the 4096 floor.
    assert!(CryptoReceiver::server(limits, false, bounded(20_000), bounded(4096)).is_ok());
    // With one, Certificate is 64 KiB plus the header.
    let minimum = 64 * 1024 + 4;
    assert_eq!(
        CryptoReceiver::server(limits, true, bounded(20_000), bounded(4096)).unwrap_err(),
        CryptoCapacityError {
            level: CryptoLevel::Handshake,
            capacity: 4096,
            minimum
        }
    );
    assert!(CryptoReceiver::server(limits, true, bounded(20_000), bounded(minimum)).is_ok());
}

#[test]
fn client_levels_are_checked() {
    let limits = MessageLimits::default();
    let err = CryptoReceiver::client(limits, bounded(20_000), bounded(20_000), bounded(20_000))
        .unwrap_err();
    assert_eq!(err.level, CryptoLevel::Handshake);
    assert_eq!(err.minimum, 64 * 1024 + 4);
    let err = CryptoReceiver::client(limits, bounded(20_000), bounded(70_000), bounded(4096))
        .unwrap_err();
    assert_eq!(err.level, CryptoLevel::OneRtt);
    let err =
        CryptoReceiver::client(limits, bounded(100), bounded(70_000), bounded(20_000)).unwrap_err();
    assert_eq!(err.level, CryptoLevel::Initial);
}
