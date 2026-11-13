use std::sync::Arc;

use sakuya_datagram_routing::route::recognizer::{ConnectionIdLengths, ConnectionIdRecognizer};
use sakuya_link::{BindingId, Link};
use sakuya_wire::connection_id::ConnectionIdLength;

use super::{ZeroLengthLocalRecognizer, ZeroLengthLocals, ZeroLengthRegistration};
use crate::test_link::TestLink;

fn length(value: usize) -> ConnectionIdLength {
    ConnectionIdLength::new(value).unwrap()
}

#[test]
fn a_local_end_is_occupied_once() {
    let locals = Arc::new(ZeroLengthLocals::new());
    let first = locals.occupy(4433_u16).unwrap();
    assert!(locals.occupy(4433).is_err());
    let other = locals.occupy(4434).unwrap();
    assert!(locals.is_occupied(&4433));
    drop(first);
    assert!(!locals.is_occupied(&4433));
    assert!(locals.is_occupied(&4434));
    let again = locals.occupy(4433).unwrap();
    assert_eq!(*again.local(), 4433);
    drop(other);
}

/// A route entry that records, when dropped, whether its local end was
/// still occupied.
struct Entry {
    locals: Arc<ZeroLengthLocals<u16>>,
    occupied_when_dropped: Arc<std::sync::Mutex<Option<bool>>>,
}

impl Drop for Entry {
    fn drop(&mut self) {
        *self.occupied_when_dropped.lock().unwrap() = Some(self.locals.is_occupied(&4433));
    }
}

#[test]
fn a_registration_revokes_its_entry_before_freeing_the_local_end() {
    let locals = Arc::new(ZeroLengthLocals::new());
    let seen = Arc::new(std::sync::Mutex::new(None));
    let registration = ZeroLengthRegistration::new(
        Entry {
            locals: Arc::clone(&locals),
            occupied_when_dropped: Arc::clone(&seen),
        },
        locals.occupy(4433).unwrap(),
    );
    assert_eq!(*registration.local(), 4433);
    drop(registration);
    assert_eq!(*seen.lock().unwrap(), Some(true));
    assert!(!locals.is_occupied(&4433));
}

fn lengths<R: ConnectionIdRecognizer<u16, std::net::SocketAddr>>(
    recognizer: &R,
    link: &TestLink,
) -> Vec<ConnectionIdLength> {
    recognizer
        .short_dcid_lengths(&[0x40; 32], link.id())
        .collect()
}

#[test]
fn an_occupied_local_end_adds_the_zero_length_reading() {
    let locals = Arc::new(ZeroLengthLocals::new());
    let recognizer =
        ZeroLengthLocalRecognizer::new(ConnectionIdLengths::new([length(8)]), Arc::clone(&locals));
    let binding = BindingId::new();
    let occupied = TestLink::new(4433, "192.0.2.1:5000".parse().unwrap(), &binding);
    let free = TestLink::new(4434, "192.0.2.1:5000".parse().unwrap(), &binding);
    assert_eq!(lengths(&recognizer, &occupied), [length(8)]);

    let _occupancy = locals.occupy(4433).unwrap();
    assert_eq!(
        lengths(&recognizer, &occupied),
        [length(8), ConnectionIdLength::ZERO]
    );
    assert_eq!(lengths(&recognizer, &free), [length(8)]);
}

#[test]
fn the_zero_length_reading_is_yielded_once() {
    let locals = Arc::new(ZeroLengthLocals::new());
    let recognizer = ZeroLengthLocalRecognizer::new(
        ConnectionIdLengths::new([ConnectionIdLength::ZERO, length(8)]),
        Arc::clone(&locals),
    );
    let link = TestLink::new(4433, "192.0.2.1:5000".parse().unwrap(), &BindingId::new());
    assert_eq!(
        lengths(&recognizer, &link),
        [ConnectionIdLength::ZERO, length(8)]
    );
    let _occupancy = locals.occupy(4433).unwrap();
    assert_eq!(
        lengths(&recognizer, &link),
        [length(8), ConnectionIdLength::ZERO]
    );
}
