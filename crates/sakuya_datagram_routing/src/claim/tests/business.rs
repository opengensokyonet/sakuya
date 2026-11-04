//! Business conditions around an attempt: keys that arrive later, and protocol
//! state that only the processing owner commits
//!
//! The judgment here follows the reference QUIC shape: the path receiver owns
//! the keys, a reusable scratch buffer and the reason of its last attempt, and
//! the judgment captures a handle to it. The deliverer only delivers.
//! Protection is a toy: a datagram is `[tag, packet_number, payload...]`,
//! authentic when the tag equals the key, and its payload is masked with the
//! key.

use std::mem;
use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use tokio::sync::Notify;

use super::support::{
    Judging, Probe, TestDatagram, UnclaimedSink, WakeCount, poll_with, ready, route,
};
use crate::claim::candidate::DatagramClaimAttempt;
use crate::claim::candidate::{DatagramClaimAccess, DatagramClaimOutcome};
use crate::claim::delivery::ExclusiveDatagramDelivery;
use crate::claim::route_match::DatagramRouteMatchInfo;
use crate::claim::shared::DatagramFinishPolicy;

/// The owner of the keys, which registers waiters and announces new keys.
#[derive(Default)]
struct KeyStore {
    key: Mutex<Option<u8>>,
    installed: Notify,
}

impl KeyStore {
    fn install(&self, key: u8) {
        *self.key.lock().unwrap() = Some(key);
        self.installed.notify_waiters();
    }

    fn current(&self) -> Option<u8> {
        *self.key.lock().unwrap()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LastAttempt {
    MissingKey,
    WrongKey,
}

/// What a claiming judgment hands over: the packet it authenticated.
#[derive(Debug)]
struct Authenticated {
    packet_number: u8,
    plaintext: Vec<u8>,
}

/// The caller of the attempts, holding everything the judgment needs.
struct PathReceiver {
    keys: Arc<KeyStore>,
    scratch: Vec<u8>,
    last_attempt: Option<LastAttempt>,
    /// The protocol state that only processing may change.
    largest_packet_number: Option<u8>,
}

impl PathReceiver {
    fn new(keys: &Arc<KeyStore>) -> Self {
        Self {
            keys: keys.clone(),
            scratch: Vec::new(),
            last_attempt: None,
            largest_packet_number: None,
        }
    }

    /// A judgment that reads and updates this receiver.
    ///
    /// Abandoning hands the scratch buffer back for reuse.
    fn judgment(
        &mut self,
    ) -> impl for<'access> FnOnce(
        DatagramClaimAccess<'access, TestDatagram>,
        &DatagramRouteMatchInfo,
    ) -> DatagramClaimOutcome<
        'access,
        Authenticated,
        Vec<u8>,
        TestDatagram,
    > + '_ {
        move |access, _route| {
            let Some(key) = self.keys.current() else {
                self.last_attempt = Some(LastAttempt::MissingKey);
                return DatagramClaimOutcome::Unclaimed(access);
            };
            // Restore from the read-only original; an earlier failure may have
            // overwritten the scratch buffer.
            let mut scratch = mem::take(&mut self.scratch);
            scratch.clear();
            scratch.extend_from_slice(access.bytes());
            for byte in &mut scratch[2..] {
                *byte ^= key;
            }
            if scratch[0] != key {
                self.last_attempt = Some(LastAttempt::WrongKey);
                return DatagramClaimOutcome::Abandoned(scratch);
            }
            // Authenticated: prepare the result, then take the datagram. The
            // packet number is only a candidate; the connection is not touched.
            let packet_number = scratch[1];
            scratch.drain(..2);
            let packet = Authenticated {
                packet_number,
                plaintext: scratch,
            };
            DatagramClaimOutcome::Claimed(access.into_exclusive(), packet)
        }
    }

    /// Processing by the owner of the connection: checks the current
    /// acceptance rules, then commits.
    fn process(
        &mut self,
        delivery: ExclusiveDatagramDelivery<TestDatagram>,
        packet: Authenticated,
    ) -> bool {
        let (_datagram, _route) = delivery.consume();
        assert_eq!(packet.plaintext, b"payload");
        if self
            .largest_packet_number
            .is_some_and(|largest| packet.packet_number <= largest)
        {
            return false;
        }
        self.largest_packet_number = Some(packet.packet_number);
        true
    }
}

fn protected(key: u8, packet_number: u8) -> TestDatagram {
    let mut bytes = vec![key, packet_number];
    bytes.extend(b"payload".iter().map(|byte| byte ^ key));
    TestDatagram::new(&bytes).0
}

/// A deliverer that only stores its deliveries.
fn deliverer() -> Arc<Probe> {
    Probe::new(Judging::Reject)
}

const KEY: u8 = 0x5a;

#[test]
fn key_installed_before_the_wait_is_found_by_the_recheck() {
    let keys = Arc::new(KeyStore::default());
    let endpoint = deliverer();
    let mut path = PathReceiver::new(&keys);
    let sink = UnclaimedSink::default();
    route(protected(KEY, 1), sink.policy(), &[&endpoint]);

    let DatagramClaimAttempt::Unclaimed(candidate) =
        ready(endpoint.take_candidate().try_exclusive(path.judgment()))
    else {
        panic!("no key yet");
    };
    assert_eq!(path.last_attempt, Some(LastAttempt::MissingKey));

    // Checking first and registering afterwards would sleep forever: the key
    // arrives between the check and the registration.
    keys.install(KEY);
    {
        let mut late = pin!(keys.installed.notified());
        assert!(poll_with(late.as_mut(), Waker::noop()).is_pending());
    }

    // Register with the condition owner first, then recheck the condition.
    let mut installed = pin!(keys.installed.notified());
    installed.as_mut().enable();
    assert_eq!(keys.current(), Some(KEY));
    let DatagramClaimAttempt::Claimed(delivery, packet) =
        ready(candidate.try_exclusive(path.judgment()))
    else {
        panic!("the key is available now");
    };
    assert!(path.process(delivery, packet));
    assert_eq!(sink.len(), 0);
}

#[test]
fn key_installed_after_registering_wakes_the_receiver() {
    let keys = Arc::new(KeyStore::default());
    let endpoint = deliverer();
    let mut path = PathReceiver::new(&keys);
    let sink = UnclaimedSink::default();
    route(protected(KEY, 1), sink.policy(), &[&endpoint]);
    let DatagramClaimAttempt::Unclaimed(candidate) =
        ready(endpoint.take_candidate().try_exclusive(path.judgment()))
    else {
        panic!("no key yet");
    };

    let mut installed = pin!(keys.installed.notified());
    installed.as_mut().enable();
    assert_eq!(keys.current(), None);
    let (wakes, waker) = WakeCount::waker();
    assert!(poll_with(installed.as_mut(), &waker).is_pending());

    keys.install(KEY);
    assert_eq!(wakes.get(), 1);
    assert!(matches!(
        poll_with(installed.as_mut(), &waker),
        Poll::Ready(())
    ));
    let DatagramClaimAttempt::Claimed(delivery, packet) =
        ready(candidate.try_exclusive(path.judgment()))
    else {
        panic!("the key is available now");
    };
    assert!(path.process(delivery, packet));
}

#[test]
fn authentication_prepares_without_committing_protocol_state() {
    let keys = Arc::new(KeyStore::default());
    let other_keys = Arc::new(KeyStore::default());
    keys.install(KEY);
    other_keys.install(KEY ^ 0xff);
    let owner = deliverer();
    let stranger = deliverer();
    let mut owner_path = PathReceiver::new(&keys);
    let mut stranger_path = PathReceiver::new(&other_keys);
    route(
        protected(KEY, 7),
        DatagramFinishPolicy::LastTakes,
        &[&stranger, &owner],
    );

    let DatagramClaimAttempt::Abandoned(scratch) = ready(
        stranger
            .take_candidate()
            .try_exclusive(stranger_path.judgment()),
    ) else {
        panic!("the other key does not authenticate");
    };
    assert_eq!(stranger_path.last_attempt, Some(LastAttempt::WrongKey));
    // The buffer comes back for the next judgment; its contents mean nothing.
    assert!(scratch.capacity() > 0);
    stranger_path.scratch = scratch;
    assert_eq!(stranger_path.largest_packet_number, None);

    // The stranger left, so the owner is the only participant and takes the
    // datagram without a judgment; nothing was authenticated.
    let DatagramClaimAttempt::Exclusive(unjudged) =
        ready(owner.take_candidate().try_exclusive(owner_path.judgment()))
    else {
        panic!("the sole participant takes the datagram");
    };
    drop(unjudged);
    assert_eq!(owner_path.last_attempt, None);

    // With competition left in place, the owner's judgment runs.
    route(
        protected(KEY, 8),
        DatagramFinishPolicy::LastTakes,
        &[&stranger, &owner],
    );
    let _competing = stranger.take_candidate();
    let DatagramClaimAttempt::Claimed(delivery, packet) =
        ready(owner.take_candidate().try_exclusive(owner_path.judgment()))
    else {
        panic!("the right key authenticates");
    };
    assert_eq!(packet.packet_number, 8);
    assert_eq!(
        owner_path.largest_packet_number, None,
        "claiming commits nothing"
    );
    assert!(owner_path.process(delivery, packet));
    assert_eq!(owner_path.largest_packet_number, Some(8));

    // A replay authenticates and is claimed again, but processing applies the
    // current rules and refuses it.
    route(
        protected(KEY, 8),
        DatagramFinishPolicy::LastTakes,
        &[&stranger, &owner],
    );
    let _competing = stranger.take_candidate();
    let DatagramClaimAttempt::Claimed(replay, packet) =
        ready(owner.take_candidate().try_exclusive(owner_path.judgment()))
    else {
        panic!("the right key authenticates");
    };
    assert!(!owner_path.process(replay, packet));
    assert_eq!(owner_path.largest_packet_number, Some(8));
}
