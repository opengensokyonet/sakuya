//! Business conditions around an attempt: keys that arrive later, and protocol
//! state that only the processing owner commits
//!
//! The deliverer here follows the shape of the reference QUIC state: an
//! `Unprepared` state with a scratch buffer and the last attempt's result, and
//! an `Authenticated` state holding the prepared packet. Protection is a toy:
//! a datagram is `[tag, packet_number, payload...]`, authentic when the tag
//! equals the key, and its payload is masked with the key.

use std::pin::pin;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use tokio::sync::Notify;

use super::support::{TestDatagram, UnclaimedSink, WakeCount, poll_with, ready};
use crate::claim::group::prepare_claim;
use crate::claim::shared::DatagramFinishPolicy;
use crate::claim::{
    DatagramClaimAccess, DatagramClaimAttempt, DatagramClaimCandidate, DatagramClaimOutcome,
    DatagramDeliverer, DatagramDelivery, DatagramRouteMatchInfo, DatagramView,
    ErasedDatagramDeliverer, ExclusiveDatagramDelivery,
};

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

/// The protocol state that only processing may change.
#[derive(Default)]
struct Connection {
    largest_packet_number: Mutex<Option<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LastAttempt {
    MissingKey,
    WrongKey,
}

enum PacketState {
    Unprepared {
        scratch: Vec<u8>,
        last_attempt: Option<LastAttempt>,
    },
    Authenticated {
        packet_number: u8,
        plaintext: Vec<u8>,
    },
}

impl PacketState {
    fn last_attempt(&self) -> Option<LastAttempt> {
        match self {
            Self::Unprepared { last_attempt, .. } => *last_attempt,
            Self::Authenticated { .. } => None,
        }
    }
}

struct Endpoint {
    keys: Arc<KeyStore>,
    connection: Arc<Connection>,
    deliveries: Mutex<Vec<DatagramDelivery<TestDatagram, Endpoint>>>,
}

impl Endpoint {
    fn new(keys: &Arc<KeyStore>) -> Arc<Self> {
        Arc::new(Self {
            keys: keys.clone(),
            connection: Arc::default(),
            deliveries: Mutex::default(),
        })
    }

    fn take_candidate(&self) -> DatagramClaimCandidate<TestDatagram, Self> {
        match self.deliveries.lock().unwrap().pop() {
            Some(DatagramDelivery::Competing(candidate)) => candidate,
            _ => panic!("expected a competing delivery"),
        }
    }

    fn largest(&self) -> Option<u8> {
        *self.connection.largest_packet_number.lock().unwrap()
    }

    /// Processing by the owner of the connection: checks the current
    /// acceptance rules, then commits.
    fn process(&self, delivery: ExclusiveDatagramDelivery<TestDatagram, Self>) -> bool {
        let (_datagram, state) = delivery.consume();
        let PacketState::Authenticated {
            packet_number,
            plaintext,
        } = state.into_parts().1
        else {
            // A directly taken datagram was never judged; this toy processing
            // does not authenticate it after the fact.
            return false;
        };
        assert_eq!(plaintext, b"payload");
        let mut largest = self.connection.largest_packet_number.lock().unwrap();
        if largest.is_some_and(|largest| packet_number <= largest) {
            return false;
        }
        *largest = Some(packet_number);
        true
    }
}

impl DatagramDeliverer<TestDatagram> for Endpoint {
    type DelivererDatagramState = PacketState;

    fn new_datagram_state(
        &self,
        _datagram: DatagramView<'_>,
        _route: &DatagramRouteMatchInfo,
    ) -> PacketState {
        PacketState::Unprepared {
            scratch: Vec::new(),
            last_attempt: None,
        }
    }

    fn try_claim<'access>(
        &self,
        access: DatagramClaimAccess<'access, TestDatagram>,
        _route: &DatagramRouteMatchInfo,
        state: PacketState,
    ) -> DatagramClaimOutcome<'access, TestDatagram, PacketState> {
        let PacketState::Unprepared { mut scratch, .. } = state else {
            unreachable!("an authenticated state is always claimed")
        };
        let Some(key) = self.keys.current() else {
            let state = PacketState::Unprepared {
                scratch,
                last_attempt: Some(LastAttempt::MissingKey),
            };
            return DatagramClaimOutcome::Unclaimed { access, state };
        };
        // Restore from the read-only original; an earlier failure may have
        // overwritten the scratch buffer.
        scratch.clear();
        scratch.extend_from_slice(access.bytes());
        for byte in &mut scratch[2..] {
            *byte ^= key;
        }
        if scratch[0] != key {
            let state = PacketState::Unprepared {
                scratch,
                last_attempt: Some(LastAttempt::WrongKey),
            };
            return DatagramClaimOutcome::Unclaimed { access, state };
        }
        // Authenticated: prepare the result, then take the datagram. The
        // packet number is only a candidate; the connection is not touched.
        let packet_number = scratch[1];
        scratch.drain(..2);
        let state = PacketState::Authenticated {
            packet_number,
            plaintext: scratch,
        };
        DatagramClaimOutcome::Claimed {
            datagram: access.into_exclusive(),
            state,
        }
    }

    fn deliver(&self, delivery: DatagramDelivery<TestDatagram, Self>) {
        self.deliveries.lock().unwrap().push(delivery);
    }
}

fn protected(key: u8, packet_number: u8) -> TestDatagram {
    let mut bytes = vec![key, packet_number];
    bytes.extend(b"payload".iter().map(|byte| byte ^ key));
    TestDatagram::new(&bytes).0
}

fn route_to(
    datagram: TestDatagram,
    finish: DatagramFinishPolicy<TestDatagram>,
    endpoints: &[&Arc<Endpoint>],
) {
    let entries = endpoints
        .iter()
        .map(|endpoint| {
            let erased: Arc<dyn ErasedDatagramDeliverer<TestDatagram>> = Arc::clone(endpoint) as _;
            (erased, DatagramRouteMatchInfo::new())
        })
        .collect();
    prepare_claim(datagram, finish, entries).dispatch();
}

const KEY: u8 = 0x5a;

#[test]
fn key_installed_before_the_wait_is_found_by_the_recheck() {
    let keys = Arc::new(KeyStore::default());
    let endpoint = Endpoint::new(&keys);
    let sink = UnclaimedSink::default();
    route_to(protected(KEY, 1), sink.policy(), &[&endpoint]);

    let DatagramClaimAttempt::Unclaimed(candidate) =
        ready(endpoint.take_candidate().try_exclusive())
    else {
        panic!("no key yet");
    };
    let last = candidate.initialized_state().unwrap().last_attempt();
    assert_eq!(last, Some(LastAttempt::MissingKey));

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
    let DatagramClaimAttempt::Claimed(delivery) = ready(candidate.try_exclusive()) else {
        panic!("the key is available now");
    };
    assert!(endpoint.process(delivery));
    assert_eq!(sink.len(), 0);
}

#[test]
fn key_installed_after_registering_wakes_the_receiver() {
    let keys = Arc::new(KeyStore::default());
    let endpoint = Endpoint::new(&keys);
    let sink = UnclaimedSink::default();
    route_to(protected(KEY, 1), sink.policy(), &[&endpoint]);
    let DatagramClaimAttempt::Unclaimed(candidate) =
        ready(endpoint.take_candidate().try_exclusive())
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
    let DatagramClaimAttempt::Claimed(delivery) = ready(candidate.try_exclusive()) else {
        panic!("the key is available now");
    };
    assert!(endpoint.process(delivery));
}

#[test]
fn authentication_prepares_without_committing_protocol_state() {
    let keys = Arc::new(KeyStore::default());
    let other_keys = Arc::new(KeyStore::default());
    keys.install(KEY);
    other_keys.install(KEY ^ 0xff);
    let owner = Endpoint::new(&keys);
    let stranger = Endpoint::new(&other_keys);
    route_to(
        protected(KEY, 7),
        DatagramFinishPolicy::LastTakes,
        &[&stranger, &owner],
    );

    let DatagramClaimAttempt::Unclaimed(rejected) =
        ready(stranger.take_candidate().try_exclusive())
    else {
        panic!("the other key does not authenticate");
    };
    assert_eq!(
        rejected.initialized_state().unwrap().last_attempt(),
        Some(LastAttempt::WrongKey)
    );
    assert_eq!(stranger.largest(), None);

    let DatagramClaimAttempt::Claimed(delivery) = ready(owner.take_candidate().try_exclusive())
    else {
        panic!("the right key authenticates");
    };
    assert!(matches!(
        delivery.initialized_state(),
        Some(PacketState::Authenticated {
            packet_number: 7,
            ..
        })
    ));
    assert_eq!(owner.largest(), None, "claiming commits nothing");
    assert!(matches!(
        ready(rejected.try_exclusive()),
        DatagramClaimAttempt::ClaimedElsewhere
    ));

    assert!(owner.process(delivery));
    assert_eq!(owner.largest(), Some(7));

    // A replay authenticates and is claimed again, but processing applies the
    // current rules and refuses it.
    route_to(
        protected(KEY, 7),
        DatagramFinishPolicy::LastTakes,
        &[&stranger, &owner],
    );
    let _competing = stranger.take_candidate();
    let DatagramClaimAttempt::Claimed(replay) = ready(owner.take_candidate().try_exclusive())
    else {
        panic!("the right key authenticates");
    };
    assert!(!owner.process(replay));
    assert_eq!(owner.largest(), Some(7));
}
