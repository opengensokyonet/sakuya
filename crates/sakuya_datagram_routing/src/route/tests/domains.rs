//! Routing domains used on one thread and shared between threads

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use sakuya_link::LinkId;

use super::support::{
    Datagram, Handoff, Index, Recorder, Router, Target, Work, binding, cid, initial, lengths, link,
    nonempty, ready,
};
use crate::claim::candidate::{DatagramClaimAttempt, DatagramClaimCandidate, DatagramClaimFuture};
use crate::claim::deliverer::{
    DatagramClaimAccess, DatagramClaimOutcome, DatagramDeliverer, DatagramView, ExclusiveDatagram,
};
use crate::claim::delivery::DatagramDelivery;
use crate::claim::erased::ErasedDatagramDeliverer;
use crate::claim::route_match::DatagramRouteMatchInfo;
use crate::route::acceptance::{
    InitialAcceptance, InitialDatagramReceiver, InitialReceiverFactory, PreparedReceiver,
    ReflowHandoff, ReflowProvider, UnclaimedWork,
};
use crate::route::association::{MatchAssociation, PacketForms, RouteMatcher};
use crate::route::datagram::ReceivedDatagram;
use crate::route::index::{RouteEntryRegistration, RouteIndex};
use crate::route::interpretation::RecognizedInitial;
use crate::route::router::DatagramRouter;
use crate::version::Version;

type LocalPayload = Rc<[u8]>;
type LocalLink = Rc<LinkId>;
type LocalDatagram = ReceivedDatagram<LocalPayload, LocalLink>;
type LocalWork = UnclaimedWork<LocalPayload, LocalLink>;
type LocalHandoff = ReflowHandoff<LocalReflow>;
type LocalTarget = dyn ErasedDatagramDeliverer<LocalDatagram, LocalHandoff>;

/// A reflow provider that keeps the work in a queue shared through `Rc`.
struct LocalReflow {
    queue: Rc<RefCell<Vec<LocalWork>>>,
}

impl ReflowProvider<LocalPayload, LocalLink> for LocalReflow {
    fn hand_off(&self, work: LocalWork) {
        self.queue.borrow_mut().push(work);
    }
}

/// A deliverer whose private state and deliveries stay on this thread.
struct LocalDeliverer {
    deliveries: RefCell<Vec<DatagramDelivery<LocalDatagram, Self>>>,
}

impl LocalDeliverer {
    #[expect(
        clippy::arc_with_non_send_sync,
        reason = "a routing domain used on one thread is the point"
    )]
    fn new() -> Arc<Self> {
        Arc::new(Self {
            deliveries: RefCell::default(),
        })
    }
}

impl DatagramDeliverer<LocalDatagram> for LocalDeliverer {
    type Handoff = LocalHandoff;
    type DelivererDatagramState = Rc<Cell<usize>>;

    fn new_datagram_state(
        &self,
        _: DatagramView<'_>,
        _: &DatagramRouteMatchInfo,
    ) -> Rc<Cell<usize>> {
        Rc::default()
    }

    fn try_claim<'access>(
        &self,
        access: DatagramClaimAccess<'access, LocalDatagram>,
        _: &DatagramRouteMatchInfo,
        state: Rc<Cell<usize>>,
    ) -> DatagramClaimOutcome<'access, LocalDatagram, Rc<Cell<usize>>> {
        state.set(state.get() + 1);
        DatagramClaimOutcome::Unclaimed { access, state }
    }

    fn deliver(&self, delivery: DatagramDelivery<LocalDatagram, Self>) {
        self.deliveries.borrow_mut().push(delivery);
    }
}

/// What a local receiver received for a newly published Initial entry.
struct LocalAccepted {
    registration: RouteEntryRegistration<LocalTarget>,
    datagram: ExclusiveDatagram<LocalDatagram>,
    deliverer: Arc<LocalDeliverer>,
}

struct LocalReceiver {
    deliverer: Arc<LocalDeliverer>,
    accepted: Rc<RefCell<Vec<LocalAccepted>>>,
}

impl InitialDatagramReceiver<LocalPayload, LocalLink, LocalTarget> for LocalReceiver {
    fn receive_first(
        self,
        registration: RouteEntryRegistration<LocalTarget>,
        datagram: ExclusiveDatagram<LocalDatagram>,
        _initial: RecognizedInitial,
    ) {
        self.accepted.borrow_mut().push(LocalAccepted {
            registration,
            datagram,
            deliverer: self.deliverer,
        });
    }
}

struct LocalFactory {
    accepted: Rc<RefCell<Vec<LocalAccepted>>>,
}

impl InitialReceiverFactory<LocalPayload, LocalLink, LocalTarget> for LocalFactory {
    type Receiver = LocalReceiver;

    fn admits(&self, _: &RecognizedInitial, _: &LocalDatagram) -> bool {
        true
    }

    fn prepare(
        &self,
        _: &RecognizedInitial,
    ) -> Option<PreparedReceiver<LocalTarget, LocalReceiver>> {
        let deliverer = LocalDeliverer::new();
        let receiver = LocalReceiver {
            deliverer: Arc::clone(&deliverer),
            accepted: Rc::clone(&self.accepted),
        };
        Some(PreparedReceiver::new(
            deliverer as Arc<LocalTarget>,
            receiver,
        ))
    }
}

#[test]
#[expect(
    clippy::arc_with_non_send_sync,
    reason = "a routing domain used on one thread is the point"
)]
fn local_routing_domain_accepts_new_initials_without_send() {
    let queue = Rc::new(RefCell::new(Vec::new()));
    let accepted = Rc::new(RefCell::new(Vec::new()));
    let index = RouteIndex::<LocalTarget>::new();
    let router = DatagramRouter::new(Arc::clone(&index), lengths(&[8])).with_initial_acceptance(
        InitialAcceptance::new(
            LocalFactory {
                accepted: Rc::clone(&accepted),
            },
            Arc::new(LocalReflow {
                queue: Rc::clone(&queue),
            }),
        ),
    );
    let existing = LocalDeliverer::new();
    let _existing = index.register(
        RouteMatcher::new(
            MatchAssociation::InitialDcid(nonempty(&cid(20))),
            PacketForms::INITIAL,
            Version::V1,
        ),
        Arc::clone(&existing) as Arc<LocalTarget>,
    );
    let link = Rc::new(link(&binding()));
    let datagram = |bytes: Vec<u8>| ReceivedDatagram::new(Rc::from(bytes), Rc::clone(&link));

    // The existing entry judges and exits; its last exit hands the work off.
    router.route(datagram(initial(&cid(20), &cid(9))));
    let Some(DatagramDelivery::Competing(candidate)) = existing.deliveries.borrow_mut().pop()
    else {
        panic!("an acceptable Initial competes");
    };
    let DatagramClaimAttempt::Unclaimed(candidate) = ready(candidate.try_exclusive()) else {
        panic!("the existing entry leaves the datagram");
    };
    assert_eq!(candidate.initialized_state().unwrap().get(), 1);
    assert!(queue.borrow().is_empty());
    drop(candidate);
    assert_eq!(queue.borrow().len(), 1);

    // Resuming outside the exit publishes a local receiver.
    let work = queue.borrow_mut().pop().unwrap();
    router.resume(work);
    let [first] = <[_; 1]>::try_from(accepted.take()).ok().unwrap();
    assert_eq!(
        first.registration.entry().matcher().association(),
        &MatchAssociation::InitialDcid(nonempty(&cid(20)))
    );
    assert_eq!(
        &first.datagram.get().payload()[..],
        &initial(&cid(20), &cid(9))[..]
    );

    // The next Initial reaches both entries in one round.
    router.route(datagram(initial(&cid(20), &cid(10))));
    assert_eq!(existing.deliveries.borrow().len(), 1);
    assert_eq!(first.deliverer.deliveries.borrow().len(), 1);
}

#[test]
fn routing_domain_shared_between_threads_is_send() {
    fn send<T: Send>() {}
    fn send_sync<T: ?Sized + Send + Sync>() {}

    send_sync::<Router>();
    send_sync::<Index>();
    send_sync::<Target>();
    send::<Handoff>();
    send::<Work>();
    send::<RouteEntryRegistration<Target>>();
    send::<DatagramClaimCandidate<Datagram, Recorder>>();
    send::<DatagramClaimFuture<Datagram, Recorder>>();
    send::<DatagramDelivery<Datagram, Recorder>>();
}
