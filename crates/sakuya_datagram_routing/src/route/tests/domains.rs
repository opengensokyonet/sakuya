//! Routing domains used on one thread and shared between threads

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use super::support::{Local, TestLink, TestLinkId, arrival};
use sakuya_link::ReceivedDatagram;
use sakuya_wire::version::Version;

use super::support::{
    Datagram, Handoff, Index, Router, Target, Work, cid, initial, lengths, link, local_end,
    nonempty, ready,
};
use crate::claim::candidate::{DatagramClaimAccess, DatagramClaimOutcome};
use crate::claim::candidate::{DatagramClaimAttempt, DatagramClaimCandidate, DatagramClaimFuture};
use crate::claim::deliverer::DatagramDeliverer;
use crate::claim::delivery::DatagramDelivery;
use crate::claim::delivery::ExclusiveDatagram;
use crate::claim::erased::ErasedDatagramDeliverer;
use crate::claim::route_match::DatagramRouteMatchInfo;
use crate::route::acceptance::{
    InitialAcceptance, InitialDatagramReceiver, InitialReceiverFactory, PreparedReceiver,
    ReflowHandoff, ReflowProvider, UnclaimedWork,
};
use crate::route::association::{MatchAssociation, PacketForms, RouteMatcher};
use crate::route::index::{RouteEntryRegistration, RouteIndex};
use crate::route::interpretation::RecognizedInitial;
use crate::route::router::DatagramRouter;

type LocalPayload = Rc<[u8]>;
type LocalLink = TestLink<Rc<TestLinkId>>;
type LocalDatagram = ReceivedDatagram<LocalPayload, LocalLink>;
type LocalWork = UnclaimedWork<LocalPayload, LocalLink>;
type LocalHandoff = ReflowHandoff<LocalReflow, Local>;
type LocalTarget = dyn ErasedDatagramDeliverer<LocalDatagram, Local, LocalHandoff>;

/// A reflow provider that keeps the work in a queue shared through `Rc`.
struct LocalReflow {
    queue: Rc<RefCell<Vec<LocalWork>>>,
}

impl ReflowProvider<LocalPayload, LocalLink> for LocalReflow {
    fn hand_off(&self, work: LocalWork) {
        self.queue.borrow_mut().push(work);
    }
}

/// A deliverer whose deliveries stay on this thread.
struct LocalDeliverer {
    deliveries: RefCell<Vec<DatagramDelivery<LocalDatagram, Local, LocalHandoff>>>,
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

impl DatagramDeliverer<LocalDatagram, Local> for LocalDeliverer {
    type Handoff = LocalHandoff;

    fn deliver(&self, delivery: DatagramDelivery<LocalDatagram, Local, LocalHandoff>) {
        self.deliveries.borrow_mut().push(delivery);
    }
}

/// What a local receiver received for a newly published Initial entry.
struct LocalAccepted {
    registration: RouteEntryRegistration<LocalTarget, Local>,
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
        registration: RouteEntryRegistration<LocalTarget, Local>,
        datagram: ExclusiveDatagram<LocalDatagram>,
        _initial: RecognizedInitial<Local>,
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

    fn admits(&self, _: &RecognizedInitial<Local>, _: &LocalDatagram) -> bool {
        true
    }

    fn prepare(
        &self,
        _: &RecognizedInitial<Local>,
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
    let index = RouteIndex::<LocalTarget, Local>::new();
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
    let link = link(&local_end()).into_rc();
    let datagram = |bytes: Vec<u8>| ReceivedDatagram::new(Rc::from(bytes), arrival(&link));

    // The existing entry judges and exits; its last exit hands the work off.
    router.route(datagram(initial(&cid(20), &cid(9))));
    let Some(DatagramDelivery::Competing(candidate)) = existing.deliveries.borrow_mut().pop()
    else {
        panic!("an acceptable Initial competes");
    };
    // The judgment keeps its own local state.
    let judged = Rc::new(Cell::new(0));
    let attempt = candidate.try_exclusive(|access, _route| {
        judged.set(judged.get() + 1);
        DatagramClaimOutcome::<(), (), _>::Unclaimed(access)
    });
    let DatagramClaimAttempt::Unclaimed(candidate) = ready(attempt) else {
        panic!("the existing entry leaves the datagram");
    };
    assert_eq!(judged.get(), 1);
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
    type Judgment = for<'access, 'route> fn(
        DatagramClaimAccess<'access, Datagram>,
        &'route DatagramRouteMatchInfo<Local>,
    ) -> DatagramClaimOutcome<'access, (), (), Datagram>;

    send_sync::<Router>();
    send_sync::<Index>();
    send_sync::<Target>();
    send::<Handoff>();
    send::<Work>();
    send::<RouteEntryRegistration<Target, Local>>();
    send::<DatagramClaimCandidate<Datagram, Local, Handoff>>();
    send::<DatagramClaimFuture<Datagram, Local, Handoff, (), (), Judgment>>();
    send::<DatagramDelivery<Datagram, Local, Handoff>>();
}
