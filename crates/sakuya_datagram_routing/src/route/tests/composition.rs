//! The whole chain: classification, stateless reset detection, freezing,
//! competition, the last exit, reflow, the recheck and the handover to a
//! queue-style connection receiver, driven by plain calls without a runtime

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sakuya_link::LinkId;
use sakuya_wire::header::v1::LongPacketType;
use sakuya_wire::version::Version;

use super::support::{
    Datagram, Handoff, Target, Work, binding, cid, datagram, initial, lengths, link, long,
    nonempty, short,
};
use crate::claim::candidate::DatagramClaimAttempt;
use crate::claim::deliverer::{
    DatagramClaimAccess, DatagramClaimOutcome, DatagramDeliverer, DatagramView, ExclusiveDatagram,
};
use crate::claim::delivery::DatagramDelivery;
use crate::claim::queue::{DatagramDeliveryPoster, DatagramDeliveryQueue};
use crate::claim::route_match::DatagramRouteMatchInfo;
use crate::route::acceptance::{
    InitialAcceptance, InitialDatagramReceiver, InitialReceiverFactory, PreparedReceiver,
};
use crate::route::association::{MatchAssociation, PacketForms, RouteMatcher};
use crate::route::index::{RouteEntryRegistration, RouteIndex};
use crate::route::interpretation::RecognizedInitial;
use crate::route::reset::{StatelessResetRegistration, StatelessResetTarget, StatelessResetTokens};
use crate::route::router::DatagramRouter;

type Delivery = DatagramDelivery<Datagram, ConnectionDeliverer>;

/// The deliverer of one connection: it claims every datagram while the
/// connection is open and queues what it is given.
struct ConnectionDeliverer {
    poster: DatagramDeliveryPoster<Delivery>,
}

impl DatagramDeliverer<Datagram> for ConnectionDeliverer {
    type Handoff = Handoff;
    type DelivererDatagramState = ();

    fn new_datagram_state(&self, _: DatagramView<'_>, _: &DatagramRouteMatchInfo) {}

    fn try_claim<'access>(
        &self,
        access: DatagramClaimAccess<'access, Datagram>,
        _: &DatagramRouteMatchInfo,
        state: (),
    ) -> DatagramClaimOutcome<'access, Datagram, ()> {
        if self.poster.is_closed() {
            return DatagramClaimOutcome::Unclaimed { access, state };
        }
        DatagramClaimOutcome::Claimed {
            datagram: access.into_exclusive(),
            state,
        }
    }

    fn deliver(&self, delivery: Delivery) {
        self.poster.post(delivery);
    }
}

/// The connection's reaction to a received stateless reset.
#[derive(Clone, Default)]
struct ResetFlag(Arc<AtomicBool>);

impl StatelessResetTarget for ResetFlag {
    fn stateless_reset_received(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// One accepted connection: its receive queue, its registrations and the
/// datagrams it processed.
struct Connection {
    queue: DatagramDeliveryQueue<Delivery>,
    deliverer: Arc<ConnectionDeliverer>,
    registrations: Vec<RouteEntryRegistration<Target>>,
    reset_registration: Option<StatelessResetRegistration<ResetFlag>>,
    reset: ResetFlag,
    processed: Vec<ExclusiveDatagram<Datagram>>,
}

impl Connection {
    /// Processes every queued delivery: attempts competing ones, consumes
    /// exclusive ones.
    fn poll(&mut self) {
        while let Some(delivery) = self.queue.try_recv() {
            let exclusive = match delivery {
                DatagramDelivery::Exclusive(exclusive) => exclusive,
                DatagramDelivery::Competing(candidate) => {
                    match super::support::ready(candidate.try_exclusive()) {
                        DatagramClaimAttempt::Claimed(exclusive) => exclusive,
                        DatagramClaimAttempt::Unclaimed(_)
                        | DatagramClaimAttempt::ClaimedElsewhere => {
                            continue;
                        }
                    }
                }
            };
            self.processed.push(exclusive.consume().0);
        }
    }

    fn kinds(&self) -> Vec<u8> {
        self.processed
            .iter()
            .map(|datagram| datagram.bytes()[0] & 0xf0)
            .collect()
    }
}

struct ConnectionReceiver {
    queue: DatagramDeliveryQueue<Delivery>,
    deliverer: Arc<ConnectionDeliverer>,
    connections: Arc<Mutex<Vec<Connection>>>,
}

impl InitialDatagramReceiver<Vec<u8>, LinkId, Target> for ConnectionReceiver {
    fn receive_first(
        self,
        registration: RouteEntryRegistration<Target>,
        datagram: ExclusiveDatagram<Datagram>,
        _initial: RecognizedInitial,
    ) {
        self.connections.lock().unwrap().push(Connection {
            queue: self.queue,
            deliverer: self.deliverer,
            registrations: vec![registration],
            reset_registration: None,
            reset: ResetFlag::default(),
            processed: vec![datagram],
        });
    }
}

struct Server {
    connections: Arc<Mutex<Vec<Connection>>>,
}

impl InitialReceiverFactory<Vec<u8>, LinkId, Target> for Server {
    type Receiver = ConnectionReceiver;

    fn admits(&self, _: &RecognizedInitial, datagram: &Datagram) -> bool {
        datagram.payload().len() >= 1200
    }

    fn prepare(
        &self,
        _: &RecognizedInitial,
    ) -> Option<PreparedReceiver<Target, ConnectionReceiver>> {
        let queue = DatagramDeliveryQueue::new(NonZeroUsize::new(8).unwrap()).unwrap();
        let deliverer = Arc::new(ConnectionDeliverer {
            poster: queue.poster(),
        });
        let receiver = ConnectionReceiver {
            queue,
            deliverer: Arc::clone(&deliverer),
            connections: Arc::clone(&self.connections),
        };
        Some(PreparedReceiver::new(deliverer as Arc<Target>, receiver))
    }
}

#[test]
fn datagrams_flow_from_the_link_to_connections_through_one_router() {
    let connections = Arc::new(Mutex::new(Vec::new()));
    let mut reflow = DatagramDeliveryQueue::<Work>::new(NonZeroUsize::new(8).unwrap()).unwrap();
    let resets = StatelessResetTokens::<ResetFlag>::new();
    let index = RouteIndex::<Target>::new();
    let router = DatagramRouter::new(Arc::clone(&index), lengths(&[8]))
        .with_stateless_reset(Arc::clone(&resets))
        .with_initial_acceptance(InitialAcceptance::new(
            Server {
                connections: Arc::clone(&connections),
            },
            Arc::new(reflow.poster()),
        ));
    let binding = binding();
    let link = link(&binding);

    // The link's datagram dispatcher: one route call per datagram, then the
    // outer layer resumes queued reflow work on its own stack.
    let mut dispatch = |bytes: Vec<u8>| {
        router.route(datagram(bytes, &link));
        let mut rounds = 0;
        while let Some(work) = reflow.try_recv() {
            router.resume(work);
            rounds += 1;
        }
        rounds
    };

    // A client Initial finds nobody, reflows once and creates a connection.
    assert_eq!(dispatch(initial(&cid(1), &cid(2))), 1);
    assert_eq!(connections.lock().unwrap().len(), 1);

    // Its retransmission reaches the new connection's Initial entry.
    assert_eq!(dispatch(initial(&cid(1), &cid(2))), 0);
    let mut connection = connections.lock().unwrap().pop().unwrap();
    connection.poll();
    assert_eq!(connection.processed.len(), 2);

    // The connection issues a connection ID and a reset token.
    connection.registrations.push(index.register(
        RouteMatcher::new(
            MatchAssociation::LocalCid(nonempty(&cid(3))),
            PacketForms::HANDSHAKE | PacketForms::SHORT,
            Version::V1,
        ),
        Arc::clone(&connection.deliverer) as Arc<Target>,
    ));
    let mut reset_packet = short(&cid(4), 24);
    reset_packet.extend([0x77; 16]);
    let token: [u8; 16] = reset_packet[reset_packet.len() - 16..].try_into().unwrap();
    connection.reset_registration = Some(resets.register(token, connection.reset.clone()));

    assert_eq!(
        dispatch(long(LongPacketType::Handshake, &cid(3), &[], 40)),
        0
    );
    assert_eq!(dispatch(short(&cid(3), 30)), 0);
    connection.poll();
    assert_eq!(connection.kinds(), [0xc0, 0xc0, 0xe0, 0x40]);

    // A stateless reset reaches the connection's target, not its queue.
    assert_eq!(dispatch(reset_packet), 0);
    connection.poll();
    assert_eq!(connection.processed.len(), 4);
    assert!(connection.reset.0.load(Ordering::SeqCst));

    // Closing the connection revokes its entries; a new Initial for the same
    // connection ID creates a new connection.
    drop(connection);
    assert_eq!(dispatch(initial(&cid(1), &cid(5))), 1);
    assert_eq!(connections.lock().unwrap().len(), 1);
}
