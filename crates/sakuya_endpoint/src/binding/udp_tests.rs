//! A binding driver over UDP sockets on the loopback interface.
//!
//! The driver's constructors belong to the crate, so this runs among the
//! unit tests rather than under `tests/`.

use core::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    task::{Context, Poll},
    time::Duration,
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use bytes::Bytes;
use frunk_core::Coprod;
use futures_util::task::AtomicWaker;
use sakuya_clock_tokio::TokioClock;
use sakuya_link::{ConnectingLinkBinding, EcnMarking, Link, LinkBinding, OutgoingDatagram};
use sakuya_udp_tokio::{UdpBinding, UdpBindingConfig, UdpLink};
use tokio::sync::mpsc;

use super::{
    BindingDriver, BindingShared, EndpointDatagram,
    driving::{Accepting, RouteDatagram, StopSignal},
};

type Sum = Coprod![UdpLink<TokioClock>];

/// How long any step may take.
const DEADLINE: Duration = Duration::from_secs(5);

/// Routing that hands every datagram to the test.
#[derive(Clone)]
struct ToTest(mpsc::UnboundedSender<EndpointDatagram<Sum>>);

impl RouteDatagram<EndpointDatagram<Sum>> for ToTest {
    fn route(&self, datagram: EndpointDatagram<Sum>) {
        // The test may have stopped listening; then the datagram is dropped.
        let _ = self.0.send(datagram);
    }
}

/// A stop signal the test raises.
#[derive(Clone, Default)]
struct Stop(Arc<(AtomicBool, AtomicWaker)>);

impl Stop {
    fn raise(&self) {
        self.0.0.store(true, Ordering::SeqCst);
        self.0.1.wake();
    }
}

impl StopSignal for Stop {
    fn poll_stop(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.0.1.register(cx.waker());
        if self.0.0.load(Ordering::SeqCst) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

fn run(test: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime builds")
        .block_on(test);
}

fn bind() -> UdpBinding<TokioClock> {
    UdpBinding::bind(
        UdpBindingConfig::new(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        TokioClock,
    )
    .expect("a loopback socket binds")
}

async fn within<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .unwrap_or_else(|_| panic!("{what} within {DEADLINE:?}"))
}

async fn send(link: &UdpLink<TokioClock>, payload: &'static [u8]) {
    let batch = [OutgoingDatagram {
        payload: Bytes::from_static(payload),
        ecn: EcnMarking::NotEct,
    }];
    within("the datagram is sent", link.send(&batch))
        .await
        .expect("the datagram is sent");
}

#[test]
fn a_driver_accepts_routes_and_lets_unused_links_go() {
    run(async {
        let server = bind();
        let server_address = server.local_address();
        let server_id = server.id().clone();
        let client = bind();
        let client_address = client.local_address();
        let to_server = within("the client connects", client.connect(server_address))
            .await
            .expect("the client connects");

        let shared = Arc::new(BindingShared::new(server));
        let (routed, mut arrivals) = mpsc::unbounded_channel();
        let stop = Stop::default();
        let driver = BindingDriver::<_, Sum, _, _, Accepting>::new(
            Arc::clone(&shared),
            ToTest(routed),
            stop.clone(),
        );
        let driver = tokio::spawn(driver);

        send(&to_server, b"hello").await;
        let datagram = within("the datagram is routed", arrivals.recv())
            .await
            .expect("the driver routes");
        assert_eq!(datagram.payload().as_ref(), b"hello");
        let first = datagram.link().id().clone();
        assert_eq!(first.peer.get::<SocketAddr, _>(), Some(&client_address));
        assert_eq!(first.binding, server_id);
        assert_eq!(datagram.link().users(), 3);

        // Routing lets the datagram go; the driver lets the link go. That
        // is the completion under test, so it is observed until a deadline.
        drop(datagram);
        let start = tokio::time::Instant::now();
        while shared.dispatched_count() != 0 {
            assert!(
                start.elapsed() < DEADLINE,
                "the unused link is still dispatched after {DEADLINE:?}: {} dispatched",
                shared.dispatched_count()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // The link was closed: the next datagram from the client makes a
        // new one.
        send(&to_server, b"again").await;
        let datagram = within("the second datagram is routed", arrivals.recv())
            .await
            .expect("the driver routes");
        assert_eq!(datagram.payload().as_ref(), b"again");
        assert_ne!(*datagram.link().id(), first);
        assert_eq!(
            datagram.link().id().peer.get::<SocketAddr, _>(),
            Some(&client_address)
        );
        drop(datagram);

        stop.raise();
        within("the driver ends", driver)
            .await
            .expect("the driver does not panic");
        assert_eq!(shared.dispatched_count(), 0);
    });
}
