//! UDP links between sockets on the loopback interfaces.

#![cfg(target_os = "linux")]

use core::{
    future::Future,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
    time::Duration,
};

use bytes::Bytes;
use sakuya_clock_tokio::TokioClock;
use sakuya_link::{
    AcceptingLinkBinding, ConnectingLinkBinding, EcnCodepoint, EcnMarking, Link, LinkBinding,
    OutgoingDatagram,
};
use sakuya_udp_tokio::{SendDatagramError, UdpBinding, UdpBindingConfig, UdpLink};

type Binding = UdpBinding<TokioClock>;

fn run(test: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime builds")
        .block_on(test);
}

fn bind(address: SocketAddr) -> Binding {
    bind_with(UdpBindingConfig::new(address))
}

fn bind_with(config: UdpBindingConfig) -> Binding {
    UdpBinding::bind(config, TokioClock).expect("a loopback socket binds")
}

fn v4() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

/// The binding's address as a peer reaches it.
fn reach(binding: &Binding) -> SocketAddr {
    binding.local_address()
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("finishes in time")
}

fn datagram(payload: &'static [u8], ecn: EcnMarking) -> OutgoingDatagram {
    OutgoingDatagram {
        payload: Bytes::from_static(payload),
        ecn,
    }
}

/// Sends every datagram of `batch`, in as many sends as the link takes.
async fn send_all(link: &UdpLink<TokioClock>, batch: &[OutgoingDatagram]) {
    let mut sent = 0;
    while sent < batch.len() {
        let accepted = within(link.send(&batch[sent..]))
            .await
            .expect("the datagram is sent");
        sent += accepted.count.get();
    }
}

async fn receive(link: &UdpLink<TokioClock>) -> (Vec<u8>, Option<EcnCodepoint>) {
    let datagram = within(link.recv()).await.expect("the link has not ended");
    assert_eq!(datagram.link().id(), link.id());
    let ecn = datagram.arrival().ecn();
    (datagram.into_parts().0.to_vec(), ecn)
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn a_new_peer_makes_a_link_whose_first_receive_delivers_its_datagram() {
    run(async {
        let server = bind(v4());
        let client = bind(v4());
        let to_server = within(client.connect(reach(&server))).await.unwrap();
        send_all(&to_server, &[datagram(b"hello", EcnMarking::Ect0)]).await;

        let to_client = within(server.accept()).await.unwrap();
        assert_eq!(to_client.id().peer, client.local_address());
        assert_eq!(to_client.id().local.address(), server.local_address());
        assert_eq!(&to_client.id().binding, server.id());
        assert_eq!(
            receive(&to_client).await,
            (b"hello".to_vec(), Some(EcnCodepoint::Ect0))
        );

        // And back, unmarked, and empty.
        send_all(&to_client, &[datagram(b"hi", EcnMarking::NotEct)]).await;
        assert_eq!(
            receive(&to_server).await,
            (b"hi".to_vec(), Some(EcnCodepoint::NotEct))
        );
        send_all(&to_client, &[datagram(b"", EcnMarking::NotEct)]).await;
        assert_eq!(receive(&to_server).await.0, b"");
    });
}

#[test]
fn connect_gives_the_live_link_of_the_peer() {
    run(async {
        let server = bind(v4());
        let client = bind(v4());
        let to_server = within(client.connect(reach(&server))).await.unwrap();
        send_all(&to_server, &[datagram(b"a", EcnMarking::NotEct)]).await;
        let accepted = within(server.accept()).await.unwrap();
        let connected = within(server.connect(client.local_address()))
            .await
            .unwrap();
        assert_eq!(accepted.id(), connected.id());
        assert_eq!(
            to_server.id(),
            within(client.connect(reach(&server))).await.unwrap().id()
        );
    });
}

#[test]
fn each_peer_receives_its_own_datagrams_whoever_reads_the_socket() {
    run(async {
        let server = bind(v4());
        let first = bind(v4());
        let second = bind(v4());
        let from_first = within(first.connect(reach(&server))).await.unwrap();
        let from_second = within(second.connect(reach(&server))).await.unwrap();
        send_all(&from_first, &[datagram(b"1a", EcnMarking::NotEct)]).await;
        let to_first = within(server.accept()).await.unwrap();
        send_all(&from_second, &[datagram(b"2a", EcnMarking::NotEct)]).await;
        let to_second = within(server.accept()).await.unwrap();

        // The second link's receive reads the first one's datagram on the
        // way to its own.
        send_all(&from_first, &[datagram(b"1b", EcnMarking::NotEct)]).await;
        send_all(&from_second, &[datagram(b"2b", EcnMarking::NotEct)]).await;
        assert_eq!(receive(&to_second).await.0, b"2a");
        assert_eq!(receive(&to_second).await.0, b"2b");
        assert_eq!(receive(&to_first).await.0, b"1a");
        assert_eq!(receive(&to_first).await.0, b"1b");
    });
}

#[test]
fn a_dropped_receive_loses_no_datagram() {
    run(async {
        let server = bind(v4());
        let client = bind(v4());
        let to_server = within(client.connect(reach(&server))).await.unwrap();
        let to_client = within(server.connect(client.local_address()))
            .await
            .unwrap();

        let mut waiting = Box::pin(to_client.recv());
        assert!(poll_once(waiting.as_mut()).is_pending());
        drop(waiting);
        send_all(&to_server, &[datagram(b"kept", EcnMarking::NotEct)]).await;
        assert_eq!(receive(&to_client).await.0, b"kept");
    });
}

#[test]
fn a_dropped_reader_hands_the_socket_over() {
    run(async {
        let server = bind(v4());
        let first = bind(v4());
        let second = bind(v4());
        let to_first = within(server.connect(first.local_address())).await.unwrap();
        let to_second = within(server.connect(second.local_address()))
            .await
            .unwrap();
        let from_second = within(second.connect(reach(&server))).await.unwrap();

        // The first receive polled takes the reader's turn; the second waits
        // for its own datagrams.
        let mut reader = Box::pin(to_first.recv());
        assert!(poll_once(reader.as_mut()).is_pending());
        let mut waiting = pin!(to_second.recv());
        assert!(poll_once(waiting.as_mut()).is_pending());
        drop(reader);

        send_all(
            &from_second,
            &[datagram(b"handed over", EcnMarking::NotEct)],
        )
        .await;
        let datagram = within(waiting).await.unwrap();
        assert_eq!(datagram.into_parts().0.as_ref(), b"handed over");
    });
}

#[test]
fn a_batch_of_equal_datagrams_arrives_as_its_datagrams() {
    run(async {
        let server = bind(v4());
        let client = bind(v4());
        let to_server = within(client.connect(reach(&server))).await.unwrap();
        let to_client = within(server.connect(client.local_address()))
            .await
            .unwrap();
        let batch = [
            datagram(&[1; 100], EcnMarking::Ect1),
            datagram(&[2; 100], EcnMarking::Ect1),
            datagram(&[3; 100], EcnMarking::Ect1),
            datagram(&[4; 40], EcnMarking::Ect1),
            datagram(&[5; 100], EcnMarking::Ect1),
        ];
        // GSO takes the datagrams of the first one's size, and the shorter
        // one that ends them.
        let accepted = within(to_server.send(&batch)).await.unwrap();
        assert_eq!(accepted.count.get(), 4);
        send_all(&to_server, &batch[4..]).await;
        for sent in &batch {
            let (payload, ecn) = receive(&to_client).await;
            assert_eq!(payload, sent.payload);
            assert_eq!(ecn, Some(EcnCodepoint::Ect1));
        }
    });
}

#[test]
fn a_link_whose_clones_are_all_dropped_is_closed() {
    run(async {
        let server = bind(v4());
        let client = bind(v4());
        let to_server = within(client.connect(reach(&server))).await.unwrap();
        send_all(&to_server, &[datagram(b"one", EcnMarking::NotEct)]).await;
        let first = within(server.accept()).await.unwrap();
        let first_id = first.id().clone();
        drop(first);

        send_all(&to_server, &[datagram(b"two", EcnMarking::NotEct)]).await;
        let second = within(server.accept()).await.unwrap();
        assert_ne!(second.id(), &first_id);
        assert_eq!(second.id().peer, first_id.peer);
        assert_eq!(receive(&second).await.0, b"two");
    });
}

#[test]
fn a_binding_that_takes_no_new_peers_reaches_only_those_it_connects_to() {
    run(async {
        let mut config = UdpBindingConfig::new(v4());
        config.accept_new_peers = false;
        let server = bind_with(config);
        let stranger = bind(v4());
        let known = bind(v4());
        let from_stranger = within(stranger.connect(reach(&server))).await.unwrap();
        let from_known = within(known.connect(reach(&server))).await.unwrap();
        let to_known = within(server.connect(known.local_address())).await.unwrap();

        send_all(&from_stranger, &[datagram(b"dropped", EcnMarking::NotEct)]).await;
        send_all(&from_known, &[datagram(b"kept", EcnMarking::NotEct)]).await;
        assert_eq!(receive(&to_known).await.0, b"kept");
        assert!(poll_once(pin!(server.accept())).is_pending());
    });
}

#[test]
fn a_dual_stack_socket_gives_ipv4_peers_as_ipv4() {
    run(async {
        let server = bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)));
        let client = bind(v4());
        let port = server.local_address().port();
        let to_server = within(client.connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port))))
            .await
            .unwrap();
        send_all(&to_server, &[datagram(b"v4", EcnMarking::Ect0)]).await;

        let to_client = within(server.accept()).await.unwrap();
        assert_eq!(to_client.id().peer, client.local_address());
        assert_eq!(
            to_client.id().local.address(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        );
        assert_eq!(
            receive(&to_client).await,
            (b"v4".to_vec(), Some(EcnCodepoint::Ect0))
        );
        send_all(&to_client, &[datagram(b"back", EcnMarking::NotEct)]).await;
        assert_eq!(receive(&to_server).await.0, b"back");
    });
}

#[test]
fn ipv6_links_carry_datagrams_and_their_ecn() {
    run(async {
        let loopback = SocketAddr::from((Ipv6Addr::LOCALHOST, 0));
        let server = bind(loopback);
        let client = bind(loopback);
        let to_server = within(client.connect(reach(&server))).await.unwrap();
        send_all(&to_server, &[datagram(b"v6", EcnMarking::Ect1)]).await;
        let to_client = within(server.accept()).await.unwrap();
        assert_eq!(
            receive(&to_client).await,
            (b"v6".to_vec(), Some(EcnCodepoint::Ect1))
        );
        assert_eq!(to_client.max_datagram_size().unwrap(), 1452);
        assert_eq!(to_server.max_datagram_size().unwrap(), 1452);
    });
}

#[test]
fn the_datagram_size_limit_follows_the_interface_mtu_and_the_ip_version() {
    run(async {
        let mut config = UdpBindingConfig::new(v4());
        config.interface_mtu = 9000;
        let server = bind_with(config);
        let link = within(server.connect(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))))
            .await
            .unwrap();
        assert_eq!(link.max_datagram_size().unwrap(), 9000 - 28);
    });
}

#[test]
fn the_clones_of_a_link_share_its_datagram_size_conclusion() {
    run(async {
        let server = bind(v4());
        let link = within(server.connect(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))))
            .await
            .unwrap();
        let clone = link.clone();
        assert_eq!(clone.datagram_size_conclusion(), 1200);
        link.record_datagram_size_confirmed(1400);
        assert_eq!(clone.datagram_size_conclusion(), 1400);
        clone.record_datagram_size_lowered(900);
        assert_eq!(link.datagram_size_conclusion(), 1200);
        assert!(poll_once(pin!(link.ended())).is_pending());
    });
}

#[test]
fn a_socket_on_the_unspecified_address_connects_from_the_address_that_routes_to_the_peer() {
    run(async {
        let unspecified = bind(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)));
        let peer = bind(v4());
        let link = within(unspecified.connect(peer.local_address()))
            .await
            .unwrap();
        let port = unspecified.local_address().port();
        assert_eq!(
            link.id().local.address(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        );
        send_all(&link, &[datagram(b"from loopback", EcnMarking::NotEct)]).await;
        let back = within(peer.accept()).await.unwrap();
        assert_eq!(
            back.id().peer,
            SocketAddr::from((Ipv4Addr::LOCALHOST, port))
        );
        assert_eq!(receive(&back).await.0, b"from loopback");

        // The reply arrives at the same local address, so on the same link.
        send_all(&back, &[datagram(b"reply", EcnMarking::NotEct)]).await;
        assert_eq!(receive(&link).await.0, b"reply");
    });
}

#[test]
fn the_links_not_yet_accepted_hold_no_more_datagrams_than_their_budget() {
    run(async {
        let mut config = UdpBindingConfig::new(v4());
        config.max_unaccepted_datagrams = 2;
        let server = bind_with(config);
        let first = bind(v4());
        let second = bind(v4());
        let known = bind(v4());
        let from_first = within(first.connect(reach(&server))).await.unwrap();
        let from_second = within(second.connect(reach(&server))).await.unwrap();
        let from_known = within(known.connect(reach(&server))).await.unwrap();
        let to_known = within(server.connect(known.local_address())).await.unwrap();

        let two = [
            datagram(b"one", EcnMarking::NotEct),
            datagram(b"two", EcnMarking::NotEct),
        ];
        send_all(&from_first, &two).await;
        send_all(&from_second, &[datagram(b"dropped", EcnMarking::NotEct)]).await;
        send_all(&from_known, &[datagram(b"known", EcnMarking::NotEct)]).await;
        // The connected link reads the socket for the strangers as well.
        assert_eq!(receive(&to_known).await.0, b"known");

        let to_first = within(server.accept()).await.unwrap();
        assert_eq!(to_first.id().peer, first.local_address());
        assert_eq!(receive(&to_first).await.0, b"one");
        assert_eq!(receive(&to_first).await.0, b"two");

        // Accepting the first link freed the budget.
        send_all(&from_second, &[datagram(b"later", EcnMarking::NotEct)]).await;
        let to_second = within(server.accept()).await.unwrap();
        assert_eq!(to_second.id().peer, second.local_address());
        assert_eq!(receive(&to_second).await.0, b"later");
    });
}

#[test]
fn a_datagram_the_kernel_refuses_for_its_peer_leaves_gso_and_ecn_on() {
    run(async {
        let server = bind(v4());
        let client = bind(v4());
        let batch = [
            datagram(b"same", EcnMarking::Ect0),
            datagram(b"size", EcnMarking::Ect0),
        ];

        // The kernel refuses to send to port 0 with EINVAL, as it refuses
        // GSO or ECN it cannot do.
        let nowhere = within(client.connect(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))))
            .await
            .unwrap();
        let refused = within(nowhere.send(&batch)).await;
        assert!(
            matches!(refused, Err(SendDatagramError::Refused { .. })),
            "{refused:?}"
        );
        assert!(nowhere.may_mark_ecn());

        let to_server = within(client.connect(reach(&server))).await.unwrap();
        let accepted = within(to_server.send(&batch))
            .await
            .expect("the batch is sent");
        assert_eq!(accepted.count.get(), 2, "one GSO send carries both");
        let to_client = within(server.accept()).await.unwrap();
        assert_eq!(
            receive(&to_client).await,
            (b"same".to_vec(), Some(EcnCodepoint::Ect0))
        );
        assert_eq!(
            receive(&to_client).await,
            (b"size".to_vec(), Some(EcnCodepoint::Ect0))
        );
    });
}
