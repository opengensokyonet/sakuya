//! Which datagrams belong to the attempt of an incoming connection, on the
//! loopback interface.

use super::*;

/// How long a datagram that is not taken is given to show that it is not.
const QUIET: Duration = Duration::from_millis(300);

/// Polls `future` for [`QUIET`], and panics if it completes.
async fn quiet<T>(what: &str, future: impl Future<Output = T>) {
    if tokio::time::timeout(QUIET, future).await.is_ok() {
        panic!("{what} within {QUIET:?}");
    }
}

#[test]
fn without_a_receiver_an_initial_from_another_link_does_not_complete_the_wait() {
    run(async {
        let server = server();
        let mut incoming = server.endpoint.incoming();
        let victim = bind();
        let victim = within("a link to the server", victim.connect(server.address))
            .await
            .unwrap();
        let dcid = [0x0d; 8];
        let scid = [0x5c; 4];
        send_on(&victim, long_packet(false, &dcid, &scid, 100)).await;
        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        assert!(half.facts().born_from_zero_rtt);
        // No receiver is left, so no datagram makes a new incoming
        // connection, and this one is given each datagram for its
        // destination connection ID.
        drop(incoming);
        let mut arrived = pin!(half.initial_arrived());

        // The same destination and source connection IDs from another link
        // are not this attempt's: they do not join its first flight.
        let other = bind();
        let other = within("another link to the server", other.connect(server.address))
            .await
            .unwrap();
        send_on(&other, long_packet(false, &dcid, &scid, 100)).await;
        send_on(&other, long_packet(true, &dcid, &scid, 1200)).await;
        quiet(
            "the Initial from another link completes the wait",
            arrived.as_mut(),
        )
        .await;

        send_on(&victim, long_packet(true, &dcid, &scid, 1200)).await;
        let half = within("the client's Initial arrives", arrived)
            .await
            .unwrap();
        assert_eq!(half.facts().token, ReturnedToken::Absent);
    });
}

#[test]
fn more_zero_rtt_of_the_attempt_makes_no_other_incoming_connection() {
    run(async {
        let server = server();
        let mut incoming = server.endpoint.incoming();
        let peer = bind();
        let link = within("a link to the server", peer.connect(server.address))
            .await
            .unwrap();
        let dcid = [0x0d; 8];
        let scid = [0x5c; 4];
        send_on(&link, long_packet(false, &dcid, &scid, 100)).await;
        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        let mut arrived = pin!(half.initial_arrived());

        // More 0-RTT of the same attempt than the first flight takes: each
        // is claimed by this incoming connection, and none makes another.
        for _ in 0..20 {
            send_on(&link, long_packet(false, &dcid, &scid, 100)).await;
        }
        quiet(
            "more 0-RTT makes another incoming connection",
            futures_util::future::select(arrived.as_mut(), incoming.next()),
        )
        .await;

        send_on(&link, long_packet(true, &dcid, &scid, 1200)).await;
        let half = within("the client's Initial arrives", arrived)
            .await
            .unwrap();
        assert!(half.facts().born_from_zero_rtt);
        assert_eq!(
            server
                .endpoint
                .dropped_input_counts()
                .zero_rtt_incoming_limit_reached,
            0
        );
    });
}

#[test]
fn without_the_reflow_driver_the_wait_for_an_initial_fails() {
    run(async {
        let server = server();
        let mut incoming = server.endpoint.incoming();
        let peer = bind();
        let link = within("a link to the server", peer.connect(server.address))
            .await
            .unwrap();
        let scid = [0x5c; 4];
        let mut halves = Vec::new();
        for dcid in [[0x0a; 8], [0x0b; 8], [0x0c; 8], [0x0d; 8]] {
            send_on(&link, long_packet(false, &dcid, &scid, 100)).await;
            let Some(Incoming::Terminable(half)) =
                within("an incoming connection", incoming.next()).await
            else {
                panic!("the server endpoint ends before a connection comes");
            };
            halves.push(half);
        }
        let reading = halves.pop().unwrap();
        let late = halves.pop().unwrap();
        let waits: Vec<_> = halves
            .into_iter()
            .map(|half| tokio::task::spawn_local(half.initial_arrived()))
            .collect();
        tokio::task::yield_now().await;
        let (reflow, _driver) = server.drivers;
        reflow.abort();
        assert!(reflow.await.unwrap_err().is_cancelled());

        // Each wait ends at once, without an Initial, and gives the incoming
        // connection back.
        for wait in waits {
            let wait = within("the wait ends", wait).await.unwrap();
            let error = wait.unwrap_err();
            assert!(error.half.facts().born_from_zero_rtt);
        }
        // So does a wait that starts once the driver is gone.
        let error = within("the wait ends", late.initial_arrived())
            .await
            .unwrap_err();
        assert!(error.half.facts().born_from_zero_rtt);
        // Reading the ClientHello waits for the Initial first, and fails
        // the same way.
        let error = within("the reading ends", reading.read_client_hello())
            .await
            .unwrap_err();
        let ReadClientHelloError::InitialCannotArrive { half, .. } = error else {
            panic!("not for want of an Initial: {error:?}");
        };
        assert!(half.facts().born_from_zero_rtt);
    });
}

#[test]
fn the_rest_of_a_first_flight_goes_to_its_incoming_connection_without_a_retry() {
    run(async {
        // Any waiting incoming connection makes the policy answer a further
        // new attempt without a token with a Retry.
        let mut config = server_config();
        config.retry_policy = LoadStatelessRetryPolicy::new(
            CapacityFraction::new(0, std::num::NonZeroU32::MIN).unwrap(),
        );
        let (endpoint, reflow) =
            Endpoint::<Udp, Server, NoClient>::new(endpoint_config(config, ())).unwrap();
        let socket = bind();
        let address = socket.local_address();
        let (_handle, driver) = endpoint
            .add_accepting_binding(socket, BindingDeclarations::default())
            .unwrap();
        let _driver = tokio::task::spawn_local(driver);
        let mut incoming = endpoint.incoming();
        let peer = bind();
        let link = within("a link to the server", peer.connect(address))
            .await
            .unwrap();
        let dcid = [0x0d; 8];
        let scid = [0x5c; 4];
        // A first flight in two datagrams. The reflow driver runs only once
        // both were routed, so both found no incoming connection.
        send_on(&link, long_packet(true, &dcid, &scid, 1200)).await;
        send_on(&link, long_packet(true, &dcid, &scid, 1200)).await;
        tokio::time::sleep(QUIET).await;
        let _reflow = tokio::task::spawn_local(reflow);
        let Some(Incoming::Terminable(half)) =
            within("an incoming connection", incoming.next()).await
        else {
            panic!("the server endpoint ends before a connection comes");
        };
        assert!(!half.facts().born_from_zero_rtt);

        // The second goes to the incoming connection the first made: it is
        // not answered with a Retry, and makes no other incoming connection.
        quiet("an answer to the second datagram", link.recv()).await;
        quiet("another incoming connection", incoming.next()).await;
        drop(half);
    });
}
