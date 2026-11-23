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
        let half = within("the client's Initial arrives", arrived).await;
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
        let half = within("the client's Initial arrives", arrived).await;
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
