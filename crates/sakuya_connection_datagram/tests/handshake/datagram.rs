//! The tests of a client and a server whose compositions have the DATAGRAM
//! extension, each announcing a `max_datagram_frame_size` or not; the
//! tests send and receive through the handles of the established layers
//! the connection handles give. The module that declares this one gives
//! the parts of the composition, in its order, and the harness for them.
use std::cell::Cell;

use sakuya_connection_datagram::{
    self as datagram, DatagramConnectionArgs, DatagramOverflow, DatagramQueueBounds,
    ServerReceivedDatagram,
    application::SendDatagramError,
    owned::OwnedDatagramQueuesConfig,
    send::{DatagramSettlement, DatagramState, DatagramTicketCredential},
};
use sakuya_wire_datagram::MaxDatagramFrameSize;

use super::*;

thread_local! {
    /// The `max_datagram_frame_size` each side announces: the
    /// server's first; 0 leaves it out.
    static ANNOUNCES: Cell<[u32; 2]> = const { Cell::new([65535, 65535]) };
    /// The server's bounds of the datagrams received; the default
    /// unless a test sets them.
    static SERVER_RECEIVES: Cell<Option<DatagramQueueBounds>> = const { Cell::new(None) };
}

/// The extension's facts of the side of `role`, as the test set them.
fn datagram_args(role: Role) -> DatagramConnectionArgs<OwnedDatagramQueuesConfig> {
    let size = ANNOUNCES.with(|announces| announces.get()[index(role)]);
    DatagramConnectionArgs {
        transport_parameters: frunk_core::hlist![
            (size > 0).then(|| MaxDatagramFrameSize::new(VarInt::from_u32(size)))
        ],
        queues: OwnedDatagramQueuesConfig {
            receive: match role {
                Role::Server => SERVER_RECEIVES.with(Cell::get).unwrap_or_default(),
                Role::Client => DatagramQueueBounds::default(),
            },
            ..OwnedDatagramQueuesConfig::default()
        },
        resumed_parameters_policy: Default::default(),
    }
}

datagram_harness!();

/// Run a handshake with the server announcing `server` and the client
/// `client` as their `max_datagram_frame_size`, as [`handshake`] does.
fn run_announcing(
    server: u32,
    client: u32,
    clock: &Arc<ManualClock<TlsSynchronization>>,
    done: impl FnMut(&Run) -> bool,
) -> Run {
    ANNOUNCES.with(|announces| announces.set([server, client]));
    handshake(client_engine(clock, 1), clock, done)
}

/// The client opens a stream and sends a datagram through the same
/// handle of its established layer, and the server accepts the stream
/// and receives the datagram through the same handle of its own: the
/// capabilities find their shares wherever the parts are.
#[test]
fn one_layer_handle_opens_streams_and_exchanges_datagrams() {
    let clock = tls_clock();
    let mut client_stream = None;
    let mut server_stream = None;
    let mut read = Vec::new();
    let mut received = None;
    run_announcing(65535, 65535, &clock, |run| {
        let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
            return false;
        };
        if client_stream.is_none() {
            let (mut writer, reader) = client.try_open_bi().expect("the server grants streams");
            ready(writer.write_all_unpin(Bytes::from_static(b"hello"), ()))
                .expect("the data is written");
            writer.close().expect("the stream ends");
            client
                .datagram_writer()
                .send(Bytes::from_static(b"ping"))
                .expect("the server announced support")
                .release();
            client_stream = Some((writer, reader));
        }
        let Poll::Ready(Ok(server)) = poll_now(run.server_handle.established()) else {
            return false;
        };
        if server_stream.is_none()
            && let Poll::Ready(stream) = poll_now(server.accept_bi())
        {
            server_stream = Some(stream.expect("the client's stream is accepted"));
        }
        if let Some((_, reader)) = &mut server_stream {
            let maximum = NonZeroUsize::new(64).expect("not zero");
            while let Poll::Ready(Ok(Some(nitori_io::ChunkSegment {
                chunk,
                metadata: (),
            }))) = poll_now(reader.read_chunk_unpin(maximum))
            {
                read.extend_from_slice(&chunk);
            }
        }
        if received.is_none()
            && let Poll::Ready(datagram) = poll_now(server.recv_datagram())
        {
            let datagram: ServerReceivedDatagram = datagram.expect("the layer goes on");
            received = Some(datagram.into_bytes());
        }
        read == b"hello" && received.is_some()
    });
    assert_eq!(read, b"hello");
    assert_eq!(received, Some(Bytes::from_static(b"ping")));
    let (server, client) = (noted(Role::Server), noted(Role::Client));
    assert_eq!(
        server.record, None,
        "the server's connection is not closing"
    );
    assert_eq!(
        client.record, None,
        "the client's connection is not closing"
    );
}

/// Over the tests' in-memory link, a client completes the handshake,
/// waits to receive a datagram, and sends one whose ticket waits to be
/// settled; before the datagram is written, a poll of the client's
/// connection panics, the host catches the panic and drops the driver.
/// Both waits are woken: the receive ends with the layer's end, the
/// driver's panic, and the ticket settles as withdrawn as the layer
/// ended.
#[test]
fn a_panic_in_the_clients_poll_ends_the_waits_on_its_datagrams() {
    let clock = tls_clock();
    let mut layer = None;
    let mut receive = None;
    let mut settle = None;
    let run = run_announcing(65535, 65535, &clock, |run| {
        if run.client_panicked {
            return true;
        }
        if layer.is_some() {
            return false;
        }
        let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
            return false;
        };
        let mut receiving = Waiting::new(client.recv_datagram_owned());
        let mut ticket = client
            .datagram_writer()
            .send(Bytes::from_static(b"ping"))
            .expect("the server announced support");
        assert_eq!(ticket.state(), DatagramState::Waiting);
        let mut settling = Waiting::new(async move {
            let settlement = ticket.settled().await;
            (settlement, ticket)
        });
        assert!(receiving.poll().is_pending(), "the server sent nothing");
        assert!(settling.poll().is_pending(), "the datagram waits");
        watch::panic_client();
        (receive, settle) = (Some(receiving), Some(settling));
        layer = Some(client);
        false
    });
    assert!(run.client_panicked, "the client's poll panicked");
    let (mut receive, mut settle) = (receive.expect("waits"), settle.expect("waits"));
    assert!(receive.wakes() > 0, "the receive is woken");
    assert!(settle.wakes() > 0, "the ticket's wait is woken");
    assert!(matches!(receive.poll(), Poll::Ready(Err(error)) if panicked(error.end())));
    let Poll::Ready((settlement, ticket)) = settle.poll() else {
        panic!("the ticket settles");
    };
    assert_eq!(
        settlement,
        DatagramSettlement::Withdrawn(datagram::send::DatagramWithdrawCause::LayerEnded)
    );
    assert_eq!(
        ticket.state(),
        DatagramState::Withdrawn(datagram::send::DatagramWithdrawCause::LayerEnded)
    );
    ticket.release();
    let layer = layer.expect("the client's layer");
    assert!(matches!(
        layer.datagram_writer().send(Bytes::from_static(b"late")),
        Err(SendDatagramError::LayerEnded { source }) if panicked(source.end())
    ));
}

/// A datagram written into a packet whose acknowledgment has not come
/// when the client's poll panics settles as lost: its packet's fate is
/// never known. One more datagram sent after it moves it out of the
/// send queue first, so that it is woken from among those in flight.
#[test]
fn a_panic_in_the_clients_poll_settles_a_datagram_in_flight_as_lost() {
    let clock = tls_clock();
    let mut ticket = None;
    let mut settle = None;
    let mut later = None;
    let run = run_announcing(65535, 65535, &clock, |run| {
        if run.client_panicked {
            return true;
        }
        if settle.is_some() {
            return false;
        }
        let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
            return false;
        };
        let ticket = ticket.get_or_insert_with(|| {
            client
                .datagram_writer()
                .send(Bytes::from_static(b"ping"))
                .expect("the server announced support")
        });
        if ticket.state() != DatagramState::Sent {
            return false;
        }
        let mut ticket = core::mem::replace(
            ticket,
            client
                .datagram_writer()
                .send(Bytes::from_static(b"pong"))
                .expect("the server announced support"),
        );
        let mut settling = Waiting::new(async move {
            let settlement = ticket.settled().await;
            (settlement, ticket)
        });
        assert!(settling.poll().is_pending(), "the datagram is in flight");
        watch::panic_client();
        settle = Some(settling);
        later = Some(client);
        false
    });
    assert!(run.client_panicked, "the client's poll panicked");
    let mut settle = settle.expect("a datagram was in flight before an acknowledgment");
    assert!(settle.wakes() > 0, "the ticket's wait is woken");
    let Poll::Ready((settlement, sent)) = settle.poll() else {
        panic!("the ticket settles");
    };
    assert_eq!(settlement, DatagramSettlement::Lost);
    assert_eq!(sent.state(), DatagramState::Lost);
    sent.release();
    ticket.expect("sent").release();
    drop(later);
}

/// The server keeps two datagrams received at most and takes no new
/// one beyond them; the client sends three, which the server does not
/// read. Its layer counts the one it dropped. Once the server closes
/// the connection, its layer is gone, and what its queues received
/// stays: it reads the first datagram while the connection closes and
/// the second once the connection ended, and only then the layer's end;
/// the count of what was dropped stays all along.
#[test]
fn what_a_layer_received_is_read_after_it_ended_and_its_drops_still_count() {
    let clock = tls_clock();
    SERVER_RECEIVES.with(|bounds| {
        bounds.set(Some(DatagramQueueBounds {
            datagrams: NonZeroUsize::new(2).expect("not zero"),
            bytes: 1024,
            overflow: DatagramOverflow::RejectNew,
        }))
    });
    let mut sent = false;
    let mut server_layer = None;
    let mut closed = false;
    let mut during_close = None;
    run_announcing(65535, 65535, &clock, |run| {
        let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
            return false;
        };
        if !sent {
            let writer = client.datagram_writer();
            for payload in [&b"one"[..], b"two", b"three"] {
                writer
                    .send(Bytes::from_static(payload))
                    .expect("the server announced support")
                    .release();
            }
            sent = true;
        }
        if server_layer.is_none()
            && let Poll::Ready(layer) = poll_now(run.server_handle.established())
        {
            server_layer = Some(layer.expect("the server's handshake completed"));
        }
        let Some(server) = &server_layer else {
            return false;
        };
        if !closed {
            if server.dropped_datagrams() == 1 {
                run.server_handle.close(common::AppClose(7));
                closed = true;
            }
            return false;
        }
        if during_close.is_none() {
            assert!(
                matches!(poll_now(server.ended()), Poll::Ready(_)),
                "the layer ended with the close"
            );
            assert!(!run.server_ended, "the connection closes");
            let Poll::Ready(first) = poll_now(Datagrams::recv_datagram(server)) else {
                panic!("what was received is there at once");
            };
            let first: ServerReceivedDatagram = first.expect("received before the end");
            during_close = Some((first.into_bytes(), server.dropped_datagrams()));
        }
        true
    });
    SERVER_RECEIVES.with(|bounds| bounds.set(None));
    assert_eq!(
        during_close,
        Some((Bytes::from_static(b"one"), 1)),
        "read while the connection closes"
    );
    let server = server_layer.expect("the server's layer");
    let Poll::Ready(Ok(second)) = poll_now(Datagrams::recv_datagram(&server)) else {
        panic!("the second is read once the connection ended");
    };
    assert_eq!(second.into_bytes(), Bytes::from_static(b"two"));
    assert!(matches!(
        poll_now(Datagrams::recv_datagram(&server)),
        Poll::Ready(Err(_))
    ));
    assert_eq!(server.dropped_datagrams(), 1);
}

/// A ticket turned into one with a shared credential is cloned: the
/// clones read the same datagram, and dropping one of them does not
/// withdraw it; dropping the last withdraws a datagram not written yet.
#[test]
fn a_shared_ticket_settles_its_datagram_and_its_last_drop_withdraws() {
    let clock = tls_clock();
    let mut tickets = None;
    let mut received = Vec::new();
    let mut settled = None;
    run_announcing(65535, 65535, &clock, |run| {
        let (Poll::Ready(Ok(client)), Poll::Ready(Ok(server))) = (
            poll_now(run.client_handle.established()),
            poll_now(run.server_handle.established()),
        ) else {
            return false;
        };
        if tickets.is_none() {
            let ticket = client
                .datagram_writer()
                .send(Bytes::from_static(b"shared"))
                .expect("the server announced support")
                .into_shared::<Rc<DatagramTicketCredential>>();
            let other = ticket.clone();
            drop(ticket);
            tickets = Some(other);
            let dropped = client
                .datagram_writer()
                .send(Bytes::from_static(b"dropped"))
                .expect("the server announced support");
            assert_eq!(dropped.state(), DatagramState::Waiting);
            drop(dropped);
        }
        while let Poll::Ready(datagram) = poll_now(Datagrams::recv_datagram(&server)) {
            let datagram: ServerReceivedDatagram = datagram.expect("the layer goes on");
            received.push(datagram.into_bytes());
        }
        if let Some(ticket) = &mut tickets
            && settled.is_none()
            && let Poll::Ready(settlement) = poll_now(ticket.settled())
        {
            settled = Some(settlement);
        }
        settled.is_some()
    });
    assert_eq!(
        received,
        [Bytes::from_static(b"shared")],
        "the drop of one clone withdrew nothing, the drop of the last its datagram"
    );
    assert_eq!(settled, Some(DatagramSettlement::Acknowledged));
    tickets.expect("sent").release();
}

#[test]
fn a_client_and_a_server_exchange_datagrams() {
    let clock = tls_clock();
    let mut ticket = None;
    let mut answered = false;
    let mut answer = None;
    let mut settled = None;
    run_announcing(65535, 65535, &clock, |run| {
        let (Poll::Ready(Ok(client)), Poll::Ready(Ok(server))) = (
            poll_now(run.client_handle.established()),
            poll_now(run.server_handle.established()),
        ) else {
            return false;
        };
        if ticket.is_none() {
            let writer = Datagrams::datagram_writer(&client);
            ticket = Some(
                writer
                    .send(Bytes::from_static(b"ping"))
                    .expect("the server announced support"),
            );
        }
        if !answered && let Poll::Ready(received) = poll_now(Datagrams::recv_datagram(&server)) {
            let received: ServerReceivedDatagram = received.expect("the layer goes on");
            assert!(!received.received_zero_rtt());
            assert_eq!(received.into_bytes(), Bytes::from_static(b"ping"));
            Datagrams::datagram_writer(&server)
                .send(Bytes::from_static(b"pong"))
                .expect("the client announced support")
                .release();
            answered = true;
        }
        if answer.is_none()
            && let Poll::Ready(received) = poll_now(Datagrams::recv_datagram(&client))
        {
            answer = Some(received.expect("the layer goes on"));
        }
        if let Some(ticket) = &mut ticket
            && settled.is_none()
            && let Poll::Ready(settlement) = poll_now(ticket.settled())
        {
            settled = Some(settlement);
        }
        answer.is_some() && settled.is_some()
    });
    assert_eq!(answer, Some(Bytes::from_static(b"pong")));
    assert_eq!(settled, Some(DatagramSettlement::Acknowledged));
    let ticket = ticket.expect("sent");
    assert_eq!(ticket.state(), DatagramState::Acknowledged);
    ticket.release();
    let (server, client) = (noted(Role::Server), noted(Role::Client));
    assert_eq!(
        server.record, None,
        "the server's connection is not closing"
    );
    assert_eq!(
        client.record, None,
        "the client's connection is not closing"
    );
}

/// A server that announces no `max_datagram_frame_size` takes no
/// DATAGRAM frame: the client's writer refuses to send (RFC 9221 §3).
#[test]
fn nothing_is_sent_to_a_server_that_did_not_announce_support() {
    let clock = tls_clock();
    let mut refused = None;
    run_announcing(0, 65535, &clock, |run| {
        let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
            return false;
        };
        let writer = Datagrams::datagram_writer(&client);
        refused = Some(
            writer
                .send(Bytes::from_static(b"ping"))
                .map(|ticket| ticket.release()),
        );
        true
    });
    assert!(
        matches!(refused, Some(Err(SendDatagramError::NotSupportedByPeer))),
        "{refused:?}"
    );
}

/// A datagram over the server's limit, counted with a Length field, is
/// refused with the limit (RFC 9221 §3); one at the limit is taken.
#[test]
fn a_datagram_over_the_servers_limit_is_too_large() {
    let clock = tls_clock();
    let mut results = None;
    run_announcing(100, 65535, &clock, |run| {
        let Poll::Ready(Ok(client)) = poll_now(run.client_handle.established()) else {
            return false;
        };
        let writer = Datagrams::datagram_writer(&client);
        let limits = writer.datagram_limits();
        let at_limit = writer
            .send(Bytes::from(vec![0; 97]))
            .map(|ticket| ticket.release());
        let over = writer
            .send(Bytes::from(vec![0; 98]))
            .map(|ticket| ticket.release());
        results = Some((limits.peer, at_limit, over));
        true
    });
    let (limit, at_limit, over) = results.expect("the client's layer was built");
    assert_eq!(limit, 97);
    assert!(at_limit.is_ok(), "{at_limit:?}");
    assert!(
        matches!(over, Err(SendDatagramError::TooLarge { limit: 97 })),
        "{over:?}"
    );
}
