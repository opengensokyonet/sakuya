use std::{
    sync::atomic::{AtomicUsize, Ordering},
    task::Wake,
};

use sakuya_stream::connection::ImmediateClose;

use super::*;

/// A cell with facts `u32`, an exporter `&'static str`, and no stream set:
/// what the tests look at is the cell's own.
type TestCell = ConnectionHandleCell<(), u32, &'static str, (), (), ()>;

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counting() -> (Arc<Wakes>, Waker) {
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(Arc::clone(&wakes));
    (wakes, waker)
}

fn idle() -> CloseReason<()> {
    CloseReason::IdleTimeout
}

fn peer_close() -> CloseReason<()> {
    CloseReason::Peer(ImmediateClose::Application(
        sakuya_stream::connection::ApplicationImmediateClose {
            code: sakuya_wire::v1::application_error::ApplicationErrorCode::new(
                sakuya_wire::var_int::VarInt::from_u32(3),
            ),
            reason_phrase: Bytes::new(),
        },
    ))
}

#[test]
fn the_record_written_wakes_closed_and_a_later_call_gets_the_same_reason() {
    let cell = TestCell::new();
    let (wakes, waker) = counting();
    let mut cx = Context::from_waker(&waker);
    assert!(cell.poll_closed(&mut cx).is_pending());
    assert!(cell.poll_closed(&mut cx).is_pending());
    cell.connection_closed(idle());
    assert_eq!(
        wakes.0.load(Ordering::SeqCst),
        1,
        "the waiter is woken once, kept once"
    );
    assert_eq!(cell.poll_closed(&mut cx), Poll::Ready(idle()));
    // a later reason does not replace the first
    cell.connection_closed(peer_close());
    let mut noop = Context::from_waker(Waker::noop());
    assert_eq!(cell.clone().poll_closed(&mut noop), Poll::Ready(idle()));
}

#[test]
fn a_close_before_the_handshake_completed_ends_its_waits_with_the_reason() {
    let cell = TestCell::new();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(cell.poll_handshake_completed(&mut cx).is_pending());
    assert!(cell.poll_established(&mut cx).is_pending());
    assert!(cell.poll_early(&mut cx).is_pending());
    cell.connection_closed(idle());
    let closed = ConnectionClosedError::new(idle());
    assert_eq!(
        cell.poll_handshake_completed(&mut cx),
        Poll::Ready(Err(closed.clone()))
    );
    assert!(matches!(
        cell.poll_established(&mut cx),
        Poll::Ready(Err(error)) if error == closed
    ));
    assert!(matches!(
        cell.poll_early(&mut cx),
        Poll::Ready(Err(error)) if error == closed
    ));
    assert_eq!(cell.poll_exporter(&mut cx), Poll::Ready(Err(closed)));
    // completing afterwards keeps no exporter
    cell.handshake_completed(7, Some(Arc::new("secret")));
    assert_eq!(cell.poll_exporter(&mut cx), Poll::Ready(Ok(None)));
}

#[test]
fn a_handshake_that_completed_stays_completed_once_the_connection_closed() {
    let cell = TestCell::new();
    let (wakes, waker) = counting();
    let mut cx = Context::from_waker(&waker);
    assert!(cell.poll_handshake_completed(&mut cx).is_pending());
    // a client: no layer before the handshake completes
    cell.no_early_layer();
    let mut noop = Context::from_waker(Waker::noop());
    assert!(matches!(cell.poll_early(&mut noop), Poll::Ready(Ok(None))));
    cell.keep_selection(());
    cell.handshake_completed(7, Some(Arc::new("secret")));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert_eq!(cell.poll_handshake_completed(&mut cx), Poll::Ready(Ok(7)));
    assert!(
        cell.poll_established(&mut cx).is_pending(),
        "the established layer is given once it is built"
    );
    cell.layer_built((), ());
    let layer = match cell.poll_established(&mut cx) {
        Poll::Ready(Ok(layer)) => layer,
        other => panic!("the layer is given: {:?}", other.map(|r| r.is_ok())),
    };
    assert_eq!(
        cell.poll_exporter(&mut cx),
        Poll::Ready(Ok(Some(Arc::new("secret"))))
    );
    cell.layer_ended(LayerEnd::ConnectionClosed(idle()));
    cell.connection_closed(idle());
    assert_eq!(cell.poll_handshake_completed(&mut cx), Poll::Ready(Ok(7)));
    assert!(matches!(cell.poll_established(&mut cx), Poll::Ready(Ok(_))));
    assert!(matches!(cell.poll_early(&mut cx), Poll::Ready(Ok(None))));
    assert_eq!(
        cell.poll_exporter(&mut cx),
        Poll::Ready(Ok(None)),
        "the connection let its exporter go"
    );
    assert_eq!(
        layer.layer.poll_ended(&mut cx),
        Poll::Ready(LayerEnd::ConnectionClosed(idle()))
    );
}

#[test]
fn a_server_gives_its_layer_before_the_handshake_completes() {
    let cell = TestCell::new();
    let mut cx = Context::from_waker(Waker::noop());
    cell.keep_selection(());
    cell.layer_built((), ());
    let early = match cell.poll_early(&mut cx) {
        Poll::Ready(Ok(Some(layer))) => layer,
        _ => panic!("the early layer is given"),
    };
    assert!(
        cell.poll_established(&mut cx).is_pending(),
        "established waits for the handshake"
    );
    cell.handshake_completed(1, None);
    let established = match cell.poll_established(&mut cx) {
        Poll::Ready(Ok(layer)) => layer,
        _ => panic!("the established layer is given"),
    };
    assert!(
        Arc::ptr_eq(&early.layer, &established.layer),
        "the same layer"
    );
}

#[test]
fn a_layer_built_before_its_selection_is_given_once_the_selection_comes() {
    let cell = TestCell::new();
    let mut cx = Context::from_waker(Waker::noop());
    cell.no_early_layer();
    cell.layer_built((), ());
    cell.handshake_completed(1, None);
    assert!(
        cell.poll_established(&mut cx).is_pending(),
        "a layer without its selection gives no handle yet"
    );
    cell.keep_selection(());
    assert!(matches!(cell.poll_established(&mut cx), Poll::Ready(Ok(_))));
    assert!(matches!(cell.poll_early(&mut cx), Poll::Ready(Ok(None))));
}
