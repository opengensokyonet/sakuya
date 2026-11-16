use std::{
    sync::atomic::{AtomicUsize, Ordering},
    task::Wake,
};

use sakuya_stream::connection::ImmediateClose;

use super::*;
use crate::v1::application_handles::{FindHandleShare, KeyedHandleShare};

/// A part that gives a layer's handle a share.
struct First;
/// Another part that gives a layer's handle a share.
struct Second;

/// The share of [`First`], which tells one layer from another.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FirstShare(u8);
impl KeyedHandleShare for FirstShare {
    type Part = First;
}

/// The share of [`Second`].
#[derive(Debug, Clone, PartialEq, Eq)]
struct SecondShare;
impl KeyedHandleShare for SecondShare {
    type Part = Second;
}

std::thread_local! {
    /// The shares told that the driver panicked, in order, with the end.
    static TOLD: core::cell::RefCell<Vec<(&'static str, LayerEnd<()>)>> =
        const { core::cell::RefCell::new(Vec::new()) };
}

fn told() -> Vec<(&'static str, LayerEnd<()>)> {
    TOLD.with(|told| core::mem::take(&mut *told.borrow_mut()))
}

impl DriverPanicHandleShare<()> for FirstShare {
    fn driver_panicked(&self, end: LayerEnd<()>) {
        TOLD.with(|told| told.borrow_mut().push(("first", end)));
    }
}

impl DriverPanicHandleShare<()> for SecondShare {
    fn driver_panicked(&self, end: LayerEnd<()>) {
        TOLD.with(|told| told.borrow_mut().push(("second", end)));
    }
}

/// The shares of a layer's handle: of [`First`], of a part that gives
/// none, and of [`Second`].
type Shares = frunk_core::HList![FirstShare, sakuya_wire::parts::HNil, SecondShare];

/// A cell with facts `u32`, an exporter `&'static str`, and the shares
/// [`Shares`]: what the tests look at is the cell's own.
type TestCell = ConnectionHandleCell<(), u32, &'static str, Shares, (), ()>;

/// The components of a layer just built hand over the intake and every
/// share, [`First`]'s with `layer`.
fn build_layer(cell: &TestCell, layer: u8) {
    cell.keep_intake(());
    cell.share_built::<First, _>(FirstShare(layer));
    cell.share_built::<Second, _>(SecondShare);
}

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
    build_layer(&cell, 1);
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
    build_layer(&cell, 1);
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
    build_layer(&cell, 1);
    cell.handshake_completed(1, None);
    assert!(
        cell.poll_established(&mut cx).is_pending(),
        "a layer without its selection gives no handle yet"
    );
    cell.keep_selection(());
    assert!(matches!(cell.poll_established(&mut cx), Poll::Ready(Ok(_))));
    assert!(matches!(cell.poll_early(&mut cx), Poll::Ready(Ok(None))));
}

#[test]
fn a_layer_is_given_once_every_share_came_and_a_layer_built_again_collects_again() {
    let cell = TestCell::new();
    let mut cx = Context::from_waker(Waker::noop());
    cell.keep_selection(());
    cell.handshake_completed(1, None);
    cell.keep_intake(());
    cell.share_built::<Second, _>(SecondShare);
    assert!(
        cell.poll_established(&mut cx).is_pending(),
        "a share is missing"
    );
    cell.share_built::<First, _>(FirstShare(1));
    let first = match cell.poll_established(&mut cx) {
        Poll::Ready(Ok(layer)) => layer,
        _ => panic!("the layer is given"),
    };
    assert_eq!(
        FindHandleShare::<First, _>::find(&first.shares),
        &FirstShare(1)
    );
    // the layer is built again, as after 0-RTT was rejected: its shares and
    // its selection come again
    cell.share_built::<First, _>(FirstShare(2));
    cell.keep_selection(());
    let still = match cell.poll_established(&mut cx) {
        Poll::Ready(Ok(layer)) => layer,
        _ => panic!("the first layer is still given"),
    };
    assert_eq!(
        FindHandleShare::<First, _>::find(&still.shares),
        &FirstShare(1),
        "a share is missing"
    );
    cell.share_built::<Second, _>(SecondShare);
    let second = match cell.poll_established(&mut cx) {
        Poll::Ready(Ok(layer)) => layer,
        _ => panic!("the second layer is given"),
    };
    assert_eq!(
        FindHandleShare::<First, _>::find(&second.shares),
        &FirstShare(2)
    );
    assert!(!Arc::ptr_eq(&first.layer, &second.layer), "another layer");
}

#[test]
fn the_drivers_panic_ends_the_latest_layer_and_tells_each_of_its_shares() {
    let cell = TestCell::new();
    let mut cx = Context::from_waker(Waker::noop());
    cell.keep_selection(());
    build_layer(&cell, 1);
    cell.keep_selection(());
    build_layer(&cell, 2);
    let Poll::Ready(Ok(Some(first))) = cell.poll_early(&mut cx) else {
        panic!("the first layer came before the handshake completed");
    };
    told();
    let end = LayerEnd::ConnectionClosed(CloseReason::Aborted(AbortCause::Panicked));
    cell.driver_panicked(end.clone());
    assert_eq!(
        told(),
        [("first", end.clone()), ("second", end.clone())],
        "each share of the latest layer, in order, the part without one skipped"
    );
    assert_eq!(
        first.layer.poll_ended(&mut cx),
        Poll::Pending,
        "only the latest layer ends"
    );
    let latest = cell.state().layer.clone().expect("the latest layer");
    assert_eq!(latest.shares.head, FirstShare(2));
    assert_eq!(latest.layer.poll_ended(&mut cx), Poll::Ready(end));
}
