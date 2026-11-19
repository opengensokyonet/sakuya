use std::{
    sync::atomic::{AtomicUsize, Ordering},
    task::Wake,
};

use sakuya_stream::connection::ImmediateClose;

use super::*;

/// A state with facts `u32`, an exporter `&'static str` and a selection
/// `u8`: what the tests look at is the state's own.
type TestState = ConnectionHandleState<(), u32, &'static str, u8>;

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Wakes {
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
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

/// The selection of the layer of a result that has one.
fn selection<C>(given: Waited<(LayerId, Arc<u8>), C>) -> Option<u8> {
    match given {
        Some(Ok((_, selection))) => Some(*selection),
        _ => None,
    }
}

#[test]
fn a_change_wakes_every_waiter_kept_once() {
    let mut state = TestState::new();
    let (wakes, waker) = counting();
    assert_eq!(state.kept().closed(), None);
    state.keep_waker(&waker);
    state.keep_waker(&waker);
    state.connection_closed(idle());
    assert_eq!(wakes.count(), 1, "the waiter is woken once, kept once");
    assert_eq!(state.kept().closed(), Some(idle()));
    // a later reason does not replace the first
    state.connection_closed(peer_close());
    assert_eq!(state.kept().closed(), Some(idle()));
    assert_eq!(wakes.count(), 1, "nobody waits any more");
}

#[test]
fn a_close_before_the_handshake_completed_ends_its_waits_with_the_reason() {
    let mut state = TestState::new();
    assert!(state.kept().handshake_completed().is_none());
    assert!(state.kept().established().is_none());
    assert!(state.kept().early().is_none());
    state.connection_closed(idle());
    let closed = ConnectionClosedError::new(idle());
    assert_eq!(
        state.kept().handshake_completed(),
        Some(Err(closed.clone()))
    );
    assert!(matches!(state.kept().established(), Some(Err(error)) if error == closed));
    assert!(matches!(state.kept().early(), Some(Err(error)) if error == closed));
    assert_eq!(state.kept().exporter(&state.exporter), Some(Err(closed)));
    // completing afterwards keeps no exporter
    state.handshake_completed(7, Some(Arc::new("secret")));
    assert_eq!(state.kept().exporter(&state.exporter), Some(Ok(None)));
}

#[test]
fn a_handshake_that_completed_stays_completed_once_the_connection_closed() {
    let mut state = TestState::new();
    // a client: no layer before the handshake completes
    state.no_early_layer();
    assert!(matches!(state.kept().early(), Some(Ok(None))));
    state.keep_selection(1);
    state.handshake_completed(7, Some(Arc::new("secret")));
    assert_eq!(state.kept().handshake_completed(), Some(Ok(7)));
    assert!(
        state.kept().established().is_none(),
        "the established layer is given once it is built"
    );
    state.layer_built();
    let Some(Ok((layer, _))) = state.kept().established() else {
        panic!("the layer is given");
    };
    assert!(state.is_current(layer));
    assert_eq!(
        state.kept().exporter(&state.exporter),
        Some(Ok(Some(Arc::new("secret"))))
    );
    assert_eq!(state.kept().layer_end(layer), None);
    state.layer_ended(LayerEnd::ConnectionClosed(idle()));
    state.connection_closed(idle());
    assert!(!state.is_current(layer));
    assert_eq!(state.kept().handshake_completed(), Some(Ok(7)));
    assert!(matches!(state.kept().established(), Some(Ok(_))));
    assert!(matches!(state.kept().early(), Some(Ok(None))));
    assert_eq!(
        state.kept().exporter(&state.exporter),
        Some(Ok(None)),
        "the connection let its exporter go"
    );
    assert_eq!(
        state.kept().layer_end(layer),
        Some(LayerEnd::ConnectionClosed(idle()))
    );
}

#[test]
fn a_server_gives_its_layer_before_the_handshake_completes() {
    let mut state = TestState::new();
    state.keep_selection(1);
    state.layer_built();
    let Some(Ok(Some((early, _)))) = state.kept().early() else {
        panic!("the early layer is given");
    };
    assert!(
        state.kept().established().is_none(),
        "established waits for the handshake"
    );
    state.handshake_completed(1, None);
    let Some(Ok((established, _))) = state.kept().established() else {
        panic!("the established layer is given");
    };
    assert_eq!(early, established, "the same layer");
}

#[test]
fn a_layer_built_before_its_selection_is_given_once_the_selection_comes() {
    let mut state = TestState::new();
    state.no_early_layer();
    state.layer_built();
    state.handshake_completed(1, None);
    assert!(
        state.kept().established().is_none(),
        "a layer without its selection gives no handle yet"
    );
    state.keep_selection(4);
    assert_eq!(selection(state.kept().established()), Some(4));
    assert!(matches!(state.kept().early(), Some(Ok(None))));
}

#[test]
fn a_layer_built_again_has_an_identity_of_its_own() {
    let mut state = TestState::new();
    state.keep_selection(1);
    state.layer_built();
    let Some(Ok(Some((first, _)))) = state.kept().early() else {
        panic!("the first layer came before the handshake completed");
    };
    // the layer is built again, as after 0-RTT was rejected
    state.layer_ended(LayerEnd::ZeroRttRejected);
    state.layer_built();
    state.handshake_completed(1, None);
    assert_eq!(
        selection(state.kept().established()),
        Some(1),
        "the second layer waits for its own selection, the first is still given"
    );
    state.keep_selection(2);
    let Some(Ok((second, selected))) = state.kept().established() else {
        panic!("the second layer is given");
    };
    assert_ne!(first, second, "another layer");
    assert_eq!(*selected, 2);
    assert!(state.is_current(second) && !state.is_current(first));
    assert_eq!(
        state.kept().layer_end(first),
        Some(LayerEnd::ZeroRttRejected)
    );
    assert_eq!(state.kept().layer_end(second), None);
    assert_eq!(
        selection(state.kept().early().and_then(|early| early.transpose())),
        Some(1)
    );
}

#[test]
fn a_layer_that_ends_before_its_selection_is_never_given() {
    let mut state = TestState::new();
    state.no_early_layer();
    state.layer_built();
    state.layer_ended(LayerEnd::ConnectionClosed(idle()));
    state.keep_selection(1);
    state.handshake_completed(1, None);
    assert!(
        state.kept().established().is_none(),
        "the selection waits for the next layer"
    );
}

#[test]
fn what_is_kept_once_the_connection_ended_ends_every_layer() {
    let mut state = TestState::new();
    state.keep_selection(1);
    state.layer_built();
    let Some(Ok(Some((layer, _)))) = state.kept().early() else {
        panic!("the layer is given");
    };
    state.connection_closed(idle());
    let mut kept = core::mem::take(&mut state.kept);
    assert_eq!(
        kept.ended().layer_end(layer),
        Some(LayerEnd::ConnectionClosed(idle())),
        "a layer that did not end ends with the connection"
    );
    assert_eq!(kept.closed(), Some(idle()));
}
