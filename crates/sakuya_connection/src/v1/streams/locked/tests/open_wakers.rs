//! Those who wait to open a stream are woken by a larger MAX_STREAMS once
//! the set's lock is let go: each takes the lock again to open, so a wake
//! under it would have them wait on the driver.

use std::sync::atomic::AtomicUsize;
use std::task::Wake;

use super::*;

/// The share of the tests' set.
type Share = StreamSetShare<(), TestTicket, TestPublish, Rfc9000StreamResets, Urgency, NoEvents>;

/// A waker that notes, each time it is woken, whether the set's lock was
/// free.
struct LockWatch {
    share: Arc<Share>,
    free: AtomicUsize,
    held: AtomicUsize,
}

impl Wake for LockWatch {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let woken = if self.share.set.try_lock().is_ok() {
            &self.free
        } else {
            &self.held
        };
        woken.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn a_larger_max_streams_wakes_those_who_wait_to_open_with_the_sets_lock_let_go() {
    let mut set = client_set();
    for _ in 0..2 {
        lent(&mut set)
            .open_held(&mut publisher(), Directionality::Bidirectional, None)
            .expect("the peer allows two");
    }
    let watch = Arc::new(LockWatch {
        share: Arc::clone(&set.shared),
        free: AtomicUsize::new(0),
        held: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&watch));
    assert!(matches!(
        lent(&mut set).open_held(
            &mut publisher(),
            Directionality::Bidirectional,
            Some(&waker)
        ),
        Err(TryOpenStreamError::AtLimit)
    ));
    lent(&mut set)
        .on_max_streams(
            &mut publisher(),
            MaxStreamsFrame::new(
                Directionality::Bidirectional,
                VarIntField::shortest(count(3)),
            ),
        )
        .expect("no rule to break");
    assert_eq!(
        watch.free.load(Ordering::Relaxed),
        1,
        "woken once, unlocked"
    );
    assert_eq!(
        watch.held.load(Ordering::Relaxed),
        0,
        "not woken under the lock"
    );
}
