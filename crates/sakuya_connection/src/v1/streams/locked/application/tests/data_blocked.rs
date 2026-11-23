//! A write held back by the connection's credit asks for DATA_BLOCKED only
//! when the credit is still used up under the set's lock, where the driver
//! clears the signal of a lower limit once it raised the limit.
//!
//! The driver's MAX_DATA comes in between, at a point a write of another
//! thread could see it: once the write was held back, when it keeps its
//! waker under the part's lock, before it looks at the limit. The test's
//! waker takes the frame for the driver the first time it is cloned.

use core::{
    cell::{Cell, RefCell},
    ptr,
    task::{RawWaker, RawWakerVTable},
};

use super::*;

thread_local! {
    /// The set the driver's side takes MAX_DATA through.
    static SET: RefCell<Option<Set>> = const { RefCell::new(None) };
    /// Whether the next clone of the waker takes MAX_DATA first.
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

/// The driver's MAX_DATA of 60, taken the first time the waker is cloned
/// once armed.
fn clone(_: *const ()) -> RawWaker {
    if ARMED.with(|armed| armed.replace(false)) {
        SET.with(|set| {
            let mut set = set.borrow_mut();
            lent(set.as_mut().expect("kept for the driver"))
                .on_max_data(&mut publisher(), max_data(60))
                .expect("taken");
        });
    }
    RawWaker::new(ptr::null(), &VTABLE)
}

fn ignore(_: *const ()) {}

static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, ignore, ignore, ignore);

fn raising_waker() -> Waker {
    // SAFETY: the functions of the table never read the data pointer, and
    // each clone gives the same table again
    unsafe { Waker::from_raw(RawWaker::new(ptr::null(), &VTABLE)) }
}

/// The server grants 30 bytes of the connection, which the first write
/// uses up without being held back; the second is held back, MAX_DATA of
/// 60 comes in before it looks at the limit, and it writes on: it was not
/// held back at 60, so no DATA_BLOCKED is asked for.
#[test]
fn a_write_the_limit_was_raised_for_in_between_asks_for_no_data_blocked() {
    let (set, layer, intake, _publish) = client(1000, 30);
    SET.with(|kept| *kept.borrow_mut() = Some(set));
    let (writer, _reader) = layer.try_open_bi().expect("a stream");
    let mut writer = writer.with_send_options(Urgency::default(), AnyActiveLinkPath);
    let mut input = Bytes::from(vec![1; 50]);
    assert_eq!(
        poll_write(&mut writer, &mut input, Waker::noop()),
        Poll::Ready(30)
    );
    intake.published();
    ARMED.with(|armed| armed.set(true));
    assert_eq!(
        poll_write(&mut writer, &mut input, &raising_waker()),
        Poll::Ready(20)
    );
    assert!(
        !ARMED.with(Cell::get),
        "MAX_DATA came in while the write was held back"
    );
    let published = intake.published();
    assert!(
        !published.contains(&StreamIntentKey::DataBlocked),
        "the write was not held back at 60: {published:?}"
    );
    drop(writer);
    SET.with(|kept| kept.borrow_mut().take());
}
