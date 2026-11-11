//! The structure of a connection, its wakes, timers and rereads, with
//! stand-in parts.
#![feature(impl_trait_in_assoc_type, yield_expr)]

mod common;

use std::{cell::Cell, future::Future};

use common::{
    Mine, Outer, TestClock, TestLink, advance_to, ms, nothing,
    parts::{self, Command, FACTORY_CALLS, IDLE_AT, a, b, c},
    take_log,
};
use sakuya_connection::{
    driver::ConnectionDriver,
    layer::{EstablishedArgs, LinkPathArgs, LogicalPathArgs, RecoveryArgs},
    request::StructureRequest,
    share::SoleLogicalPath,
};
use sakuya_link::{BindingId, LinkId};
use sakuya_wire::parts::HList;

const PATH: SoleLogicalPath = SoleLogicalPath;

fn link() -> LinkId {
    LinkId::new::<()>(BindingId::new::<()>())
}

/// A connection of the parts `L` with one link path over `first`.
macro_rules! connection {
    ($($part:ty),*; $first:expr) => {
        ConnectionDriver::<Mine, HList![$($part),*], _, _, _>::new(
            TestClock,
            frunk_core::hlist![$(nothing::<$part>()),*],
            LogicalPathArgs { path: PATH },
            LinkPathArgs { path: PATH, link: TestLink($first) },
        )
    };
}

fn reset() {
    take_log();
    advance_to(ms(0));
    IDLE_AT.with(|i| i.set(None));
    FACTORY_CALLS.with(|f| f.set(0));
    parts::COMMANDS.with(|c| c.borrow_mut().clear());
}

fn assert_send<F: Future + Send>(_: &F) {}

#[test]
fn a_new_connection_polls_each_call_once() {
    reset();
    let mut connection = connection!(a::Part, b::Part; link());
    assert_send(&connection);
    // a new node counts as changed: what reads its components is reread
    assert_eq!(take_log(), ["entry built", "b saw the record: None"]);
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(take_log(), ["watch polled", "send polled"]);
    assert!(outer.poll(&mut connection).is_pending());
    assert!(take_log().is_empty(), "nothing is polled without a wake");
}

#[test]
fn wakes_between_polls_call_the_outer_waker_once() {
    reset();
    let mut connection = connection!(a::Part; link());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    let before = outer.wakes();
    let watch = parts::WATCH_WAKER
        .with(|w| w.borrow_mut().take())
        .expect("the watch call waits");
    let sends = parts::SEND_WAKERS.with(|w| std::mem::take(&mut *w.borrow_mut()));
    std::thread::spawn(move || {
        watch.wake_by_ref();
        watch.wake();
        for send in sends {
            send.wake();
        }
    })
    .join()
    .expect("the waking thread");
    assert_eq!(outer.wakes(), before + 1, "folded into one outer wake");
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        take_log(),
        ["watch polled", "send polled"],
        "each call once"
    );
}

#[test]
fn a_wake_while_polled_is_not_lost() {
    reset();
    let mut connection = connection!(a::Part; link());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    parts::command(Command::CloseAndWakeSelf("app"));
    let before = outer.wakes();
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        outer.wakes(),
        before + 1,
        "the call woke itself during the poll"
    );
    take_log();
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(take_log(), ["watch polled"]);
}

#[test]
fn a_call_is_not_woken_by_its_own_take() {
    reset();
    let mut connection = connection!(a::Part; link());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    parts::command(Command::Close("app"));
    assert!(outer.poll(&mut connection).is_pending());
    // the watch call wrote the record it reads and waits again in the same
    // poll; it is not woken for its own write; the link path drains and its
    // send call, no longer needed, is dropped
    assert_eq!(take_log(), ["watch polled", "watch polled"]);
    let before = outer.wakes();
    assert!(outer.poll(&mut connection).is_pending());
    assert!(
        take_log().is_empty(),
        "neither the watch call nor the dropped send call runs"
    );
    let _ = before;
    // the dropped call's old waker may still mark its position: one empty
    // turn at most, the call is not polled
    parts::wake_sends();
    assert!(outer.poll(&mut connection).is_pending());
    assert!(take_log().is_empty());
}

#[test]
fn a_request_is_applied_at_once_and_the_call_goes_on_next_poll() {
    reset();
    let mut connection = connection!(a::Part; link());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    let second = link();
    parts::command(Command::Ask(StructureRequest::AddLinkPath {
        args: LinkPathArgs {
            path: PATH,
            link: TestLink(second),
        },
    }));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        take_log(),
        ["watch polled", "entry built"],
        "built within the lend's poll"
    );
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        take_log(),
        ["watch polled", "send polled"],
        "the call again, and the new node's call"
    );
}

#[test]
fn timers_run_after_calls_and_end_the_connection_at_once() {
    reset();
    IDLE_AT.with(|i| i.set(Some(ms(10))));
    let mut connection = connection!(a::Part; link());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    let before = outer.wakes();
    advance_to(ms(9));
    assert_eq!(outer.wakes(), before, "the sleep is until the deadline");
    advance_to(ms(10));
    assert_eq!(outer.wakes(), before + 1, "the sleep woke the connection");
    let watch = parts::WATCH_WAKER
        .with(|w| w.borrow_mut().take())
        .expect("the watch call waits");
    parts::wake_sends();
    assert!(outer.poll(&mut connection).is_ready());
    // the woken call ran first, then the timer ended the connection
    assert_eq!(
        take_log(),
        ["send polled", "idle expired at 10ms", "entry ended"]
    );
    let after = outer.wakes();
    watch.wake();
    assert_eq!(
        outer.wakes(),
        after,
        "an old waker does nothing once the connection ended"
    );
    assert!(outer.poll(&mut connection).is_ready());
}

#[test]
fn ending_the_connection_skips_what_is_still_queued() {
    reset();
    let mut connection = connection!(a::Part; link());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    parts::command(Command::Ask(StructureRequest::EndConnection));
    parts::wake_sends();
    assert!(outer.poll(&mut connection).is_ready());
    assert_eq!(
        take_log(),
        ["watch polled", "entry ended"],
        "the queued send call was not polled"
    );
}

#[test]
fn child_nodes_are_built_moved_and_ended() {
    reset();
    let first = link();
    let second = link();
    let mut connection = connection!(a::Part; first.clone());
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    parts::command(Command::Ask(StructureRequest::AddRecovery {
        args: RecoveryArgs {
            path: PATH,
            link: first.clone(),
        },
    }));
    assert!(outer.poll(&mut connection).is_pending());
    parts::command(Command::Ask(StructureRequest::AddLinkPath {
        args: LinkPathArgs {
            path: PATH,
            link: TestLink(second.clone()),
        },
    }));
    assert!(outer.poll(&mut connection).is_pending());
    parts::command(Command::Ask(StructureRequest::MoveRecovery {
        path: PATH,
        from: first.clone(),
        to: second.clone(),
    }));
    assert!(outer.poll(&mut connection).is_pending());
    parts::command(Command::Ask(StructureRequest::EndRecovery {
        path: PATH,
        link: second,
    }));
    assert!(outer.poll(&mut connection).is_pending());
    assert_eq!(
        FACTORY_CALLS.with(Cell::get),
        1,
        "a move does not build again"
    );
    let log = take_log();
    assert!(
        log.iter().any(|l| l == "recovery ended with HCons { head: Rtt(10ms), tail: HCons { head: Window(1000), tail: HNil } }"),
        "{log:?}",
    );
}

/// The whole end of a connection: the record is written, the established
/// layer ends with the streams reading the reason, the link path drains and
/// ends, its entry with it, and the connection ends.
fn close_flow<F: Future<Output = ()> + Unpin>(mut connection: F) -> Vec<String> {
    let outer = Outer::new();
    assert!(outer.poll(&mut connection).is_pending());
    parts::command(Command::Ask(StructureRequest::AddEstablished {
        args: EstablishedArgs::default(),
    }));
    assert!(outer.poll(&mut connection).is_pending());
    take_log();
    parts::command(Command::Close("app"));
    assert!(outer.poll(&mut connection).is_pending());
    let mut log = take_log();
    advance_to(ms(30));
    assert!(outer.poll(&mut connection).is_ready());
    log.extend(take_log());
    log
}

#[test]
fn closing_spreads_by_rereads_in_either_order_of_parts() {
    reset();
    let ab = close_flow(connection!(a::Part, b::Part; link()));
    reset();
    let ba = close_flow(connection!(b::Part, a::Part; link()));
    // the order of the rereads of one round follows the positions, so the
    // order of the parts; what happens does not
    let sorted = |mut log: Vec<String>| {
        log.sort();
        log
    };
    assert_eq!(sorted(ab.clone()), sorted(ba));
    assert_eq!(
        sorted(ab),
        sorted(
            vec![
                "watch polled",
                "watch polled",
                "b saw the record: Some(\"app\")",
                "streams ended with 3 open, the record says Some(\"app\")",
                "link path ends at 30ms",
                "entry ended",
            ]
            .into_iter()
            .map(String::from)
            .collect()
        ),
    );
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "rereads did not settle")]
fn rereads_that_never_settle_panic_in_debug_builds() {
    reset();
    drop(connection!(c::Part, a::Part; link()));
}
