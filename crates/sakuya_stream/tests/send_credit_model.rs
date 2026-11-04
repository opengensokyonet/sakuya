//! The connection credit ledger under generated reserve, split, merge,
//! commit, release and drop sequences, and reservations dropped on other
//! threads.

use proptest::prelude::*;
use sakuya_stream::connection_send_credit::{
    AtomicConnectionCreditReservation, AtomicConnectionSendFlowController,
    ConnectionCreditReservation, ConnectionSendFlowController,
};
use sakuya_wire::stream_id::StreamId;
use sakuya_wire::var_int::VarInt;

fn v(value: u64) -> VarInt {
    VarInt::new(value).unwrap()
}

fn sid(index: u32) -> StreamId {
    StreamId::from_var_int(VarInt::from_u32(index * 4))
}

#[derive(Clone, Debug)]
enum Op {
    Reserve {
        stream: u32,
        amount: u64,
    },
    ReserveUpTo {
        stream: u32,
        amount: u64,
    },
    Split {
        at: prop::sample::Index,
        amount: u64,
    },
    Absorb {
        at: prop::sample::Index,
        other: prop::sample::Index,
    },
    Commit {
        at: prop::sample::Index,
    },
    Release {
        at: prop::sample::Index,
    },
    Drop {
        at: prop::sample::Index,
    },
    MaxData {
        limit: u64,
    },
}

fn op() -> impl Strategy<Value = Op> {
    let at = any::<prop::sample::Index>;
    prop_oneof![
        5 => (0u32..3, 0u64..200).prop_map(|(stream, amount)| Op::Reserve { stream, amount }),
        5 => (0u32..3, 0u64..200).prop_map(|(stream, amount)| Op::ReserveUpTo { stream, amount }),
        3 => (at(), 0u64..120).prop_map(|(at, amount)| Op::Split { at, amount }),
        2 => (at(), at()).prop_map(|(at, other)| Op::Absorb { at, other }),
        3 => at().prop_map(|at| Op::Commit { at }),
        2 => at().prop_map(|at| Op::Release { at }),
        2 => at().prop_map(|at| Op::Drop { at }),
        1 => (0u64..1200).prop_map(|limit| Op::MaxData { limit }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 3000, ..ProptestConfig::default() })]

    #[test]
    fn ledger_conserves_credit(ops in prop::collection::vec(op(), 0..80), initial in 0u64..800) {
        let connection = AtomicConnectionSendFlowController::new(v(initial));
        let mut live: Vec<AtomicConnectionCreditReservation> = Vec::new();
        let (mut limit, mut committed) = (initial, 0u64);
        for op in ops {
            match op {
                Op::Reserve { stream, amount } => {
                    let available = connection.available().get();
                    match connection.reserve(sid(stream), v(amount)) {
                        Ok(reservation) => {
                            prop_assert!(amount <= available);
                            prop_assert_eq!(reservation.amount(), v(amount));
                            live.push(reservation);
                        }
                        Err(error) => {
                            prop_assert!(amount > available);
                            prop_assert_eq!(error.available, v(available));
                        }
                    }
                }
                Op::ReserveUpTo { stream, amount } => {
                    let available = connection.available().get();
                    let taken = connection.reserve_up_to(sid(stream), v(amount));
                    let expected = amount.min(available);
                    prop_assert_eq!(taken.as_ref().map(|r| r.amount().get()),
                        (expected > 0).then_some(expected));
                    live.extend(taken);
                }
                Op::Split { at, amount } => {
                    if !live.is_empty() {
                        let index = at.index(live.len());
                        let owned = live[index].amount().get();
                        match live[index].split_off(v(amount)) {
                            Ok(part) => {
                                prop_assert!(amount <= owned);
                                prop_assert_eq!(live[index].amount().get(), owned - amount);
                                prop_assert_eq!(part.stream_id(), live[index].stream_id());
                                live.push(part);
                            }
                            Err(_) => {
                                prop_assert!(amount > owned);
                                prop_assert_eq!(live[index].amount().get(), owned);
                            }
                        }
                    }
                }
                Op::Absorb { at, other } => {
                    if live.len() >= 2 {
                        let taken = live.swap_remove(other.index(live.len()));
                        let index = at.index(live.len());
                        let same_stream = live[index].stream_id() == taken.stream_id();
                        let (owned, added) = (live[index].amount().get(), taken.amount().get());
                        match live[index].absorb(taken) {
                            Ok(()) => {
                                prop_assert!(same_stream);
                                prop_assert_eq!(live[index].amount().get(), owned + added);
                            }
                            Err(error) => {
                                prop_assert!(!same_stream);
                                live.push(error.into_other());
                            }
                        }
                    }
                }
                Op::Commit { at } => {
                    if !live.is_empty() {
                        let reservation = live.swap_remove(at.index(live.len()));
                        let amount = reservation.amount().get();
                        prop_assert_eq!(reservation.commit().get(), amount);
                        committed += amount;
                    }
                }
                Op::Release { at } => {
                    if !live.is_empty() {
                        let reservation = live.swap_remove(at.index(live.len()));
                        let amount = reservation.amount().get();
                        prop_assert_eq!(reservation.release().get(), amount);
                    }
                }
                Op::Drop { at } => {
                    if !live.is_empty() {
                        drop(live.swap_remove(at.index(live.len())));
                    }
                }
                Op::MaxData { limit: value } => {
                    let grew = connection.on_max_data(v(value));
                    prop_assert_eq!(grew, (value > limit).then(|| v(limit)));
                    limit = limit.max(value);
                }
            }
            let reserved: u64 = live.iter().map(|r| r.amount().get()).sum();
            prop_assert_eq!(connection.limit().get(), limit);
            prop_assert_eq!(connection.reserved().get(), reserved);
            prop_assert_eq!(connection.committed().get(), committed);
            prop_assert_eq!(connection.available().get(), limit - reserved - committed);
        }
        drop(live);
        prop_assert_eq!(connection.reserved(), VarInt::ZERO);
        prop_assert_eq!(connection.available().get(), limit - committed);
    }
}

/// Multi-thread stress: reservations dropped on other threads return their
/// credit exactly once. This exercises the shared counter under real
/// contention; it is not an exhaustive exploration of interleavings.
#[test]
fn reservations_dropped_on_other_threads_return_their_credit() {
    const ROUNDS: usize = 200;
    const HANDLES: u64 = 64;
    let connection = AtomicConnectionSendFlowController::new(v(HANDLES * 10));
    for _ in 0..ROUNDS {
        let mut handles: Vec<_> = (0..HANDLES)
            .map(|_| connection.reserve(sid(0), v(10)).unwrap())
            .collect();
        let splits: Vec<_> = handles
            .iter_mut()
            .map(|handle| handle.split_off(v(3)).unwrap())
            .collect();
        assert_eq!(connection.available(), VarInt::ZERO);
        std::thread::scope(|scope| {
            for group in [handles, splits] {
                scope.spawn(move || drop(group));
            }
            // The owner keeps reading while others drop; a stale read may
            // only report too little.
            while connection.reserved() != VarInt::ZERO {
                assert!(connection.available() <= connection.limit());
            }
        });
        assert_eq!(connection.available(), connection.limit());
    }
}

/// Multi-thread stress: reservations taken, committed and dropped on several
/// threads at once never exceed the limit, and what is committed adds up.
#[test]
fn concurrent_reservations_never_exceed_the_limit() {
    const THREADS: u64 = 4;
    const LIMIT: u64 = 1000;
    let connection = AtomicConnectionSendFlowController::new(v(LIMIT));
    let committed: u64 = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|worker| {
                let connection = &connection;
                scope.spawn(move || {
                    let mut committed = 0;
                    for round in 0..2000u64 {
                        let amount = 1 + (round * 7 + worker * 3) % 13;
                        let Some(reservation) = connection.reserve_up_to(sid(0), v(amount)) else {
                            continue;
                        };
                        assert!(reservation.amount().get() <= amount);
                        // A commit adds to `C` before it leaves `R`, so a sum of
                        // two separate loads can count it twice; conservation is
                        // checked once the workers are done.
                        assert!(connection.reserved().get() <= LIMIT);
                        assert!(connection.committed().get() <= LIMIT);
                        // Commit every third reservation, release the rest.
                        if round % 3 == 0 {
                            committed += reservation.commit().get();
                        } else {
                            drop(reservation);
                        }
                    }
                    committed
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .sum()
    });
    assert_eq!(connection.reserved(), VarInt::ZERO);
    assert_eq!(connection.committed().get(), committed);
    assert!(committed <= LIMIT);
    assert_eq!(connection.available().get(), LIMIT - committed);
}
