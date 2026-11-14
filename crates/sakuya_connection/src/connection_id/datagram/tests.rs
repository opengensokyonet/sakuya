//! Choosing a datagram's connection ID and telling the strategy of its use.

use std::{cell::RefCell, rc::Rc};

use sakuya_wire::{
    connection_id::{NonEmptyCid, StatelessResetToken},
    v1::{
        frame::new_connection_id::NewConnectionIdFrame,
        transport_parameters::integer::ActiveConnectionIdLimit,
    },
    var_int::{VarInt, VarIntField},
};

use super::*;
use crate::connection_id::{
    NewConnectionId, sequence_map::SequenceMapDestinationConnectionIdStrategy,
};

type Instant = u64;

/// A registrar that counts the registrations it made and keeps alive.
#[derive(Debug, Default)]
struct Registrar(Rc<RefCell<usize>>);

#[derive(Debug)]
struct Registration(Rc<RefCell<usize>>);

impl Drop for Registration {
    fn drop(&mut self) {
        *self.0.borrow_mut() -= 1;
    }
}

impl ResetTokenRegistrar for Registrar {
    type Registration = Registration;

    fn register(&mut self, _token: StatelessResetToken) -> Registration {
        *self.0.borrow_mut() += 1;
        Registration(Rc::clone(&self.0))
    }
}

type Strategy = SequenceMapDestinationConnectionIdStrategy<u8, Registrar>;
type Chosen<'a> = DatagramConnectionId<'a, Strategy, Registrar, u8, Instant>;

fn cid(sequence: u8) -> ConnectionId {
    ConnectionId::new(&[sequence + 1; 4]).unwrap()
}

/// A strategy with the connection IDs numbered 0 and 1.
fn strategy() -> Strategy {
    let mut strategy = crate::connection_id::sequence_map::started(
        cid(0),
        Some(StatelessResetToken::new([1; 16])),
        ActiveConnectionIdLimit::new(VarInt::from(4u8)).unwrap(),
        8,
    );
    let frame = NewConnectionIdFrame::new(
        VarIntField::shortest(VarInt::from(1u8)),
        VarIntField::shortest(VarInt::from(0u8)),
        NonEmptyCid::new(cid(1)).unwrap(),
        StatelessResetToken::new([2; 16]),
    )
    .unwrap();
    DestinationConnectionIdStrategy::<u8, Instant, Registrar>::on_new_connection_id(
        &mut strategy,
        NewConnectionId::from(&frame),
    )
    .unwrap();
    strategy
}

fn offered(strategy: &Strategy, link_path: u8) -> Vec<u64> {
    DestinationConnectionIdStrategy::<u8, Instant, Registrar>::offer(strategy, &link_path)
        .map(|offered| offered.sequence)
        .collect()
}

#[test]
fn chooses_the_first_offered_that_fits() {
    let mut strategy = strategy();
    let mut registrar = Registrar::default();
    let chosen = Chosen::choose_first(&mut strategy, &mut registrar, &1, |offered| {
        offered.sequence == 1
    })
    .unwrap();
    assert_eq!(
        chosen.offered(),
        OfferedConnectionId {
            sequence: 1,
            id: cid(1)
        }
    );
    assert_eq!(chosen.connection_id(), cid(1));

    let mut tried = Vec::new();
    let none = Chosen::choose_first(&mut strategy, &mut registrar, &1, |offered| {
        tried.push(offered.sequence);
        false
    });
    assert!(none.is_none());
    assert_eq!(tried, [0, 1]);
}

#[test]
fn a_used_connection_id_is_bound_and_registered() {
    let mut strategy = strategy();
    let mut registrar = Registrar::default();
    let chosen = Chosen::choose_first(&mut strategy, &mut registrar, &1, |_| true).unwrap();
    chosen.used(1200);
    assert_eq!(*registrar.0.borrow(), 1);
    assert_eq!(offered(&strategy, 2), [1]);
}

#[test]
fn a_connection_id_dropped_unused_leaves_no_trace() {
    let mut strategy = strategy();
    let mut registrar = Registrar::default();
    // Chosen for a datagram that stays empty, then dropped.
    assert!(Chosen::choose_first(&mut strategy, &mut registrar, &1, |_| true).is_some());
    assert_eq!(*registrar.0.borrow(), 0);
    assert_eq!(offered(&strategy, 2), [0, 1]);
}
