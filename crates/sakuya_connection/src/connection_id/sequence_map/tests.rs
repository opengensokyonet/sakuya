//! The sequence-keyed destination connection ID strategy, event by event.

use std::{cell::RefCell, rc::Rc};

use sakuya_link::{BindingId, LinkId};
use sakuya_wire::{
    connection_id::NonEmptyCid,
    v1::transport_error::TransportErrorCode,
    var_int::{VarInt, VarIntField},
};

use super::*;

/// The instants of these tests; the strategy never uses them.
type Instant = u64;

/// A registrar that keeps the tokens registered and not yet revoked.
#[derive(Debug, Default)]
struct Registrar(Rc<RefCell<Vec<StatelessResetToken>>>);

/// One registration of a [`Registrar`].
#[derive(Debug)]
struct Registration(Rc<RefCell<Vec<StatelessResetToken>>>, StatelessResetToken);

impl Drop for Registration {
    fn drop(&mut self) {
        let mut live = self.0.borrow_mut();
        let position = live.iter().position(|token| *token == self.1).unwrap();
        live.remove(position);
    }
}

impl ResetTokenRegistrar for Registrar {
    type Registration = Registration;

    fn register(&mut self, token: StatelessResetToken) -> Registration {
        self.0.borrow_mut().push(token);
        Registration(Rc::clone(&self.0), token)
    }
}

impl Registrar {
    fn live(&self) -> Vec<StatelessResetToken> {
        self.0.borrow().clone()
    }
}

type Strategy = SequenceMapDestinationConnectionIdStrategy<u8, Registrar>;

fn cid(sequence: u8) -> ConnectionId {
    ConnectionId::new(&[sequence + 0x10; 8]).unwrap()
}

fn token(sequence: u8) -> StatelessResetToken {
    StatelessResetToken::new([sequence + 0x80; 16])
}

fn limit(value: u8) -> ActiveConnectionIdLimit {
    ActiveConnectionIdLimit::new(VarInt::from(value)).unwrap()
}

/// A strategy whose peer's handshake connection ID is `cid(0)` with
/// `token(0)`, under `active_limit`, tracking `retirement_limit`
/// retirements.
fn strategy(active_limit: u8, retirement_limit: usize) -> Strategy {
    started(
        cid(0),
        Some(token(0)),
        limit(active_limit),
        retirement_limit,
    )
}

fn frame_with(
    sequence: u8,
    retire_prior_to: u8,
    id: ConnectionId,
    token: StatelessResetToken,
) -> NewConnectionIdFrame {
    NewConnectionIdFrame::new(
        VarIntField::shortest(VarInt::from(sequence)),
        VarIntField::shortest(VarInt::from(retire_prior_to)),
        NonEmptyCid::new(id).unwrap(),
        token,
    )
    .unwrap()
}

fn frame(sequence: u8, retire_prior_to: u8) -> NewConnectionIdFrame {
    frame_with(sequence, retire_prior_to, cid(sequence), token(sequence))
}

fn receive(
    strategy: &mut Strategy,
    frame: NewConnectionIdFrame,
) -> Result<(), NewConnectionIdViolationError> {
    <Strategy as DestinationConnectionIdStrategy<u8, Instant, Registrar>>::on_new_connection_id(
        strategy, &frame,
    )
}

fn offer(strategy: &Strategy, link_path: u8) -> Vec<u64> {
    <Strategy as DestinationConnectionIdStrategy<u8, Instant, Registrar>>::offer(
        strategy, &link_path,
    )
    .map(|offered| offered.sequence)
    .collect()
}

fn used(strategy: &mut Strategy, registrar: &mut Registrar, sequence: u64, link_path: u8) {
    <Strategy as DestinationConnectionIdStrategy<u8, Instant, Registrar>>::on_used(
        strategy, registrar, sequence, &link_path, 1200,
    );
}

fn added(strategy: &mut Strategy, link_path: u8, peer_switched_local_id: bool) {
    <Strategy as DestinationConnectionIdStrategy<u8, Instant, Registrar>>::on_link_path_added(
        strategy,
        &link_path,
        peer_switched_local_id,
    );
}

fn ended(strategy: &mut Strategy, link_path: u8) {
    <Strategy as DestinationConnectionIdStrategy<u8, Instant, Registrar>>::on_link_path_ended(
        strategy, &link_path,
    );
}

fn pending(strategy: &Strategy) -> Vec<u64> {
    strategy.pending_retirements().collect()
}

const NONE: [u64; 0] = [];

#[test]
fn offers_bound_connection_ids_then_unused_ones() {
    let mut registrar = Registrar::default();
    let mut strategy = strategy(4, 8);
    receive(&mut strategy, frame(1, 0)).unwrap();
    receive(&mut strategy, frame(2, 0)).unwrap();
    assert_eq!(offer(&strategy, 1), [0, 1, 2]);

    used(&mut strategy, &mut registrar, 1, 1);
    assert_eq!(offer(&strategy, 1), [1, 0, 2]);
    assert_eq!(offer(&strategy, 2), [0, 2]);
}

#[test]
fn a_connection_id_used_on_another_link_path_is_never_offered() {
    let mut registrar = Registrar::default();
    let mut strategy = strategy(4, 8);
    receive(&mut strategy, frame(1, 0)).unwrap();
    used(&mut strategy, &mut registrar, 0, 1);

    // The exception of RFC 9000 §9.5 is not taken, not even when the peer
    // kept this side's connection ID.
    added(&mut strategy, 2, false);
    assert_eq!(offer(&strategy, 2), [1]);
    used(&mut strategy, &mut registrar, 1, 2);
    added(&mut strategy, 3, true);
    assert_eq!(offer(&strategy, 3), NONE);
}

#[test]
fn a_token_is_registered_on_first_use_on_each_link_path() {
    let mut registrar = Registrar::default();
    let mut strategy = strategy(4, 8);
    receive(&mut strategy, frame(1, 0)).unwrap();
    drop(offer(&strategy, 1));
    assert_eq!(registrar.live(), []);

    used(&mut strategy, &mut registrar, 1, 1);
    used(&mut strategy, &mut registrar, 1, 1);
    assert_eq!(registrar.live(), [token(1)]);

    let mut other = Registrar::default();
    used(&mut strategy, &mut other, 1, 2);
    assert_eq!(other.live(), [token(1)]);
}

#[test]
fn a_handshake_connection_id_without_a_token_registers_nothing() {
    let mut registrar = Registrar::default();
    let mut strategy = started(cid(0), None, limit(2), 4);
    used(&mut strategy, &mut registrar, 0, 1);
    assert_eq!(registrar.live(), []);
    assert_eq!(offer(&strategy, 1), [0]);
}

#[test]
fn retire_prior_to_retires_before_adding() {
    let mut registrar = Registrar::default();
    let mut strategy = strategy(2, 4);
    receive(&mut strategy, frame(1, 0)).unwrap();
    used(&mut strategy, &mut registrar, 0, 1);
    assert_eq!(registrar.live(), [token(0)]);

    // Two are active; the third fits because the first is retired before.
    receive(&mut strategy, frame(2, 1)).unwrap();
    assert_eq!(offer(&strategy, 1), [1, 2]);
    assert_eq!(pending(&strategy), [0]);
    assert_eq!(registrar.live(), []);
}

#[test]
fn a_smaller_retire_prior_to_has_no_effect() {
    let mut strategy = strategy(4, 4);
    receive(&mut strategy, frame(2, 2)).unwrap();
    receive(&mut strategy, frame(3, 1)).unwrap();
    assert_eq!(offer(&strategy, 1), [2, 3]);
    assert_eq!(pending(&strategy), [0]);
}

#[test]
fn a_connection_id_below_retire_prior_to_is_retired_at_once() {
    let mut strategy = strategy(2, 4);
    receive(&mut strategy, frame(3, 3)).unwrap();
    assert_eq!(pending(&strategy), [0]);

    receive(&mut strategy, frame(1, 0)).unwrap();
    assert_eq!(offer(&strategy, 1), [3]);
    assert_eq!(pending(&strategy), [0, 1]);
    // Its retirement is started once.
    receive(&mut strategy, frame(1, 0)).unwrap();
    assert_eq!(pending(&strategy), [0, 1]);
}

#[test]
fn more_active_connection_ids_than_the_limit_is_a_violation() {
    let mut strategy = strategy(2, 4);
    receive(&mut strategy, frame(1, 0)).unwrap();
    let error = receive(&mut strategy, frame(2, 0)).unwrap_err();
    let NewConnectionIdViolationError::ActiveLimitExceeded { source } = error else {
        panic!("{error:?}");
    };
    assert_eq!((source.active(), source.limit()), (3, limit(2)));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
    );
}

#[test]
fn more_unacknowledged_retirements_than_tracked_is_a_violation() {
    let mut strategy = strategy(2, 1);
    receive(&mut strategy, frame(1, 0)).unwrap();
    let error = receive(&mut strategy, frame(2, 2)).unwrap_err();
    let NewConnectionIdViolationError::RetirementLimitExceeded { source } = error else {
        panic!("{error:?}");
    };
    assert_eq!((source.unacknowledged(), source.limit()), (2, 1));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::CONNECTION_ID_LIMIT_ERROR
    );
}

#[test]
fn written_retirements_count_until_acknowledged() {
    let mut strategy = strategy(2, 2);
    receive(&mut strategy, frame(1, 0)).unwrap();
    receive(&mut strategy, frame(2, 2)).unwrap();
    assert_eq!(pending(&strategy), [0, 1]);

    strategy.on_retirement_written(0);
    strategy.on_retirement_written(1);
    assert_eq!(pending(&strategy), NONE);
    strategy.on_retirement_lost(1);
    assert_eq!(pending(&strategy), [1]);
    strategy.on_retirement_acknowledged(0);

    // One retirement still waits; one more is within the two tracked.
    receive(&mut strategy, frame(3, 3)).unwrap();
    assert_eq!(pending(&strategy), [1, 2]);
    assert!(matches!(
        receive(&mut strategy, frame(4, 4)),
        Err(NewConnectionIdViolationError::RetirementLimitExceeded { .. })
    ));
}

#[test]
fn a_repeated_frame_is_accepted_and_adds_nothing() {
    let mut strategy = strategy(2, 4);
    receive(&mut strategy, frame(1, 0)).unwrap();
    receive(&mut strategy, frame(1, 0)).unwrap();
    assert_eq!(offer(&strategy, 1), [0, 1]);
}

#[test]
fn a_reused_sequence_number_is_a_violation() {
    let mut strategy = strategy(4, 4);
    receive(&mut strategy, frame(1, 0)).unwrap();
    let error = receive(&mut strategy, frame_with(1, 0, cid(9), token(1))).unwrap_err();
    let NewConnectionIdViolationError::SequenceNumberReused { source } = error else {
        panic!("{error:?}");
    };
    assert_eq!(
        (source.sequence(), source.known(), source.received()),
        (1, cid(1), cid(9))
    );
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::PROTOCOL_VIOLATION
    );
}

#[test]
fn a_connection_id_with_another_sequence_number_is_a_violation() {
    let mut strategy = strategy(4, 4);
    receive(&mut strategy, frame(1, 0)).unwrap();
    let error = receive(&mut strategy, frame_with(2, 0, cid(1), token(2))).unwrap_err();
    let NewConnectionIdViolationError::ConnectionIdResequenced { source } = error else {
        panic!("{error:?}");
    };
    assert_eq!(
        (
            source.id(),
            source.known_sequence(),
            source.received_sequence()
        ),
        (cid(1), 1, 2)
    );
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::PROTOCOL_VIOLATION
    );
}

#[test]
fn a_changed_reset_token_is_a_violation() {
    let mut strategy = strategy(4, 4);
    receive(&mut strategy, frame(1, 0)).unwrap();
    let error = receive(&mut strategy, frame_with(1, 0, cid(1), token(9))).unwrap_err();
    let NewConnectionIdViolationError::ResetTokenChanged { source } = error else {
        panic!("{error:?}");
    };
    assert_eq!((source.sequence(), source.id()), (1, cid(1)));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::PROTOCOL_VIOLATION
    );
}

#[test]
fn a_reset_token_for_two_connection_ids_is_a_violation() {
    let mut strategy = strategy(4, 4);
    receive(&mut strategy, frame(1, 0)).unwrap();
    let error = receive(&mut strategy, frame_with(2, 0, cid(2), token(1))).unwrap_err();
    let NewConnectionIdViolationError::ResetTokenReused { source } = error else {
        panic!("{error:?}");
    };
    assert_eq!((source.sequence(), source.other_sequence()), (2, 1));
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::PROTOCOL_VIOLATION
    );

    // The handshake connection ID's token counts too.
    let mut strategy = self::strategy(4, 4);
    assert!(matches!(
        receive(&mut strategy, frame_with(1, 0, cid(1), token(0))),
        Err(NewConnectionIdViolationError::ResetTokenReused { .. })
    ));
}

#[test]
fn an_ended_link_path_retires_what_only_it_used() {
    let mut registrar = Registrar::default();
    let mut strategy = strategy(4, 4);
    receive(&mut strategy, frame(1, 0)).unwrap();
    receive(&mut strategy, frame(2, 0)).unwrap();
    used(&mut strategy, &mut registrar, 1, 1);
    assert_eq!(registrar.live(), [token(1)]);

    ended(&mut strategy, 1);
    assert_eq!(registrar.live(), []);
    assert_eq!(pending(&strategy), [1]);
    assert_eq!(offer(&strategy, 2), [0, 2]);

    // A late copy of its NEW_CONNECTION_ID does not bring it back.
    receive(&mut strategy, frame(1, 0)).unwrap();
    assert_eq!(offer(&strategy, 2), [0, 2]);
}

#[test]
fn an_ended_link_path_keeps_a_connection_id_another_one_uses() {
    let mut first = Registrar::default();
    let mut second = Registrar::default();
    let mut strategy = strategy(4, 4);
    used(&mut strategy, &mut first, 0, 1);
    used(&mut strategy, &mut second, 0, 2);

    ended(&mut strategy, 1);
    assert_eq!(first.live(), []);
    assert_eq!(second.live(), [token(0)]);
    assert_eq!(pending(&strategy), NONE);
    assert_eq!(offer(&strategy, 2), [0]);
}

#[test]
fn a_zero_length_connection_id_serves_every_link_path_and_is_never_retired() {
    let mut registrar = Registrar::default();
    let mut strategy = started(ConnectionId::EMPTY, Some(token(0)), limit(2), 4);
    used(&mut strategy, &mut registrar, 0, 1);
    assert_eq!(offer(&strategy, 2), [0]);
    assert_eq!(registrar.live(), [token(0)]);

    ended(&mut strategy, 1);
    assert_eq!(registrar.live(), []);
    assert_eq!(pending(&strategy), NONE);
    assert_eq!(offer(&strategy, 2), [0]);

    let error = receive(&mut strategy, frame(1, 0)).unwrap_err();
    let NewConnectionIdViolationError::ZeroLengthInUse { source } = error else {
        panic!("{error:?}");
    };
    assert_eq!(source.sequence(), 1);
    assert_eq!(
        error.transport_error_code(),
        TransportErrorCode::PROTOCOL_VIOLATION
    );
}

#[test]
fn it_has_no_deadline() {
    let strategy = strategy(2, 4);
    assert_eq!(
        <Strategy as DestinationConnectionIdStrategy<u8, Instant, Registrar>>::next_deadline(
            &strategy
        ),
        None
    );
}

#[test]
fn link_ids_identify_link_paths() {
    type LinkPath = LinkId<(), ()>;
    let binding = BindingId::new();
    let first = LinkPath::new::<()>((), (), &binding);
    let second = LinkPath::new::<()>((), (), &binding);
    let mut registrar = Registrar::default();
    let mut strategy = started::<LinkPath, Registrar>(cid(0), Some(token(0)), limit(2), 4);
    DestinationConnectionIdStrategy::<LinkPath, Instant, Registrar>::on_used(
        &mut strategy,
        &mut registrar,
        0,
        &first,
        1200,
    );
    let offered =
        DestinationConnectionIdStrategy::<LinkPath, Instant, Registrar>::offer(&strategy, &second)
            .count();
    assert_eq!(offered, 0);
}

#[cfg(feature = "connection_id_strategy_checks")]
mod contract {
    //! The checks every destination connection ID strategy passes.

    use super::*;
    use crate::connection_id::strategy_checks::{self, RecordingResetTokenRegistrar};

    type Checked = SequenceMapDestinationConnectionIdStrategy<u8, RecordingResetTokenRegistrar>;

    /// The strategy under check, tracking twice the limit in retirements
    /// as RFC 9000 §5.1.2 recommends.
    fn new(
        first: ConnectionId,
        first_token: Option<StatelessResetToken>,
        active_limit: ActiveConnectionIdLimit,
    ) -> Checked {
        let tracked = usize::try_from(active_limit.get().get()).unwrap() * 2;
        started(first, first_token, active_limit, tracked)
    }

    #[test]
    fn active_connection_id_limit() {
        strategy_checks::check_active_connection_id_limit::<Instant, u8, _, _>(new);
    }

    #[test]
    fn repeated_new_connection_id() {
        strategy_checks::check_repeated_new_connection_id::<Instant, u8, _, _>(new, 1);
    }

    #[test]
    fn zero_length_rejects_new_connection_id() {
        strategy_checks::check_zero_length_rejects_new_connection_id::<Instant, u8, _, _>(new);
    }

    #[test]
    fn retire_prior_to_leaves_offers() {
        strategy_checks::check_retire_prior_to_leaves_offers::<Instant, u8, _, _>(new, [1, 2]);
    }

    #[test]
    fn no_reuse_across_link_paths() {
        strategy_checks::check_no_reuse_across_link_paths::<Instant, u8, _, _>(new, [1, 2]);
    }

    #[test]
    fn token_registered_after_use() {
        strategy_checks::check_token_registered_after_use::<Instant, u8, _, _>(new, 1);
    }

    #[test]
    fn link_path_end_revokes() {
        strategy_checks::check_link_path_end_revokes::<Instant, u8, _, _>(new, [1, 2]);
    }
}

#[test]
fn nothing_is_offered_before_the_handshake_connection_id() {
    let config = SequenceMapDestinationConnectionIdStrategyConfig::new(4);
    let mut strategy = <Strategy as DestinationConnectionIdStrategy<u8, Instant, Registrar>>::new(
        &config,
        limit(2),
    );
    assert_eq!(offer(&strategy, 1), NONE);
    DestinationConnectionIdStrategy::<u8, Instant, Registrar>::on_handshake_connection_id(
        &mut strategy,
        cid(0),
    );
    assert_eq!(offer(&strategy, 1), [0]);
}

#[test]
fn a_new_handshake_connection_id_replaces_the_one_numbered_0() {
    let mut registrar = Registrar::default();
    let mut strategy = strategy(2, 4);
    used(&mut strategy, &mut registrar, 0, 1);
    assert_eq!(registrar.live(), [token(0)]);

    DestinationConnectionIdStrategy::<u8, Instant, Registrar>::on_handshake_connection_id(
        &mut strategy,
        cid(9),
    );
    // what was bound to the one replaced goes with it
    assert_eq!(registrar.live(), []);
    let offered: Vec<_> =
        DestinationConnectionIdStrategy::<u8, Instant, Registrar>::offer(&strategy, &1)
            .map(|offered| (offered.sequence, offered.id))
            .collect();
    assert_eq!(offered, [(0, cid(9))]);
    assert_eq!(pending(&strategy), NONE);
}
