//! Checks of a destination connection ID strategy against the contract the
//! protocol sets for it.
//!
//! Each check builds a fresh strategy, feeds it a fixed script of events
//! and panics with a message when the strategy breaks the contract, so a
//! test of any implementation calls them directly. The strategy is built by
//! a closure from the peer's handshake connection ID (sequence number 0),
//! its reset token, and this side's `active_connection_id_limit`; the
//! checks register tokens through a [`RecordingResetTokenRegistrar`], so
//! the strategy must accept that registrar. Link paths are the two
//! distinct identities the caller passes.
//!
//! Connection IDs are chosen as the sending call chooses them, through
//! [`DatagramConnectionId::choose_first`] with the first offered one.

use std::sync::{Arc, Mutex, PoisonError};

use sakuya_wire::{
    connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken},
    v1::{
        frame::new_connection_id::NewConnectionIdFrame, transport_error::TransportErrorCode,
        transport_parameters::integer::ActiveConnectionIdLimit,
    },
    var_int::{VarInt, VarIntField},
};

use super::{
    DestinationConnectionIdStrategy, OfferedConnectionId, ResetTokenRegistrar,
    datagram::DatagramConnectionId,
};
use crate::v1::datagram_batch::ConnectionIdUse as _;

/// A registrar that records which tokens are registered through it and not
/// yet revoked.
#[derive(Debug, Default)]
pub struct RecordingResetTokenRegistrar {
    live: Arc<Mutex<Vec<StatelessResetToken>>>,
}

impl RecordingResetTokenRegistrar {
    /// A registrar with nothing registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `token` is registered through this registrar.
    pub fn is_registered(&self, token: StatelessResetToken) -> bool {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&token)
    }
}

impl ResetTokenRegistrar for RecordingResetTokenRegistrar {
    type Registration = RecordedResetTokenRegistration;

    fn register(&mut self, token: StatelessResetToken) -> RecordedResetTokenRegistration {
        self.live
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(token);
        RecordedResetTokenRegistration {
            live: Arc::clone(&self.live),
            token,
        }
    }
}

/// One token registered through a [`RecordingResetTokenRegistrar`];
/// dropping it revokes that registration.
#[derive(Debug)]
pub struct RecordedResetTokenRegistration {
    live: Arc<Mutex<Vec<StatelessResetToken>>>,
    token: StatelessResetToken,
}

impl Drop for RecordedResetTokenRegistration {
    fn drop(&mut self) {
        let mut live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(position) = live.iter().position(|token| *token == self.token) {
            live.remove(position);
        }
    }
}

/// The connection ID the scripts give the sequence number `sequence`.
pub fn connection_id(sequence: u8) -> ConnectionId {
    ConnectionId::new(&[sequence.wrapping_add(0x10); 8])
        .expect("eight bytes are within the version 1 limit")
}

/// The reset token the scripts give the sequence number `sequence`.
pub fn reset_token(sequence: u8) -> StatelessResetToken {
    StatelessResetToken::new([sequence.wrapping_add(0x80); StatelessResetToken::LEN])
}

/// A NEW_CONNECTION_ID frame for the scripts' connection ID with
/// `sequence`, retiring prior to `retire_prior_to`.
///
/// # Panics
///
/// Panics if `retire_prior_to` exceeds `sequence`.
pub fn new_connection_id(sequence: u8, retire_prior_to: u8) -> NewConnectionIdFrame {
    let id =
        NonEmptyCid::new(connection_id(sequence)).expect("script connection IDs are not empty");
    NewConnectionIdFrame::new(
        VarIntField::shortest(VarInt::from(sequence)),
        VarIntField::shortest(VarInt::from(retire_prior_to)),
        id,
        reset_token(sequence),
    )
    .expect("scripts retire prior to at most the sequence number")
}

fn limit(value: u8) -> ActiveConnectionIdLimit {
    ActiveConnectionIdLimit::new(VarInt::from(value)).expect("scripts use limits of at least 2")
}

fn sequences<I, Id, S>(strategy: &S, link_path: &Id) -> Vec<u64>
where
    S: DestinationConnectionIdStrategy<Id, I, RecordingResetTokenRegistrar>,
{
    strategy
        .offer(link_path)
        .map(|offered| offered.sequence)
        .collect()
}

/// Chooses the first offered connection ID for `link_path` and seals a
/// datagram with it.
fn send<I, Id, S>(
    strategy: &mut S,
    registrar: &mut RecordingResetTokenRegistrar,
    link_path: &Id,
) -> OfferedConnectionId
where
    S: DestinationConnectionIdStrategy<Id, I, RecordingResetTokenRegistrar>,
{
    let chosen = DatagramConnectionId::<S, RecordingResetTokenRegistrar, Id, I>::choose_first(
        strategy,
        registrar,
        link_path,
        |_| true,
    )
    .expect("the strategy offers a connection ID");
    let offered = chosen.offered();
    chosen.used(1200);
    offered
}

fn accept<I, Id, S>(strategy: &mut S, frame: NewConnectionIdFrame)
where
    S: DestinationConnectionIdStrategy<Id, I, RecordingResetTokenRegistrar>,
{
    if let Err(error) = strategy.on_new_connection_id(&frame) {
        panic!("a valid NEW_CONNECTION_ID was rejected: {error}");
    }
}

fn reject<I, Id, S>(strategy: &mut S, frame: NewConnectionIdFrame) -> TransportErrorCode
where
    S: DestinationConnectionIdStrategy<Id, I, RecordingResetTokenRegistrar>,
{
    match strategy.on_new_connection_id(&frame) {
        Ok(()) => panic!("a violating NEW_CONNECTION_ID was accepted: {frame:?}"),
        Err(error) => error.transport_error_code(),
    }
}

/// More active connection IDs than `active_connection_id_limit` after a
/// NEW_CONNECTION_ID frame is a CONNECTION_ID_LIMIT_ERROR; the limit is
/// checked after the frame's Retire Prior To retired what it passes
/// (RFC 9000 §5.1.1, §5.1.2).
///
/// # Panics
///
/// Panics when the strategy breaks the contract.
pub fn check_active_connection_id_limit<I, Id, S, New>(new: New)
where
    S: DestinationConnectionIdStrategy<Id, I, RecordingResetTokenRegistrar>,
    New: Fn(ConnectionId, Option<StatelessResetToken>, ActiveConnectionIdLimit) -> S,
{
    let mut strategy = new(connection_id(0), Some(reset_token(0)), limit(2));
    accept(&mut strategy, new_connection_id(1, 0));
    assert_eq!(
        reject(&mut strategy, new_connection_id(2, 0)),
        TransportErrorCode::CONNECTION_ID_LIMIT_ERROR,
        "a third active connection ID exceeds a limit of 2"
    );

    let mut strategy = new(connection_id(0), Some(reset_token(0)), limit(2));
    accept(&mut strategy, new_connection_id(1, 0));
    accept(&mut strategy, new_connection_id(2, 1));
    accept(&mut strategy, new_connection_id(3, 3));
}

/// A repeated NEW_CONNECTION_ID frame is no violation and adds nothing
/// (RFC 9000 §19.15).
///
/// # Panics
///
/// Panics when the strategy breaks the contract.
pub fn check_repeated_new_connection_id<I, Id, S, New>(new: New, link_path: Id)
where
    S: DestinationConnectionIdStrategy<Id, I, RecordingResetTokenRegistrar>,
    New: Fn(ConnectionId, Option<StatelessResetToken>, ActiveConnectionIdLimit) -> S,
{
    let mut strategy = new(connection_id(0), Some(reset_token(0)), limit(2));
    accept(&mut strategy, new_connection_id(1, 0));
    accept(&mut strategy, new_connection_id(1, 0));
    let offered = sequences(&strategy, &link_path);
    assert_eq!(
        offered.iter().filter(|&&sequence| sequence == 1).count(),
        1,
        "a repeated connection ID is offered once: {offered:?}"
    );
}

/// With a zero-length handshake connection ID, any NEW_CONNECTION_ID frame
/// is a PROTOCOL_VIOLATION (RFC 9000 §19.15).
///
/// # Panics
///
/// Panics when the strategy breaks the contract.
pub fn check_zero_length_rejects_new_connection_id<I, Id, S, New>(new: New)
where
    S: DestinationConnectionIdStrategy<Id, I, RecordingResetTokenRegistrar>,
    New: Fn(ConnectionId, Option<StatelessResetToken>, ActiveConnectionIdLimit) -> S,
{
    let mut strategy = new(ConnectionId::EMPTY, None, limit(2));
    assert_eq!(
        reject(&mut strategy, new_connection_id(1, 0)),
        TransportErrorCode::PROTOCOL_VIOLATION
    );
}

/// Once Retire Prior To passes a connection ID, it leaves every offer and
/// its token registration is revoked (RFC 9000 §5.1.2, §10.3.1).
///
/// # Panics
///
/// Panics when the strategy breaks the contract.
pub fn check_retire_prior_to_leaves_offers<I, Id, S, New>(new: New, link_paths: [Id; 2])
where
    S: DestinationConnectionIdStrategy<Id, I, RecordingResetTokenRegistrar>,
    New: Fn(ConnectionId, Option<StatelessResetToken>, ActiveConnectionIdLimit) -> S,
{
    let [first, second] = link_paths;
    let mut registrar = RecordingResetTokenRegistrar::new();
    let mut strategy = new(connection_id(0), Some(reset_token(0)), limit(4));
    strategy.on_link_path_added(&first, true);
    accept(&mut strategy, new_connection_id(1, 0));
    accept(&mut strategy, new_connection_id(2, 0));
    let used = send(&mut strategy, &mut registrar, &first);
    let used_sequence =
        u8::try_from(used.sequence).expect("the script has sequence numbers below 3");

    accept(&mut strategy, new_connection_id(9, used_sequence + 1));
    for link_path in [&first, &second] {
        let offered = sequences(&strategy, link_path);
        assert!(
            offered.iter().all(|&sequence| sequence > used.sequence),
            "connection IDs below Retire Prior To {} are still offered: {offered:?}",
            used_sequence + 1
        );
    }
    assert!(
        !registrar.is_registered(reset_token(used_sequence)),
        "the token of a retired connection ID is still registered"
    );
}

/// A connection ID used on one link path is never offered for another,
/// whose peer switched connection IDs (RFC 9000 §9.5).
///
/// # Panics
///
/// Panics when the strategy breaks the contract.
pub fn check_no_reuse_across_link_paths<I, Id, S, New>(new: New, link_paths: [Id; 2])
where
    S: DestinationConnectionIdStrategy<Id, I, RecordingResetTokenRegistrar>,
    New: Fn(ConnectionId, Option<StatelessResetToken>, ActiveConnectionIdLimit) -> S,
{
    let [first, second] = link_paths;
    let mut first_registrar = RecordingResetTokenRegistrar::new();
    let mut second_registrar = RecordingResetTokenRegistrar::new();
    let mut strategy = new(connection_id(0), Some(reset_token(0)), limit(4));
    strategy.on_link_path_added(&first, true);
    accept(&mut strategy, new_connection_id(1, 0));
    accept(&mut strategy, new_connection_id(2, 0));
    accept(&mut strategy, new_connection_id(3, 0));

    let on_first = send(&mut strategy, &mut first_registrar, &first);
    strategy.on_link_path_added(&second, true);
    let offered = sequences(&strategy, &second);
    assert!(
        !offered.contains(&on_first.sequence),
        "connection ID {} used on one link path is offered for another: {offered:?}",
        on_first.sequence
    );
    let on_second = send(&mut strategy, &mut second_registrar, &second);
    let offered = sequences(&strategy, &first);
    assert!(
        !offered.contains(&on_second.sequence),
        "connection ID {} used on one link path is offered for another: {offered:?}",
        on_second.sequence
    );
}

/// A token is registered only once its connection ID was used: offering
/// it, or choosing it for a datagram that stays empty, registers nothing
/// (RFC 9000 §10.3.1).
///
/// # Panics
///
/// Panics when the strategy breaks the contract.
pub fn check_token_registered_after_use<I, Id, S, New>(new: New, link_path: Id)
where
    S: DestinationConnectionIdStrategy<Id, I, RecordingResetTokenRegistrar>,
    New: Fn(ConnectionId, Option<StatelessResetToken>, ActiveConnectionIdLimit) -> S,
{
    let mut registrar = RecordingResetTokenRegistrar::new();
    let mut strategy = new(connection_id(0), Some(reset_token(0)), limit(3));
    strategy.on_link_path_added(&link_path, true);
    accept(&mut strategy, new_connection_id(1, 0));
    accept(&mut strategy, new_connection_id(2, 0));

    drop(sequences(&strategy, &link_path));
    // Chosen for a datagram that stays empty: dropped unused.
    let _ = DatagramConnectionId::<S, RecordingResetTokenRegistrar, Id, I>::choose_first(
        &mut strategy,
        &mut registrar,
        &link_path,
        |_| true,
    );
    assert!(
        !(0..3).any(|sequence| registrar.is_registered(reset_token(sequence))),
        "a token is registered before its connection ID was used"
    );

    let used = send(&mut strategy, &mut registrar, &link_path);
    let used_sequence =
        u8::try_from(used.sequence).expect("the script has sequence numbers below 3");
    assert!(
        registrar.is_registered(reset_token(used_sequence)),
        "the token of a used connection ID is not registered"
    );
}

/// The registration of a used connection ID's token is revoked when its
/// link path ends (RFC 9000 §10.3.1).
///
/// # Panics
///
/// Panics when the strategy breaks the contract.
pub fn check_link_path_end_revokes<I, Id, S, New>(new: New, link_paths: [Id; 2])
where
    S: DestinationConnectionIdStrategy<Id, I, RecordingResetTokenRegistrar>,
    New: Fn(ConnectionId, Option<StatelessResetToken>, ActiveConnectionIdLimit) -> S,
{
    let [first, second] = link_paths;
    let mut first_registrar = RecordingResetTokenRegistrar::new();
    let mut second_registrar = RecordingResetTokenRegistrar::new();
    let mut strategy = new(connection_id(0), Some(reset_token(0)), limit(3));
    strategy.on_link_path_added(&first, true);
    accept(&mut strategy, new_connection_id(1, 0));
    accept(&mut strategy, new_connection_id(2, 0));
    let on_first = send(&mut strategy, &mut first_registrar, &first);
    strategy.on_link_path_added(&second, true);
    let on_second = send(&mut strategy, &mut second_registrar, &second);
    let first_token = reset_token(u8::try_from(on_first.sequence).expect("below 3"));
    let second_token = reset_token(u8::try_from(on_second.sequence).expect("below 3"));

    strategy.on_link_path_ended(&first);
    assert!(
        !first_registrar.is_registered(first_token),
        "the token registered for an ended link path is still registered"
    );
    assert!(
        second_registrar.is_registered(second_token),
        "ending one link path revoked the registration of another"
    );
}
