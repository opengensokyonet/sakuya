use core::time::Duration;
use std::cell::Cell;

use super::*;

/// Issues connection IDs `[n; 8]` for n = 1, 2, …, with token `[n; 16]`;
/// a registration is its number.
#[derive(Default)]
struct CountingIssuer(Cell<u8>);

impl ConnectionIdIssuer for CountingIssuer {
    type Registration = u8;
    fn issue(&mut self) -> IssuedConnectionId<u8> {
        let n = self.0.get() + 1;
        self.0.set(n);
        IssuedConnectionId {
            id: NonEmptyCid::new(ConnectionId::new(&[n; 8]).unwrap()).unwrap(),
            token: StatelessResetToken::new([n; 16]),
            registration: n,
        }
    }
}

type Strategy = SequenceMapLocalConnectionIdStrategy<u8, Duration>;

fn first() -> Option<IssuedConnectionId<u8>> {
    Some(IssuedConnectionId {
        id: NonEmptyCid::new(ConnectionId::new(&[0xaa; 8]).unwrap()).unwrap(),
        token: StatelessResetToken::new([0xaa; 16]),
        registration: 0,
    })
}

fn local(strategy: &mut Strategy) -> &mut impl LocalConnectionIdStrategy<(), Duration, u8> {
    strategy
}

fn made(first: Option<IssuedConnectionId<u8>>) -> Strategy {
    <Strategy as LocalConnectionIdStrategy<(), Duration, u8>>::new(first)
}

/// The sequence numbers whose NEW_CONNECTION_ID frame waits to be sent, in
/// order; each is then taken as written, as the sending call would write
/// it.
fn written(strategy: &mut Strategy) -> Vec<u64> {
    let waiting: Vec<u64> = local(strategy)
        .waiting_disclosures()
        .map(|disclosure| disclosure.sequence())
        .collect();
    for sequence in &waiting {
        let issued = strategy
            .issued
            .as_mut()
            .and_then(|issued| issued.get_mut(sequence))
            .expect("a waiting disclosure is issued");
        issued.disclosure = Disclosure::InFlight;
    }
    waiting
}

fn confirmed(limit: u64) -> (Strategy, CountingIssuer) {
    let mut strategy = made(first());
    let mut issuer = CountingIssuer::default();
    local(&mut strategy).on_issuable(&mut issuer, 2);
    assert!(
        written(&mut strategy).is_empty(),
        "nothing before the handshake is confirmed"
    );
    local(&mut strategy).on_issuable(&mut issuer, limit);
    local(&mut strategy).on_handshake_confirmed(&mut issuer);
    (strategy, issuer)
}

#[test]
fn it_issues_up_to_the_smaller_limit_once_confirmed() {
    let (mut strategy, _) = confirmed(8);
    assert_eq!(written(&mut strategy), [1, 2, 3]);
    assert_eq!(strategy.active().count(), 4);
    let (mut strategy, _) = confirmed(2);
    assert_eq!(written(&mut strategy), [1]);
    assert_eq!(strategy.active().count(), 2);
}

#[test]
fn a_retired_one_is_replaced_and_deregistered_after_three_probe_timeouts() {
    let (mut strategy, mut issuer) = confirmed(8);
    assert_eq!(written(&mut strategy), [1, 2, 3]);
    let pto = Duration::from_millis(100);
    let now = Duration::from_secs(1);
    let other = ConnectionId::new(&[2; 8]).unwrap();
    local(&mut strategy)
        .on_retired_by_peer(&mut issuer, 1, &other, now, pto)
        .unwrap();
    assert_eq!(written(&mut strategy), [4], "one more is issued");
    assert!(strategy.is_registered(1));
    assert_eq!(
        LocalConnectionIdStrategy::<(), _, u8>::next_deadline(&strategy),
        Some(now + pto * 3)
    );
    local(&mut strategy).on_deadline(&mut issuer, now + pto * 3);
    assert!(!strategy.is_registered(1));
    // the frame repeated after the registration was dropped
    local(&mut strategy)
        .on_retired_by_peer(&mut issuer, 1, &other, now, pto)
        .unwrap();
    assert!(written(&mut strategy).is_empty());
}

#[test]
fn retiring_what_was_never_issued_or_its_own_destination_is_a_violation() {
    let (mut strategy, mut issuer) = confirmed(8);
    let pto = Duration::from_millis(100);
    let other = ConnectionId::new(&[9; 8]).unwrap();
    assert_eq!(
        local(&mut strategy).on_retired_by_peer(&mut issuer, 4, &other, pto, pto),
        Err(RetiredByPeerViolationError::NotIssued { sequence: 4 })
    );
    let own = ConnectionId::new(&[2; 8]).unwrap();
    assert_eq!(
        local(&mut strategy).on_retired_by_peer(&mut issuer, 2, &own, pto, pto),
        Err(RetiredByPeerViolationError::RetiresItsPacketsDestination { sequence: 2 })
    );
}

#[test]
fn a_zero_length_connection_issues_nothing_and_takes_no_retirement() {
    let mut strategy = made(None);
    let mut issuer = CountingIssuer::default();
    local(&mut strategy).on_issuable(&mut issuer, 8);
    local(&mut strategy).on_handshake_confirmed(&mut issuer);
    assert!(written(&mut strategy).is_empty());
    assert_eq!(
        local(&mut strategy).on_retired_by_peer(
            &mut issuer,
            0,
            &ConnectionId::EMPTY,
            Duration::ZERO,
            Duration::ZERO
        ),
        Err(RetiredByPeerViolationError::ZeroLength)
    );
}

#[test]
fn a_lost_frame_waits_again_until_acknowledged_or_retired() {
    let (mut strategy, mut issuer) = confirmed(8);
    assert_eq!(written(&mut strategy), [1, 2, 3]);
    strategy.lost(
        &mut (),
        PacketNumberSpaceKind::ApplicationData,
        &NewConnectionIdSummary { sequence: 2 },
    );
    assert_eq!(written(&mut strategy), [2]);
    strategy.delivered(
        &mut (),
        PacketNumberSpaceKind::ApplicationData,
        NewConnectionIdSummary { sequence: 2 },
    );
    strategy.lost(
        &mut (),
        PacketNumberSpaceKind::ApplicationData,
        &NewConnectionIdSummary { sequence: 2 },
    );
    assert!(
        written(&mut strategy).is_empty(),
        "not again once acknowledged"
    );
    // one retired by the peer while its frame is in flight
    let pto = Duration::from_millis(100);
    let other = ConnectionId::new(&[9; 8]).unwrap();
    local(&mut strategy)
        .on_retired_by_peer(&mut issuer, 3, &other, pto, pto)
        .unwrap();
    assert_eq!(written(&mut strategy), [4], "its replacement");
    strategy.lost(
        &mut (),
        PacketNumberSpaceKind::ApplicationData,
        &NewConnectionIdSummary { sequence: 3 },
    );
    assert!(written(&mut strategy).is_empty(), "not again once retired");
}

#[test]
fn the_frame_carries_the_issued_values_and_retire_prior_to_zero() {
    let id = NonEmptyCid::new(ConnectionId::new(&[3; 8]).unwrap()).unwrap();
    let frame = new_connection_id_frame(3, id, StatelessResetToken::new([3; 16]));
    assert_eq!(frame.sequence_number().get().get(), 3);
    assert_eq!(frame.retire_prior_to().get().get(), 0);
}
