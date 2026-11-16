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

#[derive(Default)]
struct Published(Vec<u64>);

impl PublishIntent<NewConnectionIdIntent, ()> for Published {
    fn publish(&mut self, intent: NewConnectionIdIntent) {
        self.0.push(intent.sequence());
    }
}

type Strategy = SequenceMapLocalConnectionIdStrategy<u8, Duration>;

fn first() -> Option<(NonEmptyCid, StatelessResetToken)> {
    Some((
        NonEmptyCid::new(ConnectionId::new(&[0xaa; 8]).unwrap()).unwrap(),
        StatelessResetToken::new([0xaa; 16]),
    ))
}

fn local(strategy: &mut Strategy) -> &mut impl LocalConnectionIdStrategy<(), Duration, u8> {
    strategy
}

fn confirmed(limit: u64) -> (Strategy, CountingIssuer, Published) {
    let mut strategy = Strategy::new(first(), Some(0));
    let mut issuer = CountingIssuer::default();
    let mut published = Published::default();
    local(&mut strategy).on_issuable(&mut issuer, &mut published, 2);
    assert!(
        published.0.is_empty(),
        "nothing before the handshake is confirmed"
    );
    local(&mut strategy).on_issuable(&mut issuer, &mut published, limit);
    local(&mut strategy).on_handshake_confirmed(&mut issuer, &mut published);
    (strategy, issuer, published)
}

#[test]
fn it_issues_up_to_the_smaller_limit_once_confirmed() {
    let (strategy, _, published) = confirmed(8);
    assert_eq!(published.0, [1, 2, 3]);
    assert_eq!(strategy.active().count(), 4);
    let (strategy, _, published) = confirmed(2);
    assert_eq!(published.0, [1]);
    assert_eq!(strategy.active().count(), 2);
}

#[test]
fn a_retired_one_is_replaced_and_deregistered_after_three_probe_timeouts() {
    let (mut strategy, mut issuer, mut published) = confirmed(8);
    let pto = Duration::from_millis(100);
    let now = Duration::from_secs(1);
    let other = ConnectionId::new(&[2; 8]).unwrap();
    local(&mut strategy)
        .on_retired_by_peer(&mut issuer, &mut published, 1, &other, now, pto)
        .unwrap();
    assert_eq!(published.0, [1, 2, 3, 4], "one more is issued");
    assert!(strategy.is_registered(1));
    assert_eq!(
        LocalConnectionIdStrategy::<(), _, u8>::next_deadline(&strategy),
        Some(now + pto * 3)
    );
    local(&mut strategy).on_deadline(&mut issuer, &mut published, now + pto * 3);
    assert!(!strategy.is_registered(1));
    // the frame repeated after the registration was dropped
    local(&mut strategy)
        .on_retired_by_peer(&mut issuer, &mut published, 1, &other, now, pto)
        .unwrap();
    assert_eq!(published.0, [1, 2, 3, 4]);
}

#[test]
fn retiring_what_was_never_issued_or_its_own_destination_is_a_violation() {
    let (mut strategy, mut issuer, mut published) = confirmed(8);
    let pto = Duration::from_millis(100);
    let other = ConnectionId::new(&[9; 8]).unwrap();
    assert_eq!(
        local(&mut strategy).on_retired_by_peer(&mut issuer, &mut published, 4, &other, pto, pto),
        Err(RetiredByPeerViolationError::NotIssued { sequence: 4 })
    );
    let own = ConnectionId::new(&[2; 8]).unwrap();
    assert_eq!(
        local(&mut strategy).on_retired_by_peer(&mut issuer, &mut published, 2, &own, pto, pto),
        Err(RetiredByPeerViolationError::RetiresItsPacketsDestination { sequence: 2 })
    );
}

#[test]
fn a_zero_length_connection_issues_nothing_and_takes_no_retirement() {
    let mut strategy = Strategy::new(None, None);
    let mut issuer = CountingIssuer::default();
    let mut published = Published::default();
    local(&mut strategy).on_issuable(&mut issuer, &mut published, 8);
    local(&mut strategy).on_handshake_confirmed(&mut issuer, &mut published);
    assert!(published.0.is_empty());
    assert_eq!(
        local(&mut strategy).on_retired_by_peer(
            &mut issuer,
            &mut published,
            0,
            &ConnectionId::EMPTY,
            Duration::ZERO,
            Duration::ZERO
        ),
        Err(RetiredByPeerViolationError::ZeroLength)
    );
}

#[test]
fn a_lost_frame_is_published_again_until_acknowledged_or_retired() {
    let (mut strategy, _, _) = confirmed(8);
    let mut again = Published::default();
    strategy.lost(
        &mut again,
        PacketNumberSpaceKind::ApplicationData,
        &NewConnectionIdSummary { sequence: 2 },
    );
    assert_eq!(again.0, [2]);
    strategy.delivered(
        &mut again,
        PacketNumberSpaceKind::ApplicationData,
        NewConnectionIdSummary { sequence: 2 },
    );
    strategy.lost(
        &mut again,
        PacketNumberSpaceKind::ApplicationData,
        &NewConnectionIdSummary { sequence: 2 },
    );
    assert_eq!(again.0, [2], "not again once acknowledged");
}

#[test]
fn the_frame_carries_the_issued_values_and_retire_prior_to_zero() {
    let id = NonEmptyCid::new(ConnectionId::new(&[3; 8]).unwrap()).unwrap();
    let frame = new_connection_id_frame(3, id, StatelessResetToken::new([3; 16]));
    assert_eq!(frame.sequence_number().get().get(), 3);
    assert_eq!(frame.retire_prior_to().get().get(), 0);
}
