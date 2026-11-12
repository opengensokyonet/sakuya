//! The registrations of stateless reset tokens.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use sakuya_wire::connection_id::StatelessResetToken;

use super::support::*;
use crate::route::reset::{StatelessResetDetector, StatelessResetTokens};

const TOKEN: [u8; StatelessResetToken::LEN] = [0x42; StatelessResetToken::LEN];

/// A datagram of no recognizable form that ends in `TOKEN`.
fn reset_datagram() -> Vec<u8> {
    let mut bytes = vec![0x40; 24];
    bytes.extend(TOKEN);
    bytes
}

fn any_link() -> TestLinkId {
    link(&local_end())
}

#[test]
fn revoking_removes_exactly_its_registration() {
    let tokens = StatelessResetTokens::new();
    let token = StatelessResetToken::new(TOKEN);
    let (first, second) = (ResetProbe::default(), ResetProbe::default());
    let revoked = tokens.register(token, first.clone());
    let kept = tokens.register(token, second.clone());
    assert!(tokens.detect(&token, &any_link()).is_some());
    drop(revoked);
    let target = tokens
        .detect(&token, &any_link())
        .expect("the second registration remains");
    crate::route::reset::StatelessResetTarget::stateless_reset_received(&target);
    assert_eq!(first.0.load(Ordering::SeqCst), 0);
    assert_eq!(second.0.load(Ordering::SeqCst), 1);
    drop(target);
    drop(kept);
    assert!(tokens.detect(&token, &any_link()).is_none());
}

#[test]
fn revoking_after_the_detector_is_gone_does_nothing() {
    let tokens = StatelessResetTokens::new();
    let registration = tokens.register(StatelessResetToken::new(TOKEN), ResetProbe::default());
    drop(tokens);
    drop(registration);
}

#[test]
fn a_revoked_token_routes_as_an_ordinary_datagram() {
    let domain = Domain::new(&[8]);
    let probe = ResetProbe::default();
    let registration = domain
        .resets
        .register(StatelessResetToken::new(TOKEN), probe.clone());
    domain.route(reset_datagram(), &any_link());
    assert_eq!(probe.0.load(Ordering::SeqCst), 1);
    drop(registration);
    domain.route(reset_datagram(), &any_link());
    assert_eq!(probe.0.load(Ordering::SeqCst), 1);
    assert!(Arc::strong_count(&domain.resets) >= 1);
}

/// RFC 9000 §10.3.1 compares the trailing bytes only with the tokens tied to
/// the remote address the datagram came from. `StatelessResetTokens` takes no
/// context when a token is registered and ignores the link when detecting, so
/// a token matches on every link.
#[test]
#[ignore = "known defect: StatelessResetTokens matches a token on every link"]
fn a_token_does_not_apply_on_an_unrelated_link() {
    let domain = Domain::new(&[8]);
    let probe = ResetProbe::default();
    // The connection that owns the token only ever used another link.
    let _registration = domain
        .resets
        .register(StatelessResetToken::new(TOKEN), probe.clone());
    domain.route(reset_datagram(), &any_link());
    assert_eq!(probe.0.load(Ordering::SeqCst), 0);
}
