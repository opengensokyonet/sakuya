//! The registrations of stateless reset tokens.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use sakuya_link::{BindingId, Link as _, LinkId};
use sakuya_wire::connection_id::StatelessResetToken;

use super::support::*;
use crate::route::reset::{StatelessResetDetector, StatelessResetTarget, StatelessResetTokens};

const TOKEN: [u8; StatelessResetToken::LEN] = [0x42; StatelessResetToken::LEN];

/// A datagram of no recognizable form that ends in `TOKEN`.
fn reset_datagram() -> Vec<u8> {
    let mut bytes = vec![0x40; 24];
    bytes.extend(TOKEN);
    bytes
}

fn any_link() -> TestLink {
    link(&local_end())
}

/// A link from `peer` to a local end no other link has.
fn link_from(peer: Peer) -> TestLink {
    TestLink::new(LinkId::new::<TestLink>(
        local_end(),
        peer,
        &BindingId::new(),
    ))
}

#[test]
fn revoking_removes_exactly_its_registration() {
    let tokens = StatelessResetTokens::new();
    let token = StatelessResetToken::new(TOKEN);
    let link = any_link();
    let (first, second) = (ResetProbe::default(), ResetProbe::default());
    let revoked = tokens.register(link.id().peer, token, first.clone());
    let kept = tokens.register(link.id().peer, token, second.clone());
    assert!(tokens.detect(&token, link.id()).is_some());
    drop(revoked);
    let target = tokens
        .detect(&token, link.id())
        .expect("the second registration remains");
    target.stateless_reset_received();
    assert_eq!(first.0.load(Ordering::SeqCst), 0);
    assert_eq!(second.0.load(Ordering::SeqCst), 1);
    drop(target);
    drop(kept);
    assert!(tokens.detect(&token, link.id()).is_none());
}

#[test]
fn revoking_after_the_detector_is_gone_does_nothing() {
    let tokens = StatelessResetTokens::new();
    let registration = tokens.register(
        any_link().id().peer,
        StatelessResetToken::new(TOKEN),
        ResetProbe::default(),
    );
    drop(tokens);
    drop(registration);
}

#[test]
fn a_revoked_token_routes_as_an_ordinary_datagram() {
    let domain = Domain::new(&[8]);
    let probe = ResetProbe::default();
    let link = any_link();
    let registration = domain.resets.register(
        link.id().peer,
        StatelessResetToken::new(TOKEN),
        probe.clone(),
    );
    domain.route(reset_datagram(), &link);
    assert_eq!(probe.0.load(Ordering::SeqCst), 1);
    drop(registration);
    domain.route(reset_datagram(), &link);
    assert_eq!(probe.0.load(Ordering::SeqCst), 1);
    assert!(Arc::strong_count(&domain.resets) >= 1);
}

/// RFC 9000 §10.3.1 compares the trailing bytes only with the tokens tied to
/// the remote end the datagram came from.
#[test]
fn a_token_does_not_apply_on_an_unrelated_link() {
    let domain = Domain::new(&[8]);
    let probe = ResetProbe::default();
    // The connection that owns the token only ever used another link.
    let _registration = domain.resets.register(
        any_link().id().peer,
        StatelessResetToken::new(TOKEN),
        probe.clone(),
    );
    domain.route(reset_datagram(), &any_link());
    assert_eq!(probe.0.load(Ordering::SeqCst), 0);
}

/// The comparison looks only at the remote end: the same peer reached
/// through another local end still matches.
#[test]
fn a_token_applies_to_its_peer_through_another_local_end() {
    let domain = Domain::new(&[8]);
    let probe = ResetProbe::default();
    let registered_on = any_link();
    let _registration = domain.resets.register(
        registered_on.id().peer,
        StatelessResetToken::new(TOKEN),
        probe.clone(),
    );
    let arrived_on = link_from(registered_on.id().peer);
    assert_ne!(arrived_on.id().local, registered_on.id().local);
    domain.route(reset_datagram(), &arrived_on);
    assert_eq!(probe.0.load(Ordering::SeqCst), 1);
}

/// One token value registered for two peers resolves, on each peer, to the
/// target registered for that peer.
#[test]
fn the_same_token_on_two_peers_resets_the_target_of_the_arriving_peer() {
    let tokens = StatelessResetTokens::new();
    let token = StatelessResetToken::new(TOKEN);
    let (one, other) = (any_link(), any_link());
    let (one_probe, other_probe) = (ResetProbe::default(), ResetProbe::default());
    let _one = tokens.register(one.id().peer, token, one_probe.clone());
    let _other = tokens.register(other.id().peer, token, other_probe.clone());
    tokens
        .detect(&token, other.id())
        .expect("registered for this peer")
        .stateless_reset_received();
    assert_eq!(one_probe.0.load(Ordering::SeqCst), 0);
    assert_eq!(other_probe.0.load(Ordering::SeqCst), 1);
}
