//! Registering through routing's peer-grouped token table.

use sakuya_datagram_routing::route::reset::{StatelessResetDetector, StatelessResetTarget};
use sakuya_link::{BindingId, LinkId};

use super::*;

/// A target that does nothing when reset.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Target(u8);

impl StatelessResetTarget for Target {
    fn stateless_reset_received(&self) {}
}

const TOKEN: StatelessResetToken = StatelessResetToken::new([7; 16]);

#[test]
fn registers_for_its_peer_until_the_registration_is_dropped() {
    let tokens = StatelessResetTokens::<u16, Target>::new();
    let binding = BindingId::new();
    let from_peer = LinkId::new::<()>(1u8, 443u16, &binding);
    let from_other = LinkId::new::<()>(1u8, 444u16, &binding);
    let mut registrar = PeerGroupedResetTokenRegistrar::new(Arc::clone(&tokens), 443, Target(1));

    let registration = registrar.register(TOKEN);
    assert_eq!(
        tokens.detect(&TOKEN, &from_peer).as_deref(),
        Some(&Target(1))
    );
    assert!(tokens.detect(&TOKEN, &from_other).is_none());

    drop(registration);
    assert!(tokens.detect(&TOKEN, &from_peer).is_none());
}

#[test]
fn each_registration_is_revoked_on_its_own() {
    let tokens = StatelessResetTokens::<u16, Target>::new();
    let binding = BindingId::new();
    let from_peer = LinkId::new::<()>(1u8, 443u16, &binding);
    let mut first = PeerGroupedResetTokenRegistrar::new(Arc::clone(&tokens), 443, Target(1));
    let mut second = PeerGroupedResetTokenRegistrar::new(Arc::clone(&tokens), 443, Target(1));

    let kept = first.register(TOKEN);
    drop(second.register(TOKEN));
    assert!(tokens.detect(&TOKEN, &from_peer).is_some());
    drop(kept);
    assert!(tokens.detect(&TOKEN, &from_peer).is_none());
}
