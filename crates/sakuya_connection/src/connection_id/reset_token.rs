//! Registering the stateless reset tokens of the peer's connection IDs for
//! detection ([RFC 9000 §10.3.1]).
//!
//! [RFC 9000 §10.3.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3.1

use std::{fmt, hash::Hash, sync::Arc};

use sakuya_datagram_routing::route::reset::{StatelessResetRegistration, StatelessResetTokens};
use sakuya_wire::connection_id::StatelessResetToken;

/// Registers a stateless reset token so that a stateless reset carrying it
/// is detected, for the peer and target of one link path.
///
/// Whoever lends it has already chosen which peer the token applies to and
/// what a detected reset resets; the strategy only hands over the token and
/// keeps what it gets back. Dropping the registration revokes it.
pub trait ResetTokenRegistrar {
    /// Keeps the token registered until it is dropped.
    type Registration;

    /// Registers `token`.
    fn register(&mut self, token: StatelessResetToken) -> Self::Registration;
}

/// Registers tokens in routing's [`StatelessResetTokens`], which groups them
/// by the peer they apply to, for one peer and one target.
///
/// The same token registered twice for one peer through two link paths is
/// two registrations; a detected reset finds the first, and each is revoked
/// on its own.
pub struct PeerGroupedResetTokenRegistrar<Peer: Clone + Eq + Hash, Target> {
    tokens: Arc<StatelessResetTokens<Peer, Target>>,
    peer: Peer,
    target: Target,
}

impl<Peer: Clone + Eq + Hash, Target> PeerGroupedResetTokenRegistrar<Peer, Target> {
    /// Registers in `tokens` for datagrams from `peer`, resetting `target`.
    pub fn new(
        tokens: Arc<StatelessResetTokens<Peer, Target>>,
        peer: Peer,
        target: Target,
    ) -> Self {
        Self {
            tokens,
            peer,
            target,
        }
    }
}

impl<Peer: Clone + Eq + Hash, Target: Clone> ResetTokenRegistrar
    for PeerGroupedResetTokenRegistrar<Peer, Target>
{
    type Registration = StatelessResetRegistration<Peer, Target>;

    fn register(&mut self, token: StatelessResetToken) -> Self::Registration {
        self.tokens
            .register(self.peer.clone(), token, self.target.clone())
    }
}

impl<Peer: Clone + Eq + Hash, Target> fmt::Debug for PeerGroupedResetTokenRegistrar<Peer, Target> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerGroupedResetTokenRegistrar")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
