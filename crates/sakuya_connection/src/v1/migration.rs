//! Connection migration on a logical path (RFC 9000 §9): which packets
//! from a logical link with no link path make one, and when the active link
//! path changes.
//!
//! The migration policy ([`MigrationPolicy`]) is a data component of each
//! logical path, inside its [`ConnectionMigration`]. The host picks its type
//! ([`HostChoices::MigrationPolicy`](super::HostChoices::MigrationPolicy)),
//! which only has to be [`Default`] there; what it implements is asked where
//! version 1 uses it. It answers six questions, and the fixed part does
//! the rest:
//!
//! - [`admit`](MigrationPolicy::admit): a packet arrived over a logical link
//!   with no link path in the logical path, and opened, and is no
//!   duplicate. Accepting builds a `Candidate` link path over the link and
//!   first ends the link paths the answer names; dropping drops every packet
//!   of the datagram for the connection: nothing is built or recorded, the
//!   datagram counts toward no anti-amplification limit, and no stateless
//!   reset is sent (RFC 9000 §9).
//! - [`on_peer_moved`](MigrationPolicy::on_peer_moved): the non-probing
//!   packet of the highest number arrived on a link path that is neither
//!   active nor validated: switch to it now or once it is validated, with
//!   the recovery layer of the active one or a new one.
//! - [`challenge_timing`](MigrationPolicy::challenge_timing): when a
//!   PATH_CHALLENGE is sent again, and when path validation gives up.
//! - [`settling_for`](MigrationPolicy::settling_for): how long a link path
//!   that enters `Settling` keeps.
//! - [`choose_preferred_address`](MigrationPolicy::choose_preferred_address):
//!   a client whose server gave a preferred address: which of its addresses
//!   to validate and migrate to, if any (RFC 9000 §9.6.1).
//! - [`on_old_local_address`](MigrationPolicy::on_old_local_address): a
//!   packet arrived at a local end the active link path moved away from, as
//!   a server's does once it moved to its preferred address: drop it, or
//!   process it, and whether it may switch back (§9.6.2).
//!
//! What the fixed part keeps to:
//!
//! - Only a server builds link paths for new logical links, for 1-RTT
//!   packets only: a client discards packets from a server address it does
//!   not know (RFC 9000 §9), and the set of link paths changes only once
//!   the handshake completed. Nothing is built once the connection closes.
//! - The active link path and the fallback are never ended by an admission.
//!   The fallback is the link path validated last, while the active one is
//!   not validated: path validation of the active one failing reverts to it
//!   (RFC 9000 §9.3.2).
//! - Only the non-probing packet of the highest number moves the active link
//!   path (RFC 9000 §9.3). One that arrives on a validated link path, a
//!   `Settling` one or the fallback among the candidates, switches back to
//!   it without asking the policy (§9.3, §9.3.2).
//! - The recovery layer moves only with a [`SameNetworkAddressChange`] of
//!   exactly the two link paths of the switch; any other answer gets the new
//!   active link path a new recovery layer (RFC 9000 §9.4: resetting is
//!   always allowed, keeping only when the network address stayed). A link
//!   path that has a recovery layer already, a `Settling` one, keeps its
//!   own.
//! - The link path that stops being active enters `Candidate` when its
//!   recovery layer moved away, and `Settling` otherwise, for as long as
//!   the policy says; while it is the fallback, the path validation of the
//!   new active link path holds it until that validation gives up.
//! - A switch to a link path whose address is not validated validates both
//!   link paths: a PATH_CHALLENGE becomes due on the new active one and on
//!   the one it took over from (RFC 9000 §9.3, §9.3.3), and so it does on
//!   the active one when the switch waits for validation. A candidate
//!   challenges its address as soon as it is built (§9.6.3). What path
//!   validation concludes comes back to these rules
//!   ([`path_validation`](super::path_validation)).
//! - A client never follows the server's packets: clients initiate every
//!   migration (RFC 9000 §9), so no packet it receives switches its active
//!   link path. It migrates to a preferred address it chose only once the
//!   path validation of that address succeeds (§9.6.1, §9.6.2), with a new
//!   recovery layer, the peer's address having changed; a failed one leaves
//!   it on the server's original address (MUST). Until then the candidate
//!   only probes (§21.5.3). It takes the link with its
//!   [`LinkConnector`](super::link_connector::LinkConnector), from the local
//!   end of the active link path: only a binding whose own local end is that
//!   one gives it, so an address of the other family, which no specific
//!   local address reaches, is never taken, and asking again after a
//!   failure lands on the family of the same.
//! - A link path whose local end differs from the active one's, which only
//!   a server's preferred address makes, waits for validation whatever the
//!   policy would say of the peer's move: the active link path switches to
//!   it only once its validation succeeded and a non-probing packet of a new
//!   largest packet number arrived on it, with a new recovery layer, and the
//!   active link path is not challenged for it (RFC 9000 §9.6.2). Once the
//!   active link path left a local end, each packet that opens at that end
//!   goes to [`on_old_local_address`](MigrationPolicy::on_old_local_address)
//!   before its frames are handled.
//!
//! The policy's own events are only these calls: what follows from them,
//! validation, reverting and switching back, the fixed part does, and the
//! policy sees the result in the context of its next call.

use core::{fmt, net::SocketAddr, time::Duration};

use sakuya_link::{LinkId, PeerAddress, same_network_address};
use sakuya_wire::v1::transport_parameters::preferred_address::PreferredAddressFamilies;

use super::amplification::AddressValidation;
use crate::role::LinkPathRole;

pub mod rules;

#[cfg(test)]
mod tests;

/// The migration policy of a logical path: the choices of connection
/// migration that RFC 9000 leaves to the endpoint. `Lo` and `P` are the
/// types of the two ends of a link, `I` an instant of the connection's
/// clock. What the fixed part keeps to whatever the policy answers is in
/// the [module documentation](self).
pub trait MigrationPolicy<Lo, P, I> {
    /// A packet arrived over `cx.link`, which has no link path in the
    /// logical path; it opened and is no duplicate. Whether a link path is
    /// built for it, and which link paths end first.
    fn admit(&mut self, cx: &LinkPathAdmissionContext<'_, Lo, P, I>) -> LinkPathAdmission<Lo, P>;

    /// The non-probing packet of the highest number in its space arrived on
    /// the link path over `cx.to`, which is neither active nor validated,
    /// once its frames were handled: when the active link path switches to
    /// it, and with which recovery layer. Called once for each such link
    /// path until its validation has a result.
    fn on_peer_moved(&mut self, cx: &PeerMovedContext<'_, Lo, P, I>) -> MigrationDecision<Lo, P>;

    /// A link path is to send a new PATH_CHALLENGE: how long until it is
    /// sent again, and how long path validation tries.
    fn challenge_timing(&self, cx: &PathChallengeContext) -> PathChallengeTiming;

    /// A link path enters `Settling`: how long it keeps. Asked once, as it
    /// enters.
    fn settling_for(&self, cx: &SettlingContext) -> Duration;

    /// A client: the handshake is confirmed and the server gave a preferred
    /// address (RFC 9000 §9.6.1). The address whose path to validate and
    /// migrate to, or `None` to stay. Asked again, with the address added
    /// to `cx.failed`, when no link to it could be taken; an address in
    /// `cx.failed` is not tried again.
    fn choose_preferred_address(&mut self, cx: &PreferredAddressContext<'_>) -> Option<SocketAddr>;

    /// A packet opened, and is no duplicate, on a link path whose local end
    /// is one the active link path moved away from, as a server's original
    /// address once it moved to its preferred one (RFC 9000 §9.6.2); its
    /// frames are not handled yet, so whether it is a non-probing packet is
    /// not known. What becomes of it.
    fn on_old_local_address(
        &mut self,
        cx: &OldLocalAddressContext,
    ) -> OldLocalAddressPacketHandling;
}

/// What [`MigrationPolicy::admit`] is told.
#[derive(Debug)]
#[non_exhaustive]
pub struct LinkPathAdmissionContext<'a, Lo, P, I> {
    /// The logical link the packet arrived over, which the link path would
    /// be over.
    pub link: &'a LinkId<Lo, P>,
    /// The link paths of the logical path, in no order.
    pub link_paths: &'a [LinkPathFacts<Lo, P, I>],
    /// Whether this side sent the `disable_active_migration` transport
    /// parameter (RFC 9000 §18.2). A peer that migrates all the same may
    /// have its packets dropped, or its migration followed (§9).
    pub local_disabled_active_migration: bool,
    /// Whether the packet is sent to another of this side's connection IDs
    /// than the peer last used on the active link path.
    pub peer_switched_local_id: bool,
    /// When the packet arrived.
    pub now: I,
}

/// What the fixed part tells a migration policy of one link path.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LinkPathFacts<Lo, P, I> {
    /// The link path's logical link.
    pub link: LinkId<Lo, P>,
    /// Its role.
    pub role: LinkPathRole<I>,
    /// When it entered the role.
    pub since: I,
    /// Whether the address of its logical link is validated.
    pub validation: AddressValidation,
    /// Whether it is the fallback: the link path validated last while the
    /// active one is not validated, which a failed path validation of the
    /// active one reverts to (RFC 9000 §9.3.2).
    pub fallback: bool,
}

/// What a migration policy answers for a packet from a logical link with no
/// link path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkPathAdmission<Lo, P> {
    /// Build a `Candidate` link path over the logical link, after ending the
    /// link paths over `end`; the active link path and the fallback among
    /// them are kept.
    Accept {
        /// The logical links of the link paths to end first.
        end: Vec<LinkId<Lo, P>>,
    },
    /// Drop the packets of the datagram for the connection, with nothing
    /// built, recorded or counted, and no stateless reset sent.
    Drop,
}

/// What [`MigrationPolicy::on_peer_moved`] is told.
#[derive(Debug)]
#[non_exhaustive]
pub struct PeerMovedContext<'a, Lo, P, I> {
    /// The logical link of the active link path.
    pub from: &'a LinkId<Lo, P>,
    /// The logical link of the link path the packet arrived on.
    pub to: &'a LinkId<Lo, P>,
    /// Whether the peer uses another of this side's connection IDs on `to`
    /// than it last used on `from`: RFC 9000 §9.3.3 takes a peer that did as
    /// more likely to migrate on purpose than to be rebound.
    pub peer_switched_local_id: bool,
    /// When the packet arrived.
    pub now: I,
}

/// When the active link path switches to the one a packet moved to, and
/// with which recovery layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationDecision<Lo, P> {
    /// When it switches.
    pub timing: SwitchTiming,
    /// With which recovery layer.
    pub recovery: SwitchRecovery<Lo, P>,
}

/// When the active link path switches to the one a packet moved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchTiming {
    /// At once: until the new address is validated, what it is sent is held
    /// by the anti-amplification limit (RFC 9000 §9.3, §9.3.1).
    Now,
    /// Once path validation of the new link path succeeds; until then it
    /// only probes.
    AfterValidation,
}

/// Which recovery layer the link path the active one switches to gets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwitchRecovery<Lo, P> {
    /// A new one: what the congestion controller and the RTT estimator
    /// start from (RFC 9000 §9.4). Once the switch waits for validation, the
    /// new layer starts with the time from the PATH_CHALLENGE to its
    /// PATH_RESPONSE as its RTT (RFC 9002 §6.2.2).
    New,
    /// The active link path's, moved by value, as the change proves allowed
    /// (RFC 9000 §9.4). A change that is not of the two link paths of the
    /// switch is taken as [`New`](Self::New).
    Move(SameNetworkAddressChange<Lo, P>),
}

/// A change from one logical link to another whose network addresses are
/// the same, with this side's end and the transport the same too: the only
/// change in the peer's address is within its network address, a port of
/// UDP, which lets the recovery state be kept (RFC 9000 §9.4).
///
/// It is made only by [`check`](Self::check), which looks at the peer's
/// network address ([`PeerAddress`]); the fixed part compares the two
/// logical links by identity, so a policy that never checks one only ever
/// gets a new recovery layer.
#[derive(Clone, PartialEq, Eq)]
pub struct SameNetworkAddressChange<Lo, P> {
    from: LinkId<Lo, P>,
    to: LinkId<Lo, P>,
}

impl<Lo: Clone + Eq, P: PeerAddress + Clone + Eq> SameNetworkAddressChange<Lo, P> {
    /// The change from `from` to `to`, when this side's end is the same,
    /// the peer's ends differ, and both have the same network address, which
    /// both can state; `None` otherwise.
    pub fn check(from: &LinkId<Lo, P>, to: &LinkId<Lo, P>) -> Option<Self> {
        let same = from.local == to.local
            && from.peer != to.peer
            && same_network_address(&from.peer, &to.peer);
        same.then(|| Self {
            from: from.clone(),
            to: to.clone(),
        })
    }
}

impl<Lo, P> SameNetworkAddressChange<Lo, P> {
    /// The logical link the change is from.
    pub fn from(&self) -> &LinkId<Lo, P> {
        &self.from
    }

    /// The logical link the change is to.
    pub fn to(&self) -> &LinkId<Lo, P> {
        &self.to
    }

    /// Whether it is the change from `from` to `to`.
    pub(crate) fn is(&self, from: &LinkId<Lo, P>, to: &LinkId<Lo, P>) -> bool {
        self.from == *from && self.to == *to
    }

    /// The change back. The network addresses that are the same one way are
    /// the same the other way, as their equality is.
    pub(crate) fn reversed(self) -> Self {
        Self {
            from: self.to,
            to: self.from,
        }
    }
}

impl<Lo, P> fmt::Debug for SameNetworkAddressChange<Lo, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SameNetworkAddressChange")
            .finish_non_exhaustive()
    }
}

/// What [`MigrationPolicy::challenge_timing`] is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PathChallengeContext {
    /// Which PATH_CHALLENGE of the link path this is: 1 for the first.
    pub attempt: u8,
    /// The probe timeout of the link path, when it has a recovery layer.
    pub path_pto: Option<Duration>,
    /// The probe timeout of the active link path.
    pub active_pto: Duration,
    /// The probe timeout of a new path, from the initial RTT (`kInitialRtt`,
    /// RFC 9002 §6.2.2).
    pub initial_pto: Duration,
}

/// When a PATH_CHALLENGE is sent again, and when path validation gives up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathChallengeTiming {
    /// How long after this challenge the next is sent, unless a response
    /// comes. The fixed part keeps it at least the link path's probe
    /// timeout (RFC 9000 §9.4, §8.2.1).
    pub resend_after: Duration,
    /// How long after the link path's first challenge validation gives up;
    /// taken at the first challenge only.
    pub abandon_after: Duration,
}

/// What [`MigrationPolicy::settling_for`] is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SettlingContext {
    /// The probe timeout of the link path that enters `Settling`.
    pub pto: Duration,
}

/// What [`MigrationPolicy::choose_preferred_address`] is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct PreferredAddressContext<'a> {
    /// The addresses of the server's preferred address: of one family or of
    /// both.
    pub offered: &'a PreferredAddressFamilies,
    /// The addresses chosen before, to which no link could be taken.
    pub failed: &'a [SocketAddr],
}

/// What [`MigrationPolicy::on_old_local_address`] is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OldLocalAddressContext {
    /// Whether the packet's number is larger than any received on the
    /// active link path: a newer packet, not a delayed one (RFC 9000
    /// §9.6.2).
    pub newer: bool,
}

/// What becomes of a packet that arrived at a local end the active link
/// path moved away from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OldLocalAddressPacketHandling {
    /// It is dropped before its frames are handled.
    Drop,
    /// It is processed, and does not switch the active link path back.
    Process,
    /// It is processed, and switches the active link path back when it is
    /// the non-probing packet of the highest number on a validated link
    /// path, as any packet may (RFC 9000 §9.3).
    ProcessAndMaySwitchBack,
}
/// The migration policy RFC 9000 recommends, version 1's default.
///
/// - It admits every link path, and keeps at most four candidates once the
///   new one is built and one `Settling` link path, so two once a switch
///   puts the active one in `Settling`: the oldest beyond these end,
///   except the fallback. `disable_active_migration` sent changes nothing:
///   a peer rebound by a NAT changes its address without migrating on
///   purpose, and following it keeps the connection (RFC 9000 §9).
/// - It switches at once, with the recovery layer of the active link path
///   when the network address is the same ([`SameNetworkAddressChange`])
///   and a new one otherwise.
/// - The first PATH_CHALLENGE is sent again after the link path's probe
///   timeout, or the one of a new path when it has none, and each one after
///   twice as long as the one before (RFC 9000 §9.4, §8.2.1); validation
///   gives up after three times the larger of the active link path's probe
///   timeout and the one of a new path (§8.2.4).
/// - A `Settling` link path keeps for three probe timeouts.
/// - A client tries the addresses of a preferred address in the order of
///   the parameter, IPv4 first, then IPv6, each once (RFC 9000 §9.6.1
///   SHOULD validate one): an address of the other family than the local
///   end, which no link reaches, fails and the next is tried.
/// - Once the active link path left a local end, a newer packet that
///   arrives there is dropped (RFC 9000 §9.6.2 SHOULD), and a delayed one is
///   processed without switching back (MAY).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rfc9000MigrationPolicy;

impl Rfc9000MigrationPolicy {
    /// The candidates kept once a new one is built.
    const CANDIDATES: usize = 4;
    /// The `Settling` link paths kept when a new candidate is built.
    const SETTLING: usize = 1;
}

impl<Lo: Clone + Eq, P: PeerAddress + Clone + Eq, I: Copy + Ord> MigrationPolicy<Lo, P, I>
    for Rfc9000MigrationPolicy
{
    fn admit(&mut self, cx: &LinkPathAdmissionContext<'_, Lo, P, I>) -> LinkPathAdmission<Lo, P> {
        let mut end = Vec::new();
        let candidates = cx
            .link_paths
            .iter()
            .filter(|facts| facts.role == LinkPathRole::Candidate)
            .count();
        // the new one is a candidate too
        oldest_beyond(
            cx.link_paths,
            |role| *role == LinkPathRole::Candidate,
            (candidates + 1).saturating_sub(Self::CANDIDATES),
            &mut end,
        );
        let settling = cx
            .link_paths
            .iter()
            .filter(|facts| matches!(facts.role, LinkPathRole::Settling(_)))
            .count();
        oldest_beyond(
            cx.link_paths,
            |role| matches!(role, LinkPathRole::Settling(_)),
            settling.saturating_sub(Self::SETTLING),
            &mut end,
        );
        LinkPathAdmission::Accept { end }
    }

    fn on_peer_moved(&mut self, cx: &PeerMovedContext<'_, Lo, P, I>) -> MigrationDecision<Lo, P> {
        let recovery = SameNetworkAddressChange::check(cx.from, cx.to)
            .map_or(SwitchRecovery::New, SwitchRecovery::Move);
        MigrationDecision {
            timing: SwitchTiming::Now,
            recovery,
        }
    }

    fn challenge_timing(&self, cx: &PathChallengeContext) -> PathChallengeTiming {
        let base = cx.path_pto.unwrap_or(cx.initial_pto);
        let doublings = u32::from(cx.attempt.saturating_sub(1));
        let resend_after = 1u32
            .checked_shl(doublings)
            .map_or(Duration::MAX, |factor| base.saturating_mul(factor));
        PathChallengeTiming {
            resend_after,
            abandon_after: cx.active_pto.max(cx.initial_pto).saturating_mul(3),
        }
    }

    fn settling_for(&self, cx: &SettlingContext) -> Duration {
        cx.pto.saturating_mul(3)
    }

    fn choose_preferred_address(&mut self, cx: &PreferredAddressContext<'_>) -> Option<SocketAddr> {
        let in_order = match *cx.offered {
            PreferredAddressFamilies::Ipv4(ipv4) => [Some(ipv4.into()), None],
            PreferredAddressFamilies::Ipv6(ipv6) => [Some(ipv6.into()), None],
            PreferredAddressFamilies::Both(ipv4, ipv6) => [Some(ipv4.into()), Some(ipv6.into())],
        };
        in_order
            .into_iter()
            .flatten()
            .find(|address| !cx.failed.contains(address))
    }

    fn on_old_local_address(
        &mut self,
        cx: &OldLocalAddressContext,
    ) -> OldLocalAddressPacketHandling {
        if cx.newer {
            OldLocalAddressPacketHandling::Drop
        } else {
            OldLocalAddressPacketHandling::Process
        }
    }
}

/// Add to `end` the logical links of the `count` oldest link paths of
/// `link_paths` whose role `is` one of a kind, but not the fallback.
fn oldest_beyond<Lo: Clone, P: Clone, I: Copy + Ord>(
    link_paths: &[LinkPathFacts<Lo, P, I>],
    is: impl Fn(&LinkPathRole<I>) -> bool,
    count: usize,
    end: &mut Vec<LinkId<Lo, P>>,
) {
    if count == 0 {
        return;
    }
    let mut kind: Vec<_> = link_paths
        .iter()
        .filter(|facts| is(&facts.role) && !facts.fallback)
        .collect();
    kind.sort_by_key(|facts| facts.since);
    end.extend(kind.into_iter().take(count).map(|facts| facts.link.clone()));
}

/// The connection migration of a logical path: its migration policy `M`,
/// and what the fixed part keeps across packets. `Lo` and `P` are the types
/// of the two ends of a link.
pub struct ConnectionMigration<M, Lo, P> {
    policy: M,
    /// The link path validated last, while the active one is not validated
    /// or not known to carry 1200 bytes.
    fallback: Option<LinkId<Lo, P>>,
    /// The active link path whose validation failed while a switch waited
    /// for another's, with no fallback: the connection goes on until that
    /// one concludes.
    failed_active: Option<LinkId<Lo, P>>,
    /// The change the recovery layer last moved by, kept to move it back
    /// when the switch reverts.
    moved: Option<SameNetworkAddressChange<Lo, P>>,
    /// The local end the active link path last moved away from.
    left_local: Option<Lo>,
    /// The link path of the packet being received, when the policy said it
    /// is processed without switching back.
    holds_back: Option<LinkId<Lo, P>>,
    /// Whether a switch to a link path may wait for its validation: set
    /// when one starts to, cleared when the link paths were looked at.
    may_await: bool,
}

impl<M: Default, Lo, P> Default for ConnectionMigration<M, Lo, P> {
    fn default() -> Self {
        Self {
            policy: M::default(),
            fallback: None,
            failed_active: None,
            moved: None,
            left_local: None,
            holds_back: None,
            may_await: false,
        }
    }
}

impl<M, Lo, P> ConnectionMigration<M, Lo, P> {
    /// The migration policy.
    pub fn policy(&self) -> &M {
        &self.policy
    }

    /// The logical link of the fallback, if there is one: the link path
    /// validated last while the active one is not validated, or not known
    /// to carry 1200 bytes.
    pub fn fallback(&self) -> Option<&LinkId<Lo, P>> {
        self.fallback.as_ref()
    }

    /// The link path over `link`, validated, is the fallback: a switch away
    /// from it went to a link path whose address is validated but not its
    /// ability to carry 1200 bytes.
    pub(crate) fn keep_fallback(&mut self, link: LinkId<Lo, P>) {
        self.fallback = Some(link);
    }

    /// The active link path carries 1200 bytes, its address validated:
    /// there is nothing to revert to.
    pub(crate) fn drop_fallback(&mut self) {
        self.fallback = None;
    }

    /// The active link path whose validation failed while a switch waited
    /// for another's, if one did.
    pub(crate) fn failed_active(&self) -> Option<&LinkId<Lo, P>> {
        self.failed_active.as_ref()
    }

    /// The validation of the active link path over `link` failed while a
    /// switch waited for another's, with no fallback; `None` once the
    /// switch was made or the connection is over.
    pub(crate) fn set_failed_active(&mut self, link: Option<LinkId<Lo, P>>) {
        self.failed_active = link;
    }

    /// A switch to a link path started to wait for its validation.
    pub(crate) fn switch_awaits(&mut self) {
        self.may_await = true;
    }

    /// Whether a switch to a link path may wait for its validation, which
    /// is then forgotten: the link paths are to be looked at.
    pub(crate) fn take_may_await(&mut self) -> bool {
        core::mem::take(&mut self.may_await)
    }

    /// The migration policy, to ask.
    pub(crate) fn policy_mut(&mut self) -> &mut M {
        &mut self.policy
    }

    /// The local end the active link path last moved away from, if it ever
    /// did: a server's original address once it moved to its preferred one.
    pub fn left_local(&self) -> Option<&Lo> {
        self.left_local.as_ref()
    }

    /// The link path over `link` ended: it is no longer the fallback, and a
    /// change of the recovery layer that involves it moves nothing back.
    pub(crate) fn link_path_ended(&mut self, link: &LinkId<Lo, P>) {
        if self.fallback.as_ref() == Some(link) {
            self.fallback = None;
        }
        if self.holds_back.as_ref() == Some(link) {
            self.holds_back = None;
        }
        if self.failed_active.as_ref() == Some(link) {
            self.failed_active = None;
        }
        if self
            .moved
            .as_ref()
            .is_some_and(|moved| moved.from == *link || moved.to == *link)
        {
            self.moved = None;
        }
    }
}

impl<M, Lo, P> fmt::Debug for ConnectionMigration<M, Lo, P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionMigration")
            .field("fallback", &self.fallback.is_some())
            .field("moved", &self.moved.is_some())
            .field("left_local", &self.left_local.is_some())
            .finish_non_exhaustive()
    }
}

/// What connection migration keeps in a link path: when it entered its
/// role, and the answer of the migration policy that waits for its
/// validation. `Lo` and `P` are the types of the two ends of a link, `I` an
/// instant of the connection's clock.
pub struct LinkPathMigration<Lo, P, I> {
    /// `None` until the link path started.
    since: Option<I>,
    /// The recovery layer the policy chose for a switch that waits for the
    /// link path's validation.
    awaiting: Option<SwitchRecovery<Lo, P>>,
    /// The largest number of the packets that opened on the link path.
    largest_received: Option<u64>,
}

impl<Lo, P, I> Default for LinkPathMigration<Lo, P, I> {
    fn default() -> Self {
        Self {
            since: None,
            awaiting: None,
            largest_received: None,
        }
    }
}

impl<Lo, P, I: Copy> LinkPathMigration<Lo, P, I> {
    /// When the link path entered its role, once it started.
    pub fn since(&self) -> Option<I> {
        self.since
    }

    /// Whether a switch to the link path waits for its validation.
    pub fn awaits_validation(&self) -> bool {
        self.awaiting.is_some()
    }

    /// The link path started at `now`, in the role it was built with.
    pub(crate) fn started(&mut self, now: I) {
        self.since.get_or_insert(now);
    }

    /// The link path entered a role at `now`; nothing waits for it.
    pub(crate) fn entered_role(&mut self, now: I) {
        self.since = Some(now);
        self.awaiting = None;
    }

    /// A switch to the link path waits for its validation, with `recovery`.
    pub(crate) fn await_validation(&mut self, recovery: SwitchRecovery<Lo, P>) {
        self.awaiting = Some(recovery);
    }

    /// The switch to the link path that waited for its validation, which
    /// waits no more.
    pub(crate) fn take_awaiting(&mut self) -> Option<SwitchRecovery<Lo, P>> {
        self.awaiting.take()
    }

    /// The largest number of the packets that opened on the link path, and
    /// were no duplicates, once one did.
    pub fn largest_received(&self) -> Option<u64> {
        self.largest_received
    }

    /// A packet numbered `number` opened on the link path, and is no
    /// duplicate.
    pub(crate) fn received(&mut self, number: u64) {
        self.largest_received = Some(self.largest_received.map_or(number, |l| l.max(number)));
    }
}

impl<Lo, P, I: fmt::Debug> fmt::Debug for LinkPathMigration<Lo, P, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkPathMigration")
            .field("since", &self.since)
            .field("awaiting", &self.awaiting.is_some())
            .field("largest_received", &self.largest_received)
            .finish()
    }
}
