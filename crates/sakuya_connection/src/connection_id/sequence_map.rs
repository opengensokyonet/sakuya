//! A destination connection ID strategy that keeps the peer's connection
//! IDs in a map keyed by sequence number and binds each to the link paths
//! it was used on.

use std::collections::{BTreeMap, BTreeSet, btree_map};

use sakuya_wire::{
    connection_id::{ConnectionId, StatelessResetToken},
    v1::transport_parameters::integer::ActiveConnectionIdLimit,
};

use super::{
    DestinationConnectionIdStrategy, NewConnectionId, OfferedConnectionId, ResetTokenRegistrar,
    violation::{
        ActiveConnectionIdLimitExceededError, ConnectionIdResequencedError,
        NewConnectionIdViolationError, ResetTokenChangedError, ResetTokenReusedError,
        RetirementLimitExceededError, SequenceNumberReusedError, ZeroLengthConnectionIdInUseError,
    },
};

/// Keeps the peer's active connection IDs by sequence number, binds each to
/// the link paths it was sent on, and retires what is no longer used.
///
/// - **Offer.** For a link path, the connection IDs already bound to it come
///   first, then those never used on any link path, each group by
///   ascending sequence number. A connection ID bound to another link path
///   is never offered ([RFC 9000 §9.5]). The exception §9.5 allows after a
///   change of the peer's address alone is not taken: it requires sending
///   from the same local address, and link path identities say nothing
///   about addresses. A new link path therefore always needs a connection
///   ID never used before.
/// - **Use.** The first datagram on a link path with a connection ID binds
///   them and registers the connection ID's reset token through the
///   registrar lent for that link path ([RFC 9000 §10.3.1]); a handshake
///   connection ID the peer gave no token for is not registered. Every
///   link path registers on its own, even towards the same peer, because
///   ending one link path drops its registrations only.
/// - **Retirement.** A connection ID leaves the map, and with it its
///   registrations, when Retire Prior To passes it or when the last link
///   path it is bound to ends ([RFC 9000 §5.1.2]). Its sequence number then
///   waits for a RETIRE_CONNECTION_ID frame
///   ([`pending_retirements`](Self::pending_retirements)) until the frame is
///   acknowledged. A NEW_CONNECTION_ID that arrives again for a connection
///   ID retired this way does not bring it back.
/// - **Checks.** Every violation of [`NewConnectionIdViolationError`] is
///   reported, the optional ones included. Duplicate values are compared
///   with the active connection IDs only, not with retired ones.
/// - **Time.** It neither rotates connection IDs nor waits for anything,
///   so it never has a deadline.
///
/// When the peer's handshake connection ID is zero-length, it is the only
/// connection ID: it is offered on every link path, never retired, and any
/// NEW_CONNECTION_ID frame is a violation ([RFC 9000 §19.15]).
///
/// [RFC 9000 §5.1.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.1.2
/// [RFC 9000 §9.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-9.5
/// [RFC 9000 §10.3.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-10.3.1
/// [RFC 9000 §19.15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.15
pub struct SequenceMapDestinationConnectionIdStrategy<Id, R: ResetTokenRegistrar> {
    active: BTreeMap<u64, PeerConnectionId<Id, R::Registration>>,
    issuance: Issuance,
    active_limit: ActiveConnectionIdLimit,
    retirement_limit: usize,
}

/// How the peer issues connection IDs.
#[derive(Debug)]
enum Issuance {
    /// The peer's handshake connection ID is zero-length: there are no
    /// others, and none is retired.
    ZeroLength,
    /// The peer issues numbered connection IDs; the retired ones are
    /// tracked.
    Sequenced(Retirements),
}

/// The connection IDs retired, and the RETIRE_CONNECTION_ID frames that
/// still have to be sent or acknowledged.
#[derive(Debug)]
struct Retirements {
    /// The largest Retire Prior To received: every sequence number below
    /// it is retired.
    retire_prior_to: u64,
    /// The sequence numbers at or above `retire_prior_to` retired because
    /// they were no longer used.
    retired_above: BTreeSet<u64>,
    /// The retirements not yet acknowledged.
    unacknowledged: BTreeMap<u64, RetirementProgress>,
    /// How many unacknowledged retirements are tracked before a
    /// NEW_CONNECTION_ID frame is a violation.
    limit: usize,
}

/// Where the RETIRE_CONNECTION_ID frame of one retirement stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RetirementProgress {
    /// The frame waits to be written.
    Pending,
    /// The frame was written and is neither acknowledged nor lost.
    Written,
}

/// One active connection ID of the peer.
struct PeerConnectionId<Id, Reg> {
    id: ConnectionId,
    token: Option<StatelessResetToken>,
    bindings: Vec<LinkPathBinding<Id, Reg>>,
}

/// A link path a connection ID was used on, with the registration of the
/// connection ID's token made for it.
struct LinkPathBinding<Id, Reg> {
    link_path: Id,
    #[expect(
        dead_code,
        reason = "held only so that dropping the binding revokes the registration"
    )]
    registration: Option<Reg>,
}

impl<Id: PartialEq, Reg> PeerConnectionId<Id, Reg> {
    fn is_bound_to(&self, link_path: &Id) -> bool {
        self.bindings
            .iter()
            .any(|binding| binding.link_path == *link_path)
    }

    /// Drops the binding to `link_path` and its registration; whether
    /// there was one.
    fn unbind(&mut self, link_path: &Id) -> bool {
        let before = self.bindings.len();
        self.bindings
            .retain(|binding| binding.link_path != *link_path);
        self.bindings.len() != before
    }
}

impl Retirements {
    /// Starts retiring `sequence`, unless its retirement is still waiting
    /// for acknowledgment.
    fn retire(&mut self, sequence: u64) {
        if sequence >= self.retire_prior_to {
            self.retired_above.insert(sequence);
        }
        self.unacknowledged
            .entry(sequence)
            .or_insert(RetirementProgress::Pending);
    }

    /// Whether `sequence` was retired.
    fn is_retired(&self, sequence: u64) -> bool {
        sequence < self.retire_prior_to || self.retired_above.contains(&sequence)
    }
}

/// The configuration of a [`SequenceMapDestinationConnectionIdStrategy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceMapDestinationConnectionIdStrategyConfig {
    retirement_limit: usize,
}

impl SequenceMapDestinationConnectionIdStrategyConfig {
    /// `retirement_limit` is how many retirements may wait for their
    /// RETIRE_CONNECTION_ID frame to be acknowledged before a
    /// NEW_CONNECTION_ID frame that adds to them is a violation;
    /// RFC 9000 §5.1.2 recommends at least twice the
    /// `active_connection_id_limit` this side sends.
    pub fn new(retirement_limit: usize) -> Self {
        Self { retirement_limit }
    }
}

impl Retirements {
    fn new(limit: usize) -> Self {
        Self {
            retire_prior_to: 0,
            retired_above: BTreeSet::new(),
            unacknowledged: BTreeMap::new(),
            limit,
        }
    }
}

impl<Id, R: ResetTokenRegistrar> SequenceMapDestinationConnectionIdStrategy<Id, R> {
    /// The sequence numbers whose RETIRE_CONNECTION_ID frame waits to be
    /// written, ascending.
    pub fn pending_retirements(&self) -> impl Iterator<Item = u64> + '_ {
        let unacknowledged = match &self.issuance {
            Issuance::Sequenced(retirements) => Some(&retirements.unacknowledged),
            Issuance::ZeroLength => None,
        };
        unacknowledged
            .into_iter()
            .flatten()
            .filter_map(|(&sequence, &progress)| {
                (progress == RetirementProgress::Pending).then_some(sequence)
            })
    }

    /// The RETIRE_CONNECTION_ID frame for `sequence` was written into a
    /// packet: it waits for that packet's fate.
    pub fn on_retirement_written(&mut self, sequence: u64) {
        if let Some(progress) = self.retirement_progress(sequence) {
            *progress = RetirementProgress::Written;
        }
    }

    /// A packet with the RETIRE_CONNECTION_ID frame for `sequence` was
    /// acknowledged: the retirement is complete.
    pub fn on_retirement_acknowledged(&mut self, sequence: u64) {
        if let Issuance::Sequenced(retirements) = &mut self.issuance {
            retirements.unacknowledged.remove(&sequence);
        }
    }

    /// The packet with the RETIRE_CONNECTION_ID frame for `sequence` was
    /// declared lost: the same frame waits to be written again
    /// ([RFC 9000 §13.3]).
    ///
    /// [RFC 9000 §13.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-13.3
    pub fn on_retirement_lost(&mut self, sequence: u64) {
        if let Some(progress) = self.retirement_progress(sequence) {
            *progress = RetirementProgress::Pending;
        }
    }

    fn retirement_progress(&mut self, sequence: u64) -> Option<&mut RetirementProgress> {
        match &mut self.issuance {
            Issuance::Sequenced(retirements) => retirements.unacknowledged.get_mut(&sequence),
            Issuance::ZeroLength => None,
        }
    }
}

/// Checks a NEW_CONNECTION_ID frame with `sequence`, `id` and `token`
/// against the `active` connection IDs; whether it repeats the one with its
/// sequence number.
fn check_against_active<Id, Reg>(
    active: &BTreeMap<u64, PeerConnectionId<Id, Reg>>,
    sequence: u64,
    id: ConnectionId,
    token: StatelessResetToken,
) -> Result<bool, NewConnectionIdViolationError> {
    let mut repeated = false;
    for (&known_sequence, known) in active {
        if known_sequence == sequence {
            SequenceNumberReusedError::check(sequence, known.id, id)?;
            ResetTokenChangedError::check(sequence, id, known.token, token)?;
            repeated = true;
            continue;
        }
        if known.id == id {
            ConnectionIdResequencedError::check(id, known_sequence, sequence)?;
        }
        if let Some(known_token) = known.token {
            ResetTokenReusedError::check(sequence, token, known_sequence, known_token)?;
        }
    }
    Ok(repeated)
}

impl<Id, I, R> DestinationConnectionIdStrategy<Id, I, R>
    for SequenceMapDestinationConnectionIdStrategy<Id, R>
where
    Id: Clone + PartialEq,
    R: ResetTokenRegistrar,
{
    type Config = SequenceMapDestinationConnectionIdStrategyConfig;
    type Offer<'a>
        = SequenceMapConnectionIdOffer<'a, Id, R::Registration>
    where
        Self: 'a;

    fn new(config: &Self::Config, active_limit: ActiveConnectionIdLimit) -> Self {
        Self {
            active: BTreeMap::new(),
            issuance: Issuance::Sequenced(Retirements::new(config.retirement_limit)),
            active_limit,
            retirement_limit: config.retirement_limit,
        }
    }

    fn on_handshake_connection_id(&mut self, id: ConnectionId) {
        match (&self.issuance, id.is_empty()) {
            (Issuance::Sequenced(_), true) => self.issuance = Issuance::ZeroLength,
            (Issuance::ZeroLength, false) => {
                self.issuance = Issuance::Sequenced(Retirements::new(self.retirement_limit));
            }
            _ => {}
        }
        // dropping the one replaced drops its bindings and registrations
        self.active.insert(
            0,
            PeerConnectionId {
                id,
                token: None,
                bindings: Vec::new(),
            },
        );
    }

    fn offer(&self, link_path: &Id) -> Self::Offer<'_> {
        SequenceMapConnectionIdOffer {
            link_path: link_path.clone(),
            every_link_path: matches!(self.issuance, Issuance::ZeroLength),
            bound: self.active.iter(),
            unused: self.active.iter(),
        }
    }

    fn on_used(&mut self, registrar: &mut R, sequence: u64, link_path: &Id, _datagram_len: usize) {
        let Some(entry) = self.active.get_mut(&sequence) else {
            return;
        };
        if entry.is_bound_to(link_path) {
            return;
        }
        let registration = entry.token.map(|token| registrar.register(token));
        entry.bindings.push(LinkPathBinding {
            link_path: link_path.clone(),
            registration,
        });
    }

    fn on_new_connection_id(
        &mut self,
        issued: NewConnectionId,
    ) -> Result<(), NewConnectionIdViolationError> {
        let sequence = issued.sequence();
        let retire_prior_to = issued.retire_prior_to();
        let id = issued.id().get();
        let token = issued.reset_token();
        let Issuance::Sequenced(retirements) = &mut self.issuance else {
            return Err(ZeroLengthConnectionIdInUseError::new(sequence).into());
        };
        let repeated = check_against_active(&self.active, sequence, id, token)?;

        // Retire first, then add (RFC 9000 §5.1.2).
        if retire_prior_to > retirements.retire_prior_to {
            let kept = self.active.split_off(&retire_prior_to);
            let passed = core::mem::replace(&mut self.active, kept);
            retirements.retire_prior_to = retire_prior_to;
            retirements.retired_above = retirements.retired_above.split_off(&retire_prior_to);
            for &sequence in passed.keys() {
                retirements.retire(sequence);
            }
        }
        if sequence < retirements.retire_prior_to {
            // Retire a connection ID that arrives below Retire Prior To
            // (RFC 9000 §19.15).
            retirements.retire(sequence);
        } else if !repeated && !retirements.is_retired(sequence) {
            self.active.insert(
                sequence,
                PeerConnectionId {
                    id,
                    token: Some(token),
                    bindings: Vec::new(),
                },
            );
        }

        ActiveConnectionIdLimitExceededError::check(self.active.len(), self.active_limit)?;
        RetirementLimitExceededError::check(retirements.unacknowledged.len(), retirements.limit)?;
        Ok(())
    }

    fn on_link_path_added(&mut self, _link_path: &Id, _peer_switched_local_id: bool) {}

    fn on_link_path_ended(&mut self, link_path: &Id) {
        match &mut self.issuance {
            Issuance::ZeroLength => {
                for entry in self.active.values_mut() {
                    entry.unbind(link_path);
                }
            }
            Issuance::Sequenced(retirements) => {
                // A connection ID no longer used on any link path is
                // retired (RFC 9000 §5.1.2, SHOULD).
                self.active.retain(|&sequence, entry| {
                    let unused = entry.unbind(link_path) && entry.bindings.is_empty();
                    if unused {
                        retirements.retire(sequence);
                    }
                    !unused
                });
            }
        }
    }
}

impl<Id, R: ResetTokenRegistrar> core::fmt::Debug
    for SequenceMapDestinationConnectionIdStrategy<Id, R>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SequenceMapDestinationConnectionIdStrategy")
            .field("active", &self.active.keys().collect::<Vec<_>>())
            .field("issuance", &self.issuance)
            .field("active_limit", &self.active_limit)
            .finish()
    }
}

/// The offer of a [`SequenceMapDestinationConnectionIdStrategy`] for one
/// link path: the connection IDs bound to it, then those never used, each
/// by ascending sequence number.
pub struct SequenceMapConnectionIdOffer<'a, Id, Reg> {
    link_path: Id,
    every_link_path: bool,
    bound: btree_map::Iter<'a, u64, PeerConnectionId<Id, Reg>>,
    unused: btree_map::Iter<'a, u64, PeerConnectionId<Id, Reg>>,
}

impl<Id: PartialEq, Reg> Iterator for SequenceMapConnectionIdOffer<'_, Id, Reg> {
    type Item = OfferedConnectionId;

    fn next(&mut self) -> Option<OfferedConnectionId> {
        let offered =
            |(&sequence, entry): (&u64, &PeerConnectionId<Id, Reg>)| OfferedConnectionId {
                sequence,
                id: entry.id,
            };
        if let Some(bound) = self
            .bound
            .by_ref()
            .find(|(_, entry)| self.every_link_path || entry.is_bound_to(&self.link_path))
        {
            return Some(offered(bound));
        }
        if self.every_link_path {
            return None;
        }
        self.unused
            .by_ref()
            .find(|(_, entry)| entry.bindings.is_empty())
            .map(offered)
    }
}

impl<Id, Reg> core::fmt::Debug for SequenceMapConnectionIdOffer<'_, Id, Reg> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SequenceMapConnectionIdOffer")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
/// A strategy made through the trait, then told the peer's handshake
/// connection ID `first`; `first_token` is the token a client learns for
/// it from the server's transport parameters.
pub(crate) fn started<Id: Clone + PartialEq, R: ResetTokenRegistrar>(
    first: ConnectionId,
    first_token: Option<StatelessResetToken>,
    active_limit: ActiveConnectionIdLimit,
    retirement_limit: usize,
) -> SequenceMapDestinationConnectionIdStrategy<Id, R> {
    let config = SequenceMapDestinationConnectionIdStrategyConfig::new(retirement_limit);
    let mut strategy =
        <SequenceMapDestinationConnectionIdStrategy<Id, R> as DestinationConnectionIdStrategy<
            Id,
            u64,
            R,
        >>::new(&config, active_limit);
    DestinationConnectionIdStrategy::<Id, u64, R>::on_handshake_connection_id(&mut strategy, first);
    strategy
        .active
        .get_mut(&0)
        .expect("the handshake connection ID was just given")
        .token = first_token;
    strategy
}

#[cfg(test)]
mod tests;
