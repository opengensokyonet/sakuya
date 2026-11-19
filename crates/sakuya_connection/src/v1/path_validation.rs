//! Path validation of a link path (RFC 9000 §8.2): the PATH_CHALLENGE
//! frames this side sends, and what their PATH_RESPONSE frames, or the lack
//! of them, conclude.
//!
//! Each link path keeps its own ([`PathValidation`]). A validation starts
//! when a challenge becomes due: a candidate's at once when it is built
//! (RFC 9000 §9.6.3), and both link paths of a switch to an address not
//! validated yet, the new active one and the one it took over from (§9.3,
//! §9.3.3). The sending call gathers a due challenge as a
//! [`PathChallengeIntent`], which ranks as control content and holds its
//! place, so that the first datagram of a new path carries it; writing it
//! gives it data no one can predict, from the connection's cryptographic
//! backend (§8.2.1, MUST), and the datagram that carries it is expanded to
//! 1200 bytes unless the anti-amplification limit holds it (§8.2.1). A
//! packet carries one challenge at most.
//!
//! The link path keeps the last four challenges it wrote, awaiting their
//! responses; a fifth forgets the oldest. Once one is written, the
//! migration policy's [`challenge_timing`](super::migration::MigrationPolicy::challenge_timing)
//! says when the next is due and, at the first of a validation, when it
//! gives up; the fixed part keeps the time to the next at least the link
//! path's probe timeout, or the one of a new path without a recovery layer
//! (§9.4, MUST NOT be more aggressive; §8.2.1). The time to the next counts
//! from when the link accepts the challenge's datagram, too.
//!
//! A PATH_RESPONSE that echoes the data of a challenge, whichever link
//! path it arrives on, validates the link path the challenge was sent on
//! (§8.2.2, §8.2.3); one that echoes none is ignored (§19.18, MAY). A
//! challenge acknowledged in an ACK frame validates nothing (§8.2.3). The
//! address is validated by any of them, and the path's ability to carry
//! 1200 bytes only by one whose datagram was expanded: after one that was
//! not, a second validation starts at once, which the lifted
//! anti-amplification limit lets expand (§8.2.1, §8.2.3). The time from a
//! challenge's datagram accepted to its response is the new path's RTT, when
//! the response came back over the link path that sent it (RFC 9002
//! §6.2.2). A validation that reaches the instant it gives up at fails;
//! the second one failing says the path cannot carry 1200 bytes, and is
//! unusable (§8.2.4, §14). The conclusions wait in the link path, in
//! order, for the rules of connection migration ([`MigrationRules`]),
//! which the logical path's receiving call applies.
//!
//! [`MigrationRules`]: super::migration::rules::MigrationRules

use alloc::collections::VecDeque;
use core::time::Duration;

use frunk_core::hlist_pat;
use nitori_crypto::Random;
use sakuya_recovery::{
    packet_number_space::PacketNumberSpaceKind,
    pto::probe_timeout,
    rtt::{INITIAL_RTT, RttEstimate, RttEstimator},
};
use sakuya_stream::send_options::destination::Unfulfilled;
use sakuya_wire::{
    parameters::ParametersOf,
    parts::{HList, Selector},
    v1::{
        frame::{PATH_DATA_LEN, path_challenge::PathChallengeFrame},
        transport_parameters::{
            TransportParameterSlots, TransportParameterSpace, integer::MaxAckDelay,
        },
    },
};

use super::{
    Choices, LinkPathRoleReads,
    component_events::{PacketsSent, PathChallengePendingChanged, PathValidationConcluded},
    keys::PacketProtectionBackend,
    migration::{
        MigrationPolicy, PathChallengeContext, rules::ConnectionMigrationOf, rules::hold_fallback,
    },
    recovery::RttOf,
    send::FrameSourceId,
    spaces::{DEFAULT_MAX_ACK_DELAY, peer_max_ack_delay},
};
use crate::{
    call::CallBundle,
    clock::{CheckedAdd, InstantOf, LinkIdOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, RequestOf},
    component_event::{EventSubscriptions, Happened, TriggeredEvents},
    feedback::InjectSummary,
    frame_source::{FindFrameSource, FrameSource, FrameSourceKind, IgnoredFeedback},
    layer::{self, NodeKey},
    others::OtherNodes,
    role::LinkPathRole,
    send_strategy::{
        MinimumLengths, SendIntent,
        ranked::{RankedIntent, SendPriority, SendRank},
    },
    share::{FlatMut, LineageLists, LineagePartList, NodeData},
    take::{ComponentMut, GetAt, Lineage, ReadEach, TakeEach},
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// The smallest datagram that validates a path's ability to carry it, and
/// that a datagram with a PATH_CHALLENGE is expanded to (RFC 9000 §8.2.1).
const EXPANDED: usize = sakuya_link::MIN_DATAGRAM_SIZE;

/// How many challenges a link path keeps awaiting their responses.
const KEPT_CHALLENGES: usize = 4;

/// A PATH_CHALLENGE frame is to be sent on the link path whose content it
/// is; its data is chosen when it is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathChallengeIntent;

impl PathChallengeIntent {
    /// The length of the frame.
    const LEN: usize = 1 + PATH_DATA_LEN;
}

impl SendIntent for PathChallengeIntent {
    type FrameSourceId = FrameSourceId;
    type Class = InFlightClass;

    fn frame_source(&self) -> FrameSourceId {
        FrameSourceId::PathChallenge
    }

    fn min_lengths(&self) -> MinimumLengths {
        MinimumLengths {
            with_length: Self::LEN,
            as_last: Self::LEN,
        }
    }
}

/// A challenge ranks as control content and holds its place: the first
/// datagram of a new path carries it.
impl RankedIntent for PathChallengeIntent {
    fn rank(&self) -> SendRank {
        SendRank {
            priority: SendPriority::Control,
            holds_place: true,
        }
    }
}

/// What a PATH_CHALLENGE frame written into a packet is remembered by:
/// nothing, as an acknowledgment of it validates nothing (RFC 9000 §8.2.3)
/// and a lost one is followed by the next challenge when it is due.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PathChallengeSummary;

/// Where a challenge's datagram is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChallengeDatagram<I> {
    /// Being filled.
    Filling,
    /// Sealed, `expanded` to 1200 bytes or not; the link has not accepted
    /// it yet.
    Sealed { expanded: bool },
    /// Accepted by the link at `at`.
    Sent { expanded: bool, at: I },
}

/// A PATH_CHALLENGE written and awaiting its response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Challenge<I> {
    data: [u8; PATH_DATA_LEN],
    datagram: ChallengeDatagram<I>,
}

impl<I> Challenge<I> {
    fn expanded(&self) -> bool {
        match self.datagram {
            ChallengeDatagram::Filling => false,
            ChallengeDatagram::Sealed { expanded } | ChallengeDatagram::Sent { expanded, .. } => {
                expanded
            }
        }
    }
}

/// What the validation under way has established of the path so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Progress {
    /// Nothing.
    Nothing,
    /// The address, by a response to a challenge whose datagram was not
    /// expanded: the path's ability to carry 1200 bytes is validated next.
    Address,
}

/// What a link path's path validation concluded, for the rules of
/// connection migration to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathValidationConclusion {
    /// The address is validated; `initial_rtt` is the time from the
    /// challenge's datagram accepted to the response, when the response
    /// came back over the link path, and `supports_minimum` whether the
    /// challenge's datagram was expanded to 1200 bytes as well, leaving
    /// nothing to validate next.
    Validated {
        /// The time from the challenge to its response.
        initial_rtt: Option<Duration>,
        /// Whether the path's ability to carry 1200 bytes is validated
        /// with the address.
        supports_minimum: bool,
    },
    /// The path's ability to carry 1200 bytes is validated, after its
    /// address.
    MinimumSupported,
    /// The validation of the address gave up.
    Failed,
    /// The validation of the path's ability to carry 1200 bytes, after its
    /// address, gave up: the path is unusable (RFC 9000 §8.2.4, §14).
    MinimumUnsupported,
}

/// The path validation of a link path (`PathValidation`), in the link
/// path's node: whether a PATH_CHALLENGE is due, the challenges awaiting
/// their responses, when the next is due and when the validation gives up,
/// what it established so far, and its conclusion until the rules of
/// connection migration act on it. `I` is an instant of the connection's
/// clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathValidation<I> {
    due: bool,
    challenges: VecDeque<Challenge<I>>,
    /// The challenges written in the validation under way.
    attempts: u8,
    /// Whether a challenge was written since the timing was last taken.
    untimed: bool,
    /// The time to the next challenge last taken.
    resend_after: Duration,
    resend_at: Option<I>,
    abandon_at: Option<I>,
    progress: Progress,
    /// What it concluded, oldest first, until the rules of connection
    /// migration act on it.
    conclusions: VecDeque<PathValidationConclusion>,
}

/// The path validation of a link path of the choices `T`.
pub type PathValidationOf<T> = PathValidation<InstantOf<T>>;

impl<I> Default for PathValidation<I> {
    fn default() -> Self {
        Self {
            due: false,
            challenges: VecDeque::new(),
            attempts: 0,
            untimed: false,
            resend_after: Duration::ZERO,
            resend_at: None,
            abandon_at: None,
            progress: Progress::Nothing,
            conclusions: VecDeque::new(),
        }
    }
}

impl<I: Copy + Ord + CheckedAdd<Duration> + core::ops::Sub<Output = Duration>> PathValidation<I> {
    /// Whether a PATH_CHALLENGE is to be written.
    pub fn is_due(&self) -> bool {
        self.due
    }

    /// Whether a validation is under way: a challenge is due or awaits its
    /// response.
    pub fn is_validating(&self) -> bool {
        self.due || self.attempts > 0
    }

    /// The instant the validation under way gives up at, once its first
    /// challenge was written.
    pub fn abandon_at(&self) -> Option<I> {
        self.abandon_at
    }

    /// When the next challenge is due, unless a response comes first.
    pub fn resend_at(&self) -> Option<I> {
        self.resend_at
    }

    /// Its earliest deadline: the next challenge due, or the validation
    /// giving up.
    pub fn deadline(&self) -> Option<I> {
        match (self.resend_at, self.abandon_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// A challenge is due: the validation under way sends another, and a
    /// new one starts when none is. What happened.
    pub(crate) fn challenge_due(&mut self) -> Happened<PathChallengePendingChanged> {
        if !self.is_validating() {
            self.start();
        }
        self.due = true;
        Happened::new()
    }

    /// A new validation, from nothing established.
    fn start(&mut self) {
        self.attempts = 0;
        self.abandon_at = None;
        self.resend_at = None;
        self.progress = Progress::Nothing;
    }

    /// The validation under way is over: nothing is due or awaited.
    fn finish(&mut self) {
        self.due = false;
        self.challenges.clear();
        self.attempts = 0;
        self.untimed = false;
        self.resend_at = None;
        self.abandon_at = None;
        self.progress = Progress::Nothing;
    }

    /// A challenge with `data` was written into the datagram being filled.
    fn written(&mut self, data: [u8; PATH_DATA_LEN]) {
        if self.challenges.len() == KEPT_CHALLENGES {
            self.challenges.pop_front();
        }
        self.challenges.push_back(Challenge {
            data,
            datagram: ChallengeDatagram::Filling,
        });
        self.due = false;
        self.attempts = self.attempts.saturating_add(1);
        self.untimed = true;
    }

    /// The datagram being filled was sealed with `len` bytes.
    pub(crate) fn datagram_sealed(&mut self, len: usize) {
        for challenge in &mut self.challenges {
            if challenge.datagram == ChallengeDatagram::Filling {
                challenge.datagram = ChallengeDatagram::Sealed {
                    expanded: len >= EXPANDED,
                };
            }
        }
    }

    /// The link accepted datagrams of the link path at `at`: the
    /// challenges sealed and not accepted yet count as sent then, and the
    /// next is due no sooner than the time to it after the last of them.
    pub(crate) fn accepted(&mut self, at: I) {
        let mut sent = false;
        for challenge in &mut self.challenges {
            if let ChallengeDatagram::Sealed { expanded } = challenge.datagram {
                challenge.datagram = ChallengeDatagram::Sent { expanded, at };
                sent = true;
            }
        }
        if sent && let Some(resend_at) = self.resend_at {
            // a time past what the instant type represents keeps the one
            // there is
            let later = at.checked_add(self.resend_after).unwrap_or(resend_at);
            self.resend_at = Some(resend_at.max(later));
        }
    }

    /// The challenge written since the timing was last taken, if one was:
    /// which of the validation under way it is, 1 for the first.
    pub(crate) fn untimed_attempt(&self) -> Option<u8> {
        self.untimed.then_some(self.attempts)
    }

    /// The timing of the challenge written last is taken at `now`: the next
    /// is due after `resend_after`, and the validation gives up after
    /// `abandon_after` from its first challenge. `None` past what the
    /// instant type represents: no deadline then.
    pub(crate) fn timed(&mut self, now: I, resend_after: Duration, abandon_after: Duration) {
        self.untimed = false;
        self.resend_after = resend_after;
        self.resend_at = now.checked_add(resend_after);
        if self.abandon_at.is_none() {
            self.abandon_at = now.checked_add(abandon_after);
        }
    }

    /// A PATH_RESPONSE with `data` arrived at `at`, over this link path
    /// when `here`: what it concludes, when it echoes a challenge of the
    /// validation under way and validates the address, or, after the
    /// address, the path's ability to carry 1200 bytes.
    pub(crate) fn responded(
        &mut self,
        data: [u8; PATH_DATA_LEN],
        here: bool,
        at: I,
    ) -> Option<PathValidationConclusion> {
        let index = self
            .challenges
            .iter()
            .position(|challenge| challenge.data == data)?;
        let challenge = self.challenges.remove(index)?;
        let expanded = challenge.expanded();
        match self.progress {
            Progress::Nothing => {
                let initial_rtt = match challenge.datagram {
                    ChallengeDatagram::Sent { at: sent, .. } if here && at >= sent => {
                        Some(at - sent)
                    }
                    _ => None,
                };
                if expanded {
                    self.finish();
                } else {
                    // the ability to carry 1200 bytes is validated next, in
                    // a validation of its own; the challenges of this one
                    // may still answer it
                    self.attempts = 0;
                    self.untimed = false;
                    self.resend_at = None;
                    self.abandon_at = None;
                    self.progress = Progress::Address;
                    self.due = true;
                }
                let conclusion = PathValidationConclusion::Validated {
                    initial_rtt,
                    supports_minimum: expanded,
                };
                self.conclusions.push_back(conclusion);
                Some(conclusion)
            }
            Progress::Address => {
                if !expanded {
                    return None;
                }
                self.finish();
                let conclusion = PathValidationConclusion::MinimumSupported;
                self.conclusions.push_back(conclusion);
                Some(conclusion)
            }
        }
    }

    /// The deadline came at `now`: the validation under way gives up, or
    /// the next challenge is due. Whether it gave up.
    fn expired(&mut self, now: I) -> bool {
        if self.abandon_at.is_some_and(|at| at <= now) {
            let conclusion = match self.progress {
                Progress::Nothing => PathValidationConclusion::Failed,
                Progress::Address => PathValidationConclusion::MinimumUnsupported,
            };
            self.finish();
            self.conclusions.push_back(conclusion);
            return true;
        }
        if self.resend_at.is_some_and(|at| at <= now) {
            self.resend_at = None;
            self.due = true;
        }
        false
    }

    /// The validation under way stops, concluding nothing: the link path
    /// closes.
    fn dropped(&mut self) {
        self.finish();
    }

    /// The oldest conclusion the rules of connection migration have not
    /// acted on, taken.
    pub(crate) fn take_conclusion(&mut self) -> Option<PathValidationConclusion> {
        self.conclusions.pop_front()
    }
}

/// A PATH_CHALLENGE frame is written when one is due and its data could be
/// drawn: the item is the intent's, which has no data of its own.
#[derive(Debug)]
pub struct PathChallengeSource<'l, I> {
    validation: &'l mut PathValidation<I>,
    /// The data drawn for the challenge, taken when it is written; `None`
    /// when the backend gave none.
    data: Option<[u8; PATH_DATA_LEN]>,
}

impl<I> FrameSource for PathChallengeSource<'_, I>
where
    I: Copy + Ord + CheckedAdd<Duration> + core::ops::Sub<Output = Duration>,
{
    type Summary = PathChallengeSummary;
    type Class = InFlightClass;
    type Item<'a> = ();

    fn supply<W, P, Idx>(
        &mut self,
        (): (),
        mut packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<PathChallengeSummary, Idx>,
        P: PacketPosition,
    {
        if self.validation.is_due()
            && let Some(data) = self.data
            && packet
                .write_frame(
                    PathChallengeFrame::new(data),
                    <SummaryOf<W>>::inject_summary(PathChallengeSummary),
                )
                .is_ok()
        {
            // one challenge in a packet (RFC 9000 §8.2.1, SHOULD NOT more)
            self.data = None;
            self.validation.written(data);
        }
        Supplied::Open(packet)
    }

    fn delivered(&mut self, _: PacketNumberSpaceKind, _: PathChallengeSummary) {}

    fn lost(&mut self, _: PacketNumberSpaceKind, _: &PathChallengeSummary) {}

    /// The challenge is the driver's content, which no strategy ends.
    fn unfulfilled(&mut self, (): (), _: Unfulfilled) {}
}

/// The PATH_CHALLENGE frames, as a kind of frame source.
#[derive(Debug)]
pub enum PathChallengeFrames {}

impl FrameSourceKind for PathChallengeFrames {
    type Item<'a> = ();
    type Summary<I> = PathChallengeSummary;
    /// Nothing is done when a frame comes back, and the source is found
    /// only in the link path's lineage.
    type Feedback = IgnoredFeedback<Self>;
}

/// The frames are written by the link path's [`PathValidation`] in the
/// lineage, with data drawn from the connection's cryptographic backend,
/// which is to give random bytes ([`Random`]).
impl<T, L, V, Ipv, Ib> FindFrameSource<T, L, V, (Ipv, Ib)> for PathChallengeFrames
where
    T: Choices,
    T::Crypto: Random,
    V: GetAt<PathValidationOf<T>, Ipv> + GetAt<PacketProtectionBackend<T::Crypto>, Ib>,
{
    type Source<'l, 'r>
        = PathChallengeSource<'l, InstantOf<T>>
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(lineage: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> Self::Source<'l, 'r> {
        let data = lineage
            .get::<PacketProtectionBackend<T::Crypto>, Ib>()
            .0
            .random::<PATH_DATA_LEN>()
            .ok();
        // found to write a challenge, which then is due no more
        lineage.publish(Happened::<PathChallengePendingChanged>::new());
        PathChallengeSource {
            validation: ComponentMut::into_mut(lineage.get_mut::<PathValidationOf<T>, Ipv>()),
            data,
        }
    }
}

/// A candidate starts with a challenge due (RFC 9000 §9.6.3); any other
/// link path starts with nothing to validate.
impl<T: Choices, L> Build<T, L, layer::LinkPath, ()> for PathValidationOf<T>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        args: &mut ArgsOf<T, L, layer::LinkPath>,
    ) -> Self {
        let mut validation = Self::default();
        if args.role == LinkPathRole::Candidate {
            let _due = validation.challenge_due();
        }
        validation
    }
}

/// The probe timeout of a path from `rtt`, in the Application Data space,
/// with the peer's `max_ack_delay`.
fn pto_of(rtt: &RttEstimate, granularity: Duration, max_ack_delay: Duration) -> Duration {
    probe_timeout(
        rtt,
        granularity,
        PacketNumberSpaceKind::ApplicationData,
        max_ack_delay,
        0,
    )
}

/// Its deadline is the next challenge due or the validation giving up: the
/// first makes a challenge due, the second fails the validation, unless the
/// link path closes, which drops it. It subscribes to its own challenges
/// written, whose timing it takes from the migration policy then, and to
/// the link path's packets sent, which its challenges count as sent at.
/// When the active link path's validation sets the instant it gives up at,
/// the fallback in `Settling` keeps at least until one timer granularity
/// past it ([`hold_fallback`]): the failure, which the logical path's
/// receiving call acts on, then finds it still there. When the active link
/// path's validation fails, the fallback keeps one granularity past then
/// as well, for a timer that fires late.
///
/// The timing's probe timeouts are read from the recovery layers: the link
/// path's own, the active link path's, and the one of a new path, from the
/// initial RTT (RFC 9002 §6.2.2).
impl<T, L, Ipv, Ir, Iv, Ima, Irt, Imig, Ilr, Ix>
    DataComponent<T, L, layer::LinkPath, ((Ipv, Ir, Iv), (Ima, Irt), (Imig, Ilr, Ix))>
    for PathValidationOf<T>
where
    T: Choices,
    L: LineagePartList<T> + ParametersOf<TransportParameterSpace>,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    super::MigrationPolicyOf<T>: MigrationPolicy<
            <T::Link as sakuya_link::Link>::Local,
            <T::Link as sakuya_link::Link>::Peer,
            InstantOf<T>,
        >,
    for<'v> <L as LineageLists<'v, T>>::LinkPath: GetAt<PathValidationOf<T>, Ipv>
        + GetAt<LinkPathRole<InstantOf<T>>, Ir>
        + ReadEach<LinkPathRoleReads<T, L>, Iv>
        + GetAt<ConnectionMigrationOf<T>, Imig>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Irt>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out: GetAt<LinkPathRole<InstantOf<T>>, Ilr>
        + TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Ix>,
{
    const DEADLINE: bool = true;

    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<PathChallengePendingChanged>()
            .add::<PacketsSent>();
    }

    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::LinkPath>) -> Option<InstantOf<T>> {
        lineage.get::<PathValidationOf<T>, Ipv>().deadline()
    }

    fn expire<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        let role = *lineage.get::<LinkPathRole<InstantOf<T>>, Ir>();
        let closing = matches!(role, LinkPathRole::Closing(_) | LinkPathRole::Draining(_));
        let (failed, due) = {
            let mut validation = lineage.get_mut::<PathValidationOf<T>, Ipv>();
            if closing {
                validation.dropped();
                return None;
            }
            (validation.expired(now), validation.is_due())
        };
        if failed {
            // the fallback was held one timer granularity past the instant
            // the validation gives up at; a timer that fires late reaches
            // both in one turn, and the fallback would end before the
            // logical path's receiving call, woken for the failure, reverts
            // to it (RFC 9000 §9.3.2): it keeps one granularity past now
            let fallback = lineage
                .get::<ConnectionMigrationOf<T>, Imig>()
                .fallback()
                .cloned();
            if role == LinkPathRole::Active
                && let Some(fallback) = fallback
            {
                let hlist_pat![_, thresholds, _] =
                    lineage.read_each::<LinkPathRoleReads<T, L>, Iv>();
                if let Some(until) = now.checked_add(thresholds.granularity()) {
                    let NodeKey::LinkPath(path, _) = others.here().clone() else {
                        unreachable!("a link path's lend carries its key")
                    };
                    hold_settling::<T, L, B, Ix>(others, &path, &fallback, until);
                }
            }
            lineage.publish(Happened::<PathValidationConcluded>::new());
        } else if due {
            lineage.publish(Happened::<PathChallengePendingChanged>::new());
        }
        None
    }

    fn on_events<'v, B: CallBundle>(
        events: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        if events.contains::<PacketsSent>() {
            lineage.get_mut::<PathValidationOf<T>, Ipv>().accepted(now);
        }
        let attempt = lineage
            .get::<PathValidationOf<T>, Ipv>()
            .untimed_attempt()?;
        let NodeKey::LinkPath(path, link) = others.here().clone() else {
            unreachable!("a link path's lend carries its key")
        };
        let hlist_pat![peer, thresholds, _] = lineage.read_each::<LinkPathRoleReads<T, L>, Iv>();
        let max_ack_delay = peer_max_ack_delay::<L, Ima>(peer).unwrap_or(DEFAULT_MAX_ACK_DELAY);
        let granularity = thresholds.granularity();
        let initial_pto = pto_of(
            &RttEstimate::initial(INITIAL_RTT),
            granularity,
            max_ack_delay,
        );
        let active = *lineage.get::<LinkPathRole<InstantOf<T>>, Ir>() == LinkPathRole::Active;
        let mut actives = Vec::new();
        others.each_link_path_read::<LinkPathRole<InstantOf<T>>, Ilr>(|key, role| {
            if *role == LinkPathRole::Active
                && let NodeKey::LinkPath(each, over) = key
                && *each == path
            {
                actives.push(over.clone());
            }
        });
        let mut path_pto = None;
        let mut active_pto = None;
        others.each_recovery_read::<RttOf<T, L>, Irt>(|key, rtt| {
            let Some(rtt) = rtt else { return };
            let pto = pto_of(&rtt.estimate(), granularity, max_ack_delay);
            match key {
                // the lent link path's own layer
                NodeKey::Recovery(each, over) if *each == path && *over == link => {
                    path_pto = Some(pto);
                }
                NodeKey::Recovery(each, over) if *each == path && actives.contains(over) => {
                    active_pto = Some(pto);
                }
                _ => {}
            }
        });
        if active {
            active_pto = path_pto;
        }
        let migration = lineage.get::<ConnectionMigrationOf<T>, Imig>();
        let timing = migration.policy().challenge_timing(&PathChallengeContext {
            attempt,
            path_pto,
            active_pto: active_pto.unwrap_or(initial_pto),
            initial_pto,
        });
        let fallback = migration.fallback().cloned();
        // never more often than the probe timeout (RFC 9000 §9.4, §8.2.1)
        let resend_after = timing.resend_after.max(path_pto.unwrap_or(initial_pto));
        let abandon_at = {
            let mut validation = lineage.get_mut::<PathValidationOf<T>, Ipv>();
            validation.timed(now, resend_after, timing.abandon_after);
            validation.abandon_at()
        };
        // one timer granularity past it, so that the failure, which the
        // logical path's receiving call acts on, finds the fallback there
        if active
            && let (Some(fallback), Some(until)) = (
                fallback,
                abandon_at.and_then(|at| at.checked_add(granularity)),
            )
        {
            hold_settling::<T, L, B, Ix>(others, &path, &fallback, until);
        }
        None
    }
}

/// The link path over `link` of the logical path `path`, when it is
/// `Settling`, keeps at least until `until` ([`hold_fallback`]); the change
/// is published at it.
pub(crate) fn hold_settling<T, L, B, Ix>(
    others: &mut OtherNodes<'_, T, L, B>,
    path: &crate::share::PathKey<L>,
    link: &LinkIdOf<T>,
    until: InstantOf<T>,
) where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Ix>,
{
    let held = others
        .link_path::<HList![LinkPathRole<InstantOf<T>>], Ix>(path, link)
        .and_then(|hlist_pat![mut role]| hold_fallback(&mut *role, until));
    if let Some(held) = held {
        others.publish_at(&NodeKey::LinkPath(path.clone(), link.clone()), held);
    }
}

#[cfg(test)]
mod tests;
