//! The fixed part of ECN on a link path (RFC 9000 §13.4): whether a
//! datagram is marked, and the validation of the counts the peer reports.
//!
//! [`LinkPathEcnState`] is a component of each link path's recovery layer,
//! beside [`LinkPathCongestionState`](super::recovery::LinkPathCongestionState):
//! it moves with the layer when only the port changes, so the link path the
//! layer moves to goes on with what the validation concluded, and a layer
//! built anew starts [`Unvalidated`](EcnValidationOutcome::Unvalidated).
//! What can be replaced, the codepoint, how long the test lasts and whether
//! to validate again, is the link path's [`EcnPolicy`], the same value as
//! its congestion controller.
//!
//! - Marking. At the start of each datagram, a link path that is active,
//!   over a link that may mark, asks its policy for the marking, unless it
//!   holds or its validation failed; every other datagram is Not-ECT, the
//!   probes of a candidate and the packets of a settling link path among
//!   them. A link path whose validation failed asks its policy whether to
//!   validate again instead (RFC 9000 §13.4.2.2, MAY), and goes on as
//!   unvalidated, with a new test, when it says so. The test starts at
//!   the first marking asked for, and counts the QUIC packets of the
//!   marked datagrams sealed since.
//! - Held. In a packet number space one link path marks at a time, as an
//!   ACK frame's counts are of the whole space: an active link path holds,
//!   sending Not-ECT and starting no test, while another link path of its
//!   logical path has marked packets outstanding, and stops holding once
//!   they are all acknowledged or declared lost.
//! - Outstanding marked packets. A marked packet the link accepted is
//!   outstanding in its space until it is newly acknowledged, declared
//!   lost, or its space is retired, or until the link path that sent it
//!   ends, which hands it back as lost, when the layer moved away from that
//!   link path: the packets the loss detection state of the layer keeps
//!   whose records the send journals still have.
//! - Validation. An ACK frame that increases the largest acknowledged
//!   packet number of a space is checked against the link path that has
//!   marked packets outstanding in the space, the one marking for it; an
//!   ACK frame that does not increase it is not looked at, and leaves the
//!   base its counts are compared with as it was (RFC 9000 §13.4.2.1,
//!   MUST NOT fail). The validation fails when the frame newly
//!   acknowledges a marked packet of the link path and has no ECN counts,
//!   when the increase of the ECT(0) or ECT(1) count with the CE count is
//!   less than the newly acknowledged packets sent with that codepoint, or
//!   when a reported count exceeds the packets the space sent with that
//!   codepoint (§13.4.2.1); and, while unvalidated, when every newly
//!   acknowledged marked packet was reported CE (Appendix A.4). Otherwise a
//!   frame that newly acknowledges a marked packet makes an unvalidated
//!   link path capable. A failed validation stops the marking at once
//!   (§13.4.2.2, MUST).
//! - Losses. While unvalidated, the validation fails once every marked
//!   packet the link path sent since its test started was declared lost
//!   and none was acknowledged (§13.4.2).
//! - CE. An increase of the CE count is one congestion event of the link
//!   path marking for the space, at the send time of the largest
//!   acknowledged packet (RFC 9002 §7.1, Appendix B.7), unless its
//!   validation failed.
use core::time::Duration;

use sakuya_link::EcnMarking;
use sakuya_recovery::{
    congestion::{CongestionContext, CongestionController},
    ecn::{EcnContext, EcnPolicy, EcnValidationOutcome},
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState},
    receive_journals::ReceivedEcnCounts,
    rtt::RttEstimate,
};
use sakuya_wire::v1::packet_number::PacketNumber;

use super::Choices;
use crate::{
    clock::InstantOf,
    component::{ArgsOf, Build, ParentsOf, PassiveDataComponent},
    layer,
    share::LineagePartList,
};

/// What the protocol defines for ECN on a link path: where its validation
/// stands, whether it holds, the test of its validation, and its marked
/// packets outstanding in each packet number space.
///
/// The policy is not in it; the methods take what the recovery factory
/// lends. `I` is the type of instants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkPathEcnState<I> {
    outcome: EcnValidationOutcome,
    hold: bool,
    test: EcnTest<I>,
    outstanding: MarkedOutstanding,
}

/// The test of the current validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EcnTest<I> {
    /// No marking was asked for since the validation started.
    NotStarted,
    /// Started at the first marking asked for.
    Started {
        /// When it started.
        at: I,
        /// The QUIC packets of the marked datagrams sealed since.
        marked: u64,
        /// Whether a marked packet was newly acknowledged since.
        acknowledged: bool,
        /// Whether a marked packet was declared lost since.
        lost: bool,
    },
}

/// The marked packets outstanding in each packet number space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct MarkedOutstanding {
    initial: u64,
    handshake: u64,
    application_data: u64,
}

impl MarkedOutstanding {
    fn of(&mut self, space: PacketNumberSpaceKind) -> &mut u64 {
        match space {
            PacketNumberSpaceKind::Initial => &mut self.initial,
            PacketNumberSpaceKind::Handshake => &mut self.handshake,
            PacketNumberSpaceKind::ApplicationData => &mut self.application_data,
        }
    }

    fn get(&self, space: PacketNumberSpaceKind) -> u64 {
        match space {
            PacketNumberSpaceKind::Initial => self.initial,
            PacketNumberSpaceKind::Handshake => self.handshake,
            PacketNumberSpaceKind::ApplicationData => self.application_data,
        }
    }

    fn total(&self) -> u64 {
        self.initial
            .saturating_add(self.handshake)
            .saturating_add(self.application_data)
    }
}

impl<I> Default for LinkPathEcnState<I> {
    fn default() -> Self {
        Self {
            outcome: EcnValidationOutcome::Unvalidated,
            hold: false,
            test: EcnTest::NotStarted,
            outstanding: MarkedOutstanding::default(),
        }
    }
}

/// What the ECN counts of an ACK frame that increases the largest
/// acknowledged packet number of a space come to in the space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EcnAckCounts {
    /// The increase of the counts over those of the last such frame of the
    /// space; `None` when the frame has no ECN counts.
    pub(crate) increase: Option<ReceivedEcnCounts>,
    /// Whether a count the frame reports exceeds the packets the space sent
    /// with that codepoint.
    pub(crate) exceeds_sent: bool,
}

/// The ECN counts `counts` of an ACK frame whose largest acknowledged
/// packet number is `largest`, in the space whose state `numbers` has not
/// taken the frame yet: `None` when the frame does not increase the
/// largest acknowledged packet number, and is not validated (RFC 9000
/// §13.4.2.1, MUST NOT fail); otherwise what they come to, and they are
/// the base the next such frame is compared with.
pub(crate) fn ack_counts(
    numbers: &mut PacketNumberSpaceState,
    largest: PacketNumber,
    counts: Option<ReceivedEcnCounts>,
) -> Option<EcnAckCounts> {
    if numbers
        .largest_acked()
        .is_some_and(|before| largest <= before)
    {
        return None;
    }
    let exceeds_sent = counts.is_some_and(|counts| {
        counts.ect0 > numbers.ect0_sent() || counts.ect1 > numbers.ect1_sent()
    });
    Some(EcnAckCounts {
        increase: counts.map(|counts| numbers.on_ecn_counts(counts)),
        exceeds_sent,
    })
}

/// What an ACK frame that increases the largest acknowledged packet number
/// of a space says of ECN to the link path marking for the space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EcnAck {
    /// What its counts come to in the space.
    pub(crate) counts: EcnAckCounts,
    /// The packets of the link path the frame newly acknowledges that were
    /// sent with ECT(0).
    pub(crate) newly_ect0: u64,
    /// The packets of the link path the frame newly acknowledges that were
    /// sent with ECT(1).
    pub(crate) newly_ect1: u64,
}

impl<I: Copy> LinkPathEcnState<I> {
    /// Unvalidated, not holding, with no test started and nothing
    /// outstanding.
    pub fn new() -> Self {
        Self::default()
    }

    /// Where the validation stands.
    pub fn outcome(&self) -> EcnValidationOutcome {
        self.outcome
    }

    /// Whether the link path held at the start of its last datagram:
    /// another link path of its logical path had marked packets
    /// outstanding.
    pub fn hold(&self) -> bool {
        self.hold
    }

    /// The marked packets outstanding, in every packet number space.
    pub fn marked_outstanding(&self) -> u64 {
        self.outstanding.total()
    }

    /// Whether marked packets of `space` are outstanding: the link path is
    /// the one marking for the space, and the counts of an ACK frame of the
    /// space are its.
    pub fn marks_for(&self, space: PacketNumberSpaceKind) -> bool {
        self.outstanding.get(space) > 0
    }

    /// The marking of a datagram that starts at `now`, on a link path whose
    /// RTT estimate is `rtt` and whose probe timeout without backoff is
    /// `pto`: Not-ECT unless it `may_mark`, being active over a link that
    /// may mark, and does not `hold` (another link path of its logical
    /// path has marked packets outstanding). A failed validation asks
    /// `policy` whether to validate again, and gives Not-ECT unless it
    /// does; then the test starts with the first marking asked for, and
    /// `policy` gives the marking.
    pub fn marking<P: EcnPolicy<I>>(
        &mut self,
        policy: &mut P,
        may_mark: bool,
        hold: bool,
        now: I,
        rtt: RttEstimate,
        pto: Duration,
    ) -> EcnMarking {
        self.hold = hold;
        if !may_mark || hold {
            return EcnMarking::NotEct;
        }
        if self.outcome == EcnValidationOutcome::Failed {
            if !policy.wants_revalidation(&self.context(now, rtt, pto)) {
                return EcnMarking::NotEct;
            }
            // the counts at this moment are the base already: each space
            // compares the next frame's counts with its last frame's
            self.outcome = EcnValidationOutcome::Unvalidated;
            self.test = EcnTest::NotStarted;
        }
        if matches!(self.test, EcnTest::NotStarted) {
            self.test = EcnTest::Started {
                at: now,
                marked: 0,
                acknowledged: false,
                lost: false,
            };
        }
        policy.marking(&self.context(now, rtt, pto))
    }

    /// What the policy decides from at `now`.
    fn context(&self, now: I, rtt: RttEstimate, pto: Duration) -> EcnContext<I> {
        let (started_at, marked_since_start) = match self.test {
            EcnTest::NotStarted => (now, 0),
            EcnTest::Started { at, marked, .. } => (at, marked),
        };
        EcnContext {
            now,
            outcome: self.outcome,
            marked_since_start,
            started_at,
            rtt,
            pto,
        }
    }

    /// A datagram marked `marking` was sealed with `packets` QUIC packets:
    /// a marked one's count toward the test.
    pub fn on_datagram_sealed(&mut self, marking: EcnMarking, packets: u64) {
        if marking == EcnMarking::NotEct {
            return;
        }
        if let EcnTest::Started { marked, .. } = &mut self.test {
            *marked = marked.saturating_add(packets);
        }
    }

    /// The link accepted a packet of `space` sent marked `marking`: a
    /// marked one is outstanding until it is acknowledged, declared lost,
    /// or its space is retired.
    pub fn on_accepted(&mut self, space: PacketNumberSpaceKind, marking: EcnMarking) {
        if marking != EcnMarking::NotEct {
            let outstanding = self.outstanding.of(space);
            *outstanding = outstanding.saturating_add(1);
        }
    }

    /// Validate `ack`, an ACK frame of a space this link path marks for, as
    /// the [module documentation](self) says; an increase of the CE count
    /// is then a congestion event of `controller`, with the send time of
    /// the largest acknowledged packet, `largest_sent_at`, and `context`,
    /// unless the validation failed. A link path whose validation failed
    /// looks at nothing.
    pub(crate) fn on_ack<C: CongestionController<I>>(
        &mut self,
        ack: &EcnAck,
        controller: &mut C,
        largest_sent_at: Option<I>,
        context: &CongestionContext<I>,
    ) {
        if self.outcome == EcnValidationOutcome::Failed {
            return;
        }
        let newly = ack.newly_ect0.saturating_add(ack.newly_ect1);
        let Some(increase) = ack.counts.increase else {
            if newly > 0 {
                self.outcome = EcnValidationOutcome::Failed;
            }
            return;
        };
        let failed = ack.counts.exceeds_sent
            || ack.newly_ect0 > increase.ect0.saturating_add(increase.ce)
            || ack.newly_ect1 > increase.ect1.saturating_add(increase.ce)
            || (self.outcome == EcnValidationOutcome::Unvalidated
                && newly > 0
                && increase.ect0 == 0
                && increase.ect1 == 0);
        if failed {
            self.outcome = EcnValidationOutcome::Failed;
            return;
        }
        if newly > 0 {
            self.outcome = EcnValidationOutcome::Capable;
        }
        if increase.ce > 0
            && let Some(sent_at) = largest_sent_at
        {
            controller.on_ce(increase.ce, sent_at, context);
        }
    }

    /// `marked` marked packets of `space` were newly acknowledged: they are
    /// no longer outstanding, and the test saw one acknowledged.
    pub fn on_acknowledged(&mut self, space: PacketNumberSpaceKind, marked: u64) {
        if marked == 0 {
            return;
        }
        let outstanding = self.outstanding.of(space);
        *outstanding = outstanding.saturating_sub(marked);
        if let EcnTest::Started { acknowledged, .. } = &mut self.test {
            *acknowledged = true;
        }
    }

    /// `marked` marked packets of `space` were declared lost: they are no
    /// longer outstanding, and an unvalidated link path fails once every
    /// marked packet since its test started is lost.
    pub fn on_lost(&mut self, space: PacketNumberSpaceKind, marked: u64) {
        if marked == 0 {
            return;
        }
        let outstanding = self.outstanding.of(space);
        *outstanding = outstanding.saturating_sub(marked);
        let EcnTest::Started {
            acknowledged, lost, ..
        } = &mut self.test
        else {
            return;
        };
        *lost = true;
        if self.outcome == EcnValidationOutcome::Unvalidated
            && !*acknowledged
            && self.outstanding.total() == 0
        {
            self.outcome = EcnValidationOutcome::Failed;
        }
    }

    /// The space `space` was retired: its packets left without a signal,
    /// and none of it is outstanding.
    pub fn on_space_retired(&mut self, space: PacketNumberSpaceKind) {
        *self.outstanding.of(space) = 0;
    }

    /// The server rejected 0-RTT: the marked packets of the Application
    /// Data space outstanding, all 0-RTT packets then, left without a
    /// signal, and the test hears of nothing.
    pub fn on_zero_rtt_rejected(&mut self) {
        *self.outstanding.of(PacketNumberSpaceKind::ApplicationData) = 0;
    }

    /// `marked` marked packets of `space`, sent by a link path that ended
    /// after this layer moved away from it, left with the link path: they
    /// are no longer outstanding, and, as they left without a signal, the
    /// test hears of nothing.
    pub(crate) fn on_link_path_ended(&mut self, space: PacketNumberSpaceKind, marked: u64) {
        let outstanding = self.outstanding.of(space);
        *outstanding = outstanding.saturating_sub(marked);
    }
}

/// A recovery layer built anew starts unvalidated.
impl<T: Choices, L> Build<T, L, layer::Recovery, ()> for LinkPathEcnState<InstantOf<T>>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Recovery>,
        _: &mut ArgsOf<T, L, layer::Recovery>,
    ) -> Self {
        Self::new()
    }
}
impl<I> PassiveDataComponent for LinkPathEcnState<I> {}

#[cfg(test)]
mod tests;
