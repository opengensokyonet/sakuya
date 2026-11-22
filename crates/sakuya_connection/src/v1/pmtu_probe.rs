//! The datagram size probes of a link path (RFC 9000 §14.3, §14.4).
//!
//! The link path's datagram size probing policy says what size to probe
//! ([`probe_size`](sakuya_recovery_v1::pmtu::PmtuPolicy::probe_size)); the
//! link path keeps the probe to send now ([`PendingPmtuProbe`]), copied
//! from the policy after each of its events, and the driver gathers it for
//! the link path's planner as a [`PmtuProbeIntent`]. A probe is sent on an
//! `Active` link path once the handshake is confirmed, and not again while
//! one of the same size awaits its result
//! ([`LinkPathCongestionState::pmtu_probe_awaited`]).
//!
//! The probe is a 1-RTT packet that is the whole datagram: a PING, which
//! [`PendingPmtuProbe`] writes, and PADDING to the probe's size, which
//! filling adds; the packet is marked a probe in its record, so that its
//! loss is no congestion signal (§14.4). Nothing is done when the PING is
//! acknowledged or lost: the result goes to the policy from the packet's
//! record.
//!
//! [`LinkPathCongestionState::pmtu_probe_awaited`]: super::recovery::LinkPathCongestionState::pmtu_probe_awaited

use crate::v1::state_choices::StateChoices;
use sakuya_recovery_v1::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream_v1::send_options::destination::Unfulfilled;
use sakuya_wire_v1::frame::ping::PingFrame;
use sakuya_wire_v1::frame::write::InFlightClass;

use super::{
    component_events::PmtuProbePendingChanged, confirmation::HandshakeConfirmation,
    send::FrameSourceId,
};
use crate::{
    clock::{ConnectionChoices, InstantOf},
    component::{ArgsOf, Build, ParentsOf, PassiveDataComponent},
    component_event::Happened,
    feedback::InjectSummary,
    frame_source::{FindFrameSource, FrameSource, FrameSourceKind, IgnoredFeedback},
    layer,
    send_strategy::{
        LinkPathRoleKind, MinimumLengths, SendIntent,
        ranked::{RankedIntent, SendPriority, SendRank},
    },
    share::LineagePartList,
    take::{ComponentMut, GetAt, Lineage},
    write::{OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// A datagram size probe of `size` bytes is to be sent on the link path
/// whose content it is: a datagram of exactly that size, led by a PING.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PmtuProbeIntent {
    size: usize,
}

impl PmtuProbeIntent {
    /// A probe of `size` bytes.
    pub const fn new(size: usize) -> Self {
        Self { size }
    }

    /// The size of the probe's datagram.
    pub const fn size(&self) -> usize {
        self.size
    }
}

impl SendIntent for PmtuProbeIntent {
    type FrameSourceId = FrameSourceId;
    type Class = InFlightClass;

    fn frame_source(&self) -> FrameSourceId {
        FrameSourceId::PmtuProbe
    }

    fn min_lengths(&self) -> MinimumLengths {
        MinimumLengths {
            with_length: 1,
            as_last: 1,
        }
    }
}

/// A probe ranks as a path MTU probe, does not hold its place, and is a
/// datagram of its size.
impl RankedIntent for PmtuProbeIntent {
    fn rank(&self) -> SendRank {
        SendRank {
            priority: SendPriority::PathMtuProbe,
            holds_place: false,
        }
    }

    fn exact_datagram_size(&self) -> Option<usize> {
        Some(self.size)
    }
}

/// What the PING of a datagram size probe written into a packet is
/// remembered by: nothing, as the probe's result goes to the probing policy
/// from the packet's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PmtuProbeSummary;

/// The size of the datagram size probe a link path is to send now
/// (`PendingPmtuProbe`), in the link path's node; `None` while there is
/// none. It is set anew after each event of the link path's probing policy
/// and cleared when its PING is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PendingPmtuProbe(Option<usize>);

impl PendingPmtuProbe {
    /// The size of the probe to send, if one is to be sent.
    pub fn size(&self) -> Option<usize> {
        self.0
    }

    /// The probe a link path in `role` is to send, with the handshake in
    /// `confirmation`, when its probing policy gives `probe_size` and a
    /// probe of `awaited` bytes awaits its result: the policy's size on an
    /// `Active` link path once the handshake is confirmed, unless a probe
    /// of that size awaits its result.
    pub(super) fn wanted(
        role: LinkPathRoleKind,
        confirmation: HandshakeConfirmation,
        probe_size: impl FnOnce() -> Option<usize>,
        awaited: Option<usize>,
    ) -> Option<usize> {
        if role != LinkPathRoleKind::Active || confirmation != HandshakeConfirmation::Confirmed {
            return None;
        }
        probe_size().filter(|&size| awaited != Some(size))
    }

    /// The probe to send is now `size`. What happened.
    pub(super) fn set(&mut self, size: Option<usize>) -> Happened<PmtuProbePendingChanged> {
        self.0 = size;
        Happened::new()
    }
}

/// The PING is written when the item's size is the probe waiting, which
/// then no longer waits; nothing is done when it is acknowledged or lost.
impl FrameSource for PendingPmtuProbe {
    type Summary = PmtuProbeSummary;
    type Class = InFlightClass;
    type Item<'a> = usize;

    fn supply<W, P, Idx>(
        &mut self,
        size: usize,
        mut packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<PmtuProbeSummary, Idx>,
        P: PacketPosition,
    {
        if self.0 == Some(size)
            && packet
                .write_frame(PingFrame, <SummaryOf<W>>::inject_summary(PmtuProbeSummary))
                .is_ok()
        {
            self.0 = None;
        }
        Supplied::Open(packet)
    }

    fn delivered(&mut self, _: PacketNumberSpaceKind, _: PmtuProbeSummary) {}

    fn lost(&mut self, _: PacketNumberSpaceKind, _: &PmtuProbeSummary) {}

    /// The probe is the driver's content, which no strategy ends.
    fn unfulfilled(&mut self, _: usize, _: Unfulfilled) {}
}

/// The PING of a datagram size probe, as a kind of frame source.
#[derive(Debug)]
pub enum PmtuProbeFrames {}

impl FrameSourceKind for PmtuProbeFrames {
    type Item<'a> = usize;
    type Summary<I> = PmtuProbeSummary;
    /// Nothing is done when a frame comes back, and the source is found
    /// only in the link path's lineage.
    type Feedback = IgnoredFeedback<Self>;
}

/// The PING is written by the link path's [`PendingPmtuProbe`] in the
/// lineage.
impl<T: ConnectionChoices, L, V, Ip> FindFrameSource<T, L, V, Ip> for PmtuProbeFrames
where
    V: GetAt<PendingPmtuProbe, Ip>,
{
    type Source<'l, 'r>
        = &'l mut PendingPmtuProbe
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(lineage: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> Self::Source<'l, 'r> {
        // found to write its PING, which clears the probe to send
        lineage.publish(Happened::<PmtuProbePendingChanged>::new());
        ComponentMut::into_mut(lineage.get_mut::<PendingPmtuProbe, Ip>())
    }
}

/// A link path starts with no probe to send.
impl<T: StateChoices, L> Build<T, L, layer::LinkPath, ()> for PendingPmtuProbe
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        _: &mut ArgsOf<T, L, layer::LinkPath>,
    ) -> Self {
        Self::default()
    }
}
/// It has no deadline and subscribes to nothing; filling and the link path's
/// planner set it from the probing policy, and the sending call writes it.
impl PassiveDataComponent for PendingPmtuProbe {}
