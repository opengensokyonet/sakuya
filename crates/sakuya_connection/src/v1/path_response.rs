//! The PATH_RESPONSE frames this side sends to the peer's PATH_CHALLENGE
//! frames (RFC 9000 §8.2.2).
//!
//! An endpoint that receives a PATH_CHALLENGE frame must answer with a
//! PATH_RESPONSE frame that echoes its data, on the network path the
//! challenge arrived on (§8.2.2, MUST); the response is not sent again when
//! it is lost (§13.3), as a new challenge comes instead, and a datagram that
//! carries it is expanded to at least 1200 bytes unless the
//! anti-amplification limit holds it (§8.2.1, §8.2.2).
//!
//! The frame dispatch publishes a [`PathResponseIntent`] with the
//! challenge's data on the planner of the link path the packet arrived on;
//! the link path keeps the planner's outcome of the latest one
//! ([`PathResponsePublication`]), so that a newer challenge withdraws the
//! response to an older one before it is sent. The response goes in a 1-RTT
//! packet only (§12.4, Table 3); a link path that does not take intents, one
//! that is not active, sends none. The frame is written by
//! [`PathResponseSource`], which needs nothing but the intent's data, and
//! nothing is done when it is acknowledged or lost.

use core::fmt;

use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream::send_options::destination::Unfulfilled;
use sakuya_wire::v1::frame::{PATH_DATA_LEN, path_response::PathResponseFrame};

use super::{Choices, send::FrameSourceId};
use crate::{
    clock::{ConnectionChoices, InstantOf},
    component::{ArgsOf, Build, ParentsOf, PassiveDataComponent},
    feedback::InjectSummary,
    frame_source::{FindFrameSource, FrameSource, FrameSourceKind, NoIntent, PublishIntent},
    layer,
    send_strategy::{
        MinimumLengths, SendIntent,
        ranked::{RankedIntent, SendPriority, SendRank},
    },
    share::LineagePartList,
    take::Lineage,
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// A PATH_RESPONSE frame that echoes `data`, the data of the peer's
/// PATH_CHALLENGE, is to be sent on the link path it is published on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathResponseIntent {
    data: [u8; PATH_DATA_LEN],
}

impl PathResponseIntent {
    /// The response to a PATH_CHALLENGE frame with `data`.
    pub const fn new(data: [u8; PATH_DATA_LEN]) -> Self {
        Self { data }
    }

    /// The data the response echoes.
    pub const fn data(&self) -> [u8; PATH_DATA_LEN] {
        self.data
    }

    /// The frame of the response.
    pub const fn frame(&self) -> PathResponseFrame {
        PathResponseFrame::new(self.data)
    }
}

impl SendIntent for PathResponseIntent {
    type FrameSourceId = FrameSourceId;
    type Class = InFlightClass;

    fn frame_source(&self) -> FrameSourceId {
        FrameSourceId::PathResponse
    }

    fn min_lengths(&self) -> MinimumLengths {
        let len = self.frame().encoded_len();
        MinimumLengths {
            with_length: len,
            as_last: len,
        }
    }
}

/// The rank is provisional.
impl RankedIntent for PathResponseIntent {
    fn rank(&self) -> SendRank {
        SendRank {
            priority: SendPriority::Control,
            holds_place: true,
        }
    }
}

/// What a PATH_RESPONSE frame written into a packet is remembered by:
/// nothing, as nothing is done when it is acknowledged or lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathResponseSummary;

/// Writes the PATH_RESPONSE frame of an intent from the intent's data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PathResponseSource;

/// The frame is written whenever it is supplied; a lost one is not sent
/// again (RFC 9000 §13.3).
impl FrameSource for PathResponseSource {
    type Summary = PathResponseSummary;
    type Class = InFlightClass;
    type Item<'a> = [u8; PATH_DATA_LEN];
    type Intent = NoIntent;

    fn supply<W, P, Idx>(
        &mut self,
        data: [u8; PATH_DATA_LEN],
        mut packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<PathResponseSummary, Idx>,
        P: PacketPosition,
    {
        let written = packet.write_frame(
            PathResponseFrame::new(data),
            <SummaryOf<W>>::inject_summary(PathResponseSummary),
        );
        debug_assert!(written.is_ok(), "the intent asks room for the whole frame");
        Supplied::Open(packet)
    }

    fn delivered<Pb, Idx>(&mut self, _: &mut Pb, _: PacketNumberSpaceKind, _: PathResponseSummary)
    where
        Pb: PublishIntent<NoIntent, Idx>,
    {
    }

    fn lost<Pb, Idx>(&mut self, _: &mut Pb, _: PacketNumberSpaceKind, _: &PathResponseSummary)
    where
        Pb: PublishIntent<NoIntent, Idx>,
    {
    }

    /// A response the strategy ends is not sent: the peer challenges again
    /// if it still needs one.
    fn unfulfilled(&mut self, _: [u8; PATH_DATA_LEN], _: Unfulfilled) {}
}

/// The PATH_RESPONSE frames, as a kind of frame source.
#[derive(Debug)]
pub enum PathResponseFrames {}

impl FrameSourceKind for PathResponseFrames {
    type Item<'a> = [u8; PATH_DATA_LEN];
    type Summary<I> = PathResponseSummary;
    type Intent = NoIntent;
}

/// The frames are written from the intents alone, in any lineage.
impl<T: ConnectionChoices, L, V> FindFrameSource<T, L, V, ()> for PathResponseFrames {
    type Source<'l, 'r>
        = PathResponseSource
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(_: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> PathResponseSource {
        PathResponseSource
    }
}

/// What the planner of a link path gave back for the response to the
/// latest PATH_CHALLENGE that arrived on it, `O`; `None` before one did.
/// Replacing it drops the outcome of the response before, which withdraws
/// that response if it was not sent yet.
pub struct PathResponsePublication<O>(Option<O>);

impl<O> PathResponsePublication<O> {
    /// The response to a newer challenge was published, with `outcome`.
    pub(super) fn published(&mut self, outcome: O) {
        self.0 = Some(outcome);
    }
}

impl<O> fmt::Debug for PathResponsePublication<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PathResponsePublication")
            .field(&self.0.is_some())
            .finish()
    }
}

/// A link path starts with no challenge answered.
impl<T: Choices, L, O> Build<T, L, layer::LinkPath, ()> for PathResponsePublication<O>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        _: &mut ArgsOf<T, L, layer::LinkPath>,
    ) -> Self {
        Self(None)
    }
}
/// It has no deadline and reads nothing; the frame dispatch replaces it.
impl<O> PassiveDataComponent for PathResponsePublication<O> {}
