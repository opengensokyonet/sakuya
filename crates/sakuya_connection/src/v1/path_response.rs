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
//! The frame dispatch keeps the challenge's data in the link path the
//! packet arrived on ([`PendingPathResponse`]), replacing the data of an
//! older challenge not answered yet, so that only the latest is answered;
//! the sending call gathers it for the link path's planner as a
//! [`PathResponseIntent`]. The response goes in a 1-RTT packet only (§12.4,
//! Table 3); a link path that is not active sends none. The frame is
//! written by the [`PendingPathResponse`] itself, which forgets the data once
//! it is written, and nothing is done when it is acknowledged or lost.

use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream::send_options::destination::Unfulfilled;
use sakuya_wire::v1::frame::{PATH_DATA_LEN, path_response::PathResponseFrame};

use super::{Choices, send::FrameSourceId};
use crate::{
    clock::{ConnectionChoices, InstantOf},
    component::{ArgsOf, Build, ParentsOf, PassiveDataComponent},
    feedback::InjectSummary,
    frame_source::{FindFrameSource, FrameSource, FrameSourceKind, IgnoredFeedback},
    layer,
    send_strategy::{
        MinimumLengths, SendIntent,
        ranked::{RankedIntent, SendPriority, SendRank},
    },
    share::LineagePartList,
    take::{ComponentMut, GetAt, Lineage},
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// A PATH_RESPONSE frame that echoes `data`, the data of the peer's
/// PATH_CHALLENGE, is to be sent on the link path whose content it is.
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

/// The data of the latest PATH_CHALLENGE that arrived on a link path and is
/// not answered yet (`PendingPathResponse`), in the link path's node;
/// `None` while there is none. A newer challenge replaces it (RFC 9000
/// §8.2.2: only the latest is answered), and writing its response forgets
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PendingPathResponse(Option<[u8; PATH_DATA_LEN]>);

impl PendingPathResponse {
    /// The data the response to send echoes, if one is to be sent.
    pub fn data(&self) -> Option<[u8; PATH_DATA_LEN]> {
        self.0
    }

    /// A PATH_CHALLENGE with `data` arrived: its response is the one to
    /// send.
    pub(super) fn challenged(&mut self, data: [u8; PATH_DATA_LEN]) {
        self.0 = Some(data);
    }
}

/// The frame is written when the item's data is the one waiting, which it
/// then no longer is; a lost one is not sent again (RFC 9000 §13.3).
impl FrameSource for PendingPathResponse {
    type Summary = PathResponseSummary;
    type Class = InFlightClass;
    type Item<'a> = [u8; PATH_DATA_LEN];

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
        if self.0 == Some(data)
            && packet
                .write_frame(
                    PathResponseFrame::new(data),
                    <SummaryOf<W>>::inject_summary(PathResponseSummary),
                )
                .is_ok()
        {
            self.0 = None;
        }
        Supplied::Open(packet)
    }

    fn delivered(&mut self, _: PacketNumberSpaceKind, _: PathResponseSummary) {}

    fn lost(&mut self, _: PacketNumberSpaceKind, _: &PathResponseSummary) {}

    /// The response is the driver's content, which no strategy ends.
    fn unfulfilled(&mut self, _: [u8; PATH_DATA_LEN], _: Unfulfilled) {}
}

/// The PATH_RESPONSE frames, as a kind of frame source.
#[derive(Debug)]
pub enum PathResponseFrames {}

impl FrameSourceKind for PathResponseFrames {
    type Item<'a> = [u8; PATH_DATA_LEN];
    type Summary<I> = PathResponseSummary;
    /// Nothing is done when a frame comes back, and the source is found
    /// only in the link path's lineage.
    type Feedback = IgnoredFeedback<Self>;
}

/// The frames are written by the link path's [`PendingPathResponse`] in the
/// lineage.
impl<T: ConnectionChoices, L, V, Ip> FindFrameSource<T, L, V, Ip> for PathResponseFrames
where
    V: GetAt<PendingPathResponse, Ip>,
{
    type Source<'l, 'r>
        = &'l mut PendingPathResponse
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(lineage: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> Self::Source<'l, 'r> {
        ComponentMut::into_mut(lineage.get_mut::<PendingPathResponse, Ip>())
    }
}

/// A link path starts with no challenge to answer.
impl<T: Choices, L> Build<T, L, layer::LinkPath, ()> for PendingPathResponse
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
/// It has no deadline and reads nothing; the frame dispatch sets it, and
/// the sending call writes it.
impl PassiveDataComponent for PendingPathResponse {}
