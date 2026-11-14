//! What only one side of a connection keeps in its connection node: the
//! [`Own`](super::Side::Own) data of each side.
//!
//! A server keeps where its HANDSHAKE_DONE frame stands
//! ([`HandshakeDoneSource`]): it sends one once the handshake is complete,
//! in 1-RTT packets only, and sends it again while it is lost and not
//! acknowledged (RFC 9000 §12.4, §13.3, §19.20). A client keeps
//! [`ClientOnlyState`], which has nothing yet. Both are where the
//! HANDSHAKE_DONE frames of version 1 are found; a client never publishes
//! one, and writes nothing if it is given one, as a client must not send
//! the frame (RFC 9000 §19.20).

use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_wire::v1::frame::handshake_done::HandshakeDoneFrame;

use super::{Choices, feedback::HandshakeDoneSummary, send::HandshakeDoneIntent};
use crate::{
    component::{ArgsOf, Build, ParentsOf, PassiveDataComponent},
    frame_source::{FrameSource, PublishIntent},
    layer,
    share::LineagePartList,
    write::{InFlightClass, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// Where a server's HANDSHAKE_DONE frame stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandshakeDoneSource {
    /// The handshake is not complete: nothing is to be sent.
    #[default]
    NotDue,
    /// The frame is to be sent, or was sent and is not acknowledged yet.
    Due,
    /// A packet with the frame was acknowledged.
    Delivered,
}

impl HandshakeDoneSource {
    /// The handshake is complete: the frame is due, and its intent is
    /// published to `publish`. A frame due already, or delivered, stays as
    /// it is.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the server's advancing call makes it due")
    )]
    pub(crate) fn due<Pb, Idx>(&mut self, publish: &mut Pb)
    where
        Pb: PublishIntent<HandshakeDoneIntent, Idx>,
    {
        if *self == Self::NotDue {
            *self = Self::Due;
            publish.publish(HandshakeDoneIntent);
        }
    }
}

/// The frame is written whenever it is supplied, also after a copy of it
/// was acknowledged: the intent was published, and writing nothing would
/// leave it there. One frame more is harmless to the client.
impl FrameSource for HandshakeDoneSource {
    type Summary = HandshakeDoneSummary;
    type Class = InFlightClass;
    type Item<'a> = ();
    type Intent = HandshakeDoneIntent;

    fn supply<W, P>(
        &mut self,
        (): (),
        mut packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: From<HandshakeDoneSummary>,
        P: PacketPosition,
    {
        let written = packet.write_frame(HandshakeDoneFrame, HandshakeDoneSummary);
        debug_assert!(written.is_ok(), "the intent asks room for the whole frame");
        Supplied::Open(packet)
    }

    fn delivered<Pb, Idx>(&mut self, _: &mut Pb, _: PacketNumberSpaceKind, _: HandshakeDoneSummary)
    where
        Pb: PublishIntent<HandshakeDoneIntent, Idx>,
    {
        *self = Self::Delivered;
    }

    fn lost<Pb, Idx>(
        &mut self,
        publish: &mut Pb,
        _: PacketNumberSpaceKind,
        _: &HandshakeDoneSummary,
    ) where
        Pb: PublishIntent<HandshakeDoneIntent, Idx>,
    {
        if *self != Self::Delivered {
            publish.publish(HandshakeDoneIntent);
        }
    }
}

/// No connection starts with its handshake complete.
impl<T: Choices, L> Build<T, L, layer::Connection, ()> for HandshakeDoneSource
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        Self::NotDue
    }
}
/// It has no deadline and reads nothing; the advancing call makes it due,
/// and the sending call and the settling of its packets change it.
impl PassiveDataComponent for HandshakeDoneSource {}

/// What only a client keeps in its connection node: nothing yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClientOnlyState;

/// A client sends no HANDSHAKE_DONE frame (RFC 9000 §19.20): it publishes
/// no intent for one, and writes nothing when given one.
impl FrameSource for ClientOnlyState {
    type Summary = HandshakeDoneSummary;
    type Class = InFlightClass;
    type Item<'a> = ();
    type Intent = HandshakeDoneIntent;

    fn supply<W, P>(
        &mut self,
        (): (),
        packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: From<HandshakeDoneSummary>,
        P: PacketPosition,
    {
        Supplied::Open(packet)
    }

    fn delivered<Pb, Idx>(&mut self, _: &mut Pb, _: PacketNumberSpaceKind, _: HandshakeDoneSummary)
    where
        Pb: PublishIntent<HandshakeDoneIntent, Idx>,
    {
    }

    fn lost<Pb, Idx>(&mut self, _: &mut Pb, _: PacketNumberSpaceKind, _: &HandshakeDoneSummary)
    where
        Pb: PublishIntent<HandshakeDoneIntent, Idx>,
    {
    }
}

/// A client's connection starts with nothing of its own.
impl<T: Choices, L> Build<T, L, layer::Connection, ()> for ClientOnlyState
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        _: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        Self
    }
}
/// It has no deadline and reads nothing.
impl PassiveDataComponent for ClientOnlyState {}

#[cfg(test)]
mod tests;
