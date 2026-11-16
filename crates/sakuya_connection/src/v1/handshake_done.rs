//! What only one side of a connection keeps in its connection node: the
//! [`Own`](super::Side::Own) data of each side.
//!
//! A server keeps where its HANDSHAKE_DONE frame stands
//! ([`HandshakeDoneSource`]): it sends one once the handshake is complete,
//! in 1-RTT packets only, and sends it again while it is lost and not
//! acknowledged (RFC 9000 §12.4, §13.3, §19.20). A client keeps
//! [`ClientOnlyState`]: the token its Initial packets carry, where the
//! tokens its server gives in NEW_TOKEN frames go, and its Retry policy.
//! Both are where the HANDSHAKE_DONE frames of version 1 are found; a
//! client never publishes one, and writes nothing if it is given one, as a
//! client must not send the frame (RFC 9000 §19.20).

use core::fmt;
use std::collections::VecDeque;

use bytes::Bytes;
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream::send_options::destination::Unfulfilled;
use sakuya_wire::{parts::Selector, v1::frame::handshake_done::HandshakeDoneFrame};

use super::{
    Choices, Client, ConnectionArgs, address_token::AddressTokenSink,
    feedback::HandshakeDoneSummary, own_args, send::HandshakeDoneIntent,
};
use crate::{
    component::{ArgsOf, Build, ParentsOf, PassiveDataComponent},
    feedback::InjectSummary,
    frame_source::{FrameSource, PublishIntent},
    layer,
    share::{ConnectionArgsOf, LineagePartList},
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

    fn supply<W, P, Idx>(
        &mut self,
        (): (),
        mut packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<HandshakeDoneSummary, Idx>,
        P: PacketPosition,
    {
        let written = packet.write_frame(
            HandshakeDoneFrame,
            <SummaryOf<W>>::inject_summary(HandshakeDoneSummary),
        );
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

    /// The frame is sent and forgotten for any active link path: the
    /// strategy ends it only once no link path will be active again, which
    /// is the end of the connection, not an unfulfilled intent.
    fn unfulfilled(&mut self, (): (), _: Unfulfilled) {}
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

/// What a client's [`ClientOnlyState`] is made from, which the connection
/// node takes once when it is built.
pub struct ClientOnlyStart<Tk, Rp> {
    start: Option<(Bytes, Tk, Rp)>,
}

impl<Tk, Rp> ClientOnlyStart<Tk, Rp> {
    /// A connection attempt that sends `token` in its Initial packets, an
    /// empty one for none, puts the tokens its server gives into `sink`,
    /// and decides with `retry_policy` whether to go on after a Retry.
    ///
    /// `token` is a token from a NEW_TOKEN frame of an earlier connection
    /// to the same server (RFC 9000 §8.1.3); whoever makes the connection
    /// leaves out one that does not fit in an Initial packet
    /// ([`fits_initial_packet`](super::address_token::fits_initial_packet)).
    pub fn new(token: Bytes, sink: Tk, retry_policy: Rp) -> Self {
        Self {
            start: Some((token, sink, retry_policy)),
        }
    }
}

impl<Tk, Rp> fmt::Debug for ClientOnlyStart<Tk, Rp> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientOnlyStart")
            .field("taken", &self.start.is_none())
            .finish_non_exhaustive()
    }
}

/// How many of the tokens received on a connection a client remembers to
/// tell a token that comes again: a NEW_TOKEN frame sent again because it
/// was declared lost comes within a few round trips of the first.
const REMEMBERED_TOKENS: usize = 4;

/// What only a client keeps in its connection node: the token every
/// Initial packet of the connection attempt carries, where the tokens its
/// server gives go, its Retry policy, and the tokens received last, to drop
/// one that comes again.
pub struct ClientOnlyState<Tk, Rp> {
    initial_token: Bytes,
    sink: Tk,
    retry_policy: Rp,
    received: VecDeque<Bytes>,
}

impl<Tk, Rp> ClientOnlyState<Tk, Rp> {
    /// The token the Initial packets carry; empty for none.
    pub fn initial_token(&self) -> &Bytes {
        &self.initial_token
    }

    /// The Retry policy.
    pub fn retry_policy_mut(&mut self) -> &mut Rp {
        &mut self.retry_policy
    }
}

impl<Tk: AddressTokenSink, Rp> ClientOnlyState<Tk, Rp> {
    /// The server gave `token`: it goes to the sink unless it is one of the
    /// tokens received last (RFC 9000 §19.7).
    pub(super) fn new_token(&mut self, token: Bytes) {
        if self.received.contains(&token) {
            return;
        }
        if self.received.len() == REMEMBERED_TOKENS {
            self.received.pop_front();
        }
        self.received.push_back(token.clone());
        self.sink.keep(token);
    }
}

impl<Tk, Rp> fmt::Debug for ClientOnlyState<Tk, Rp> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientOnlyState")
            .field("initial_token_len", &self.initial_token.len())
            .field("received", &self.received.len())
            .finish_non_exhaustive()
    }
}

/// A client sends no HANDSHAKE_DONE frame (RFC 9000 §19.20): it publishes
/// no intent for one, and writes nothing when given one.
impl<Tk, Rp> FrameSource for ClientOnlyState<Tk, Rp> {
    type Summary = HandshakeDoneSummary;
    type Class = InFlightClass;
    type Item<'a> = ();
    type Intent = HandshakeDoneIntent;

    fn supply<W, P, Idx>(
        &mut self,
        (): (),
        packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<HandshakeDoneSummary, Idx>,
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

    /// A client publishes no intent, so none goes unfulfilled.
    fn unfulfilled(&mut self, (): (), _: Unfulfilled) {}
}

/// A client's connection starts with what [`ConnectionArgs::side`] gives,
/// having received no token yet.
impl<T, L, I, Tls, Tk, Rp> Build<T, L, layer::Connection, (I,)> for ClientOnlyState<Tk, Rp>
where
    T: Choices<Side = Client<Tls, Tk, Rp>>,
    Client<Tls, Tk, Rp>: super::Side<Start = ClientOnlyStart<Tk, Rp>>,
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        // invariant: the connection node, the only one that takes it, is
        // built once
        let (initial_token, sink, retry_policy) = own_args::<T, L, I>(args)
            .side
            .start
            .take()
            .expect("the connection node is built once");
        Self {
            initial_token,
            sink,
            retry_policy,
            received: VecDeque::new(),
        }
    }
}
/// It has no deadline and reads nothing; the receiving of NEW_TOKEN frames
/// and of a Retry changes it, and the sending call reads its token.
impl<Tk, Rp> PassiveDataComponent for ClientOnlyState<Tk, Rp> {}

#[cfg(test)]
mod tests;
