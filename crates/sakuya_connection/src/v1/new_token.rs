//! The NEW_TOKEN frames a server sends (RFC 9000 §8.1.3, §19.7): the
//! [`NewTokens`](super::Side::NewTokens) data of each side, in the
//! connection node.
//!
//! A server keeps the tokens it issued and has not seen delivered
//! ([`NewTokenSource`]), with the issuer it was started with
//! ([`ServerOnlyStart`]). It issues one once its handshake is confirmed,
//! bound to the peer of the active link path, and one each time the address
//! of a later link path is validated, bound to that link path's peer, a
//! change of the port alone among them (§8.1.3: a token for the address the
//! client is on now). It sends each in 1-RTT packets of the active link
//! path, again while it is lost and not acknowledged, and not again once
//! it is acknowledged (§13.3). A token that cannot be bound to the peer, or
//! that the issuer could not make, is not sent.
//!
//! A client sends no NEW_TOKEN frame (§19.7): its [`NoNewTokens`] never has
//! one waiting, and writes nothing if it is given one.

use alloc::collections::VecDeque;
use core::fmt;
use sakuya_wire_v1::frame::write::InFlightClass;

use bytes::Bytes;
use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream::send_options::destination::Unfulfilled;
use sakuya_wire::{
    parts::Selector,
    var_int::{VarInt, VarIntWidth},
};
use sakuya_wire_v1::frame::new_token::NewTokenFrame;

use super::{
    Choices, ConnectionArgs, Server, address_token::ConnectionNewTokenIssuer,
    component_events::NewTokenPendingChanged, own_args, send::FrameSourceId,
};
use crate::{
    component::{ArgsOf, Build, ParentsOf, PassiveDataComponent},
    component_event::Happened,
    feedback::InjectSummary,
    frame_source::FrameSource,
    layer,
    send_strategy::{
        MinimumLengths, SendIntent,
        ranked::{RankedIntent, SendPriority, SendRank},
    },
    share::{ConnectionArgsOf, LineagePartList},
    write::{OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// How many of the tokens it issued a server keeps until they are
/// delivered: once more are issued, the oldest is not sent again, as a
/// token for an address the client left is the least useful.
const KEPT_TOKENS: usize = 4;

/// What a server's connection is started with besides its handshake
/// engine: the issuer of its NEW_TOKEN tokens, which its
/// [`NewTokenSource`] takes once when the connection node is built.
pub struct ServerOnlyStart<Ti> {
    issuer: Option<Ti>,
}

impl<Ti> ServerOnlyStart<Ti> {
    /// A server connection that takes the tokens of its NEW_TOKEN frames
    /// from `issuer`.
    pub fn new(issuer: Ti) -> Self {
        Self {
            issuer: Some(issuer),
        }
    }
}

impl<Ti> fmt::Debug for ServerOnlyStart<Ti> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerOnlyStart")
            .field("taken", &self.issuer.is_none())
            .finish_non_exhaustive()
    }
}

/// The tokens a server issued for its NEW_TOKEN frames and has not seen
/// delivered, and the issuer `Ti` it takes them from.
pub struct NewTokenSource<Ti> {
    issuer: Ti,
    /// The tokens, oldest first.
    tokens: VecDeque<IssuedNewToken>,
    /// How many tokens were issued.
    issued: u64,
}

/// A token issued, and where its frame stands.
#[derive(Debug, Clone)]
struct IssuedNewToken {
    /// How many tokens were issued before it.
    number: u64,
    frame: NewTokenFrame<Bytes>,
    /// Whether a frame of it is in a packet whose fate is not known yet.
    in_flight: bool,
}

impl<Ti> NewTokenSource<Ti> {
    /// A source that has issued nothing yet, and takes its tokens from
    /// `issuer`.
    pub fn new(issuer: Ti) -> Self {
        Self {
            issuer,
            tokens: VecDeque::new(),
            issued: 0,
        }
    }

    /// The issuer the tokens are taken from.
    pub fn issuer(&self) -> &Ti {
        &self.issuer
    }

    /// The intent of the tokens that wait to be sent: issued and not in
    /// flight, or lost while none of their frames is acknowledged; `None`
    /// when none waits.
    pub fn intent(&self) -> Option<NewTokenIntent> {
        let first = self.tokens.iter().find(|token| !token.in_flight)?;
        Some(NewTokenIntent {
            len: first.frame.encoded_len(),
        })
    }

    /// Issues a token bound to `peer`, which waits to be sent. What
    /// happened, when the issuer gave one: none when the token cannot be
    /// bound to `peer` or could not be made, and none for an empty token,
    /// which no NEW_TOKEN frame carries (RFC 9000 §19.7).
    #[must_use = "what happened is to be published in the lend"]
    pub fn issue<Peer>(&mut self, peer: &Peer) -> Option<Happened<NewTokenPendingChanged>>
    where
        Ti: ConnectionNewTokenIssuer<Peer>,
    {
        let token = self.issuer.issue(peer)?;
        let length = VarInt::try_from(token.len()).ok()?;
        let frame = NewTokenFrame::new(VarIntWidth::shortest(length), token).ok()?;
        if self.tokens.len() == KEPT_TOKENS {
            self.tokens.pop_front();
        }
        self.tokens.push_back(IssuedNewToken {
            number: self.issued,
            frame,
            in_flight: false,
        });
        self.issued += 1;
        Some(Happened::new())
    }

    /// The token numbered `number`, while it is kept.
    fn token_mut(&mut self, number: u64) -> Option<&mut IssuedNewToken> {
        self.tokens.iter_mut().find(|token| token.number == number)
    }
}

impl<Ti> fmt::Debug for NewTokenSource<Ti> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NewTokenSource")
            .field("kept", &self.tokens.len())
            .field("issued", &self.issued)
            .finish_non_exhaustive()
    }
}

/// The tokens that wait are written in the order they were issued, as long
/// as they fit, and are then in flight; a token whose frame is lost while
/// none is acknowledged waits again, and one whose frame is acknowledged is
/// not sent again.
impl<Ti> FrameSource for NewTokenSource<Ti> {
    type Summary = NewTokenSummary;
    type Class = InFlightClass;
    type Item<'a> = ();

    fn supply<W, P, Idx>(
        &mut self,
        (): (),
        mut packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<NewTokenSummary, Idx>,
        P: PacketPosition,
    {
        for token in self.tokens.iter_mut().filter(|token| !token.in_flight) {
            let summary = NewTokenSummary {
                number: token.number,
            };
            if packet
                .write_frame(token.frame.clone(), <SummaryOf<W>>::inject_summary(summary))
                .is_err()
            {
                break;
            }
            token.in_flight = true;
        }
        Supplied::Open(packet)
    }

    fn delivered(&mut self, _: PacketNumberSpaceKind, summary: NewTokenSummary) {
        self.tokens.retain(|token| token.number != summary.number);
    }

    fn lost(&mut self, _: PacketNumberSpaceKind, summary: &NewTokenSummary) {
        if let Some(token) = self.token_mut(summary.number) {
            token.in_flight = false;
        }
    }

    /// The tokens are the driver's content, which no strategy ends.
    fn unfulfilled(&mut self, (): (), _: Unfulfilled) {}
}

/// A server's connection starts with the issuer [`ConnectionArgs::side`]
/// gives, having issued nothing yet.
impl<T, L, I, Tls, Ti> Build<T, L, layer::Connection, (I,)> for NewTokenSource<Ti>
where
    T: Choices<Side = Server<Tls, Ti>>,
    Server<Tls, Ti>: super::Side<Start = ServerOnlyStart<Ti>>,
    L: LineagePartList<T>,
    ConnectionArgsOf<T, L>: Selector<ConnectionArgs<T, L>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::Connection>,
        args: &mut ArgsOf<T, L, layer::Connection>,
    ) -> Self {
        // invariant: the connection node, the only one that takes it, is
        // built once
        let issuer = own_args::<T, L, I>(args)
            .side
            .issuer
            .take()
            .expect("the connection node is built once");
        Self::new(issuer)
    }
}
/// It has no deadline and subscribes to nothing; the advancing call and the
/// rules of connection migration issue its tokens, and the sending call and
/// the settling of its packets change it.
impl<Ti> PassiveDataComponent for NewTokenSource<Ti> {}

/// What a client keeps of NEW_TOKEN frames to send: nothing, as a client
/// sends none (RFC 9000 §19.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NoNewTokens;

/// A client never has a token waiting, and writes nothing when given one.
impl FrameSource for NoNewTokens {
    type Summary = NewTokenSummary;
    type Class = InFlightClass;
    type Item<'a> = ();

    fn supply<W, P, Idx>(
        &mut self,
        (): (),
        packet: OpenPacket<W, InFlightClass, P>,
    ) -> Supplied<W, InFlightClass, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<NewTokenSummary, Idx>,
        P: PacketPosition,
    {
        Supplied::Open(packet)
    }

    fn delivered(&mut self, _: PacketNumberSpaceKind, _: NewTokenSummary) {}

    fn lost(&mut self, _: PacketNumberSpaceKind, _: &NewTokenSummary) {}

    /// A client has no token waiting, so none goes unfulfilled.
    fn unfulfilled(&mut self, (): (), _: Unfulfilled) {}
}

impl<T: Choices, L> Build<T, L, layer::Connection, ()> for NoNewTokens
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
/// It has no deadline and subscribes to nothing, and never changes.
impl PassiveDataComponent for NoNewTokens {}

/// What issues the NEW_TOKEN tokens of a side for links whose peers are
/// `Peer`: a server's [`NewTokenSource`] with its issuer; a client's
/// [`NoNewTokens`], which issues none.
pub trait NewTokenIssuance<Peer> {
    /// Issues a token bound to `peer`, which waits to be sent. What
    /// happened, when one was issued.
    #[must_use = "what happened is to be published in the lend"]
    fn issue_for(&mut self, peer: &Peer) -> Option<Happened<NewTokenPendingChanged>>;
}

impl<Peer, Ti: ConnectionNewTokenIssuer<Peer>> NewTokenIssuance<Peer> for NewTokenSource<Ti> {
    fn issue_for(&mut self, peer: &Peer) -> Option<Happened<NewTokenPendingChanged>> {
        self.issue(peer)
    }
}

impl<Peer> NewTokenIssuance<Peer> for NoNewTokens {
    fn issue_for(&mut self, _: &Peer) -> Option<Happened<NewTokenPendingChanged>> {
        None
    }
}

/// NEW_TOKEN frames wait to be sent: a server issued tokens, or the frame
/// of one was lost while none was acknowledged (RFC 9000 §13.3).
///
/// `len` is the length of the frame of the first token that waits, the
/// least room a packet needs to carry one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NewTokenIntent {
    len: usize,
}

impl NewTokenIntent {
    /// The length of the frame of the first token that waits.
    pub fn frame_len(&self) -> usize {
        self.len
    }

    /// The intent of a token whose frame is `len` bytes long.
    #[cfg(test)]
    pub(crate) fn of_frame_len(len: usize) -> Self {
        Self { len }
    }
}

impl SendIntent for NewTokenIntent {
    type FrameSourceId = FrameSourceId;
    type Class = InFlightClass;

    fn frame_source(&self) -> FrameSourceId {
        FrameSourceId::NewToken
    }

    fn min_lengths(&self) -> MinimumLengths {
        MinimumLengths {
            with_length: self.len,
            as_last: self.len,
        }
    }
}

/// The tokens rank as control frames, and hold their place.
impl RankedIntent for NewTokenIntent {
    fn rank(&self) -> SendRank {
        SendRank {
            priority: SendPriority::Control,
            holds_place: true,
        }
    }
}

/// The summary of a NEW_TOKEN frame written into a packet: which of the
/// tokens the connection issued it carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NewTokenSummary {
    /// How many tokens the connection issued before this one.
    pub number: u64,
}

#[cfg(test)]
mod tests;
