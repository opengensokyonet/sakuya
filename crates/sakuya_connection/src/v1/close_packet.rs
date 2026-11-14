//! The close packet of each link path: sealed once as the link path closes,
//! then sent again as it is.
//!
//! When a link path enters `Closing`, its [`ClosePacket`] is sealed: one
//! datagram with a CONNECTION_CLOSE frame in a packet of each level that
//! has keys to send with at that moment, in increasing level (RFC 9000
//! §10.2.3); once the handshake is confirmed only 1-RTT. No 0-RTT packet
//! is written, as no keys to send one with are kept. It waits while the
//! peer's connection ID is not known, and is sealed once it is; a link path
//! that is draining seals nothing.
//!
//! The close of each level follows from this endpoint's reason in the
//! record of why the connection closed: the close its error gives
//! ([`LocalCloseCause::immediate_close`]), adjusted by the connection's
//! [`ImmediateClosePolicy`] for the level, and then, in Initial and
//! Handshake packets, an application close becomes a transport close with
//! APPLICATION_ERROR and no reason phrase (RFC 9000 §10.2.3). A reason
//! phrase that does not fit is cut to its longest prefix that does,
//! at a character boundary when it is UTF-8: the levels are filled from
//! the lowest, each leaving room for the frames of the levels after it
//! without a reason phrase, so every level carries its error code. The
//! datagram is at most as large as every path carries (RFC 9000 §14), and
//! its reason phrases keep within the anti-amplification credit of the
//! logical link; a client's datagram with an Initial packet is padded to
//! 1200 bytes (§14.1).
//!
//! The destination connection ID is the first the link path is offered,
//! chosen once. Each packet takes the next packet number of its space, past
//! those the close packets of the other link paths of the logical path
//! took, so that no packet number protects two packets; the close packet
//! does not enter the send journals, and counts nothing in flight. Once it
//! is sealed, a first resend of it is published on the link path's
//! planner ([`ResendCloseIntent::Sealed`]); the keys of each level then
//! keep only their receiving half, once every closing link path has
//! sealed its own.

use core::fmt;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use frunk_core::hlist_pat;
use sakuya_link::Link as _;
use sakuya_packet_protection::backend::CryptoBackend;
use sakuya_recovery::{
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    send_journals::{PacketSendAttempt, SendJournals},
};
use sakuya_stream::connection::{CloseReason, ImmediateClose, TransportImmediateClose};
use sakuya_tls::engine::HandshakeError;
use sakuya_wire::{
    connection_id::ConnectionId,
    parameters::ParametersOf,
    parts::{HList, Selector},
    v1::{
        encryption_level::EncryptionLevel,
        frame::connection_close::{CloseErrorCode, ConnectionCloseFrame},
        packet_number::PacketNumber,
        role::Role,
        transport_error::TransportErrorCode,
        transport_parameters::{
            TransportParameterSlots, TransportParameterSpace, integer::MaxUdpPayloadSize,
        },
    },
    var_int::{VarInt, VarIntField, VarIntWidth},
};

use super::{
    Choices, CloseCauseOf, Side,
    aead_usage::AeadUsage,
    close::{CloseReasonRecord, ImmediateClosePolicy, LocalCloseCause, TransportClose},
    confirmation::HandshakeConfirmation,
    connection_ids::{ConnectionIdsOf, LinkPathResetTokenRegistrar, ResetTokenRegistrarOf},
    datagram_batch::{ConnectionIdUse as _, DatagramState, SealedInDatagram},
    keys::{DirectionKeys, HandshakeKeys, InitialKeys, OneRttKeys, OneRttSendKeys},
    packet_writer::{PacketStart, PacketWriter},
    recovery::peer_max_udp_payload_size,
    role::LinkPathRole,
    send::SendTypes,
    send_planning::{
        DatagramLimitsReads, LinkPathPlanner, LinkPathSendPlannerOf, NextPacketNumber,
        SendStrategyOf, datagram_limits, packet_overheads,
    },
    spaces::SendJournalsOf,
};
use crate::{
    call::CallBundle,
    clock::{InstantOf, LinkIdOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf},
    connection_id::{DestinationConnectionIdStrategy, datagram::DatagramConnectionId},
    error::{ConnectionErrorOf, ConnectionErrorsOf},
    feedback::FeedbackSummariesOf,
    layer::{self, NodeKey},
    others::OtherNodes,
    send_strategy::{
        PlannedPacketKind, Publish, ResendCloseIntent, SendStrategy, SendStrategyTypes,
    },
    share::{FlatMut, LineageLists, LineagePartList, NodeData},
    take::{GetAt, ReadEach, Reborrow, Take, TakeEach},
    write::{AckOnlyClass, PaddingSummary},
};

/// The close packet of a link path, in the link path's node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosePacket {
    /// Not sealed: the link path is not closing, the peer's connection ID
    /// is not known yet, or the link path drained before it was sealed.
    Unsealed,
    /// Sealed, to be sent again as it is.
    Sealed(SealedClosePacket),
}

impl ClosePacket {
    /// The sealed close packet, once there is one.
    pub fn sealed(&self) -> Option<&SealedClosePacket> {
        match self {
            Self::Unsealed => None,
            Self::Sealed(sealed) => Some(sealed),
        }
    }

    /// Whether the close packet is sealed.
    pub fn is_sealed(&self) -> bool {
        matches!(self, Self::Sealed(_))
    }
}

/// A sealed close packet: the bytes of its datagram, and the packet number
/// it took in each space it has a packet of.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedClosePacket {
    datagram: Bytes,
    packet_numbers: [Option<PacketNumber>; 3],
}

impl SealedClosePacket {
    /// The bytes of the datagram.
    pub fn datagram(&self) -> &Bytes {
        &self.datagram
    }

    /// The packet number its packet of `space` took, if it has one.
    pub fn packet_number(&self, space: PacketNumberSpaceKind) -> Option<PacketNumber> {
        self.packet_numbers[space_index(space)]
    }
}

impl fmt::Debug for SealedClosePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedClosePacket")
            .field("len", &self.datagram.len())
            .field("packet_numbers", &self.packet_numbers)
            .finish()
    }
}

fn space_index(space: PacketNumberSpaceKind) -> usize {
    match space {
        PacketNumberSpaceKind::Initial => 0,
        PacketNumberSpaceKind::Handshake => 1,
        PacketNumberSpaceKind::ApplicationData => 2,
    }
}

/// The connection's [`ImmediateClosePolicy`] `P`, in the connection node.
#[derive(Debug)]
pub struct ConnectionImmediateClosePolicy<P>(P);

impl<P> ConnectionImmediateClosePolicy<P> {
    /// The policy `policy`.
    pub fn new(policy: P) -> Self {
        Self(policy)
    }

    /// The policy.
    pub fn policy(&self) -> &P {
        &self.0
    }

    /// The policy, to adjust a close with.
    pub fn policy_mut(&mut self) -> &mut P {
        &mut self.0
    }
}

// ---- the close of each level ----

/// The close to send in a packet of `level`, from what the policy gave: in
/// Initial and Handshake packets an application close becomes a transport
/// close with APPLICATION_ERROR and no reason phrase (RFC 9000 §10.2.3);
/// the policy cannot change that.
fn close_at_level(close: ImmediateClose, level: EncryptionLevel) -> ImmediateClose {
    match (close, level) {
        (ImmediateClose::Application(_), EncryptionLevel::Initial | EncryptionLevel::Handshake) => {
            ImmediateClose::Transport(TransportImmediateClose {
                code: TransportErrorCode::APPLICATION_ERROR,
                frame_type: None,
                reason_phrase: Bytes::new(),
            })
        }
        (close, _) => close,
    }
}

/// The CONNECTION_CLOSE frame of `close` in at most `room` bytes: the
/// longest prefix of its reason phrase that fits, cut at a character
/// boundary when the phrase is UTF-8 and at a byte otherwise (RFC 9000
/// §19.19). Where not even an empty reason phrase fits, the frame has none
/// and is longer than `room`.
fn close_frame(close: &ImmediateClose, room: usize) -> ConnectionCloseFrame<Bytes> {
    let (error_code, phrase) = match close {
        ImmediateClose::Transport(close) => (
            CloseErrorCode::Transport {
                code: VarIntField::shortest(close.code),
                frame_type: VarIntField::shortest(close.frame_type.unwrap_or(VarInt::ZERO)),
            },
            &close.reason_phrase,
        ),
        ImmediateClose::Application(close) => (
            CloseErrorCode::Application {
                code: VarIntField::shortest(close.code),
            },
            &close.reason_phrase,
        ),
    };
    let fields =
        frame_with(error_code, Bytes::new()).encoded_len() - VarIntWidth::One.encoded_len();
    let len = reason_phrase_prefix(phrase, room.saturating_sub(fields));
    frame_with(error_code, phrase.slice(..len))
}

/// The frame of `error_code` with `phrase`, its Reason Phrase Length field
/// as short as the phrase allows.
fn frame_with(error_code: CloseErrorCode, phrase: Bytes) -> ConnectionCloseFrame<Bytes> {
    // invariant: a reason phrase is far shorter than 2^62 bytes, and the
    // shortest width holds its length
    let length = VarInt::try_from(phrase.len()).expect("a reason phrase is shorter than 2^62");
    ConnectionCloseFrame::new(error_code, VarIntWidth::shortest(length), phrase)
        .expect("the shortest width holds the reason phrase's length")
}

/// The length of the longest prefix of `phrase` that, with its Reason
/// Phrase Length field, takes at most `room` bytes; at a character boundary
/// when `phrase` is UTF-8.
fn reason_phrase_prefix(phrase: &[u8], room: usize) -> usize {
    let mut len = 0;
    for width in [
        VarIntWidth::One,
        VarIntWidth::Two,
        VarIntWidth::Four,
        VarIntWidth::Eight,
    ] {
        let Some(left) = room.checked_sub(width.encoded_len()) else {
            break;
        };
        let longest = usize::try_from(width.max_value().get()).unwrap_or(usize::MAX);
        len = len.max(phrase.len().min(left).min(longest));
    }
    if let Ok(text) = core::str::from_utf8(phrase) {
        while !text.is_char_boundary(len) {
            len -= 1;
        }
    }
    len
}

// ---- writing the datagram ----

/// What a packet of the close packet hands its packet number to: no record
/// is made of it.
#[derive(Debug)]
struct ClosePacketAttempt {
    number: PacketNumber,
    framed: bool,
}

impl PacketSendAttempt for ClosePacketAttempt {
    type Summary = PaddingSummary;
    type Sealed = PacketNumber;

    fn packet_number(&self) -> PacketNumber {
        self.number
    }

    fn record_frame(&mut self, _: PaddingSummary, _: bool, _: bool) {
        self.framed = true;
    }

    fn seal(self, _: usize, _: bool) -> Option<PacketNumber> {
        self.framed.then_some(self.number)
    }
}

/// The keys one level of the close packet is sealed with.
#[derive(Debug)]
enum ClosePacketKeys<'k, B: CryptoBackend> {
    /// An Initial packet's.
    Initial(&'k DirectionKeys<B>),
    /// A Handshake packet's.
    Handshake(&'k DirectionKeys<B>),
    /// A 1-RTT packet's, of the current sending generation.
    OneRtt(&'k OneRttSendKeys<B>),
}

impl<B: CryptoBackend> ClosePacketKeys<'_, B> {
    fn space(&self) -> PacketNumberSpaceKind {
        match self {
            Self::Initial(_) => PacketNumberSpaceKind::Initial,
            Self::Handshake(_) => PacketNumberSpaceKind::Handshake,
            Self::OneRtt(_) => PacketNumberSpaceKind::ApplicationData,
        }
    }

    fn kind(&self) -> PlannedPacketKind {
        match self {
            Self::Initial(_) => PlannedPacketKind::Initial,
            Self::Handshake(_) => PlannedPacketKind::Handshake,
            Self::OneRtt(_) => PlannedPacketKind::OneRtt,
        }
    }
}

/// One level of the close packet: the keys of its packet, its packet
/// number and the largest acknowledged in its space, and its close.
#[derive(Debug)]
struct ClosePacketLevel<'k, B: CryptoBackend> {
    keys: ClosePacketKeys<'k, B>,
    number: PacketNumber,
    largest_acked: Option<PacketNumber>,
    close: ImmediateClose,
}

/// What the datagram of a close packet is written to: its connection IDs,
/// the side that sends it, the largest it may be, and the bytes within
/// which its reason phrases keep.
#[derive(Debug, Clone, Copy)]
struct ClosePacketShape {
    dcid: ConnectionId,
    scid: ConnectionId,
    role: Role,
    max_len: usize,
    budget: usize,
}

/// Write `levels`, in increasing level, into one datagram of `shape`, the
/// use of 1-RTT keys counted in `usage`; `None` when no packet fits.
fn write_close_datagram<B: CryptoBackend>(
    levels: Vec<ClosePacketLevel<'_, B>>,
    shape: ClosePacketShape,
    usage: &mut AeadUsage,
) -> Option<SealedClosePacket> {
    let next = |kind| {
        levels
            .iter()
            .find(|level| level.keys.kind() == kind)
            .map(|level| NextPacketNumber {
                next: level.number,
                largest_acked: level.largest_acked,
            })
    };
    let overheads = packet_overheads(
        Some(shape.dcid.len()),
        shape.scid.len(),
        shape.max_len,
        next(PlannedPacketKind::Initial),
        next(PlannedPacketKind::Handshake),
        next(PlannedPacketKind::OneRtt),
        shape.role,
    );
    // what each level leaves for the levels after it: their packets with
    // frames that have no reason phrase
    let least: Vec<usize> = levels
        .iter()
        .map(|level| {
            overheads.of(level.keys.kind()).unwrap_or(0)
                + close_frame(&level.close, 0).encoded_len()
        })
        .collect();
    let mut reserves = vec![0; levels.len()];
    for at in (0..levels.len().saturating_sub(1)).rev() {
        reserves[at] = reserves[at + 1] + least[at + 1];
    }
    let slack = shape.max_len.saturating_sub(shape.budget);
    let mut buffer = BytesMut::new();
    let mut state = DatagramState {
        dcid: shape.dcid,
        role: shape.role,
        local_id_length: shape.scid.length(),
        start: 0,
        max_len: shape.max_len,
        in_flight_room: shape.max_len,
        in_flight: 0,
        floor: 0,
        packets: 0,
        ends_with_short_header: false,
    };
    let mut packet_numbers = [None; 3];
    let count = levels.len();
    for (at, level) in levels.into_iter().enumerate() {
        let space = level.keys.space();
        let start = match level.keys {
            ClosePacketKeys::Initial(keys) => PacketStart::Initial {
                keys,
                scid: shape.scid,
                token: Bytes::new(),
            },
            ClosePacketKeys::Handshake(keys) => PacketStart::Handshake {
                keys,
                scid: shape.scid,
            },
            ClosePacketKeys::OneRtt(keys) => PacketStart::OneRtt {
                keys,
                usage: &mut *usage,
            },
        };
        let mut slot: Option<SealedInDatagram<PacketNumber>> = None;
        let attempt = ClosePacketAttempt {
            number: level.number,
            framed: false,
        };
        let Ok(writer) = PacketWriter::start(
            &mut buffer,
            &mut state,
            &mut slot,
            attempt,
            start,
            level.largest_acked,
        ) else {
            continue;
        };
        let mut open = writer.open::<AckOnlyClass>();
        let room = open
            .remaining()
            .saturating_sub(reserves[at])
            .saturating_sub(slack);
        // a frame that does not fit at all leaves the packet empty, and
        // its header is taken back
        let _ = open.write_frame(close_frame(&level.close, room), PaddingSummary);
        open.conclude(at + 1 < count);
        if let Some(sealed) = slot {
            packet_numbers[space_index(space)] = Some(sealed.sealed);
        }
    }
    (state.packets > 0).then(|| SealedClosePacket {
        datagram: buffer.freeze(),
        packet_numbers,
    })
}

// ---- the component ----

/// A link path's close packet starts unsealed.
impl<T: Choices, L> Build<T, L, layer::LinkPath, ()> for ClosePacket
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        _: &mut ArgsOf<T, L, layer::LinkPath>,
    ) -> Self {
        ClosePacket::Unsealed
    }
}

/// What sealing takes out of the link path's lineage first, which nothing
/// reads: the connection's close policy and the count of the AEAD's usage.
type SealTakes<T> = HList![
    ConnectionImmediateClosePolicy<<T as Choices>::ImmediateClosePolicy>,
    AeadUsage,
];

/// What sealing reads from what is left: the keys of each level, the send
/// journals and the packet number states of the spaces, and whether the
/// handshake is confirmed.
type SealReads<T, L> = HList![
    InitialKeys<<T as Choices>::Crypto>,
    HandshakeKeys<<T as Choices>::Crypto>,
    OneRttKeys<<T as Choices>::Crypto, InstantOf<T>>,
    SendJournalsOf<T, L>,
    PacketNumberSpaces<PacketNumberSpaceState>,
    HandshakeConfirmation,
];

/// What a sealed close packet takes then: itself, the connection IDs and
/// the registrar of the link path's reset tokens, which learn of the
/// connection ID's use, and the planner it is published on.
type SealedTakes<T, L> = HList![
    ClosePacket,
    ConnectionIdsOf<T>,
    LinkPathResetTokenRegistrar<ResetTokenRegistrarOf<T>>,
    LinkPathPlanner<LinkPathSendPlannerOf<T, L>>,
];

/// What is left of a link path's lineage once sealing took [`SealTakes`].
type SealRest<'x, T, L, It> =
    <<L as LineageLists<'x, T>>::LinkPath as TakeEach<'x, SealTakes<T>, It>>::Rest;

/// The positions the close packet takes by: `Ip` of itself, `Ir` of the
/// role, `Ic` of the record of why the connection closed and `Iid` of the
/// connection IDs, which it looks at first; `Il` of what the limits of a
/// datagram are read from and `Ipp` of the peer's `max_udp_payload_size`;
/// `It` of [`SealTakes`], `Iw` of [`SealReads`] in what is left and `Is` of
/// [`SealedTakes`]; `Jc` of the close packet of every other link path; and
/// `Irc` of the resend among the planner's intents.
type Positions<Ip, Ir, Ic, Iid, Il, Ipp, It, Iw, Is, Jc, Irc> =
    ((Ip, Ir, Ic, Iid), (Il, Ipp), (It, Iw, Is), Jc, Irc);

/// The close packet reads the link path's role and the connection IDs of
/// its logical path: it is sealed once the role is `Closing` and the peer's
/// connection ID is known, as the [module documentation](self) says, and
/// then the first resend is published.
impl<T, L, Ip, Ir, Ic, Iid, Il, Ipp, It, Iw, Is, Jc, Irc>
    DataComponent<T, L, layer::LinkPath, Positions<Ip, Ir, Ic, Iid, Il, Ipp, It, Iw, Is, Jc, Irc>>
    for ClosePacket
where
    T: Choices,
    L: LineagePartList<T>
        + FeedbackSummariesOf
        + ParametersOf<TransportParameterSpace>
        + ConnectionErrorsOf,
    ConnectionErrorOf<L>: TransportClose,
    HandshakeError<T::HandshakeFailure, ConnectionErrorOf<L>>: TransportClose,
    T::ImmediateClosePolicy: ImmediateClosePolicy<CloseCauseOf<T, L>>,
    TransportParameterSlots<L>: Selector<Option<MaxUdpPayloadSize>, Ipp>,
    SendTypes<T, L>: SendStrategyTypes,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    LinkPathSendPlannerOf<T, L>: Publish<ResendCloseIntent, Irc>,
    for<'v, 's> <L as LineageLists<'v, T>>::LinkPath:
        Reborrow<'s, Out = <L as LineageLists<'s, T>>::LinkPath>,
    for<'x> <L as LineageLists<'x, T>>::LinkPath: GetAt<ClosePacket, Ip>
        + GetAt<LinkPathRole<InstantOf<T>>, Ir>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<ConnectionIdsOf<T>, Iid>
        + ReadEach<DatagramLimitsReads<T, L>, Il>
        + TakeEach<'x, SealTakes<T>, It>
        + TakeEach<'x, SealedTakes<T, L>, Is>,
    for<'x> SealRest<'x, T, L, It>: TakeEach<'x, SealReads<T, L>, Iw>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out: GetAt<ClosePacket, Jc>,
{
    fn reads(reads: &mut ReadSet) {
        reads
            .add::<LinkPathRole<InstantOf<T>>>()
            .add::<ConnectionIdsOf<T>>();
    }

    fn reread<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        _: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        if lineage.get::<ClosePacket, Ip>().is_sealed()
            || !matches!(
                lineage.get::<LinkPathRole<InstantOf<T>>, Ir>(),
                LinkPathRole::Closing(_)
            )
        {
            return None;
        }
        // a link path closes only for this endpoint's own reason; the
        // others end the connection without a closing period
        let Some(CloseReason::Local(cause)) = lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
            .reason()
        else {
            return None;
        };
        let cause = Arc::clone(cause);
        let NodeKey::LinkPath(path, link) = others.here().clone() else {
            unreachable!("a link path's lend carries its key")
        };
        // the peer's connection ID: none is offered before it is known
        let offered = DestinationConnectionIdStrategy::<
            LinkIdOf<T>,
            InstantOf<T>,
            ResetTokenRegistrarOf<T>,
        >::offer(
            lineage.get::<ConnectionIdsOf<T>, Iid>().destination(),
            &link,
        )
        .next()?;
        let scid = lineage.get::<ConnectionIdsOf<T>, Iid>().local();
        // the packet numbers the close packets of the logical path's other
        // link paths took
        let mut taken: [Option<PacketNumber>; 3] = [None; 3];
        others.each_link_path_read::<ClosePacket, Jc>(|key, packet| {
            let NodeKey::LinkPath(other, _) = key else {
                return;
            };
            let Some(sealed) = packet.sealed().filter(|_| *other == path) else {
                return;
            };
            for (slot, number) in taken.iter_mut().zip(sealed.packet_numbers) {
                *slot = (*slot).max(number);
            }
        });
        let frunk_core::hlist_pat![link_clone, facts, amplification, peer] =
            lineage.read_each::<DatagramLimitsReads<T, L>, Il>();
        let max_len = datagram_limits(
            link_clone.0.max_datagram_size().ok(),
            peer_max_udp_payload_size::<L, Ipp>(peer),
            None,
            None,
        )
        .max_udp_payload();
        let budget = amplification
            .credit(facts.validation)
            .map_or(max_len, |credit| {
                usize::try_from(credit).unwrap_or(usize::MAX).min(max_len)
            });
        let shape = ClosePacketShape {
            dcid: offered.id,
            scid,
            role: <T::Side as Side>::ROLE,
            max_len,
            budget,
        };

        let sealed = {
            let (hlist_pat![policy, usage], rest) =
                Take::<SealTakes<T>, It>::take(lineage.reborrow());
            let (hlist_pat![initial, handshake, one_rtt, journals, numbers, confirmation], _) =
                rest.take_read::<SealReads<T, L>, Iw>();
            let close = LocalCloseCause::immediate_close(&*cause);
            let mut level_close = |level| {
                close_at_level(
                    policy.policy_mut().adjust(&cause, level, close.clone()),
                    level,
                )
            };
            let next = |space: PacketNumberSpaceKind| {
                let next = journals.get(space)?.next_packet_number();
                let past_taken = taken[space_index(space)].and_then(|number| number.checked_add(1));
                Some(next.max(past_taken.unwrap_or(next)))
            };
            let largest = |space| {
                numbers
                    .get(space)
                    .and_then(PacketNumberSpaceState::largest_acked)
            };
            // once the handshake is confirmed, only 1-RTT (RFC 9000 §10.2.3)
            let confirmed = *confirmation == HandshakeConfirmation::Confirmed;
            let keys = [
                initial
                    .send()
                    .filter(|_| !confirmed)
                    .map(|keys| (ClosePacketKeys::Initial(keys), EncryptionLevel::Initial)),
                handshake
                    .send()
                    .filter(|_| !confirmed)
                    .map(|keys| (ClosePacketKeys::Handshake(keys), EncryptionLevel::Handshake)),
                one_rtt
                    .send()
                    .map(|keys| (ClosePacketKeys::OneRtt(keys), EncryptionLevel::OneRtt)),
            ];
            let mut levels = Vec::new();
            for (keys, level) in keys.into_iter().flatten() {
                let space = keys.space();
                let Some(number) = next(space) else {
                    continue;
                };
                levels.push(ClosePacketLevel {
                    keys,
                    number,
                    largest_acked: largest(space),
                    close: level_close(level),
                });
            }
            write_close_datagram(levels, shape, usage)?
        };

        let (hlist_pat![packet, ids, registrar, planner], _) =
            Take::<SealedTakes<T, L>, Is>::take(lineage);
        let chosen = DatagramConnectionId::<_, _, _, InstantOf<T>>::choose_first(
            ids.destination_mut(),
            registrar.registrar_mut(),
            &link,
            |each| each.sequence == offered.sequence,
        );
        if let Some(chosen) = chosen {
            chosen.used(sealed.datagram.len());
        }
        *packet = ClosePacket::Sealed(sealed);
        Publish::<ResendCloseIntent, Irc>::publish(
            planner.planner_mut(),
            ResendCloseIntent::Sealed,
        );
        None
    }
}

#[cfg(test)]
mod tests;
