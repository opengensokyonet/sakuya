//! What a logical path receives: the datagram receiver it takes datagrams
//! from, the inputs it holds until their keys come, and the call that takes
//! each of them in.
//!
//! [`logical_path_receiving`] is the call of each logical path. It goes
//! through one input at a time:
//!
//! 1. The next input is the first held one, in the order of arrival, that
//!    the keys installed since can process; otherwise the next of the first
//!    datagrams the connection was made with, which the first logical path
//!    owns; otherwise the next delivery of the logical path's datagram
//!    receiver ([`LogicalPathDatagramReceiver`]).
//!    A logical path without a receiver waits until a held input can go.
//!    One poll handles at most
//!    [`max_datagrams_per_poll`](LogicalPathReceivingLimits::max_datagrams_per_poll)
//!    inputs; at the limit the call wakes itself and yields once, so that
//!    the connection's other calls, and other tasks of the executor, are
//!    not held up while the peer keeps sending.
//! 2. A delivery the logical path already owns is taken as it is. A
//!    competing candidate is judged by the first packet of its datagram. A
//!    short header is a 1-RTT packet: before the 1-RTT receive keys this
//!    side waits, holding the candidate; with them, the logical path takes
//!    the datagram when a copy of the packet opens with them, and leaves it
//!    to the other candidates otherwise (RFC 9001 §5.7). A long header is
//!    left: telling one connection attempt from another under the same
//!    Destination Connection ID takes the client's Source Connection ID,
//!    which the connection does not keep yet, so such a datagram is lost to
//!    this connection rather than taken from another.
//! 3. The anti-amplification limit of the logical link the datagram arrived
//!    over counts the whole datagram before any packet in it is read (RFC
//!    9000 §8.1).
//! 4. The packets are cut from the datagram and received one by one
//!    ([`receive_packet`]), each with its
//!    own copy of the facts of the datagram's arrival. A packet whose keys
//!    have not come is held; a packet whose Destination Connection ID
//!    differs from the first one's is passed over (RFC 9000 §12.2); a
//!    header that tells no boundary ends the datagram. A server passes over
//!    the Initial packets of a datagram whose whole payload is shorter than
//!    [`MIN_DATAGRAM_SIZE`] and receives its other packets (RFC 9000 §14.1). A packet that causes
//!    a connection error writes it into the record of why the connection
//!    closed; the rest of the datagram is dropped, and the call yields, so
//!    that the link paths enter closing before the next input.
//!
//! The inputs held, packets and candidates alike, are at most
//! [`max_held_inputs`](LogicalPathReceivingLimits::max_held_inputs) for the
//! logical path; past it the input that arrives is dropped. Retry and
//! Version Negotiation packets are dropped: a client's handling of them is
//! not here yet.
//!
//! [`logical_path_receiving`] is also the operation struct
//! [`LogicalPathReceiving`], with `LogicalPathReceivingExt` on receiver
//! accesses.
// `#[call]` generates a constructor and an extension trait without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use core::{
    fmt,
    future::poll_fn,
    num::NonZeroUsize,
    ops::ControlFlow,
    pin::Pin,
    task::{Context, Poll},
};
use std::{collections::VecDeque, sync::Arc};

use bytes::Bytes;
use frunk_core::{coproduct::CoproductSelector, hlist_pat};
use nitori_call::{LentAccess, LentCall, ReceiverFamily, call};
use nitori_io::SplitTo;
use sakuya_datagram_routing::{
    claim::{
        candidate::{
            DatagramClaimAccess, DatagramClaimAttempt, DatagramClaimCandidate, DatagramClaimOutcome,
        },
        delivery::{DatagramDelivery, ExclusiveDatagramDelivery},
        finish::UnclaimedHandoff,
        queue::DatagramDeliveryQueue,
        route_match::DatagramRouteMatchInfo,
    },
    route::{association::MatchAssociation, interpretation::FirstPacketInterpretation},
};
use sakuya_link::{Link, MIN_DATAGRAM_SIZE, ReceivedDatagram};
use sakuya_packet_protection::backend::CryptoBackend;
use sakuya_recovery::{
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaces},
    receive_journals::{MaxAckRanges, ReceiveJournals},
};
use sakuya_stream::connection::CloseReason;
use sakuya_wire::{
    connection_id::{ConnectionId, ConnectionIdLength},
    parts::{CoprodInjector, HList},
    v1::{
        encryption_level::EncryptionLevel,
        frame::{FrameType, set::FrameSet},
        packet_number::PacketNumber,
        protected_packet::{IntoPacketsError, Packet, ProtectedPacket, into_packets},
        role::Role,
    },
};

use super::{
    Choices, CloseCauseOf, Side,
    aead_usage::AeadUsage,
    amplification::AntiAmplification,
    close::{CloseReasonRecord, LocalCloseCause},
    error::ConnectionError,
    idle::IdleTimeout,
    key_phase::KeyPhaseNumbers,
    keys::{HandshakeKeys, InitialKeys, OneRttKeys, OneRttReceiveKeys},
    receive::{
        LevelReceiveKeys, PacketOutcome, ReceivedPacket, one_rtt_receive_keys, open_one_rtt,
        packet_number_offset, receive_keys, receive_packet,
    },
    role::LinkPathRole,
    spaces::AckObligationsOf,
};
use crate::{
    call::{CallBundle, CallKind, NodeCallFamily, NodeLoan},
    clock::InstantOf,
    component::{ArgsOf, LineageOf, ReadSet},
    dispatch::FrameSetDispatch,
    error::ConnectionErrorsOf,
    layer::{self, LogicalPath},
    others::OtherNodes,
    share::{FlatMut, LineageLists, LineagePartList, NodeData},
    take::{GetAt, TakeEach},
};

/// A datagram as it arrived over the link `Lk`.
type DatagramOf<Lk> = ReceivedDatagram<<Lk as Link>::Payload, Lk>;

/// The datagram receiver of one logical path: where the deliverers of its
/// route entries put what routing gives them, and where its receiving call
/// takes each delivery from.
///
/// `Lk` is the link datagrams arrive over.
pub trait LogicalPathDatagramReceiver<Lk: Link> {
    /// What takes over a datagram that every candidate left, in the routing
    /// domain the receiver's deliverers serve.
    type Handoff: UnclaimedHandoff<DatagramOf<Lk>>;

    /// The next delivery, or `Pending` until there is one; the waker of `cx`
    /// is woken when one comes.
    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<DatagramDelivery<DatagramOf<Lk>, Lk::Local, Self::Handoff>>;
}

/// A delivery queue is a receiver: its deliverers post to it.
impl<Lk: Link, H: UnclaimedHandoff<DatagramOf<Lk>>> LogicalPathDatagramReceiver<Lk>
    for DatagramDeliveryQueue<DatagramDelivery<DatagramOf<Lk>, Lk::Local, H>>
{
    type Handoff = H;

    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<DatagramDelivery<DatagramOf<Lk>, Lk::Local, H>> {
        self.poll_recv(cx)
    }
}

/// An input a logical path holds until the keys to process it come.
///
/// `Lk` is the link datagrams arrive over, `H` the handoff of the routing
/// domain.
// most held inputs are packets: boxing them would allocate for each
#[allow(clippy::large_enum_variant)]
pub enum HeldInput<Lk: Link, H: UnclaimedHandoff<DatagramOf<Lk>>> {
    /// A packet cut from a datagram this logical path took, whose level has
    /// no receive keys yet: a Handshake packet before the Handshake keys, a
    /// 1-RTT packet before the 1-RTT receive keys.
    Packet(ReceivedPacket<Lk::Payload, Lk>),
    /// A competing candidate whose first packet is a 1-RTT packet, which
    /// waits for the 1-RTT receive keys to be judged.
    Candidate(DatagramClaimCandidate<DatagramOf<Lk>, Lk::Local, H>),
}

impl<Lk: Link, H: UnclaimedHandoff<DatagramOf<Lk>>> HeldInput<Lk, H> {
    /// Whether the input can go on: the level it waits for is no longer
    /// waited for.
    fn released(&self, levels: ReceivableLevels) -> bool {
        match self {
            Self::Packet(packet) => levels.at(packet.packet().level()),
            // the first packet of a held candidate is a 1-RTT packet
            Self::Candidate(_) => levels.at(EncryptionLevel::OneRtt),
        }
    }
}

/// For each encryption level, whether its packets are no longer waited
/// for: the receive keys have come, or none are to come.
#[derive(Debug, Clone, Copy)]
struct ReceivableLevels {
    initial: bool,
    zero_rtt: bool,
    handshake: bool,
    one_rtt: bool,
}

impl ReceivableLevels {
    /// The levels as the keys in `lineage` stand now.
    fn of<T, L, Ii, Ih, Io>(lineage: &LineageOf<'_, T, L, LogicalPath>) -> Self
    where
        T: Choices,
        L: LineagePartList<T>,
        for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialKeys<T::Crypto>, Ii>
            + GetAt<HandshakeKeys<T::Crypto>, Ih>
            + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>,
    {
        let receivable = |level| {
            !matches!(
                receive_keys::<T, L, Ii, Ih, Io>(lineage, level),
                LevelReceiveKeys::NotYet
            )
        };
        Self {
            initial: receivable(EncryptionLevel::Initial),
            zero_rtt: receivable(EncryptionLevel::ZeroRtt),
            handshake: receivable(EncryptionLevel::Handshake),
            one_rtt: receivable(EncryptionLevel::OneRtt),
        }
    }

    /// Whether the packets of `level` are no longer waited for.
    fn at(self, level: EncryptionLevel) -> bool {
        match level {
            EncryptionLevel::Initial => self.initial,
            EncryptionLevel::ZeroRtt => self.zero_rtt,
            EncryptionLevel::Handshake => self.handshake,
            EncryptionLevel::OneRtt => self.one_rtt,
        }
    }
}

impl<Lk, H> fmt::Debug for HeldInput<Lk, H>
where
    Lk: Link + fmt::Debug,
    Lk::Payload: fmt::Debug,
    Lk::Local: fmt::Debug,
    Lk::Instant: fmt::Debug,
    H: UnclaimedHandoff<DatagramOf<Lk>>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(packet) => f.debug_tuple("Packet").field(packet).finish(),
            Self::Candidate(candidate) => f.debug_tuple("Candidate").field(candidate).finish(),
        }
    }
}

/// The datagram receiver of a connection's initial path, given when the
/// connection is made and taken by the first logical path built.
pub struct InitialPathReceiver<R>(Option<R>);

impl<R> InitialPathReceiver<R> {
    /// The receiver `receiver`, for the connection's initial path.
    pub fn new(receiver: R) -> Self {
        Self(Some(receiver))
    }

    /// Move the receiver out into a new value, leaving this one empty.
    pub(crate) fn moved(&mut self) -> Self {
        Self(self.0.take())
    }

    /// The receiver, the first time it is asked for; `None` afterwards.
    pub(crate) fn take(&mut self) -> Option<R> {
        self.0.take()
    }
}

impl<R> fmt::Debug for InitialPathReceiver<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InitialPathReceiver")
            .field("taken", &self.0.is_none())
            .finish_non_exhaustive()
    }
}

/// The limits of the receiving call of every logical path of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogicalPathReceivingLimits {
    /// How many inputs, datagrams and held inputs released, one poll of the
    /// call handles at most before it yields.
    pub max_datagrams_per_poll: NonZeroUsize,
    /// How many inputs a logical path holds at most until their keys come.
    pub max_held_inputs: usize,
}

/// What a logical path receives: its datagram receiver, if it has one, the
/// datagrams it receives before what the receiver delivers, and the inputs
/// it holds until their keys come, in the order of arrival.
///
/// `Lk` is the link datagrams arrive over, `R` the receiver.
pub struct LogicalPathInput<Lk: Link, R: LogicalPathDatagramReceiver<Lk>> {
    receiver: Option<R>,
    /// The first datagrams not read yet, and the length of a short
    /// header's Destination Connection ID they are cut with.
    first: VecDeque<DatagramOf<Lk>>,
    first_dcid_len: ConnectionIdLength,
    held: VecDeque<HeldInput<Lk, R::Handoff>>,
    limits: LogicalPathReceivingLimits,
    /// The inputs handled in this poll of the receiving call.
    handled: usize,
}

impl<Lk: Link, R: LogicalPathDatagramReceiver<Lk>> LogicalPathInput<Lk, R> {
    /// The input of a logical path that takes datagrams from `receiver`, if
    /// any, within `limits`, and holds nothing yet.
    pub fn new(receiver: Option<R>, limits: LogicalPathReceivingLimits) -> Self {
        Self {
            receiver,
            first: VecDeque::new(),
            first_dcid_len: ConnectionIdLength::ZERO,
            held: VecDeque::new(),
            limits,
            handled: 0,
        }
    }

    /// Receive `datagrams`, which the logical path owns, before anything
    /// the receiver delivers, cutting them with `dcid_len` as the length of
    /// a short header's Destination Connection ID; and hold `held`, as far
    /// as the limit allows.
    pub(super) fn start_with(
        &mut self,
        datagrams: Vec<DatagramOf<Lk>>,
        dcid_len: ConnectionIdLength,
        held: Vec<HeldInput<Lk, R::Handoff>>,
    ) {
        self.first.extend(datagrams);
        self.first_dcid_len = dcid_len;
        for input in held {
            self.hold(input);
        }
    }

    /// The limits the logical path receives within.
    pub fn limits(&self) -> LogicalPathReceivingLimits {
        self.limits
    }

    /// How many inputs are held.
    pub fn held_len(&self) -> usize {
        self.held.len()
    }

    /// The inputs held, in the order of arrival.
    pub fn held(&self) -> impl Iterator<Item = &HeldInput<Lk, R::Handoff>> {
        self.held.iter()
    }

    /// Hold `input`, unless as many inputs as the limit allows are held
    /// already: then it is dropped.
    fn hold(&mut self, input: HeldInput<Lk, R::Handoff>) {
        if self.held.len() < self.limits.max_held_inputs {
            self.held.push_back(input);
        }
    }

    /// The first held input, in the order of arrival, that `levels`
    /// release.
    fn release(&mut self, levels: ReceivableLevels) -> Option<HeldInput<Lk, R::Handoff>> {
        let at = self.held.iter().position(|input| input.released(levels))?;
        self.held.remove(at)
    }

    /// Whether this poll has handled as many inputs as it may; if so, the
    /// count starts again for the next poll.
    fn yield_due(&mut self) -> bool {
        let due = self.handled >= self.limits.max_datagrams_per_poll.get();
        if due {
            self.handled = 0;
        }
        due
    }

    /// Use up this poll's inputs, so that the call yields before the next.
    fn use_up(&mut self) {
        self.handled = self.limits.max_datagrams_per_poll.get();
    }
}

impl<Lk: Link, R: LogicalPathDatagramReceiver<Lk>> fmt::Debug for LogicalPathInput<Lk, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogicalPathInput")
            .field("receiver", &self.receiver.is_some())
            .field("first", &self.first.len())
            .field("held", &self.held.len())
            .finish_non_exhaustive()
    }
}

/// What the receiving call of a logical path does with its view: everything
/// but waiting.
pub trait LogicalPathReceivingCapability: ReceiverFamily {
    /// The link datagrams arrive over.
    type Link: Link;
    /// The handoff of the routing domain.
    type Handoff: UnclaimedHandoff<DatagramOf<Self::Link>>;

    /// The next input to judge or take, after receiving the held packets
    /// that were released; `Pending` at the limit of a poll, having woken
    /// the call, or until a delivery comes.
    #[allow(clippy::type_complexity)] // the delivery of the routing crate
    fn poll_next_input<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
    ) -> Poll<DatagramDelivery<DatagramOf<Self::Link>, <Self::Link as Link>::Local, Self::Handoff>>
    where
        Self: 'v;

    /// Judge whether the logical path takes the datagram of a competing
    /// candidate, by its first packet.
    fn judge<'v, 'access>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        access: DatagramClaimAccess<'access, DatagramOf<Self::Link>>,
        route: &DatagramRouteMatchInfo<<Self::Link as Link>::Local>,
    ) -> DatagramClaimOutcome<'access, (), (), DatagramOf<Self::Link>>
    where
        Self: 'v;

    /// Hold a candidate whose judgment waits for keys.
    fn hold_candidate<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        candidate: DatagramClaimCandidate<
            DatagramOf<Self::Link>,
            <Self::Link as Link>::Local,
            Self::Handoff,
        >,
    ) where
        Self: 'v;

    /// Receive a datagram the logical path owns: count it, cut it into
    /// packets and receive each.
    fn receive_datagram<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        delivery: ExclusiveDatagramDelivery<DatagramOf<Self::Link>, <Self::Link as Link>::Local>,
    ) where
        Self: 'v;
}

/// The positions the receiving call takes by: `Ip` of its input and `Ic` of
/// the record of why the connection closed in the logical path's lineage;
/// those of [`receive_packet`]; and `Ian` of
/// the anti-amplification limit in the entry of a logical link.
type Positions<Ip, Ic, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd, Ian> = (
    (Ip, Ic),
    (Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp),
    (Ir, Ie, Ik, Hd),
    Ian,
);

impl<T, L, K, B, Ip, Ic, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd, Ian>
    LogicalPathReceivingCapability
    for NodeCallFamily<
        T,
        L,
        LogicalPath,
        K,
        Positions<Ip, Ic, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd, Ian>,
        B,
    >
where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
    B: CallBundle,
    <T::Link as Link>::Payload: SplitTo + AsRef<[u8]> + AsMut<[u8]> + Into<Bytes>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
    <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LogicalPathInput<T::Link, T::Receiver>, Ip>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<MaxAckRanges, Im>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<IdleTimeout<InstantOf<T>>, It>
        + GetAt<AeadUsage, Iu>
        + GetAt<KeyPhaseNumbers, Ikp>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification], Ian>,
{
    type Link = T::Link;
    type Handoff = <T::Receiver as LogicalPathDatagramReceiver<T::Link>>::Handoff;

    fn poll_next_input<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        cx: &mut Context<'_>,
    ) -> Poll<DatagramDelivery<DatagramOf<T::Link>, <T::Link as Link>::Local, Self::Handoff>>
    where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        loop {
            let levels = ReceivableLevels::of::<T, L, Ii, Ih, Io>(lineage);
            let input = lineage.get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>();
            if input.yield_due() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            if let Some(held) = input.release(levels) {
                input.handled += 1;
                match held {
                    HeldInput::Candidate(candidate) => {
                        return Poll::Ready(DatagramDelivery::Competing(candidate));
                    }
                    HeldInput::Packet(packet) => {
                        // a connection error has used up the poll; the check
                        // above yields
                        let _ = receive_one::<
                            T,
                            L,
                            B,
                            Ip,
                            Ic,
                            Ii,
                            Ih,
                            Io,
                            Ij,
                            Im,
                            Ia,
                            It,
                            Iu,
                            Ikp,
                            Ir,
                            Ie,
                            Ik,
                            Hd,
                        >(lineage, others, packet);
                        continue;
                    }
                }
            }
            if let Some(datagram) = input.first.pop_front() {
                input.handled += 1;
                let dcid_len = input.first_dcid_len;
                receive_owned::<
                    T,
                    L,
                    B,
                    Ip,
                    Ic,
                    Ii,
                    Ih,
                    Io,
                    Ij,
                    Im,
                    Ia,
                    It,
                    Iu,
                    Ikp,
                    Ir,
                    Ie,
                    Ik,
                    Hd,
                    Ian,
                >(lineage, others, datagram, dcid_len);
                continue;
            }
            let Some(receiver) = input.receiver.as_mut() else {
                input.handled = 0;
                return Poll::Pending;
            };
            return match receiver.poll_next(cx) {
                Poll::Ready(delivery) => {
                    input.handled += 1;
                    Poll::Ready(delivery)
                }
                Poll::Pending => {
                    input.handled = 0;
                    Poll::Pending
                }
            };
        }
    }

    fn judge<'v, 'access>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        access: DatagramClaimAccess<'access, DatagramOf<T::Link>>,
        route: &DatagramRouteMatchInfo<<T::Link as Link>::Local>,
    ) -> DatagramClaimOutcome<'access, (), (), DatagramOf<T::Link>>
    where
        Self: 'v,
    {
        let lineage = &view.get_mut().lineage;
        // a long header is judged by the client's Source Connection ID,
        // which the connection does not keep yet
        let FirstPacketInterpretation::Short { dcid_len } = route.interpretation() else {
            return DatagramClaimOutcome::Abandoned(());
        };
        let keys = match one_rtt_receive_keys::<T, L, Io>(lineage) {
            LevelReceiveKeys::Ready(keys) => keys,
            LevelReceiveKeys::NotYet => return DatagramClaimOutcome::Unclaimed(access),
            LevelReceiveKeys::Gone => return DatagramClaimOutcome::Abandoned(()),
        };
        let largest = lineage
            .get::<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>()
            .get(PacketNumberSpaceKind::ApplicationData)
            .and_then(|journals| journals.largest())
            .map(|(number, _)| number);
        let lowest = lineage
            .get::<KeyPhaseNumbers, Ikp>()
            .lowest_received(keys.current().generation());
        if first_packet_opens(keys, lowest, access.bytes(), dcid_len, largest) {
            DatagramClaimOutcome::Claimed(access.into_exclusive(), ())
        } else {
            DatagramClaimOutcome::Abandoned(())
        }
    }

    fn hold_candidate<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        candidate: DatagramClaimCandidate<
            DatagramOf<T::Link>,
            <T::Link as Link>::Local,
            Self::Handoff,
        >,
    ) where
        Self: 'v,
    {
        view.get_mut()
            .lineage
            .get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>()
            .hold(HeldInput::Candidate(candidate));
    }

    fn receive_datagram<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LogicalPath, B>>,
        delivery: ExclusiveDatagramDelivery<DatagramOf<T::Link>, <T::Link as Link>::Local>,
    ) where
        Self: 'v,
    {
        let NodeLoan { lineage, others } = view.get_mut();
        let (datagram, route) = delivery.consume();
        receive_owned::<T, L, B, Ip, Ic, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd, Ian>(
            lineage,
            others,
            datagram.into_inner(),
            short_dcid_len(&route),
        );
    }
}

/// Receive `datagram`, which the logical path of `lineage` owns: count it
/// toward the anti-amplification limit of the logical link it arrived
/// over, cut it into packets, a short header's Destination Connection ID
/// being `dcid_len` long, and receive each, until one causes a connection
/// error.
#[allow(clippy::type_complexity)] // the positions of what it takes
fn receive_owned<'v, T, L, B, Ip, Ic, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd, Ian>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    datagram: DatagramOf<T::Link>,
    dcid_len: ConnectionIdLength,
) where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
    B: CallBundle,
    <T::Link as Link>::Payload: SplitTo + AsRef<[u8]> + AsMut<[u8]> + Into<Bytes>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
    <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LogicalPathInput<T::Link, T::Receiver>, Ip>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<MaxAckRanges, Im>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<IdleTimeout<InstantOf<T>>, It>
        + GetAt<AeadUsage, Iu>
        + GetAt<KeyPhaseNumbers, Ikp>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification], Ian>,
{
    let size = datagram.payload().as_ref().len();
    // the entry of a logical link no link path is over yet does not
    // exist; there is nothing to count
    if let Some(hlist_pat![limit]) =
        others.link_entry::<HList![AntiAmplification], Ian>(datagram.link().id())
    {
        limit.received(size);
    }
    // a server takes no Initial packet from a datagram too short to
    // have carried a client's first flight (RFC 9000 §14.1)
    let initial_allowed = <T::Side as Side>::ROLE == Role::Client || size >= MIN_DATAGRAM_SIZE;
    let (payload, arrival) = datagram.into_parts();
    for packet in into_packets(payload, dcid_len) {
        let packet = match packet {
            Ok(Packet::Protected(ProtectedPacket::Initial(..))) if !initial_allowed => continue,
            Ok(Packet::Protected(packet)) => packet,
            // a client's handling of these is not here yet
            Ok(Packet::Retry(..) | Packet::VersionNegotiation(..)) => continue,
            Err(IntoPacketsError::DcidDiffersFromFirst) => continue,
            Err(IntoPacketsError::UnreadableBoundary { .. }) => break,
        };
        let packet = ReceivedPacket::new(packet, arrival.clone());
        let next =
            receive_one::<T, L, B, Ip, Ic, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd>(
                lineage, others, packet,
            );
        if next.is_break() {
            break;
        }
    }
}

/// Receive `packet` on the logical path of `lineage`: hold it when its keys
/// have not come; on a connection error write the error into the record of
/// why the connection closed, use up this poll's inputs and break, so that
/// what follows waits until the link paths have entered closing.
#[allow(clippy::type_complexity)] // the positions of what it takes
fn receive_one<'v, T, L, B, Ip, Ic, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    packet: ReceivedPacket<<T::Link as Link>::Payload, T::Link>,
) -> ControlFlow<()>
where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
    B: CallBundle,
    <T::Link as Link>::Payload: AsMut<[u8]> + Into<Bytes>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
    <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LogicalPathInput<T::Link, T::Receiver>, Ip>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<MaxAckRanges, Im>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<IdleTimeout<InstantOf<T>>, It>
        + GetAt<AeadUsage, Iu>
        + GetAt<KeyPhaseNumbers, Ikp>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
{
    let outcome = receive_packet::<
        T,
        L,
        B,
        <T::Link as Link>::Payload,
        Ii,
        Ih,
        Io,
        Ij,
        Im,
        Ia,
        It,
        Iu,
        Ikp,
        Ir,
        Ie,
        Ik,
        Hd,
    >(lineage, others, packet);
    match outcome {
        // what a processed packet tells of migration is acted on with
        // migration
        Ok(
            PacketOutcome::Processed { .. } | PacketOutcome::Closing | PacketOutcome::Dropped(_),
        ) => ControlFlow::Continue(()),
        Ok(PacketOutcome::Held(packet)) => {
            lineage
                .get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>()
                .hold(HeldInput::Packet(packet));
            ControlFlow::Continue(())
        }
        Err(error) => {
            lineage
                .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>()
                .record(CloseReason::Local(Arc::new(LocalCloseCause::Connection(
                    error,
                ))));
            lineage
                .get_mut::<LogicalPathInput<T::Link, T::Receiver>, Ip>()
                .use_up();
            ControlFlow::Break(())
        }
    }
}

/// The length of the Destination Connection ID of a short header in a
/// datagram routed as `route` says: the length the interpretation read,
/// and after a long header that of the connection ID it was found by, which
/// every packet of the datagram carries (RFC 9000 §12.2).
pub(super) fn short_dcid_len<Local>(route: &DatagramRouteMatchInfo<Local>) -> ConnectionIdLength {
    match route.interpretation() {
        FirstPacketInterpretation::Short { dcid_len } => dcid_len,
        FirstPacketInterpretation::Long { .. } | FirstPacketInterpretation::VersionNegotiation => {
            match route.association() {
                MatchAssociation::LocalCid(cid) | MatchAssociation::InitialDcid(cid) => {
                    AsRef::<ConnectionId>::as_ref(cid).length()
                }
                MatchAssociation::ZeroCid(_) => ConnectionIdLength::ZERO,
            }
        }
    }
}

/// Whether the first packet of `datagram`, a 1-RTT packet whose
/// Destination Connection ID is `dcid_len` long, opens with `keys`, its
/// packet number decoded against `largest` and its generation selected
/// against `lowest` as [`open_one_rtt`] does. A copy is opened: the datagram
/// stays as it arrived, and nothing is recorded or counted.
fn first_packet_opens<B: CryptoBackend, I: Copy>(
    keys: &OneRttReceiveKeys<B, I>,
    lowest: Option<PacketNumber>,
    datagram: &[u8],
    dcid_len: ConnectionIdLength,
    largest: Option<PacketNumber>,
) -> bool {
    let Some(Ok(Packet::Protected(packet @ ProtectedPacket::OneRtt(..)))) =
        into_packets(datagram, dcid_len).next()
    else {
        return false;
    };
    let Some(pn_offset) = packet_number_offset(&packet) else {
        return false;
    };
    let mut copy = packet.into_bytes().to_vec();
    open_one_rtt(keys, lowest, &mut copy, pn_offset, largest).is_ok()
}

/// The receiving call of a logical path; the steps are those of the
/// [module documentation](self).
#[call]
pub async fn logical_path_receiving<W: LogicalPathReceivingCapability>(
    host: &mut impl LentAccess<Family = W>,
) {
    loop {
        let delivery =
            poll_fn(|cx| host.with(|mut view| W::poll_next_input(view.as_pin(), cx))).await;
        let delivery = match delivery {
            DatagramDelivery::Exclusive(delivery) => delivery,
            DatagramDelivery::Competing(candidate) => {
                let attempt = candidate
                    .try_exclusive(|access, route| {
                        host.with(|mut view| W::judge(view.as_pin(), access, route))
                    })
                    .await;
                match attempt {
                    DatagramClaimAttempt::Claimed(delivery, ())
                    | DatagramClaimAttempt::Exclusive(delivery) => delivery,
                    DatagramClaimAttempt::Unclaimed(candidate) => {
                        host.with(|mut view| W::hold_candidate(view.as_pin(), candidate));
                        continue;
                    }
                    DatagramClaimAttempt::Abandoned(())
                    | DatagramClaimAttempt::ClaimedElsewhere => {
                        continue;
                    }
                }
            }
        };
        host.with(|mut view| W::receive_datagram(view.as_pin(), delivery));
    }
}

/// The kind of the receiving call of a logical path. It reads the
/// Handshake and 1-RTT keys: once they are installed, the inputs held for
/// them go.
#[derive(Debug)]
pub struct LogicalPathReceivingKind;

impl<T, L, Ip, Ic, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd, Ian>
    CallKind<
        T,
        L,
        LogicalPath,
        Positions<Ip, Ic, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd, Ian>,
    > for LogicalPathReceivingKind
where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
    <T::Link as Link>::Payload: SplitTo + AsRef<[u8]> + AsMut<[u8]> + Into<Bytes>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
    <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<LogicalPathInput<T::Link, T::Receiver>, Ip>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ic>
        + GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<MaxAckRanges, Im>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<IdleTimeout<InstantOf<T>>, It>
        + GetAt<AeadUsage, Iu>
        + GetAt<KeyPhaseNumbers, Ikp>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification], Ian>,
    Positions<Ip, Ic, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd, Ian>: 'static,
{
    type Call<B: CallBundle> = LentCall<
        NodeCallFamily<
            T,
            L,
            LogicalPath,
            LogicalPathReceivingKind,
            Positions<Ip, Ic, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd, Ian>,
            B,
        >,
        LogicalPathReceiving,
    >;
    fn start<B: CallBundle>(_: &mut ArgsOf<T, L, LogicalPath>) -> Self::Call<B> {
        LentCall::new(LogicalPathReceiving::new())
    }
    fn reads(reads: &mut ReadSet) {
        reads
            .add::<HandshakeKeys<T::Crypto>>()
            .add::<OneRttKeys<T::Crypto, InstantOf<T>>>();
    }
}
