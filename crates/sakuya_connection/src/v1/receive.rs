//! Receiving one packet on a logical path: version 1's packet protection,
//! duplicate detection, the dispatch of each frame and the record of the
//! packet.
//!
//! [`receive_packet`] takes one packet cut from a datagram, with the facts
//! of the datagram's arrival ([`ReceivedPacket`]), and goes through it in
//! order:
//!
//! 1. The role of the link path the packet arrived on decides how far it is
//!    read. A packet with no link path in this logical path, or on a
//!    draining one, is dropped; on a closing one it is only searched for a
//!    CONNECTION_CLOSE frame. A client drops an Initial packet that carries
//!    a token, which a server never sends (RFC 9000 §17.2.2).
//! 2. The receive keys of the packet's level. A Handshake packet before the
//!    Handshake keys, or a 1-RTT packet before the 1-RTT receive keys, is
//!    handed back to wait, unless the link path is closing: a closing link
//!    path only has the receive keys it had, and no more come. A packet of
//!    a level whose keys are gone, or of 0-RTT, which the connection does
//!    not read yet, is dropped.
//! 3. Header protection and the AEAD are removed in place, with the packet
//!    number decoded against the largest one processed in its space; a
//!    packet that does not open is dropped (RFC 9001 §5.4.2, §5.5).
//! 4. Reserved bits set once both layers are removed end the connection
//!    (RFC 9000 §17.2, §17.3.1); a packet number already processed is
//!    dropped (§12.3).
//! 5. The frames are read and dispatched one by one, each checked against
//!    the level and this side's role first; a failure ends the connection,
//!    and what follows it is not dispatched. A packet without frames ends
//!    it too (§12.4).
//! 6. Only once every frame was handled is the packet recorded: in the
//!    receive journals of its space, which then keep at most the configured
//!    number of ranges (§13.2.3), in the ACK obligation of its space
//!    (§13.1), and as a restart of the idle timeout (§10.1). A server
//!    discards its Initial keys when it first processes a Handshake packet
//!    (RFC 9001 §4.9.1).
//!
//! What follows from the record, such as an ACK frame becoming due, belongs
//! to sending and timing; so do the close packets a closing link path sends
//! back. The anti-amplification limit counts whole datagrams and is the
//! caller's. Migration is decided per packet (RFC 9000 §9.3, §9.3.2): the
//! outcome of a processed packet says whether it is non-probing and has the
//! highest packet number of its space, for the caller to act on.
use core::{convert::Infallible, fmt, marker::PhantomData, ops::Range};

use bytes::Bytes;
use frunk_core::coproduct::CoproductSelector;
use sakuya_link::{ArrivalFacts, EcnCodepoint, Link};
use sakuya_packet_protection::{
    backend::CryptoBackend, header_protection::HeaderProtectionError, packet_key::OpenPacketError,
};
use sakuya_recovery::{
    ack_obligation::AckObligation,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaces},
    receive_journals::{MaxAckRanges, ReceiveJournals},
};
use sakuya_wire::{
    parts::{CoprodInjector, PartsError},
    v1::{
        encryption_level::EncryptionLevel,
        frame::{
            FrameType,
            set::{FrameSet, Frames, codec::ReadFrameError},
        },
        header::TypeFields,
        packet_number::PacketNumber,
        protected_packet::ProtectedPacket,
        role::Role,
    },
};

use super::{
    Choices, Side,
    dispatch::permitted,
    error::ConnectionError,
    idle::IdleTimeout,
    keys::{DirectionKeys, HandshakeKeys, InitialKeys, OneRttKeys},
    role::LinkPathRole,
    spaces::AckObligationsOf,
};
use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::LineageOf,
    dispatch::{DispatchFacts, FrameSetDispatch, PacketFacts},
    error::{ConnectionErrorOf, ConnectionErrorsOf},
    layer::{self, LogicalPath, NodeKey},
    others::OtherNodes,
    share::{FlatMut, LineageLists, LineagePartList, NodeData},
    take::GetAt,
};

/// A packet cut from a datagram, with its protection still on, and its own
/// copy of the facts of the datagram's arrival.
///
/// It is not a datagram: what counts whole datagrams, such as routing and
/// the anti-amplification limit, does not take it.
pub struct ReceivedPacket<P, Lk: Link> {
    packet: ProtectedPacket<P>,
    arrival: ArrivalFacts<Lk>,
}

impl<P, Lk: Link> ReceivedPacket<P, Lk> {
    /// The packet `packet`, cut from a datagram that arrived as `arrival`
    /// says.
    pub fn new(packet: ProtectedPacket<P>, arrival: ArrivalFacts<Lk>) -> Self {
        Self { packet, arrival }
    }

    /// The packet.
    pub fn packet(&self) -> &ProtectedPacket<P> {
        &self.packet
    }

    /// The facts of the datagram's arrival.
    pub fn arrival(&self) -> &ArrivalFacts<Lk> {
        &self.arrival
    }

    /// Takes the packet and the facts of its arrival.
    pub fn into_parts(self) -> (ProtectedPacket<P>, ArrivalFacts<Lk>) {
        (self.packet, self.arrival)
    }
}

impl<P: fmt::Debug, Lk: Link + fmt::Debug> fmt::Debug for ReceivedPacket<P, Lk>
where
    Lk::Instant: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceivedPacket")
            .field("packet", &self.packet)
            .field("arrival", &self.arrival)
            .finish()
    }
}

/// What came of a packet that did not end the connection.
// The held packet is handed back as it came in, by value, as large as the
// packet passed in; boxing it would allocate for every packet that waits.
#[allow(clippy::large_enum_variant)]
pub enum PacketOutcome<P, Lk: Link> {
    /// Every frame was handled and the packet is recorded.
    ///
    /// The peer migrates with the non-probing packet of the highest packet
    /// number (RFC 9000 §9.3); the two fields are what that takes from this
    /// packet.
    Processed {
        /// Whether the packet number is higher than any processed before in
        /// the packet's space.
        highest_numbered: bool,
        /// Whether the packet has a frame that is not a probing frame: it
        /// is a non-probing packet (RFC 9000 §9.1).
        non_probing: bool,
    },
    /// The link path is closing: the packet was read only for a
    /// CONNECTION_CLOSE frame, which was handled if there was one; nothing
    /// is recorded.
    Closing,
    /// The keys of the packet's level have not come yet: the packet is
    /// handed back, unchanged, to wait for them.
    Held(ReceivedPacket<P, Lk>),
    /// The packet is dropped without a trace.
    Dropped(DropReason),
}

impl<P: fmt::Debug, Lk: Link + fmt::Debug> fmt::Debug for PacketOutcome<P, Lk>
where
    Lk::Instant: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Processed {
                highest_numbered,
                non_probing,
            } => f
                .debug_struct("Processed")
                .field("highest_numbered", highest_numbered)
                .field("non_probing", non_probing)
                .finish(),
            Self::Closing => f.write_str("Closing"),
            Self::Held(packet) => f.debug_tuple("Held").field(packet).finish(),
            Self::Dropped(reason) => f.debug_tuple("Dropped").field(reason).finish(),
        }
    }
}

/// Why a packet was dropped without a trace.
#[derive(Debug)]
pub enum DropReason {
    /// The logical link the packet arrived on has no link path in this
    /// logical path.
    NoLinkPath,
    /// The link path the packet arrived on is draining: nothing it receives
    /// is read (RFC 9000 §10.2.2).
    Draining,
    /// A client received an Initial packet whose Token Length is not zero,
    /// which a server never sends (RFC 9000 §17.2.2).
    TokenFromServer,
    /// The packet's level has no keys to read it with, and none are to come:
    /// they were discarded, the link path is closing, or, for 0-RTT, the
    /// connection does not read the level.
    NoReceiveKeys {
        /// The level of the packet.
        level: EncryptionLevel,
    },
    /// The packet is held as protected, but its header is that of a Retry
    /// packet, which has no packet protection.
    NotProtected,
    /// Header protection could not be removed: the packet is too short for
    /// the sample (RFC 9001 §5.4.2).
    HeaderProtectionNotRemoved {
        /// The failure.
        source: HeaderProtectionError,
    },
    /// The payload did not open, such as when it fails authentication (RFC
    /// 9001 §5.5).
    PayloadNotOpened {
        /// The failure.
        source: OpenPacketError,
    },
    /// The packet number was already processed in its space, or lies below
    /// what the space still tells apart (RFC 9000 §12.3).
    Duplicate {
        /// The packet number.
        number: PacketNumber,
    },
}

/// Receive one packet on the logical path that `lineage` and `others` are
/// the lend of; the steps are those of the [module documentation](self).
///
/// The positions are found from the composition: `Ii`, `Ih`, `Io` of the
/// keys of the three levels, `Ij` of the receive journals, `Im` of their
/// maximum number of ACK ranges, `Ia` of the ACK obligations and `It` of
/// the idle timeout, among the components of the logical path's lineage; `Ir` of the role among a link path's; `Ie` of
/// version 1's error in the connection's error; `Ik` of version 1's frame
/// kinds among the kinds of the frame set; `Hd` of what each part's
/// dispatch takes.
///
/// # Errors
///
/// The connection error the packet causes: reserved bits set, a frame that
/// does not read or is not permitted, a failure of the part that handles a
/// frame, or no frames at all. The packet is then not recorded.
pub fn receive_packet<'v, T, L, B, P, Ii, Ih, Io, Ij, Im, Ia, It, Ir, Ie, Ik, Hd>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    packet: ReceivedPacket<P, T::Link>,
) -> Result<PacketOutcome<P, T::Link>, ConnectionErrorOf<L>>
where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
    B: CallBundle,
    P: AsMut<[u8]> + Into<Bytes>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
    <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto>, Io>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<MaxAckRanges, Im>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<IdleTimeout<InstantOf<T>>, It>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
{
    let role = match arrival_role::<T, L, B, Ir>(others, packet.arrival()) {
        None => return Ok(PacketOutcome::Dropped(DropReason::NoLinkPath)),
        Some(LinkPathRole::Draining(_)) => return Ok(PacketOutcome::Dropped(DropReason::Draining)),
        Some(role) => role,
    };
    if <T::Side as Side>::ROLE == Role::Client && carries_token(packet.packet()) {
        return Ok(PacketOutcome::Dropped(DropReason::TokenFromServer));
    }
    let closing = matches!(role, LinkPathRole::Closing(_));
    let level = packet.packet().level();
    let space = space_of(level);
    let (packet, arrival) = packet.into_parts();
    let (opened, bytes) = {
        let keys = match receive_keys::<T, L, Ii, Ih, Io>(lineage, level) {
            LevelReceiveKeys::Ready(keys) => keys,
            // a closing link path gets no more keys than it has
            LevelReceiveKeys::NotYet if closing => {
                return Ok(PacketOutcome::Dropped(DropReason::NoReceiveKeys { level }));
            }
            LevelReceiveKeys::NotYet => {
                return Ok(PacketOutcome::Held(ReceivedPacket::new(packet, arrival)));
            }
            LevelReceiveKeys::Gone => {
                return Ok(PacketOutcome::Dropped(DropReason::NoReceiveKeys { level }));
            }
        };
        // a space is gone only where its keys were discarded before the
        // logical path was built, and they do not come back
        let Some(journals) = lineage
            .get::<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>()
            .get(space)
        else {
            return Ok(PacketOutcome::Dropped(DropReason::NoReceiveKeys { level }));
        };
        let largest = journals.largest().map(|(number, _)| number);
        let Some(pn_offset) = packet_number_offset(&packet) else {
            return Ok(PacketOutcome::Dropped(DropReason::NotProtected));
        };
        let mut bytes = packet.into_bytes();
        match open(keys, bytes.as_mut(), pn_offset, largest) {
            Ok(opened) => (opened, bytes),
            Err(reason) => return Ok(PacketOutcome::Dropped(reason)),
        }
    };
    let payload = bytes.into().slice(opened.payload);
    let at = arrival.at();
    let facts = DispatchFacts::new(level, at);
    if closing {
        find_close::<T, L, B, Ik, Hd>(lineage, others, payload, &facts)?;
        return Ok(PacketOutcome::Closing);
    }
    if reserved_bits_set(level, opened.first_byte) {
        return Err(v1_error::<L, Ie>(ConnectionError::ReservedBitsSet {
            level,
        }));
    }
    let number = opened.number;
    let admission = lineage
        .get::<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>()
        .get(space)
        .and_then(|journals| journals.admit(number));
    let Some(admission) = admission else {
        return Ok(PacketOutcome::Dropped(DropReason::Duplicate { number }));
    };

    let mut packet_facts = PacketFacts::default();
    for run in Frames::new(payload, PhantomData::<L>) {
        let run = run.map_err(read_frame_error::<T, L, Ie, Hd>)?;
        let kind = <L as FrameSet>::run_kind(&run);
        permitted(kind, level, <T::Side as Side>::ROLE)
            .map_err(|source| v1_error::<L, Ie>(ConnectionError::FrameNotPermitted { source }))?;
        packet_facts.note(kind);
        <L as FrameSetDispatch<T, L, Hd>>::dispatch(lineage, others, run, &facts)
            .map_err(PartsError)?;
    }
    if packet_facts.is_empty() {
        return Err(v1_error::<L, Ie>(ConnectionError::EmptyPacket { level }));
    }

    let ecn = arrival.ecn();
    let max_ranges = *lineage.get::<MaxAckRanges, Im>();
    // a space does not go while its packets are dispatched
    let highest_numbered = if let Some(journals) = lineage
        .get_mut::<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>()
        .get_mut(space)
    {
        // compared before the packet is recorded, which makes it the largest
        let highest_numbered = journals
            .largest()
            .is_none_or(|(largest, _)| number > largest);
        let run_below = journals.received_run_below(number);
        journals.record(admission, at, ecn);
        journals.limit(max_ranges);
        if let Some(obligation) = lineage.get_mut::<AckObligationsOf<T>, Ia>().get_mut(space) {
            obligation.record(
                number,
                at,
                packet_facts.is_ack_eliciting(),
                ecn == Some(EcnCodepoint::Ce),
                run_below,
            );
        }
        highest_numbered
    } else {
        false
    };
    lineage
        .get_mut::<IdleTimeout<InstantOf<T>>, It>()
        .packet_processed(at);
    if level == EncryptionLevel::Handshake
        && <T::Side as Side>::ROLE == Role::Server
        && !matches!(
            lineage.get::<InitialKeys<T::Crypto>, Ii>(),
            InitialKeys::Discarded
        )
    {
        lineage.get_mut::<InitialKeys<T::Crypto>, Ii>().discard();
    }
    Ok(PacketOutcome::Processed {
        highest_numbered,
        non_probing: packet_facts.is_non_probing(),
    })
}

/// The role of the link path of this logical path that the packet arrived
/// on; `None` when it has none.
fn arrival_role<T, L, B, Ir>(
    others: &mut OtherNodes<'_, T, L, B>,
    arrival: &ArrivalFacts<T::Link>,
) -> Option<LinkPathRole<InstantOf<T>>>
where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        GetAt<LinkPathRole<InstantOf<T>>, Ir>,
{
    let NodeKey::LogicalPath(path) = others.here().clone() else {
        unreachable!("a logical path's lend carries its key")
    };
    let key = NodeKey::LinkPath(path, arrival.link().id().clone());
    let mut found = None;
    others.each_link_path_read::<LinkPathRole<InstantOf<T>>, Ir>(|each, role| {
        if *each == key {
            found = Some(*role);
        }
    });
    found
}

/// Whether `packet` is an Initial packet whose Token Length is not zero.
fn carries_token<P>(packet: &ProtectedPacket<P>) -> bool {
    match packet {
        ProtectedPacket::Initial(long, _) => {
            matches!(long.fields(), TypeFields::Initial { token, .. } if !token.is_empty())
        }
        ProtectedPacket::ZeroRtt(..)
        | ProtectedPacket::Handshake(..)
        | ProtectedPacket::OneRtt(..) => false,
    }
}

/// The receive keys of one level, as far as there are any.
enum LevelReceiveKeys<'k, B: CryptoBackend> {
    /// The keys to read the level's packets with.
    Ready(&'k DirectionKeys<B>),
    /// The handshake has not produced them yet; the packet waits.
    NotYet,
    /// None are to come.
    Gone,
}

/// The receive keys of `level`.
///
/// A server's 1-RTT level that has only its sending half has not come for
/// receiving: a 1-RTT packet is not read before the handshake completes
/// (RFC 9001 §5.7).
fn receive_keys<'k, T, L, Ii, Ih, Io>(
    lineage: &'k LineageOf<'_, T, L, LogicalPath>,
    level: EncryptionLevel,
) -> LevelReceiveKeys<'k, T::Crypto>
where
    T: Choices,
    L: LineagePartList<T>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto>, Io>,
{
    match level {
        EncryptionLevel::Initial => lineage
            .get::<InitialKeys<T::Crypto>, Ii>()
            .receive()
            .map_or(LevelReceiveKeys::Gone, LevelReceiveKeys::Ready),
        // the connection reads no 0-RTT yet; a server may drop it (RFC 9001
        // §4.6.1)
        EncryptionLevel::ZeroRtt => LevelReceiveKeys::Gone,
        EncryptionLevel::Handshake => match lineage.get::<HandshakeKeys<T::Crypto>, Ih>() {
            HandshakeKeys::NotYet => LevelReceiveKeys::NotYet,
            keys => keys
                .receive()
                .map_or(LevelReceiveKeys::Gone, LevelReceiveKeys::Ready),
        },
        EncryptionLevel::OneRtt => match lineage.get::<OneRttKeys<T::Crypto>, Io>() {
            OneRttKeys::NotYet | OneRttKeys::SendOnly(_) => LevelReceiveKeys::NotYet,
            keys => keys
                .receive()
                .map_or(LevelReceiveKeys::Gone, LevelReceiveKeys::Ready),
        },
    }
}

/// The packet number space of the packets of `level`.
fn space_of(level: EncryptionLevel) -> PacketNumberSpaceKind {
    match level {
        EncryptionLevel::Initial => PacketNumberSpaceKind::Initial,
        EncryptionLevel::Handshake => PacketNumberSpaceKind::Handshake,
        EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => {
            PacketNumberSpaceKind::ApplicationData
        }
    }
}

/// Where the Packet Number field of `packet` starts: the start of the
/// protected range; `None` for a header of a Retry packet.
fn packet_number_offset<P>(packet: &ProtectedPacket<P>) -> Option<usize> {
    match packet {
        ProtectedPacket::Initial(long, _)
        | ProtectedPacket::ZeroRtt(long, _)
        | ProtectedPacket::Handshake(long, _) => match long.fields() {
            TypeFields::Initial { protected, .. }
            | TypeFields::ZeroRtt { protected, .. }
            | TypeFields::Handshake { protected, .. } => Some(protected.start),
            TypeFields::Retry { .. } => None,
        },
        ProtectedPacket::OneRtt(short, _) => Some(short.packet_number_offset()),
    }
}

/// A packet with both layers of protection removed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Opened {
    /// The packet number.
    number: PacketNumber,
    /// The first byte, unprotected.
    first_byte: u8,
    /// Where the plaintext payload lies in the packet.
    payload: Range<usize>,
}

/// Remove header protection and the AEAD from `packet` in place, with the
/// Packet Number field at `pn_offset`, decoding the packet number against
/// `largest`, the largest one processed in its space.
fn open<B: CryptoBackend>(
    keys: &DirectionKeys<B>,
    packet: &mut [u8],
    pn_offset: usize,
    largest: Option<PacketNumber>,
) -> Result<Opened, DropReason> {
    let truncated = keys
        .header
        .remove(packet, pn_offset)
        .map_err(|source| DropReason::HeaderProtectionNotRemoved { source })?;
    let number = truncated.decode(largest);
    let header_len = pn_offset + truncated.encoded_len().get();
    let payload_len = keys
        .packet
        .open(number, packet, header_len)
        .map_err(|source| DropReason::PayloadNotOpened { source })?
        .len();
    Ok(Opened {
        number,
        first_byte: packet[0],
        payload: header_len..header_len + payload_len,
    })
}

/// Whether a reserved bit of the unprotected first byte of a packet of
/// `level` is set: `0x0c` of a long header, `0x18` of a short header, the
/// header of 1-RTT packets.
fn reserved_bits_set(level: EncryptionLevel, first_byte: u8) -> bool {
    let reserved = match level {
        EncryptionLevel::OneRtt => 0x18,
        EncryptionLevel::Initial | EncryptionLevel::ZeroRtt | EncryptionLevel::Handshake => 0x0c,
    };
    first_byte & reserved != 0
}

/// Read the frames of `payload`, received on a closing link path, and
/// dispatch the first CONNECTION_CLOSE frame the packet may carry, if any;
/// the other frames, and a failure of reading, are passed over.
fn find_close<'v, T, L, B, Ik, Hd>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    payload: Bytes,
    facts: &DispatchFacts<InstantOf<T>>,
) -> Result<(), ConnectionErrorOf<L>>
where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
    B: CallBundle,
    <L as FrameSet>::Kind: CoproductSelector<FrameType, Ik>,
{
    for run in Frames::new(payload, PhantomData::<L>) {
        let Ok(run) = run else { break };
        let kind = <L as FrameSet>::run_kind(&run);
        let close = matches!(
            CoproductSelector::<FrameType, Ik>::get(&kind),
            Some(FrameType::ConnectionCloseTransport | FrameType::ConnectionCloseApplication)
        );
        if close && permitted(kind, facts.level(), <T::Side as Side>::ROLE).is_ok() {
            return <L as FrameSetDispatch<T, L, Hd>>::dispatch(lineage, others, run, facts)
                .map_err(PartsError);
        }
    }
    Ok(())
}

/// Version 1's `error` as the connection's error.
fn v1_error<L, Ie>(error: ConnectionError) -> ConnectionErrorOf<L>
where
    L: ConnectionErrorsOf,
    L::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
{
    PartsError(CoprodInjector::inject(error))
}

/// The connection's error for a frame that could not be read: version 1's
/// for a Frame Type that failed, the part's that claims the frame for its
/// fields.
fn read_frame_error<T, L, Ie, Hd>(
    error: ReadFrameError<Infallible, <L as FrameSet>::FieldsError<Infallible>>,
) -> ConnectionErrorOf<L>
where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
    L::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
{
    let source = match error {
        ReadFrameError::FrameType { source } => ReadFrameError::FrameType { source },
        ReadFrameError::LongerTypeEncoding { source } => {
            ReadFrameError::LongerTypeEncoding { source }
        }
        ReadFrameError::UnknownType { frame_type } => ReadFrameError::UnknownType { frame_type },
        ReadFrameError::Fields {
            source: PartsError(source),
        } => return PartsError(<L as FrameSetDispatch<T, L, Hd>>::fields_error(source)),
    };
    v1_error::<L, Ie>(ConnectionError::ReadFrame { source })
}

#[cfg(test)]
mod tests {
    use sakuya_packet_protection::{
        backend::ring::RingBackend,
        initial::{INITIAL_AEAD, InitialSecrets},
        packet_number::{PacketNumberLength, TruncatedPacketNumber},
    };
    use sakuya_wire::connection_id::ConnectionId;

    use super::*;

    fn keys() -> DirectionKeys<RingBackend> {
        let cid = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).unwrap();
        let secrets = InitialSecrets::derive(&RingBackend, &cid);
        DirectionKeys::derive(&RingBackend, INITIAL_AEAD, &secrets.client)
    }

    /// A short header packet of `number` in a 2-byte field, with a 1-byte
    /// destination connection ID, carrying `payload`, protected with
    /// `keys`; the first byte before protection is `first_byte` with the
    /// field length bits added.
    fn sealed(
        keys: &DirectionKeys<RingBackend>,
        first_byte: u8,
        number: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let pn_len = PacketNumberLength::new(2).unwrap();
        let truncated = TruncatedPacketNumber::new(u32::try_from(number).unwrap(), pn_len).unwrap();
        let number = PacketNumber::new(number).unwrap();
        let mut packet = vec![first_byte | 0x01, 0x07];
        packet.extend_from_slice(truncated.as_bytes());
        packet.extend_from_slice(payload);
        packet.extend_from_slice(&[0; 16]);
        keys.packet.seal(number, &mut packet, 4).unwrap();
        keys.header.apply(&mut packet, 2).unwrap();
        packet
    }

    #[test]
    fn a_packet_opens_with_its_number_and_payload() {
        let keys = keys();
        let payload = [0x01; 20];
        let mut packet = sealed(&keys, 0x40, 3, &payload);
        let opened = open(&keys, &mut packet, 2, Some(PacketNumber::new(2).unwrap())).unwrap();
        assert_eq!(opened.number, PacketNumber::new(3).unwrap());
        assert_eq!(opened.first_byte, 0x41);
        assert_eq!(packet[opened.payload], payload);
    }

    #[test]
    fn a_changed_byte_fails_authentication() {
        let keys = keys();
        let mut packet = sealed(&keys, 0x40, 0, &[0x01; 20]);
        let last = packet.len() - 1;
        packet[last] ^= 1;
        assert!(matches!(
            open(&keys, &mut packet, 2, None),
            Err(DropReason::PayloadNotOpened {
                source: OpenPacketError::Authentication { .. }
            })
        ));
    }

    #[test]
    fn a_packet_too_short_for_the_sample_does_not_open() {
        let mut packet = [0x40, 0x07, 0, 0, 0, 0];
        assert!(matches!(
            open(&keys(), &mut packet, 2, None),
            Err(DropReason::HeaderProtectionNotRemoved { .. })
        ));
    }

    #[test]
    fn reserved_bits_are_those_of_the_header_form() {
        assert!(!reserved_bits_set(EncryptionLevel::Initial, 0xc3));
        assert!(reserved_bits_set(EncryptionLevel::Initial, 0xc4));
        assert!(reserved_bits_set(EncryptionLevel::Handshake, 0xe8));
        // the Key Phase bit and the Spin Bit are not reserved
        assert!(!reserved_bits_set(EncryptionLevel::OneRtt, 0x67));
        assert!(reserved_bits_set(EncryptionLevel::OneRtt, 0x48));
        assert!(reserved_bits_set(EncryptionLevel::OneRtt, 0x50));
    }

    #[test]
    fn zero_rtt_and_one_rtt_share_the_application_data_space() {
        assert_eq!(
            space_of(EncryptionLevel::ZeroRtt),
            PacketNumberSpaceKind::ApplicationData
        );
        assert_eq!(
            space_of(EncryptionLevel::OneRtt),
            PacketNumberSpaceKind::ApplicationData
        );
        assert_eq!(
            space_of(EncryptionLevel::Handshake),
            PacketNumberSpaceKind::Handshake
        );
    }
}
