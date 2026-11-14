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
//!    packet that does not open is dropped (RFC 9001 §5.4.2, §5.5), and
//!    one that fails authentication counts toward the integrity limit of
//!    its AEAD, past which the connection ends (§6.6). A 1-RTT packet is
//!    opened once, with the one receiving generation its Key Phase and
//!    packet number select, as [`key_phase`](super::key_phase) says. The
//!    first Initial packet a server opens tells the logical path's
//!    destination connection ID strategy the client's Source Connection
//!    ID, which the server sends with (RFC 9000 §7.2).
//! 4. Reserved bits set once both layers are removed end the connection
//!    (RFC 9000 §17.2, §17.3.1); a packet number already processed is
//!    dropped (§12.3). A 1-RTT packet that is not dropped notes its number
//!    for its generation; one opened with the next generation makes it
//!    current, and when the peer updated first, the sending generation
//!    moves with it, before anything acknowledges the packet (RFC 9001
//!    §6.2). A second update of the peer's before this side acknowledged
//!    the first with its keys ends the connection, as the
//!    [`key_update`](super::key_update) module says.
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
    backend::CryptoBackend,
    header_protection::{HeaderProtectionError, HeaderProtectionKey},
    packet_key::{OpenPacketError, PacketKey},
};
use sakuya_recovery::{
    ack_obligation::AckObligation,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaces},
    receive_journals::{Admission, MaxAckRanges, ReceiveJournals},
};
use sakuya_wire::{
    parts::{CoprodInjector, PartsError},
    v1::{
        encryption_level::EncryptionLevel,
        frame::{
            FrameType,
            set::{FrameSet, Frames, codec::ReadFrameError},
        },
        header::{KeyPhase, TypeFields},
        packet_number::PacketNumber,
        protected_packet::ProtectedPacket,
        role::Role,
    },
};

use super::{
    Choices, Side,
    aead_usage::AeadUsage,
    connection_ids::{ConnectionIdsOf, ResetTokenRegistrarOf},
    dispatch::permitted,
    error::ConnectionError,
    idle::IdleTimeout,
    key_phase::KeyPhaseNumbers,
    key_update::check_peer_update,
    keys::{DirectionKeys, HandshakeKeys, InitialKeys, OneRttKeys, OneRttReceiveKeys},
    role::LinkPathRole,
    spaces::AckObligationsOf,
};
use crate::{
    call::CallBundle,
    clock::{InstantOf, LinkIdOf},
    component::LineageOf,
    dispatch::{DispatchFacts, FrameSetDispatch, PacketFacts, ReceivedProtection},
    error::{ConnectionErrorOf, ConnectionErrorsOf},
    layer::{self, LogicalPath, NodeKey},
    others::OtherNodes,
    share::{FlatMut, LineageLists, LineagePartList, LinkPathIdentifierOf, NodeData},
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
/// maximum number of ACK ranges, `Ia` of the ACK obligations, `It` of the
/// idle timeout, `Iu` of the AEAD usage and `Ikp` of the key phase numbers,
/// among the components of the logical path's lineage; `Ir` of the role
/// among a link path's; `Ie` of
/// version 1's error in the connection's error; `Ik` of version 1's frame
/// kinds among the kinds of the frame set; `Hd` of what each part's
/// dispatch takes.
///
/// # Errors
///
/// The connection error the packet causes: the integrity limit exceeded,
/// reserved bits set, a second key update of the peer's before the first
/// was acknowledged, a frame that does not read
/// or is not permitted, a failure of the part that handles a frame, or no
/// frames at all. The packet is then not recorded.
pub fn receive_packet<'v, T, L, B, P, Ii, Ih, Io, Ij, Im, Ia, It, Iu, Ikp, Ir, Ie, Ik, Hd, Icid>(
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
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>
        + GetAt<MaxAckRanges, Im>
        + GetAt<AckObligationsOf<T>, Ia>
        + GetAt<IdleTimeout<InstantOf<T>>, It>
        + GetAt<AeadUsage, Iu>
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<ConnectionIdsOf<T>, Icid>,
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
    let (opened, bytes, one_rtt, initial_scid) = {
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
        let initial_scid = match &packet {
            ProtectedPacket::Initial(long, _) => Some(*long.scid()),
            ProtectedPacket::ZeroRtt(..)
            | ProtectedPacket::Handshake(..)
            | ProtectedPacket::OneRtt(..) => None,
        };
        let mut bytes = packet.into_bytes();
        let (opening, aead) = match keys {
            ReceiveKeys::Level(keys) => (
                open(keys, bytes.as_mut(), pn_offset, largest).map(|opened| (opened, None)),
                keys.aead(),
            ),
            ReceiveKeys::OneRtt(keys) => {
                let current = keys.current().generation();
                let lowest = lineage
                    .get::<KeyPhaseNumbers, Ikp>()
                    .lowest_received(current);
                (
                    open_one_rtt(keys, lowest, bytes.as_mut(), pn_offset, largest)
                        .map(|(opened, generation)| (opened, Some((generation, current, lowest)))),
                    keys.current().aead(),
                )
            }
        };
        match opening {
            Ok((opened, one_rtt)) => (opened, bytes, one_rtt, initial_scid),
            Err(reason) => {
                if fails_authentication(&reason) {
                    lineage
                        .get_mut::<AeadUsage, Iu>()
                        .authentication_failed(aead)
                        .map_err(|source| {
                            v1_error::<L, Ie>(ConnectionError::AeadLimitReached { source })
                        })?;
                }
                return Ok(PacketOutcome::Dropped(reason));
            }
        }
    };
    // the first Initial packet that opens sets the connection ID a server
    // sends with (RFC 9000 §7.2)
    if let Some(scid) = initial_scid
        && <T::Side as Side>::ROLE == Role::Server
    {
        lineage
            .get_mut::<ConnectionIdsOf<T>, Icid>()
            .handshake_connection_id::<LinkIdOf<T>, InstantOf<T>, ResetTokenRegistrarOf<T>>(scid);
    }
    let payload = bytes.into().slice(opened.payload);
    let at = arrival.at();
    let NodeKey::LogicalPath(path) = others.here() else {
        unreachable!("a logical path's lend carries its key")
    };
    let link_path = L::link_path_identifier(path, arrival.link().id());
    let protection = match (one_rtt, level) {
        (Some((generation, current, _)), _) => ReceivedProtection::OneRtt {
            key_generation: match generation {
                // invariant: a previous generation is kept only after a
                // promotion, which made the current one at least 1
                ReceiveGeneration::Previous => current - 1,
                ReceiveGeneration::Current => current,
                ReceiveGeneration::Next => current + 1,
            },
        },
        (None, EncryptionLevel::Initial) => ReceivedProtection::Initial,
        (None, EncryptionLevel::ZeroRtt) => ReceivedProtection::ZeroRtt,
        (None, EncryptionLevel::Handshake) => ReceivedProtection::Handshake,
        // invariant: the 1-RTT keys open a packet with one of their
        // generations, which `one_rtt` holds
        (None, EncryptionLevel::OneRtt) => unreachable!("1-RTT keys open with a generation"),
    };
    let facts = DispatchFacts::new(protection, at, link_path);
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
    match one_rtt {
        // taken only to change it
        Some((ReceiveGeneration::Current, current, lowest))
            if lowest.is_none_or(|lowest| number < lowest) =>
        {
            lineage
                .get_mut::<KeyPhaseNumbers, Ikp>()
                .received(current, number);
        }
        Some((ReceiveGeneration::Next, ..)) => {
            // a level that only receives, as the connection closes, has
            // nothing to derive with: the packet is processed all the same
            let promotion = lineage
                .get_mut::<OneRttKeys<T::Crypto, InstantOf<T>>, Io>()
                .promote_next();
            if let Some(promotion) = promotion {
                check_peer_update(lineage.get::<KeyPhaseNumbers, Ikp>(), promotion, number)
                    .map_err(|source| v1_error::<L, Ie>(ConnectionError::KeyUpdate { source }))?;
                if promotion.send_updated {
                    lineage.get_mut::<AeadUsage, Iu>().send_keys_updated();
                }
                lineage
                    .get_mut::<KeyPhaseNumbers, Ikp>()
                    .promoted(promotion.generation, number);
            }
        }
        Some((ReceiveGeneration::Current | ReceiveGeneration::Previous, ..)) | None => {}
    }

    let packet_facts =
        read_frames::<T, L, Ie, Hd, _>(payload, level, core::convert::identity, |_, run| {
            <L as FrameSetDispatch<T, L, Hd>>::dispatch(lineage, others, run, &facts)
                .map_err(PartsError)
        })?;

    let ecn = arrival.ecn();
    let max_ranges = *lineage.get::<MaxAckRanges, Im>();
    // a space does not go while its packets are dispatched
    let highest_numbered = if let Some(journals) = lineage
        .get_mut::<PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>, Ij>()
        .get_mut(space)
    {
        let (highest_numbered, run_below) =
            record_received(journals, admission, at, ecn, max_ranges);
        if let Some(obligation) = lineage.get_mut::<AckObligationsOf<T>, Ia>().get_mut(space) {
            owe_ack(obligation, number, at, ecn, &packet_facts, run_below);
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

/// Read the frames of `payload`, the plaintext of a packet protected at
/// `level` that this side received, and hand each to `handle` with its
/// kind, after checking that the packet may carry it; return what the
/// frames make of the packet. A connection error of reading or of the
/// check becomes the error with `into`.
///
/// # Errors
///
/// A frame that does not read or is not permitted, no frames at all, or an
/// error of `handle`; the frames after it are not read.
pub(super) fn read_frames<T, L, Ie, Hd, E>(
    payload: Bytes,
    level: EncryptionLevel,
    into: impl Fn(ConnectionErrorOf<L>) -> E,
    mut handle: impl FnMut(<L as FrameSet>::Kind, <L as FrameSet>::Run<Bytes>) -> Result<(), E>,
) -> Result<PacketFacts, E>
where
    T: Choices,
    L: LineagePartList<T> + FrameSetDispatch<T, L, Hd>,
    <L as ConnectionErrorsOf>::ConnectionErrors: CoprodInjector<ConnectionError, Ie>,
{
    let mut packet_facts = PacketFacts::default();
    for run in Frames::new(payload, PhantomData::<L>) {
        let run = run.map_err(|error| into(read_frame_error::<T, L, Ie, Hd>(error)))?;
        let kind = <L as FrameSet>::run_kind(&run);
        permitted(kind, level, <T::Side as Side>::ROLE).map_err(|source| {
            into(v1_error::<L, Ie>(ConnectionError::FrameNotPermitted {
                source,
            }))
        })?;
        packet_facts.note(kind);
        handle(kind, run)?;
    }
    if packet_facts.is_empty() {
        return Err(into(v1_error::<L, Ie>(ConnectionError::EmptyPacket {
            level,
        })));
    }
    Ok(packet_facts)
}

/// Record the packet that `admission` admitted, arrived at `at` with
/// `ecn`, in `journals`, which keep at most `max_ranges`; return whether
/// its number is higher than any recorded before, and the lowest number of
/// the run received just below it, which its ACK obligation takes.
pub(super) fn record_received<I: Copy>(
    journals: &mut ReceiveJournals<I>,
    admission: Admission,
    at: I,
    ecn: Option<EcnCodepoint>,
    max_ranges: MaxAckRanges,
) -> (bool, Option<PacketNumber>) {
    let number = admission.number();
    // compared before the packet is recorded, which makes it the largest
    let highest_numbered = journals
        .largest()
        .is_none_or(|(largest, _)| number > largest);
    let run_below = journals.received_run_below(number);
    journals.record(admission, at, ecn);
    journals.limit(max_ranges);
    (highest_numbered, run_below)
}

/// Tell `obligation` of the packet `number`, arrived at `at` with `ecn`,
/// whose frames made `packet_facts`, recorded after `run_below` as
/// [`record_received`] returned it.
pub(super) fn owe_ack<I: Copy, X: AckObligation<I>>(
    obligation: &mut X,
    number: PacketNumber,
    at: I,
    ecn: Option<EcnCodepoint>,
    packet_facts: &PacketFacts,
    run_below: Option<PacketNumber>,
) {
    obligation.record(
        number,
        at,
        packet_facts.is_ack_eliciting(),
        ecn == Some(EcnCodepoint::Ce),
        run_below,
    );
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
pub(super) enum LevelReceiveKeys<K> {
    /// The keys to read the level's packets with.
    Ready(K),
    /// The handshake has not produced them yet; the packet waits.
    NotYet,
    /// None are to come.
    Gone,
}

/// The keys a level's packets are read with.
pub(super) enum ReceiveKeys<'k, B: CryptoBackend, I> {
    /// Those of Initial or Handshake.
    Level(&'k DirectionKeys<B>),
    /// The generations of 1-RTT.
    OneRtt(&'k OneRttReceiveKeys<B, I>),
}

/// The receive keys of `level`.
///
/// A server's 1-RTT level that has only its sending half has not come for
/// receiving: a 1-RTT packet is not read before the handshake completes
/// (RFC 9001 §5.7).
pub(super) fn receive_keys<'k, T, L, Ii, Ih, Io>(
    lineage: &'k LineageOf<'_, T, L, LogicalPath>,
    level: EncryptionLevel,
) -> LevelReceiveKeys<ReceiveKeys<'k, T::Crypto, InstantOf<T>>>
where
    T: Choices,
    L: LineagePartList<T>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>,
{
    let level_keys = |keys: Option<_>| {
        keys.map_or(LevelReceiveKeys::Gone, |keys| {
            LevelReceiveKeys::Ready(ReceiveKeys::Level(keys))
        })
    };
    match level {
        EncryptionLevel::Initial => {
            level_keys(lineage.get::<InitialKeys<T::Crypto>, Ii>().receive())
        }
        // the connection reads no 0-RTT yet; a server may drop it (RFC 9001
        // §4.6.1)
        EncryptionLevel::ZeroRtt => LevelReceiveKeys::Gone,
        EncryptionLevel::Handshake => match lineage.get::<HandshakeKeys<T::Crypto>, Ih>() {
            HandshakeKeys::NotYet => LevelReceiveKeys::NotYet,
            keys => level_keys(keys.receive()),
        },
        EncryptionLevel::OneRtt => match one_rtt_receive_keys::<T, L, Io>(lineage) {
            LevelReceiveKeys::Ready(keys) => LevelReceiveKeys::Ready(ReceiveKeys::OneRtt(keys)),
            LevelReceiveKeys::NotYet => LevelReceiveKeys::NotYet,
            LevelReceiveKeys::Gone => LevelReceiveKeys::Gone,
        },
    }
}

/// The receive keys of 1-RTT; as [`receive_keys`] says, a server's level
/// with only its sending half has not come for receiving.
pub(super) fn one_rtt_receive_keys<'k, T, L, Io>(
    lineage: &'k LineageOf<'_, T, L, LogicalPath>,
) -> LevelReceiveKeys<&'k OneRttReceiveKeys<T::Crypto, InstantOf<T>>>
where
    T: Choices,
    L: LineagePartList<T>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>,
{
    match lineage.get::<OneRttKeys<T::Crypto, InstantOf<T>>, Io>() {
        OneRttKeys::NotYet | OneRttKeys::SendOnly(..) => LevelReceiveKeys::NotYet,
        keys => keys
            .receive()
            .map_or(LevelReceiveKeys::Gone, LevelReceiveKeys::Ready),
    }
}

/// The packet number space of the packets of `level`.
pub(super) fn space_of(level: EncryptionLevel) -> PacketNumberSpaceKind {
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
pub(super) fn packet_number_offset<P>(packet: &ProtectedPacket<P>) -> Option<usize> {
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
pub(super) struct Opened {
    /// The packet number.
    pub(super) number: PacketNumber,
    /// The first byte, unprotected.
    pub(super) first_byte: u8,
    /// Where the plaintext payload lies in the packet.
    pub(super) payload: Range<usize>,
}

/// Which receiving generation of the 1-RTT keys opened a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReceiveGeneration {
    /// The one before the current generation: the packet was delayed.
    Previous,
    /// The current generation.
    Current,
    /// The one after the current generation: the peer updated its keys.
    Next,
}

/// Remove header protection and the AEAD from `packet` in place, with the
/// Packet Number field at `pn_offset`, decoding the packet number against
/// `largest`, the largest one processed in its space.
pub(super) fn open<B: CryptoBackend>(
    keys: &DirectionKeys<B>,
    packet: &mut [u8],
    pn_offset: usize,
    largest: Option<PacketNumber>,
) -> Result<Opened, DropReason> {
    let header = remove_header(&keys.header, packet, pn_offset, largest)?;
    open_payload(&keys.packet, packet, &header)
}

/// Remove header protection and the AEAD from the 1-RTT `packet` in place,
/// as [`open`] does, with the one receiving generation its Key Phase and
/// packet number select (RFC 9001 §6.5): the current one for the current
/// Key Phase; for the other, the previous one when it is kept and the
/// packet number is lower than `lowest`, the lowest one this logical path
/// received with the current generation, or `lowest` is `None`; the next
/// one otherwise. The payload is opened once, with that generation only, as
/// the [`key_phase`](super::key_phase) module says.
///
/// # Errors
///
/// The packet does not open with the selected generation.
pub(super) fn open_one_rtt<B: CryptoBackend, I: Copy>(
    keys: &OneRttReceiveKeys<B, I>,
    lowest: Option<PacketNumber>,
    packet: &mut [u8],
    pn_offset: usize,
    largest: Option<PacketNumber>,
) -> Result<(Opened, ReceiveGeneration), DropReason> {
    let header = remove_header(keys.header(), packet, pn_offset, largest)?;
    let number = header.number;
    let key_phase = if packet[0] & KEY_PHASE_BIT == 0 {
        KeyPhase::Zero
    } else {
        KeyPhase::One
    };
    let (packet_key, generation) = if key_phase == keys.current().key_phase() {
        (keys.current().packet(), ReceiveGeneration::Current)
    } else {
        match keys.previous() {
            // "lower than any" holds when there is none
            Some(previous) if lowest.is_none_or(|lowest| number < lowest) => {
                (previous, ReceiveGeneration::Previous)
            }
            // the peer updated; or the previous generation is discarded,
            // and the next one fails authentication
            _ => (keys.next().packet(), ReceiveGeneration::Next),
        }
    };
    open_payload(packet_key, packet, &header).map(|opened| (opened, generation))
}

/// The Key Phase bit of the unprotected first byte of a short header (RFC
/// 9000 §17.3.1).
const KEY_PHASE_BIT: u8 = 0x04;

/// A packet with header protection removed.
struct Unprotected {
    /// The packet number.
    number: PacketNumber,
    /// The length of the header, up to the end of the Packet Number field.
    len: usize,
}

/// Remove header protection from `packet` in place with `header`, as
/// [`open`] says.
fn remove_header<B: CryptoBackend>(
    header: &HeaderProtectionKey<B>,
    packet: &mut [u8],
    pn_offset: usize,
    largest: Option<PacketNumber>,
) -> Result<Unprotected, DropReason> {
    let truncated = header
        .remove(packet, pn_offset)
        .map_err(|source| DropReason::HeaderProtectionNotRemoved { source })?;
    Ok(Unprotected {
        number: truncated.decode(largest),
        len: pn_offset + truncated.encoded_len().get(),
    })
}

/// Remove the AEAD from `packet`, whose header protection is removed, in
/// place with `key`.
fn open_payload<B: CryptoBackend>(
    key: &PacketKey<B>,
    packet: &mut [u8],
    header: &Unprotected,
) -> Result<Opened, DropReason> {
    let payload_len = key
        .open(header.number, packet, header.len)
        .map_err(|source| DropReason::PayloadNotOpened { source })?
        .len();
    Ok(Opened {
        number: header.number,
        first_byte: packet[0],
        payload: header.len..header.len + payload_len,
    })
}

/// Whether the packet dropped for `reason` failed authentication, which
/// counts toward the integrity limit (RFC 9001 §6.6).
fn fails_authentication(reason: &DropReason) -> bool {
    matches!(
        reason,
        DropReason::PayloadNotOpened {
            source: OpenPacketError::Authentication { .. }
        }
    )
}

/// Whether a reserved bit of the unprotected first byte of a packet of
/// `level` is set: `0x0c` of a long header, `0x18` of a short header, the
/// header of 1-RTT packets.
pub(super) fn reserved_bits_set(level: EncryptionLevel, first_byte: u8) -> bool {
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
    facts: &DispatchFacts<InstantOf<T>, LinkPathIdentifierOf<T, L>>,
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
pub(super) fn v1_error<L, Ie>(error: ConnectionError) -> ConnectionErrorOf<L>
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
    use core::time::Duration;

    use sakuya_packet_protection::{
        backend::{AeadAlgorithm, KdfAlgorithm, ring::RingBackend},
        initial::{INITIAL_AEAD, InitialSecrets},
        packet_number::{PacketNumberLength, TruncatedPacketNumber},
        secret::TrafficSecret,
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
        sealed_with(&keys.packet, &keys.header, first_byte, number, payload)
    }

    /// The packet [`sealed`] makes, protected with `packet` and `header`.
    fn sealed_with(
        packet_key: &PacketKey<RingBackend>,
        header: &HeaderProtectionKey<RingBackend>,
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
        packet_key.seal(number, &mut packet, 4).unwrap();
        header.apply(&mut packet, 2).unwrap();
        packet
    }

    /// 1-RTT keys whose receiving generation 1 is current, generation 0
    /// previous.
    fn promoted() -> OneRttKeys<RingBackend, Duration> {
        let secret = |byte| TrafficSecret::new(KdfAlgorithm::HkdfSha256, &[byte; 32]).unwrap();
        let mut keys = OneRttKeys::NotYet;
        keys.install(RingBackend, AeadAlgorithm::Aes128Gcm, secret(1), secret(2));
        keys.promote_next().unwrap();
        keys
    }

    fn pn(number: u64) -> PacketNumber {
        PacketNumber::new(number).unwrap()
    }

    #[test]
    fn the_key_phase_and_the_packet_number_select_the_generation() {
        let keys = promoted();
        let receive = keys.receive().unwrap();
        let previous = receive.previous().unwrap();
        // generation 1 has Key Phase 1, generations 0 and 2 have 0
        let current = sealed_with(
            receive.current().packet(),
            receive.header(),
            0x44,
            7,
            &[1; 20],
        );
        let next = sealed_with(receive.next().packet(), receive.header(), 0x40, 9, &[1; 20]);
        let old = |number| sealed_with(previous, receive.header(), 0x40, number, &[1; 20]);
        let open = |mut packet: Vec<u8>, lowest| {
            open_one_rtt(receive, lowest, &mut packet, 2, Some(pn(5)))
                .map(|(opened, generation)| (opened.number.get(), generation))
        };
        assert!(matches!(
            open(current, Some(pn(6))),
            Ok((7, ReceiveGeneration::Current))
        ));
        assert!(matches!(
            open(next, Some(pn(6))),
            Ok((9, ReceiveGeneration::Next))
        ));
        assert!(matches!(
            open(old(4), Some(pn(6))),
            Ok((4, ReceiveGeneration::Previous))
        ));
        // nothing received with the current generation is lower than any
        assert!(matches!(
            open(old(8), None),
            Ok((8, ReceiveGeneration::Previous))
        ));
        // old keys after newer ones are tried with the next generation only
        assert!(matches!(
            open(old(8), Some(pn(6))),
            Err(DropReason::PayloadNotOpened {
                source: OpenPacketError::Authentication { .. }
            })
        ));
        let mut forged = old(4);
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert!(matches!(
            open(forged, Some(pn(6))),
            Err(DropReason::PayloadNotOpened {
                source: OpenPacketError::Authentication { .. }
            })
        ));
    }

    #[test]
    fn a_discarded_previous_generation_leaves_the_next_one() {
        let mut keys = promoted();
        let old = {
            let receive = keys.receive().unwrap();
            sealed_with(
                receive.previous().unwrap(),
                receive.header(),
                0x40,
                4,
                &[1; 20],
            )
        };
        keys.discard_previous();
        let receive = keys.receive().unwrap();
        let mut packet = old;
        assert!(matches!(
            open_one_rtt(receive, Some(pn(6)), &mut packet, 2, Some(pn(5))),
            Err(DropReason::PayloadNotOpened {
                source: OpenPacketError::Authentication { .. }
            })
        ));
    }

    #[test]
    fn numbers_of_an_older_generation_select_the_previous_one() {
        let keys = promoted();
        let receive = keys.receive().unwrap();
        let current = receive.current().generation();
        // this logical path received packet 3 with generation 0, then
        // another one promoted generation 1
        let mut numbers = KeyPhaseNumbers::new();
        numbers.received(current - 1, pn(3));
        let lowest = numbers.lowest_received(current);
        assert_eq!(lowest, None);
        let mut packet = sealed_with(
            receive.previous().unwrap(),
            receive.header(),
            0x40,
            8,
            &[1; 20],
        );
        assert!(matches!(
            open_one_rtt(receive, lowest, &mut packet, 2, Some(pn(5))),
            Ok((opened, ReceiveGeneration::Previous)) if opened.number == pn(8)
        ));
        // the first packet of generation 1 starts its numbers afresh
        numbers.received(current, pn(9));
        assert_eq!(numbers.lowest_received(current), Some(pn(9)));
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
