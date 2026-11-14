//! How version 1 dispatches the frames it reads, and which frames a packet
//! may carry.
//!
//! Version 1 is the part of the frame set that RFC 9000 defines; the
//! connection's [`Part`] reads its frames as the wire format's part does.
//! Before a run is dispatched, [`permitted`] checks its kind against the
//! packet type and this endpoint's role, from the kind alone; checks that
//! need state are made where the frame is handled.
//!
//! A frame of version 1 goes to the component it concerns:
//!
//! | Frame | Component |
//! | --- | --- |
//! | PADDING, PING | none: they only make a packet ack-eliciting or not |
//! | CRYPTO | [`CryptoReceiver`], at the level of the packet |
//! | HANDSHAKE_DONE | [`HandshakeConfirmation`]: the handshake is confirmed |
//! | CONNECTION_CLOSE | the [`CloseReasonRecord`], with the peer's close; every link path drains |
//! | NEW_CONNECTION_ID | the destination connection ID strategy of the logical path ([`ConnectionIds`](super::connection_ids::ConnectionIds)) |
//! | ACK | the send journals of its space, the recovery layers of the logical path's link paths, and the parts the summaries of the packets settled go back to ([`ack`](super::ack)) |
//!
//! The components of the other frames are not in the connection yet; such a
//! frame ends the connection with INTERNAL_ERROR
//! ([`ConnectionError::UnhandledFrame`]).
use core::convert::Infallible;

use bytes::{Buf, Bytes};
use frunk_core::hlist_pat;
use nitori_call::{Direct, Receiver};
use nitori_io::{Read, ReadChunk};
use sakuya_stream::connection::{
    ApplicationImmediateClose, CloseReason, ImmediateClose, TransportImmediateClose,
};
use sakuya_tls::engine::CryptoLevel;
use sakuya_wire::{
    parameters::ParametersOf,
    parts::{HList, Selector},
    v1::{
        encryption_level::EncryptionLevel,
        frame::{
            FrameRun, FrameType, FrameTypeValue,
            codec::ReadFieldsError,
            connection_close::{CloseErrorCode, ConnectionCloseFrame},
            set::{FrameKind, FrameSetPart, FrameTypeValues},
        },
        role::Role,
        transport_parameters::{
            TransportParameterSlots, TransportParameterSpace,
            integer::{AckDelayExponent, MaxAckDelay, MaxUdpPayloadSize},
        },
    },
    var_int::VarInt,
};
use snafu::{ResultExt, Snafu, ensure};

use super::{
    Choices, CloseCauseOf, LinkPathRoleReads, Part,
    ack::{AckReads, AckRecoveryTakes, receive_ack},
    close::CloseReasonRecord,
    confirmation::HandshakeConfirmation,
    connection_ids::ConnectionIdsOf,
    crypto::CryptoReceiver,
    current_probe_timeout,
    error::{self, ConnectionError},
    key_phase::KeyPhaseNumbers,
    keys::OneRttKeys,
    link::LinkClone,
    recovery::{CongestionPartOf, OthersOf, RecoveryFactoryOf, RttOf},
    role::LinkPathRole,
    spaces::SendJournalsOf,
};
use crate::{
    call::CallBundle,
    clock::{CheckedAdd, InstantOf},
    component::LineageOf,
    connection_id::{DestinationConnectionIdStrategy, NewConnectionId},
    dispatch::{DispatchFacts, FrameDispatch},
    error::ConnectionErrorsOf,
    feedback::{FeedbackSummariesOf, PartsSendFeedback},
    layer::{self, LogicalPath},
    others::OtherNodes,
    share::{FlatMut, FlatRef, LineageLists, LineagePartList, LinkPathIdentifierOf, NodeData},
    take::{GetAt, ReadEach, TakeEach},
};
use sakuya_recovery::{
    factory::{LendCongestion, RecoveryFactory},
    packet_number_space::{PacketNumberSpaceState, PacketNumberSpaces},
};

/// Version 1 reads its frames as the wire format's version 1 part.
impl FrameSetPart for Part {
    type Run<D> = FrameRun<D>;
    type Kind = FrameType;
    type TypeValue = FrameTypeValue;
    type FieldsError<E> = ReadFieldsError<E>;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues =
        <sakuya_wire::v1::Part as FrameSetPart>::FRAME_TYPE_VALUES;

    fn type_value_of(value: VarInt) -> Option<FrameTypeValue> {
        <sakuya_wire::v1::Part as FrameSetPart>::type_value_of(value)
    }

    fn kind_of(type_value: FrameTypeValue) -> FrameType {
        <sakuya_wire::v1::Part as FrameSetPart>::kind_of(type_value)
    }

    fn run_kind<D>(run: &FrameRun<D>) -> FrameType {
        <sakuya_wire::v1::Part as FrameSetPart>::run_kind(run)
    }

    fn read_run<H>(
        source: &mut H,
        type_value: FrameTypeValue,
    ) -> Result<
        FrameRun<<Direct<H> as ReadChunk>::Chunk>,
        ReadFieldsError<<Direct<H> as Read>::Error>,
    >
    where
        H: Buf + Receiver<Family = Direct<H>> + Unpin,
        Direct<H>: ReadChunk<Chunk: Default>,
    {
        <sakuya_wire::v1::Part as FrameSetPart>::read_run(source, type_value)
    }
}

/// Whether a frame of `kind` may be in a packet protected at `level` that
/// an endpoint of `role` received.
///
/// The kind answers both for the part that defines it ([`FrameKind`]), so
/// the check knows no extension.
///
/// # Errors
///
/// The rule the frame breaks; either is a PROTOCOL_VIOLATION.
pub fn permitted<K: FrameKind>(
    kind: K,
    level: EncryptionLevel,
    role: Role,
) -> Result<(), FrameNotPermittedError> {
    ensure!(kind.can_appear_in(level), NotAtLevelSnafu { level });
    ensure!(kind.receivable_by(role), NotForRoleSnafu { role });
    Ok(())
}

/// A frame that a packet cannot carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
pub enum FrameNotPermittedError {
    /// The frame cannot appear in a packet of this level (RFC 9000 §12.4,
    /// Table 3).
    #[snafu(display("frame not permitted in a {level:?} packet"))]
    NotAtLevel {
        /// The level of the packet.
        level: EncryptionLevel,
    },
    /// An endpoint of this role does not receive the frame: a server
    /// receives no NEW_TOKEN and no HANDSHAKE_DONE (RFC 9000 §19.7,
    /// §19.20).
    #[snafu(display("frame not received by a {role:?}"))]
    NotForRole {
        /// The role of the endpoint.
        role: Role,
    },
}

/// The frames of version 1 go to the components of version 1.
///
/// CONNECTION_CLOSE writes the peer's close into the record, unless a reason
/// is already there, and puts every link path into `Draining`, for three
/// times the current probe timeout (RFC 9000 §10.2.2), measured as a
/// closing link path measures it; a link path that was closing keeps its end.
/// An ACK frame is received as [`receive_ack`] says.
impl<
    T: Choices,
    L,
    Ic,
    Ir,
    Ih,
    Icid,
    Iv,
    Ima,
    Irt,
    Il,
    S,
    Ls,
    Ij,
    In,
    If,
    Ird,
    Io,
    Ikp,
    Ide,
    Ipp,
    Ile,
    Ik,
    Jx,
    Jr,
    Hf,
>
    FrameDispatch<
        T,
        L,
        (
            (Ic, Ir, Ih, Icid),
            (Iv, Ima, Irt),
            Il,
            (
                (Ij, In, If, Ird, Io, Ikp),
                (Ide, Ipp),
                (Ile, Ik),
                (Jx, Jr),
                Hf,
            ),
        ),
    > for Part
where
    L: LineagePartList<T>,
    L: ParametersOf<TransportParameterSpace> + ConnectionErrorsOf + FeedbackSummariesOf,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>
        + Selector<Option<AckDelayExponent>, Ide>
        + Selector<Option<MaxUdpPayloadSize>, Ipp>,
    S: 'static,
    Ls: Clone + 'static,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>
        + for<'s> LendCongestion<
            InstantOf<T>,
            OthersOf<'s, T, L>,
            Part = CongestionPartOf<T, L>,
            SentState = S,
            LossState = Ls,
        >,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<PacketNumberSpaces<PacketNumberSpaceState>, In>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + ReadEach<AckReads<L>, Ird>
        + GetAt<OneRttKeys<T::Crypto, InstantOf<T>>, Io>
        + GetAt<KeyPhaseNumbers, Ikp>,
    for<'x> L: PartsSendFeedback<T, L, <L as LineageLists<'x, T>>::LogicalPath, Hf>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Ile>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, AckRecoveryTakes<T, L, S, Ls>, Ik>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Jx> + Selector<&'a RttOf<T, L>, Jr>,
    for<'v> <L as LineageLists<'v, T>>::LogicalPath: GetAt<CryptoReceiver<T::CryptoReceiveBuffer>, Ic>
        + GetAt<ConnectionIdsOf<T>, Icid>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<HandshakeConfirmation, Ih>
        + ReadEach<LinkPathRoleReads<T, L>, Iv>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Irt>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
{
    fn dispatch<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, L, LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        run: FrameRun<Bytes>,
        packet: &DispatchFacts<InstantOf<T>, LinkPathIdentifierOf<T, L>>,
    ) -> Result<(), ConnectionError> {
        match run {
            FrameRun::Ack(frame) => receive_ack::<
                T,
                L,
                B,
                S,
                Ls,
                Ij,
                In,
                If,
                Ird,
                Io,
                Ikp,
                Ide,
                Ima,
                Ipp,
                Ile,
                Ik,
                Jx,
                Jr,
                Hf,
            >(lineage, others, &frame, packet),
            FrameRun::Padding(_) | FrameRun::Ping(_) => Ok(()),
            FrameRun::Crypto(frame) => {
                let level = crypto_level(packet.level())?;
                let offset = frame.offset().into_inner();
                lineage
                    .get_mut::<CryptoReceiver<T::CryptoReceiveBuffer>, Ic>()
                    .receive_frame(level, offset, frame.into_data())
                    .context(error::CryptoSnafu)
            }
            FrameRun::NewConnectionId(frame) => lineage
                .get_mut::<ConnectionIdsOf<T>, Icid>()
                .destination_mut()
                .on_new_connection_id(NewConnectionId::from(&frame))
                .context(error::NewConnectionIdSnafu),
            FrameRun::HandshakeDone(_) => {
                *lineage.get_mut::<HandshakeConfirmation, Ih>() = HandshakeConfirmation::Confirmed;
                Ok(())
            }
            FrameRun::ConnectionClose(frame) => {
                lineage
                    .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
                    .record(CloseReason::Peer(immediate_close(frame)));
                drain_link_paths::<T, L, B, Iv, Ima, Irt, Il>(lineage, others);
                Ok(())
            }
            other => error::UnhandledFrameSnafu {
                kind: other.frame_type(),
            }
            .fail(),
        }
    }

    fn fields_error(error: ReadFieldsError<Infallible>) -> ConnectionError {
        ConnectionError::ReadFrameFields { source: error }
    }
}

/// Put every link path of the connection into `Draining`, for three times
/// the current probe timeout (RFC 9000 §10.2.2), measured as a closing link
/// path measures it; a link path that was closing keeps its end.
///
/// Whoever finds that the connection drains calls it after writing the
/// reason into the record: the receiving of a CONNECTION_CLOSE frame and of
/// a stateless reset.
pub(super) fn drain_link_paths<'v, T, L, B, Iv, Ima, Irt, Il>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
) where
    T: Choices,
    L: LineagePartList<T> + ParametersOf<TransportParameterSpace>,
    B: CallBundle,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: ReadEach<LinkPathRoleReads<T, L>, Iv>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Irt>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
{
    let hlist_pat![peer, thresholds, idle] = (*lineage).read_each::<LinkPathRoleReads<T, L>, Iv>();
    let pto = current_probe_timeout::<T, L, B, Ima, Irt>(peer, thresholds, others)
        // with no recovery layer, the last one the idle timeout took
        .unwrap_or_else(|| idle.probe_timeout());
    let now = others.now();
    // an end beyond what the instant type represents is none: the draining
    // period is cut short rather than kept forever
    let end = now.checked_add(pto.saturating_mul(3)).unwrap_or(now);
    others.each_link_path::<HList![LinkPathRole<InstantOf<T>>], Il>(|_, hlist_pat![role]| {
        role.drain(end)
    });
}

/// The CRYPTO stream of `level`; a 0-RTT packet carries no CRYPTO frames
/// (RFC 9000 §12.4, Table 3).
pub(super) fn crypto_level(level: EncryptionLevel) -> Result<CryptoLevel, ConnectionError> {
    match level {
        EncryptionLevel::Initial => Ok(CryptoLevel::Initial),
        EncryptionLevel::Handshake => Ok(CryptoLevel::Handshake),
        EncryptionLevel::OneRtt => Ok(CryptoLevel::OneRtt),
        EncryptionLevel::ZeroRtt => Err(ConnectionError::FrameNotPermitted {
            source: FrameNotPermittedError::NotAtLevel { level },
        }),
    }
}

/// The peer's close as the frame carries it; a Frame Type field of 0 is no
/// frame type.
pub(super) fn immediate_close(frame: ConnectionCloseFrame<Bytes>) -> ImmediateClose {
    match frame.error_code() {
        CloseErrorCode::Transport { code, frame_type } => TransportImmediateClose {
            code: code.into_inner(),
            frame_type: Some(frame_type.into_inner()).filter(|value| value.get() != 0),
            reason_phrase: frame.into_reason_phrase(),
        }
        .into(),
        CloseErrorCode::Application { code } => ApplicationImmediateClose {
            code: code.into_inner(),
            reason_phrase: frame.into_reason_phrase(),
        }
        .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_is_not_permitted_in_zero_rtt() {
        assert_eq!(
            permitted(FrameType::Crypto, EncryptionLevel::ZeroRtt, Role::Server),
            Err(FrameNotPermittedError::NotAtLevel {
                level: EncryptionLevel::ZeroRtt
            })
        );
        assert_eq!(
            permitted(FrameType::Crypto, EncryptionLevel::Initial, Role::Server),
            Ok(())
        );
    }

    #[test]
    fn a_server_receives_no_handshake_done() {
        assert_eq!(
            permitted(
                FrameType::HandshakeDone,
                EncryptionLevel::OneRtt,
                Role::Server
            ),
            Err(FrameNotPermittedError::NotForRole { role: Role::Server })
        );
        assert_eq!(
            permitted(
                FrameType::HandshakeDone,
                EncryptionLevel::OneRtt,
                Role::Client
            ),
            Ok(())
        );
    }

    #[test]
    fn handshake_done_is_only_in_one_rtt_packets() {
        assert!(
            permitted(
                FrameType::HandshakeDone,
                EncryptionLevel::Handshake,
                Role::Client
            )
            .is_err()
        );
    }
}
