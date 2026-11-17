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
//! | PATH_CHALLENGE | the link path the packet arrived on: it keeps the data, to answer with a PATH_RESPONSE ([`path_response`](super::path_response)) |
//! | PATH_RESPONSE | none: this side sends no PATH_CHALLENGE yet, and a response that matches none is ignored |
//! | CRYPTO | [`CryptoReceiver`], at the level of the packet |
//! | NEW_TOKEN | the data only this side has ([`Side::on_new_token`]): a client hands the token over |
//! | HANDSHAKE_DONE | [`HandshakeConfirmation`]: the handshake is confirmed |
//! | CONNECTION_CLOSE | the [`CloseReasonRecord`], with the peer's close; every link path drains |
//! | NEW_CONNECTION_ID | the destination connection ID strategy of the logical path ([`ConnectionIds`](super::connection_ids::ConnectionIds)) |
//! | RETIRE_CONNECTION_ID | the local connection ID strategy of the logical path, with the Destination Connection ID of the packet, its arrival and the current probe timeout |
//! | ACK | the send journals of its space, the recovery layers of the logical path's link paths, and the parts the summaries of the packets settled go back to ([`ack`](super::ack)) |
//! | STREAM, RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED | the [`StreamSet`] of the established layer, with the handle of the send strategy's intake the connection node keeps; a STREAM frame with the level of its packet |
//!
//! A frame of streams or flow control that arrives without an established
//! layer is ignored while the connection closes, and does not arrive
//! otherwise ([`ConnectionError::NoEstablishedLayer`]).

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
    Choices, CloseCauseOf, LinkPathRoleReads, Part, Side,
    ack::{AckReads, AckRecoveryTakes, receive_ack},
    close::CloseReasonRecord,
    confirmation::HandshakeConfirmation,
    connection_ids::LineageConnectionIdEvents,
    crypto::CryptoReceiver,
    current_probe_timeout,
    error::{self, ConnectionError, V1ConnectionErrorOf},
    feedback::CoreLentFeedback,
    key_phase::KeyPhaseNumbers,
    keys::OneRttKeys,
    link::LinkClone,
    path_response::PendingPathResponse,
    recovery::{CongestionPartOf, OthersOf, RecoveryFactoryOf, RttOf},
    send::SendTypes,
    send_planning::{IntakeOf, IntakePublishOutcome, SendStrategyIntake, SendStrategyOf},
    spaces::SendJournalsOf,
    streams::{
        StreamSet, StreamSetFrameErrorOf, StreamsOf,
        resets::StreamResetsOfParts,
        send::{StreamIntent, StreamIntentHandle, StreamIntentHandleOf, StreamIntentTicketOf},
    },
};
use crate::role::LinkPathRole;
use crate::v1::{CryptoReceiveBufferOf, SendParametersOf};
use crate::{
    call::CallBundle,
    clock::{CheckedAdd, InstantOf},
    component::LineageOf,
    connection_id::NewConnectionId,
    dispatch::{DispatchFacts, FrameDispatch},
    error::ConnectionErrorsOf,
    feedback::FeedbackSummariesOf,
    frame_source::{EstablishedSourceComponentsOf, EstablishedSourceComponentsOfParts},
    layer::{self, LogicalPath, NodeKey},
    others::OtherNodes,
    send_strategy::{
        AnyActiveLinkPath, IntentTicketResize, IntentTicketWithdraw, SendIntentIntake,
        SendStrategy, SendStrategyTypes, SharedPublishTo,
    },
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
/// An ACK frame is received as [`receive_ack`] says. RETIRE_CONNECTION_ID
/// gives the local connection ID strategy the current probe timeout,
/// measured as a closing link path measures it.
impl<
    T: Choices,
    L,
    Ic,
    Ir,
    Ih,
    Icid,
    Iw,
    Ipr,
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
    Ies,
    Is,
    Ii,
    Idx,
>
    FrameDispatch<
        T,
        L,
        (
            (Ic, Ir, Ih, Icid, Iw, Ipr),
            (Iv, Ima, Irt),
            (Il, Is, Ii, Idx),
            (
                (Ij, In, If, Ird, Io, Ikp),
                (Ide, Ipp),
                (Ile, Ik),
                (Jx, Jr),
                Hf,
                Ies,
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
    for<'x> <L as LineageLists<'x, T>>::LogicalPath:
        CoreLentFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Ile>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, AckRecoveryTakes<T, L, S, Ls>, Ik>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Jx> + Selector<&'a RttOf<T, L>, Jr>,
    for<'v> <L as LineageLists<'v, T>>::LogicalPath: GetAt<CryptoReceiver<CryptoReceiveBufferOf<T>>, Ic>
        + LineageConnectionIdEvents<T, L, Icid>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<HandshakeConfirmation, Ih>
        + GetAt<<T::Side as Side>::Own, Iw>
        + ReadEach<LinkPathRoleReads<T, L>, Iv>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![PendingPathResponse], Ipr>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Irt>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
    SendTypes<T, L>: SendStrategyTypes
        + IntakePublishOutcome<StreamIntent<SendParametersOf<T>>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    StreamsOf<T, L>: StreamSet<
            CloseCauseOf<T, L>,
            StreamIntentTicketOf<T, L>,
            StreamResetsOfParts<L>,
            SendParameters = SendParametersOf<T>,
        > + 'static,
    StreamIntentTicketOf<T, L>: IntentTicketResize + IntentTicketWithdraw,
    IntakeOf<T, L>: SendIntentIntake<AnyActiveLinkPath>
        + SharedPublishTo<StreamIntent<SendParametersOf<T>>, AnyActiveLinkPath, Idx>,
    StreamIntentHandleOf<T, L, Idx>:
        StreamIntentHandle<SendParametersOf<T>, StreamIntentTicketOf<T, L>>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<SendStrategyIntake<IntakeOf<T, L>>, Ii>,
    L: EstablishedSourceComponentsOf<T, L>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out: TakeEach<'s, HList![StreamsOf<T, L>], Is>
        + TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Ies>,
{
    fn dispatch<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, L, LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        run: FrameRun<Bytes>,
        packet: &DispatchFacts<InstantOf<T>, LinkPathIdentifierOf<T, L>>,
    ) -> Result<(), V1ConnectionErrorOf<L>> {
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
                Ies,
            >(lineage, others, &frame, packet),
            FrameRun::Padding(_) | FrameRun::Ping(_) => Ok(()),
            // this side sends no PATH_CHALLENGE yet, so no response matches
            // one; a response that matches none may be ignored (RFC 9000
            // §19.18, MAY close)
            FrameRun::PathResponse(_) => Ok(()),
            FrameRun::PathChallenge(frame) => {
                let NodeKey::LogicalPath(path) = others.here().clone() else {
                    unreachable!("a logical path's lend carries its key")
                };
                others.each_link_path::<HList![PendingPathResponse], Ipr>(
                    |key, hlist_pat![pending]| {
                        let NodeKey::LinkPath(each, link) = key else {
                            return;
                        };
                        if *each == path
                            && L::link_path_identifier(each, link) == *packet.link_path()
                        {
                            pending.challenged(frame.data());
                        }
                    },
                );
                Ok(())
            }
            FrameRun::Crypto(frame) => {
                let level = crypto_level(packet.level())?;
                let offset = frame.offset().into_inner();
                lineage
                    .get_mut::<CryptoReceiver<CryptoReceiveBufferOf<T>>, Ic>()
                    .receive_frame(level, offset, frame.into_data())
                    .context(error::CryptoSnafu)
            }
            FrameRun::NewConnectionId(frame) => {
                LineageConnectionIdEvents::<T, L, Icid>::new_connection_id(
                    lineage,
                    NewConnectionId::from(&frame),
                )
                .context(error::NewConnectionIdSnafu)
            }
            FrameRun::RetireConnectionId(frame) => {
                let hlist_pat![peer, thresholds, idle] =
                    (*lineage).read_each::<LinkPathRoleReads<T, L>, Iv>();
                let pto = current_probe_timeout::<T, L, B, Ima, Irt>(peer, thresholds, others)
                    // with no recovery layer, the last one the idle timeout took
                    .unwrap_or_else(|| idle.probe_timeout());
                LineageConnectionIdEvents::<T, L, Icid>::retired_by_peer(
                    lineage,
                    frame.sequence_number().get().get(),
                    packet.destination(),
                    packet.at(),
                    pto,
                )
                .context(error::RetireConnectionIdSnafu)
            }
            FrameRun::NewToken(frame) => {
                <T::Side as Side>::on_new_token(
                    lineage.get_mut::<<T::Side as Side>::Own, Iw>(),
                    frame.into_token(),
                );
                Ok(())
            }
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
            FrameRun::Stream(frame) => {
                let level = packet.level();
                to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                    lineage,
                    others,
                    frame.type_value(),
                    |streams, publish| streams.on_stream_frame(publish, level, frame),
                )
            }
            FrameRun::ResetStream(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_reset_stream(publish, frame),
            ),
            FrameRun::StopSending(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_stop_sending(publish, frame),
            ),
            FrameRun::MaxData(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_max_data(publish, frame),
            ),
            FrameRun::MaxStreamData(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_max_stream_data(publish, frame),
            ),
            FrameRun::MaxStreams(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_max_streams(publish, frame),
            ),
            FrameRun::DataBlocked(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_data_blocked(publish, frame),
            ),
            FrameRun::StreamDataBlocked(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_stream_data_blocked(publish, frame),
            ),
            FrameRun::StreamsBlocked(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_streams_blocked(publish, frame),
            ),
        }
    }

    fn fields_error(error: ReadFieldsError<Infallible>) -> V1ConnectionErrorOf<L> {
        ConnectionError::ReadFrameFields { source: error }
    }
}

/// Hand a frame of streams or flow control, whose Frame Type is
/// `type_value`, to the stream set of the established layer with `handle`,
/// which publishes through the handle of the strategy's intake that the
/// connection node keeps.
///
/// Without an established layer the frame is ignored once the record of why
/// the connection closed is written: the layer ended as the connection
/// closes. Otherwise there is always one (a server builds it once its
/// ServerHello is written, a client before it can open 1-RTT packets, and no
/// 0-RTT packet is taken); a release build closes with INTERNAL_ERROR if
/// there is not.
fn to_streams<'v, T, L, B, Ir, Is, Ii, Idx>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    type_value: VarInt,
    handle: impl FnOnce(
        &mut StreamsOf<T, L>,
        &StreamIntentHandleOf<T, L, Idx>,
    ) -> Result<(), StreamSetFrameErrorOf<StreamResetsOfParts<L>>>,
) -> Result<(), V1ConnectionErrorOf<L>>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    B: CallBundle,
    SendTypes<T, L>: SendStrategyTypes
        + IntakePublishOutcome<StreamIntent<SendParametersOf<T>>, AnyActiveLinkPath>,
    SendStrategyOf<T, L>: SendStrategy<SendTypes<T, L>>,
    StreamsOf<T, L>: 'static,
    IntakeOf<T, L>: SendIntentIntake<AnyActiveLinkPath>
        + SharedPublishTo<StreamIntent<SendParametersOf<T>>, AnyActiveLinkPath, Idx>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<SendStrategyIntake<IntakeOf<T, L>>, Ii>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![StreamsOf<T, L>], Is>,
{
    let Some(hlist_pat![streams]) = others.borrow_established::<HList![StreamsOf<T, L>], Is>()
    else {
        if lineage
            .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
            .is_written()
        {
            return Ok(());
        }
        debug_assert!(
            false,
            "a frame of streams arrived without an established layer"
        );
        return error::NoEstablishedLayerSnafu {
            frame_type: frame_type_value(type_value),
        }
        .fail();
    };
    let publish = lineage
        .get::<SendStrategyIntake<IntakeOf<T, L>>, Ii>()
        .intake()
        .handle::<StreamIntent<SendParametersOf<T>>, Idx>();
    handle(streams, &publish).with_context(|_| error::StreamSetSnafu {
        frame_type: frame_type_value(type_value),
    })
}

/// The Frame Type value of a frame of version 1, with its kind.
fn frame_type_value(type_value: VarInt) -> FrameTypeValue {
    // invariant: a frame of version 1 has a Frame Type value RFC 9000
    // defines
    FrameTypeValue::of(type_value).expect("a frame of version 1 has a type of version 1")
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
pub(super) fn crypto_level<R>(level: EncryptionLevel) -> Result<CryptoLevel, ConnectionError<R>> {
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
