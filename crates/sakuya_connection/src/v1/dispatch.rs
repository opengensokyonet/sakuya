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
//! | PATH_RESPONSE | the link path that sent the PATH_CHALLENGE it echoes, whichever link path it arrives on ([`path_validation`](super::path_validation)): the address of its logical link is validated; a response that matches none is ignored |
//! | CRYPTO | [`CryptoReceiver`], at the level of the packet; a server that had all of an Initial frame's data asks the policy of the link path it arrived on whether to send its unacknowledged Initial CRYPTO data again at once (RFC 9002 §6.2.3) |
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

use bytes::{Buf, Bytes};
use frunk_core::hlist_pat;
use kasen_handshake::engine::CryptoLevel;
use nitori_io::SplitTo;
use sakuya_stream_sets::resets::StreamResetsOfParts;
use sakuya_stream_v1::connection::{
    ApplicationImmediateClose, CloseReason, ImmediateClose, TransportImmediateClose,
};
use sakuya_wire::parts::{HList, Selector};
use sakuya_wire_v1::{
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
};
use sakuya_wire_v1::{parameters::ParametersOf, var_int::VarInt};
use snafu::{ResultExt, Snafu, ensure};

use super::{
    Choices, CloseCauseOf, EventsOf, LinkPathRoleReads, Part, Side,
    ack::{AckReads, AckRecoveryTakes, receive_ack},
    amplification::{AddressValidation, AntiAmplification},
    close::CloseReasonRecord,
    component_events::{
        AmplificationCreditChanged, PathChallengePendingChanged, PathValidationConcluded,
    },
    confirmation::HandshakeConfirmation,
    connection_ids::LineageConnectionIdEvents,
    crypto::{CryptoReceiver, send::CryptoSender},
    current_probe_timeout,
    error::{self, ConnectionError, V1ConnectionErrorOf},
    events::{ConnectionEventSink, ConnectionEvents, ConnectionState},
    feedback::LineageFeedback,
    key_phase::KeyPhaseNumbers,
    keys::OneRttKeys,
    link::LinkClone,
    link::LinkFacts,
    path_response::PendingPathResponse,
    path_validation::PathValidationOf,
    recovery::{CongestionPartOf, OthersOf, RecoveryFactoryOf, RttOf, lend_congestion},
    send::SendTypes,
    send_planning::{
        ComponentPublishing, HostSendStrategyTypes, PublisherOf, SendStrategyPublisher,
        StrategyPublisherFor,
    },
    spaces::SendJournalsOf,
    streams::{StreamSet, StreamSetFrameErrorOf, StreamsOf, send::StreamIntent},
};
use crate::role::LinkPathRole;
use crate::v1::{CryptoReceiveBufferOf, CryptoSendBufferOf, SendParametersOf, StreamSetFamilyOf};
use crate::{
    call::CallBundle,
    clock::{CheckedAdd, InstantOf},
    component::LineageOf,
    component_event::Happened,
    connection_id::NewConnectionId,
    dispatch::{DispatchFacts, FrameDispatch},
    error::ConnectionErrorsOf,
    feedback::FeedbackSummariesOf,
    frame_source::{EstablishedSourceComponentsOf, EstablishedSourceComponentsOfParts},
    layer::{self, LogicalPath, NodeKey},
    others::OtherNodes,
    share::{FlatMut, FlatRef, LineageLists, LineagePartList, LinkPathIdentifierOf, NodeData},
    take::{GetAt, ReadEach, TakeEach},
};
use sakuya_recovery_v1::{
    factory::{LendCongestion, RecoveryFactory},
    packet_number_space::{PacketNumberSpaceState, PacketNumberSpaces},
    pto::PtoPolicy,
};

/// Version 1 reads its frames as the wire format's version 1 part.
impl FrameSetPart for Part {
    type Run<D> = FrameRun<D>;
    type Kind = FrameType;
    type TypeValue = FrameTypeValue;
    type FieldsError = ReadFieldsError;

    const FRAME_TYPE_VALUES: &'static FrameTypeValues =
        <sakuya_wire_v1::Part as FrameSetPart>::FRAME_TYPE_VALUES;

    fn type_value_of(value: VarInt) -> Option<FrameTypeValue> {
        <sakuya_wire_v1::Part as FrameSetPart>::type_value_of(value)
    }

    fn kind_of(type_value: FrameTypeValue) -> FrameType {
        <sakuya_wire_v1::Part as FrameSetPart>::kind_of(type_value)
    }

    fn run_kind<D>(run: &FrameRun<D>) -> FrameType {
        <sakuya_wire_v1::Part as FrameSetPart>::run_kind(run)
    }

    fn read_run<S: Buf + SplitTo>(
        source: &mut S,
        type_value: FrameTypeValue,
    ) -> Result<FrameRun<S>, ReadFieldsError> {
        <sakuya_wire_v1::Part as FrameSetPart>::read_run(source, type_value)
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
    Ipv,
    Ian,
    Ics,
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
    Iev,
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
            (Ic, Ir, Ih, Icid, Iw, (Ipr, Ipv, Ian), Ics),
            (Iv, Ima, Irt),
            (Il, Is, Ii, Idx),
            (
                (Ij, In, If, Ird, Io, Ikp, Iev),
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
        + GetAt<KeyPhaseNumbers, Ikp>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath:
        LineageFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Ile>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, AckRecoveryTakes<T, L, S, Ls>, Ik>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Jx> + Selector<&'a RttOf<T, L>, Jr>,
    for<'v> <L as LineageLists<'v, T>>::LogicalPath: GetAt<CryptoReceiver<CryptoReceiveBufferOf<T>>, Ic>
        + GetAt<CryptoSender<CryptoSendBufferOf<T>>, Ics>
        + LineageConnectionIdEvents<T, L, Icid>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<HandshakeConfirmation, Ih>
        + GetAt<<T::Side as Side>::Own, Iw>
        + ReadEach<LinkPathRoleReads<T, L>, Iv>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out: TakeEach<'s, HList![PendingPathResponse], Ipr>
        + TakeEach<'s, HList![PathValidationOf<T>], Ipv>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification, LinkFacts], Ian>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Irt>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    StreamsOf<T, L>: StreamSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
            SendParameters = SendParametersOf<T>,
        > + 'static,
    PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, Idx>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath:
        GetAt<SendStrategyPublisher<PublisherOf<T, L>>, Ii>,
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
                Iev,
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
            FrameRun::PathResponse(frame) => {
                receive_path_response::<T, L, B, Ipv, Ian>(others, frame.data(), packet);
                Ok(())
            }
            FrameRun::PathChallenge(frame) => {
                let NodeKey::LogicalPath(path) = others.here().clone() else {
                    unreachable!("a logical path's lend carries its key")
                };
                let mut challenged = Vec::new();
                others.each_link_path::<HList![PendingPathResponse], Ipr>(
                    |key, hlist_pat![mut pending]| {
                        let NodeKey::LinkPath(each, link) = key else {
                            return;
                        };
                        if *each == path
                            && L::link_path_identifier(each, link) == *packet.link_path()
                        {
                            challenged.push((key.clone(), pending.challenged(frame.data())));
                        }
                    },
                );
                for (key, happened) in challenged {
                    others.publish_at(&key, happened);
                }
                Ok(())
            }
            FrameRun::Crypto(frame) => {
                let level = crypto_level(packet.level())?;
                let offset = frame.offset().into_inner();
                // a server that receives Initial CRYPTO data it had all
                // received: its own Initial was likely lost (RFC 9002
                // §6.2.3)
                let duplicate = <T::Side as crate::v1::common_choices::CommonSide>::ROLE
                    == Role::Server
                    && level == CryptoLevel::Initial
                    && lineage
                        .get::<CryptoReceiver<CryptoReceiveBufferOf<T>>, Ic>()
                        .already_received(level, offset, frame.data().len());
                lineage
                    .get_mut::<CryptoReceiver<CryptoReceiveBufferOf<T>>, Ic>()
                    .receive_frame(level, offset, frame.into_data())
                    .context(error::CryptoSnafu)?;
                if duplicate {
                    duplicate_initial_crypto::<T, L, B, S, Ls, If, Ik, Jx, Jr, Ics>(
                        lineage, others, packet,
                    );
                }
                Ok(())
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
                    &mut *lineage.get_mut::<<T::Side as Side>::Own, Iw>(),
                    frame.into_token(),
                );
                Ok(())
            }
            FrameRun::HandshakeDone(_) => {
                let confirmed = lineage.get_mut::<HandshakeConfirmation, Ih>().confirm();
                let newly = confirmed.is_some();
                if let Some(confirmed) = confirmed {
                    lineage.publish(confirmed);
                }
                if <EventsOf<T, L> as ConnectionEvents<InstantOf<T>>>::ENABLED
                    && newly
                    && let Some(events) = lineage
                        .get_mut::<ConnectionEventSink<EventsOf<T, L>>, Iev>()
                        .active::<InstantOf<T>>()
                {
                    events.connection_state(packet.at(), ConnectionState::HandshakeConfirmed);
                }
                Ok(())
            }
            FrameRun::ConnectionClose(frame) => {
                let written = lineage
                    .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
                    .record(CloseReason::Peer(immediate_close(frame)));
                if let Some(written) = written {
                    lineage.publish(written);
                }
                drain_link_paths::<T, L, B, Iv, Ima, Irt, Il>(lineage, others);
                Ok(())
            }
            FrameRun::Stream(frame) => {
                let level = packet.level();
                to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                    lineage,
                    others,
                    frame.type_value(),
                    |streams, publish| streams.on_stream_frame::<Idx, _>(publish, level, frame),
                )
            }
            FrameRun::ResetStream(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_reset_stream::<Idx, _>(publish, frame),
            ),
            FrameRun::StopSending(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_stop_sending::<Idx, _>(publish, frame),
            ),
            FrameRun::MaxData(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_max_data::<Idx, _>(publish, frame),
            ),
            FrameRun::MaxStreamData(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_max_stream_data::<Idx, _>(publish, frame),
            ),
            FrameRun::MaxStreams(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_max_streams::<Idx, _>(publish, frame),
            ),
            FrameRun::DataBlocked(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_data_blocked::<Idx, _>(publish, frame),
            ),
            FrameRun::StreamDataBlocked(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_stream_data_blocked::<Idx, _>(publish, frame),
            ),
            FrameRun::StreamsBlocked(frame) => to_streams::<T, L, B, Ir, Is, Ii, Idx>(
                lineage,
                others,
                frame.type_value(),
                |streams, publish| streams.on_streams_blocked::<Idx, _>(publish, frame),
            ),
        }
    }

    fn fields_error(error: ReadFieldsError) -> V1ConnectionErrorOf<L> {
        ConnectionError::ReadFrameFields { source: error }
    }
}

/// Hand a frame of streams or flow control, whose Frame Type is
/// `type_value`, to the stream set of the established layer with `handle`,
/// lent the send strategy's publisher that the connection node keeps; what
/// the set did there is handed on at the connection afterwards.
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
        &mut PublisherOf<T, L>,
    ) -> Result<(), StreamSetFrameErrorOf<StreamResetsOfParts<L>>>,
) -> Result<(), V1ConnectionErrorOf<L>>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    B: CallBundle,
    SendTypes<T, L>: HostSendStrategyTypes,
    StreamSetFamilyOf<T>: ComponentPublishing<SendTypes<T, L>, StreamIntent<SendParametersOf<T>>>,
    StreamsOf<T, L>: 'static,
    PublisherOf<T, L>: StrategyPublisherFor<StreamIntent<SendParametersOf<T>>, Idx>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<SendStrategyPublisher<PublisherOf<T, L>>, Ii>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![StreamsOf<T, L>], Is>,
{
    let Some(hlist_pat![mut streams]) = others.borrow_established::<HList![StreamsOf<T, L>], Is>()
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
    let (handled, changed) = {
        let mut publisher = lineage.get_mut::<SendStrategyPublisher<PublisherOf<T, L>>, Ii>();
        let handled = handle(&mut *streams, publisher.publisher_mut());
        (handled, publisher.take_changed())
    };
    if let Some(changed) = changed {
        lineage.publish(changed);
    }
    handled.with_context(|_| error::StreamSetSnafu {
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
    drain_each_link_path::<T, L, B, Il>(others, end);
}

/// Put every link path of the connection into `Draining`, ending at `end`
/// unless it was closing, and publish that the role changed at each whose
/// role did.
pub(super) fn drain_each_link_path<T, L, B, Il>(
    others: &mut OtherNodes<'_, T, L, B>,
    end: InstantOf<T>,
) where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkPathRole<InstantOf<T>>], Il>,
{
    let mut drained = Vec::new();
    others.each_link_path::<HList![LinkPathRole<InstantOf<T>>], Il>(|key, hlist_pat![mut role]| {
        if let Some(changed) = role.drain(end) {
            drained.push((key.clone(), changed));
        }
    });
    for (key, changed) in drained {
        others.publish_at(&key, changed);
    }
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

/// A server received Initial CRYPTO data it had all received before, in a
/// packet that `packet` tells of: the policy of the link path it arrived on
/// is asked whether to answer it ([`PtoPolicy::on_duplicate_initial_crypto`],
/// RFC 9002 §6.2.3); if it says yes, the unacknowledged Initial CRYPTO data
/// is unsent again, for the next datagram to carry without waiting for the
/// probe timeout. The anti-amplification limit holds it back as any other
/// datagram. A link path without a recovery layer asks nothing.
///
/// Duplicate Initial CRYPTO data comes before the handshake is confirmed,
/// when a client does not migrate (RFC 9000 §9): the first link path's
/// policy answers for the connection.
fn duplicate_initial_crypto<T, L, B, S, Ls, If, Ik, Jx, Jr, Ics>(
    lineage: &mut LineageOf<'_, T, L, LogicalPath>,
    others: &mut OtherNodes<'_, T, L, B>,
    packet: &DispatchFacts<InstantOf<T>, LinkPathIdentifierOf<T, L>>,
) where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
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
    for<'x> <L as LineageLists<'x, T>>::LogicalPath:
        GetAt<RecoveryFactoryOf<T, L>, If> + GetAt<CryptoSender<CryptoSendBufferOf<T>>, Ics>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, AckRecoveryTakes<T, L, S, Ls>, Ik>,
    for<'a> NodeData<T, L, layer::Recovery>: FlatRef<'a>,
    for<'a> <NodeData<T, L, layer::Recovery> as FlatRef<'a>>::Out:
        Selector<&'a CongestionPartOf<T, L>, Jx> + Selector<&'a RttOf<T, L>, Jr>,
{
    let NodeKey::LogicalPath(path) = others.here().clone() else {
        unreachable!("a logical path's lend carries its key")
    };
    let Some(link) = others.link_path_keys().find_map(|key| match key {
        NodeKey::LinkPath(of, link)
            if *of == path && L::link_path_identifier(of, link) == *packet.link_path() =>
        {
            Some(link.clone())
        }
        _ => None,
    }) else {
        return;
    };
    let mut factory = lineage.get_mut::<RecoveryFactoryOf<T, L>, If>();
    let answered = others.with_recovery_at::<AckRecoveryTakes<T, L, S, Ls>, Ik, _>(
        &path,
        &link,
        |hlist_pat![_, mut part, _, _, _, _, _], rest| {
            lend_congestion::<T, L, B, Jx, Jr, _>(&mut *factory, &mut *part, rest, |mut access| {
                access.on_duplicate_initial_crypto()
            })
        },
    );
    if answered == Some(true) {
        // every byte not acknowledged, in flight or not
        lineage
            .get_mut::<CryptoSender<CryptoSendBufferOf<T>>, Ics>()
            .lost(CryptoLevel::Initial, VarInt::ZERO, usize::MAX);
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

/// A PATH_RESPONSE with `data` arrived in `packet`: the link path of the
/// logical path of this lend that sent the PATH_CHALLENGE it echoes, over
/// whichever link path it arrived (RFC 9000 §8.2.2, §8.2.3), concludes its
/// path validation as its [`PathValidation`](super::path_validation::PathValidation)
/// says. When that validates the address, the entry of its logical link
/// counts it validated, and the anti-amplification limit lifts (§8.1). A
/// response that echoes no challenge is ignored (§19.18, MAY close).
fn receive_path_response<T, L, B, Ipv, Ian>(
    others: &mut OtherNodes<'_, T, L, B>,
    data: [u8; sakuya_wire_v1::frame::PATH_DATA_LEN],
    packet: &DispatchFacts<InstantOf<T>, LinkPathIdentifierOf<T, L>>,
) where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![PathValidationOf<T>], Ipv>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification, LinkFacts], Ian>,
{
    let NodeKey::LogicalPath(path) = others.here().clone() else {
        unreachable!("a logical path's lend carries its key")
    };
    let mut validated = None;
    others.each_link_path::<HList![PathValidationOf<T>], Ipv>(|key, hlist_pat![mut validation]| {
        let NodeKey::LinkPath(each, link) = key else {
            return;
        };
        if validated.is_some() || *each != path {
            return;
        }
        let here = L::link_path_identifier(each, link) == *packet.link_path();
        if validation.responded(data, here, packet.at()).is_some() {
            validated = Some((key.clone(), link.clone(), validation.is_due()));
        }
    });
    let Some((key, link, due)) = validated else {
        return;
    };
    others.publish_at(&key, Happened::<PathValidationConcluded>::new());
    if due {
        // the second validation, of the path's 1200 bytes
        others.publish_at(&key, Happened::<PathChallengePendingChanged>::new());
    }
    let lifted = others
        .link_entry::<HList![AntiAmplification, LinkFacts], Ian>(&link)
        .is_some_and(|hlist_pat![mut limit, mut facts]| {
            let lifted = facts.validation == AddressValidation::NotValidated;
            if lifted {
                facts.validation = AddressValidation::Validated;
                limit.validated();
            }
            lifted
        });
    if lifted {
        others.publish_at(
            &NodeKey::LinkEntry(link),
            Happened::<AmplificationCreditChanged>::new(),
        );
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
