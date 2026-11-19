//! The default stream set with the reliable stream reset extension: it
//! takes RESET_STREAM_AT as it takes RESET_STREAM, and its stream writers
//! reset at a reliable size when the peer allows it.

use bytes::Bytes;
use sakuya_stream::{
    connection::LayerEndedError, connection_send_credit::AtomicConnectionCreditReservation,
    reset_stream_at::send, send_buffer::StreamSendBuffer,
    send_buffer::offset_map::OffsetMapStreamSendBuffer, send_options::urgency::SendUrgency,
    stream_id_ledger::ReceivingPartFrameType,
};
use sakuya_wire::{
    parts::Selector, reset_stream_at::ResetStreamAtFrame,
    v1::application_error::ApplicationErrorCode, var_int::VarInt,
};
use snafu::ResultExt;

use super::{
    LockedStreamSet, LockedStreamSetHandle, MarkerOf, ResetStreamSnafu, StreamSetFrameErrorOf,
    application::{LockedStreamSendShare, SendingAccess},
    lock,
};
use crate::{
    driver::LendNode,
    error::ConnectionErrorsOf,
    reset_stream_at::{
        NotSupportedByPeerSnafu, ReliableStreamResets, ResetAtError, ResetStreamAtSet,
        StreamResetAt,
    },
    send_strategy::{AnyActiveLinkPath, IntentPublisher, IntentTicketWithdraw},
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::GetAt,
    v1::{
        Choices, CloseCauseOf, SendParametersOf, StreamSetFamilyOf,
        application_handles::{
            connection::{ConnectionHandleRemainsOf, ConnectionHandleStateOf},
            shared_stream::SharedStreamSend,
        },
        send::SendTypes,
        send_planning::{ComponentPublishing, HostSendStrategyTypes, StrategyPublisherOf},
        streams::{
            StreamSet, StreamsOf,
            resets::{StreamResetsOf, StreamResetsOfParts},
            send::StreamIntent,
        },
    },
    v1::{
        application_handles::credential::CredentialPointer,
        events::{EventInitiator, SharedEvents},
    },
};

/// A RESET_STREAM_AT frame passes the checks of the streams' identity as
/// RESET_STREAM does, and goes to the stream's receiving part.
impl<Lc, K, H, I, P, E> ResetStreamAtSet<Lc, I, ReliableStreamResets>
    for LockedStreamSet<Lc, K, H, ReliableStreamResets, P, E>
where
    I: HostSendStrategyTypes,
    K: IntentTicketWithdraw,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    P: Clone + PartialEq + Default + SendUrgency,
    E: SharedEvents,
    OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>:
        StreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>,
{
    fn on_reset_stream_at<Ij, Kp>(
        &mut self,
        _: &mut StrategyPublisherOf<I>,
        frame: ResetStreamAtFrame,
    ) -> Result<(), StreamSetFrameErrorOf<ReliableStreamResets>> {
        let publish = &mut self.intake;
        let id = frame.stream_id().get();
        let Some(part) = self
            .shared
            .receiving_part(id, ReceivingPartFrameType::ResetStreamAt)?
        else {
            return Ok(());
        };
        let mut end = part.lock();
        let before = self.shared.state_before(&*end);
        {
            let mut connection = lock(&self.shared.connection_receive);
            end.receiver
                .on_reset_stream_at(frame, &mut connection.flow)
                .context(ResetStreamSnafu)?;
        }
        end.sync_intents(id, publish);
        end.wake_reader();
        part.note_done(&end);
        self.shared
            .state_after(id, before, &*end, EventInitiator::Remote);
        drop(end);
        self.shared.reclaim_if_done(&part, id, publish);
        Ok(())
    }
}

impl<Lc, K, P, H, E> SendingAccess<'_, Lc, K, ReliableStreamResets, P, H, E>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
{
    /// See [`StreamResetAt::reset_at`]: with what the peer's parameters
    /// allowed when the set was made.
    fn reset_at(
        &mut self,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<Lc>> {
        let Some(support) = self.shared.facts.peer_reset_support else {
            return NotSupportedByPeerSnafu.fail();
        };
        self.with_part(|end| end.sender.reset_at(support, code, reliable_size))
            .map_err(send::ResetAtError::from)??;
        Ok(())
    }
}

/// A writer resets at a reliable size with what the peer's parameters
/// allowed when the set was made.
impl<Lc, K, P, H, E, C> StreamResetAt
    for LockedStreamSendShare<Lc, K, ReliableStreamResets, P, H, E, C>
where
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    E: SharedEvents,
    C: CredentialPointer,
{
    fn reset_at(
        &mut self,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<Lc>> {
        self.access().reset_at(code, reliable_size)
    }
}

/// A writer through the shared connection resets at a reliable size as a
/// share does.
impl<T, L, S, C, K, H, P, E, Ie, Ic, Ir, Is, In, I> StreamResetAt
    for SharedStreamSend<T, L, S, (Ie, Ic, Ir, Is, In, I), C>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    C: CredentialPointer,
    E: SharedEvents,
    P: Clone + PartialEq + Default + SendUrgency,
    H: IntentPublisher<StreamIntent<P>, AnyActiveLinkPath, Ticket = K> + Clone,
    SendTypes<T, L>: ComponentPublishing<StreamSetFamilyOf<T>, StreamIntent<SendParametersOf<T>>>,
    StreamsOf<T, L>: StreamSet<
            CloseCauseOf<T, L>,
            SendTypes<T, L>,
            StreamResetsOfParts<L>,
            Handle = LockedStreamSetHandle<CloseCauseOf<T, L>, K, H, ReliableStreamResets, P, E>,
        >,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Established:
        GetAt<ConnectionHandleStateOf<T, L>, Ie> + GetAt<StreamsOf<T, L>, Is>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
{
    fn reset_at(
        &mut self,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<CloseCauseOf<T, L>>> {
        self.with_access(|mut access| access.reset_at(code, reliable_size))
            .unwrap_or_else(|end| Err(send::ResetAtError::from(LayerEndedError::new(end)).into()))
    }
}
