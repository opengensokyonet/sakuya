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
    application::{LockedStreamSendShare, SendingAccess, StreamPublishOf},
    lock,
};
use crate::{
    driver::LendNode,
    error::ConnectionErrorsOf,
    reset_stream_at::{
        NotSupportedByPeerSnafu, ReliableStreamResets, ResetAtError, ResetStreamAtSet,
        StreamResetAt,
    },
    send_strategy::{AnyActiveLinkPath, SendIntentIntake, SharedPublishTo},
    send_strategy::{IntentTicketResize, IntentTicketWithdraw},
    share::{LineageLists, LineagePartList, RemainsOf},
    shared::SharedConnection,
    take::GetAt,
    v1::{
        Choices, CloseCauseOf, SendParametersOf,
        application_handles::{
            connection::{ConnectionHandleRemainsOf, ConnectionHandleStateOf},
            shared_stream::SharedStreamSend,
        },
        send::SendTypes,
        send_planning::{
            HostSendStrategyTypes, IntakeOf, IntakePublishOutcome, SendStrategyIntake,
        },
        streams::{
            StreamSet, StreamsOf,
            resets::{StreamResetsOf, StreamResetsOfParts},
            send::{StreamIntent, StreamIntentTicketOf},
        },
    },
    v1::{
        application_handles::credential::CredentialPointer,
        events::{EventInitiator, SharedEvents},
        streams::send::StreamIntentHandle,
    },
};

/// A RESET_STREAM_AT frame passes the checks of the streams' identity as
/// RESET_STREAM does, and goes to the stream's receiving part.
impl<Lc, K, P, E> ResetStreamAtSet<Lc, K, ReliableStreamResets>
    for LockedStreamSet<Lc, K, ReliableStreamResets, P, E>
where
    P: Clone + PartialEq + Default + SendUrgency,
    E: SharedEvents,
    OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>:
        StreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>,
{
    fn on_reset_stream_at<H>(
        &mut self,
        publish: &H,
        frame: ResetStreamAtFrame,
    ) -> Result<(), StreamSetFrameErrorOf<ReliableStreamResets>>
    where
        H: StreamIntentHandle<P, K>,
        K: IntentTicketResize + IntentTicketWithdraw,
    {
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
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
    E: SharedEvents,
{
    /// See [`StreamResetAt::reset_at`]: with what the peer's parameters
    /// allowed when the set was made.
    fn reset_at(
        &self,
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
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
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
impl<T, L, S, C, K, P, E, Ie, Ic, Ir, Is, In, I> StreamResetAt
    for SharedStreamSend<T, L, S, (Ie, Ic, Ir, Is, In, I), C>
where
    T: Choices,
    L: LineagePartList<T> + ConnectionErrorsOf + StreamResetsOf,
    S: SharedConnection<Driver: LendNode<T, L>>,
    C: CredentialPointer,
    E: SharedEvents,
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<SendParametersOf<T>>, AnyActiveLinkPath>
        + HostSendStrategyTypes,
    StreamsOf<T, L>: StreamSet<
            CloseCauseOf<T, L>,
            StreamIntentTicketOf<T, L>,
            StreamResetsOfParts<L>,
            Handle = LockedStreamSetHandle<CloseCauseOf<T, L>, K, ReliableStreamResets, P, E>,
        >,
    IntakeOf<T, L>: SendIntentIntake<AnyActiveLinkPath>
        + SharedPublishTo<StreamIntent<P>, AnyActiveLinkPath, I>,
    StreamPublishOf<T, L, P, I>: StreamIntentHandle<P, K>,
    RemainsOf<T, L>: Selector<ConnectionHandleRemainsOf<T, L>, Ir>,
    for<'v> <L as LineageLists<'v, T>>::Established: GetAt<ConnectionHandleStateOf<T, L>, Ie>
        + GetAt<StreamsOf<T, L>, Is>
        + GetAt<SendStrategyIntake<IntakeOf<T, L>>, In>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<ConnectionHandleStateOf<T, L>, Ic>,
{
    fn reset_at(
        &mut self,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<CloseCauseOf<T, L>>> {
        self.with_access(|access| access.reset_at(code, reliable_size))
            .unwrap_or_else(|end| Err(send::ResetAtError::from(LayerEndedError::new(end)).into()))
    }
}
