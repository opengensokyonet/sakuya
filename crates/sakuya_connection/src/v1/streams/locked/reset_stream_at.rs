//! The default stream set with the reliable stream reset extension: it
//! takes RESET_STREAM_AT as it takes RESET_STREAM, and its stream writers
//! reset at a reliable size when the peer allows it.

use bytes::Bytes;
use sakuya_stream::{
    connection_send_credit::AtomicConnectionCreditReservation, send_buffer::StreamSendBuffer,
    send_buffer::offset_map::OffsetMapStreamSendBuffer, send_options::urgency::SendUrgency,
    stream_id_ledger::ReceivingPartFrameType,
};
use sakuya_wire::{
    reset_stream_at::ResetStreamAtFrame, v1::application_error::ApplicationErrorCode,
    var_int::VarInt,
};
use snafu::ResultExt;

use super::{
    LockedStreamSet, MarkerOf, ResetStreamSnafu, StreamSetFrameErrorOf,
    application::LockedStreamSendShare, lock,
};
use crate::{
    reset_stream_at::{
        NotSupportedByPeerSnafu, ReliableStreamResets, ResetAtError, ResetStreamAtSet,
        StreamResetAt,
    },
    send_strategy::{IntentTicketResize, IntentTicketWithdraw},
    v1::streams::send::StreamIntentHandle,
};

/// A RESET_STREAM_AT frame passes the checks of the streams' identity as
/// RESET_STREAM does, and goes to the stream's receiving part.
impl<Lc, K, P> ResetStreamAtSet<Lc, K, ReliableStreamResets>
    for LockedStreamSet<Lc, K, ReliableStreamResets, P>
where
    P: Clone + PartialEq + Default + SendUrgency,
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
        {
            let mut connection = lock(&self.shared.connection_receive);
            end.receiver
                .on_reset_stream_at(frame, &mut connection.flow)
                .context(ResetStreamSnafu)?;
        }
        end.sync_intents(id, publish);
        end.wake_reader();
        Ok(())
    }
}

/// A writer resets at a reliable size with what the peer's parameters
/// allowed when the set was made.
impl<Lc, K, P, H> StreamResetAt for LockedStreamSendShare<Lc, K, ReliableStreamResets, P, H>
where
    K: IntentTicketResize + IntentTicketWithdraw,
    P: Clone + PartialEq + Default + SendUrgency,
    H: StreamIntentHandle<P, K>,
{
    fn reset_at(
        &mut self,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<Lc>> {
        let Some(support) = self.shared.facts.peer_reset_support else {
            return NotSupportedByPeerSnafu.fail();
        };
        self.with_part(|end| end.sender.reset_at(support, code, reliable_size))
            .map_err(sakuya_stream::reset_stream_at::send::ResetAtError::from)??;
        Ok(())
    }
}
