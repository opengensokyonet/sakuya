//! The set held by the connection with the reliable stream reset
//! extension: it takes RESET_STREAM_AT as it takes RESET_STREAM.

use bytes::Bytes;
use sakuya_stream::reset_stream_at::send;
use sakuya_stream::{
    connection_send_credit::AtomicConnectionCreditReservation,
    send_buffer::{StreamSendBuffer, offset_map::OffsetMapStreamSendBuffer},
    send_options::{destination::AnyActiveLinkPath, urgency::SendUrgency},
    stream_id_ledger::ReceivingPartFrameType,
};
use sakuya_wire::{
    reset_stream_at::ResetStreamAtFrame, v1::application_error::ApplicationErrorCode,
    var_int::VarInt,
};
use snafu::ResultExt;

use super::{OwnedStreamSet, placed};
use crate::{
    reset_stream_at::{
        NotSupportedByPeerSnafu, ReliableStreamResets, ResetAtError, ResetStreamAtSet,
    },
    send_strategy::PublishOutcome,
    v1::{
        events::SharedEvents,
        send_planning::{
            HostSendStrategyTypes, PublishedTicketOf, StrategyPublisherForTicket,
            StrategyPublisherOf,
        },
        streams::{
            HeldSend, ResetStreamSnafu, StreamSetFrameErrorOf, send::StreamIntent,
            set_state::MarkerOf,
        },
    },
};

/// A RESET_STREAM_AT frame passes the checks of the streams' identity as
/// RESET_STREAM does, and goes to the stream's receiving part.
impl<Lc, I, P, E> ResetStreamAtSet<Lc, I, ReliableStreamResets>
    for OwnedStreamSet<Lc, PublishedTicketOf<I, StreamIntent<P>>, ReliableStreamResets, P, E>
where
    I: HostSendStrategyTypes,
    StrategyPublisherOf<I>: PublishOutcome<StreamIntent<P>, AnyActiveLinkPath>,
    P: Clone + PartialEq + Default + SendUrgency,
    E: SharedEvents,
    OffsetMapStreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>:
        StreamSendBuffer<Bytes, AtomicConnectionCreditReservation, MarkerOf<P>>,
{
    fn on_reset_stream_at<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        frame: ResetStreamAtFrame,
    ) -> Result<(), StreamSetFrameErrorOf<ReliableStreamResets>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        let id = frame.stream_id().get();
        if !self.identify_receiving(id, ReceivingPartFrameType::ResetStreamAt)? {
            return Ok(());
        }
        self.take_receiving_frame(id, &mut placed::<_, P, Ij>(publish), |end, flow| {
            end.receiver
                .on_reset_stream_at(frame, flow)
                .context(ResetStreamSnafu)
        })
    }

    fn reset_at<Ij, Kp>(
        &mut self,
        publish: &mut StrategyPublisherOf<I>,
        held: HeldSend<'_>,
        code: ApplicationErrorCode,
        reliable_size: VarInt,
    ) -> Result<(), ResetAtError<Lc>>
    where
        StrategyPublisherOf<I>: StrategyPublisherForTicket<StreamIntent<P>, Ij, Kp>,
    {
        let Some(support) = self.set.peer_reset_support else {
            return NotSupportedByPeerSnafu.fail();
        };
        self.change_held_sending(
            held.stream_id(),
            &mut placed::<_, P, Ij>(publish),
            |end, _, _| end.sender.reset_at(support, code, reliable_size),
        )
        .map_err(send::ResetAtError::from)??;
        Ok(())
    }
}
