//! A reset kind for the tests of the stream sets that stands for one an
//! extension adds ([`ExtensionTestResets`]): RFC 9000's resets, a reset
//! request that the peer's parameters must allow, and a reset frame of its
//! own.

use sakuya_stream_v1::{
    connection::LayerEndedError,
    connection_receive_flow::ConnectionReceiveFlowController,
    connection_send_credit::ConnectionSendFlowController,
    receive::{
        StreamReceiver, flow_control::ReceiveFlowControlPolicy, remote_reset::RemoteReset,
        termination::ReceiveTerminationPolicy, violation::OnResetStreamError,
    },
    receive_buffer::StreamReceiveBuffer,
    send::{
        StreamSender,
        finish::ResetError,
        flow_control::SendFlowControlPolicy,
        local_reset::LocalReset,
        termination::{ResetOnAbandonTermination, SendTerminationPolicy},
    },
    send_buffer::{SendMarker, StreamSendBuffer},
    stream_id_ledger::ReceivingPartFrameType,
};
use sakuya_wire_v1::var_int::VarInt;
use sakuya_wire_v1::{
    application_error::ApplicationErrorCode, frame::reset_stream::ResetStreamFrame,
    stream_id::StreamId,
};

use sakuya_stream_v1::resets::{Rfc9000StreamResets, StreamResets};

/// The reset kind of the tests (`ExtensionTestResets`): the resets of
/// RFC 9000, with a request the peer must allow ([`TestResetRequest`]) and
/// a frame of the kind's own ([`TestResetFrame`]), as an extension's kind
/// has them.
#[derive(Debug)]
pub(crate) enum ExtensionTestResets {}

/// The Frame Type the tests' reset frame stands for.
pub(crate) const TEST_RESET_FRAME_TYPE: u32 = 0x24;

/// The reset frame of the tests' kind: a RESET_STREAM frame under a Frame
/// Type of its own, taken as RESET_STREAM is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TestResetFrame(pub(crate) ResetStreamFrame);

/// A request of the tests' kind: a reset with `code`, which only a peer
/// that allows the kind's resets takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TestResetRequest {
    /// The application's error code.
    pub(crate) code: ApplicationErrorCode,
}

/// Why a request of the tests' kind fails.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TestResetError<Lc> {
    /// The peer's parameters do not allow the kind's resets.
    NotSupportedByPeer,
    /// The sending part refused the reset.
    Stream(ResetError<Lc>),
}

impl<Lc> From<LayerEndedError<Lc>> for TestResetError<Lc> {
    fn from(ended: LayerEndedError<Lc>) -> Self {
        Self::Stream(ended.into())
    }
}

impl StreamResets for ExtensionTestResets {
    type Local = LocalReset;
    type Remote = RemoteReset;
    type OnResetStreamError = OnResetStreamError;
    type SendTermination = ResetOnAbandonTermination;
    /// Whether the peer allows the kind's resets.
    type PeerSupport = bool;
    type ResetFrame = TestResetFrame;
    type ResetRequest = TestResetRequest;
    type ResetRequestError<Lc> = TestResetError<Lc>;

    fn send_termination(
        abandon_code: ApplicationErrorCode,
        destination_exhausted_code: ApplicationErrorCode,
    ) -> ResetOnAbandonTermination {
        Rfc9000StreamResets::send_termination(abandon_code, destination_exhausted_code)
    }

    fn on_reset_stream<C, Lc>(
        receiver: &mut StreamReceiver<C, Lc, RemoteReset>,
        frame: ResetStreamFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnResetStreamError>
    where
        C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<RemoteReset>,
    {
        Rfc9000StreamResets::on_reset_stream(receiver, frame, connection)
    }

    fn reset<C, K, Lc, B, M>(
        sender: &mut StreamSender<C, K, Lc, LocalReset, B, M>,
        error_code: ApplicationErrorCode,
    ) -> Result<(), ResetError<Lc>>
    where
        K: ConnectionSendFlowController,
        M: SendMarker,
        C: StreamSendBuffer<B, K::Reservation, M>
            + SendFlowControlPolicy<LocalReset>
            + SendTerminationPolicy<LocalReset>,
    {
        Rfc9000StreamResets::reset(sender, error_code)
    }

    fn reset_frame_stream_id(frame: &TestResetFrame) -> StreamId {
        frame.0.stream_id().get()
    }

    fn reset_frame_type(_: &TestResetFrame) -> ReceivingPartFrameType {
        ReceivingPartFrameType::Extension(VarInt::from_u32(TEST_RESET_FRAME_TYPE))
    }

    fn on_reset_frame<C, Lc>(
        receiver: &mut StreamReceiver<C, Lc, RemoteReset>,
        frame: TestResetFrame,
        connection: &mut ConnectionReceiveFlowController,
    ) -> Result<(), OnResetStreamError>
    where
        C: StreamReceiveBuffer + ReceiveFlowControlPolicy + ReceiveTerminationPolicy<RemoteReset>,
    {
        Rfc9000StreamResets::on_reset_stream(receiver, frame.0, connection)
    }

    fn reset_with<C, K, Lc, B, M>(
        sender: &mut StreamSender<C, K, Lc, LocalReset, B, M>,
        support: bool,
        request: TestResetRequest,
    ) -> Result<(), TestResetError<Lc>>
    where
        K: ConnectionSendFlowController,
        M: SendMarker,
        C: StreamSendBuffer<B, K::Reservation, M>
            + SendFlowControlPolicy<LocalReset>
            + SendTerminationPolicy<LocalReset>,
    {
        if !support {
            return Err(TestResetError::NotSupportedByPeer);
        }
        sender.reset(request.code).map_err(TestResetError::Stream)
    }
}

#[cfg(test)]
mod tests {
    use frunk_core::HList;
    use sakuya_stream_v1::resets::{Rfc9000StreamResets, StreamResetsOfParts};

    use crate::v1;

    /// Compiles only when `A` and `B` are the same type.
    fn same_type<A, B>()
    where
        A: SameAs<B>,
    {
    }

    trait SameAs<B> {}

    impl<A> SameAs<A> for A {}

    #[test]
    fn version_1_alone_resets_as_rfc_9000() {
        same_type::<StreamResetsOfParts<HList![v1::Part]>, Rfc9000StreamResets>();
    }
}
