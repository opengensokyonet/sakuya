/// The receiver that also takes `RESET_STREAM_AT`: a reset can keep a
/// reliable prefix, later resets can lower it, and resets must agree on the
/// error code.
mod dialect {
    use super::model::{Event, Receiver, Violation};
    use sakuya_stream::connection_receive_flow::ConnectionReceiveFlowController;
    use sakuya_stream::receive::termination::TerminationEvent;
    use sakuya_stream::reset_stream_at::receive::{
        OnResetStreamError as ResetAtOnResetStreamError, RemoteResetAt, RemoteResetAtChange,
    };
    use sakuya_stream::stream_end::ResetCodeChangeError;
    use sakuya_wire::reset_stream_at::ResetStreamAtFrame;
    use sakuya_wire::v1::frame::reset_stream::ResetStreamFrame;
    use sakuya_wire::var_int::VarIntField;

    pub type Facts = RemoteResetAt;

    /// Whether the peer also sends resets that keep a prefix.
    pub const PARTIAL_RESETS: bool = true;

    /// The violations the extension adds to those of RFC 9000.
    #[derive(Clone, Copy, Debug)]
    pub enum Extra {
        ResetCodeChanged(ResetCodeChangeError),
    }

    pub fn facts(code: u32, final_size: u64, owed: u64) -> Facts {
        RemoteResetAt::new(
            super::model::code(code),
            super::model::v(final_size),
            super::model::v(owed),
        )
        .unwrap()
    }

    pub fn check_code(known: u32, stated: u32) -> Result<(), Extra> {
        ResetCodeChangeError::check(super::model::code(known), super::model::code(stated))
            .map_err(Extra::ResetCodeChanged)
    }

    /// The event of a later reset that lowers the reliable prefix.
    pub fn lowered() -> Event {
        TerminationEvent::ResetChanged(RemoteResetAtChange::ReliablePrefixLowered)
    }

    fn shared(violation: Violation) -> ResetAtOnResetStreamError {
        match violation {
            Violation::Extra(Extra::ResetCodeChanged(source)) => {
                ResetAtOnResetStreamError::ResetCodeChanged { source }
            }
            other => other.on_reset_stream().into(),
        }
    }

    pub fn on_reset_stream(
        receiver: &mut Receiver,
        frame: ResetStreamFrame,
        connection: &mut ConnectionReceiveFlowController,
        expected: Result<(), Violation>,
    ) {
        let actual = receiver.on_reset_stream(frame, connection);
        assert_eq!(actual, expected.map_err(shared));
    }

    pub fn on_partial_reset(
        receiver: &mut Receiver,
        frame: ResetStreamFrame,
        owed: u64,
        connection: &mut ConnectionReceiveFlowController,
        expected: Result<(), Violation>,
    ) {
        let frame = ResetStreamAtFrame::new(
            frame.stream_id(),
            frame.application_error_code(),
            frame.final_size(),
            VarIntField::shortest(super::model::v(owed)),
        )
        .unwrap();
        let actual = receiver.on_reset_stream_at(frame, connection);
        assert_eq!(actual, expected.map_err(shared));
    }
}

// The same model runs against each dialect.
#[allow(clippy::duplicate_mod)]
#[path = "model.rs"]
mod model;
