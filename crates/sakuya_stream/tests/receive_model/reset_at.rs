/// The receiver that also takes `RESET_STREAM_AT`: a reset can keep a
/// reliable prefix, later resets can lower it, and resets must agree on the
/// error code.
mod dialect {
    use super::model::{Event, Receiver, Violation};
    use sakuya_stream::connection_receive_flow::ConnectionReceiveFlowController;
    use sakuya_stream::receive::ResetStreamFrame;
    use sakuya_stream::receive::termination::TerminationEvent;
    use sakuya_stream::reset_stream_at::receive::{
        OnResetStreamAtError, OnResetStreamError as ResetAtOnResetStreamError, RemoteResetAt,
        RemoteResetAtChange, ResetStreamAtFrame,
    };
    use sakuya_stream::stream_end::ResetCodeChangeError;
    use sakuya_wire::reset_stream_at::ReliableSizeError;

    pub type Facts = RemoteResetAt;

    /// Whether the peer also sends resets that keep a prefix.
    pub const PARTIAL_RESETS: bool = true;

    /// The violations the extension adds to those of RFC 9000.
    #[derive(Clone, Copy, Debug)]
    pub enum Extra {
        ResetCodeChanged(ResetCodeChangeError),
        ReliableSizeExceedsFinalSize(ReliableSizeError),
    }

    pub fn facts(code: u32, final_size: u64, owed: u64) -> Facts {
        RemoteResetAt::new(
            super::model::code(code),
            super::model::v(final_size),
            super::model::v(owed),
        )
        .unwrap()
    }

    pub fn check_owed(final_size: u64, owed: u64) -> Result<(), Extra> {
        ReliableSizeError::check(super::model::v(final_size), super::model::v(owed))
            .map_err(Extra::ReliableSizeExceedsFinalSize)
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
            Violation::Extra(Extra::ReliableSizeExceedsFinalSize(_)) => {
                panic!("a RESET_STREAM frame cannot commit {violation:?}")
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
        let frame = ResetStreamAtFrame {
            code: frame.code,
            final_size: frame.final_size,
            reliable_size: super::model::v(owed),
        };
        let actual = receiver.on_reset_stream_at(frame, connection);
        let expected = expected.map_err(|violation| match violation {
            Violation::Extra(Extra::ReliableSizeExceedsFinalSize(source)) => {
                OnResetStreamAtError::ReliableSizeExceedsFinalSize { source }
            }
            other => shared(other).into(),
        });
        assert_eq!(actual, expected);
    }
}

// The same model runs against each dialect.
#[allow(clippy::duplicate_mod)]
#[path = "model.rs"]
mod model;
