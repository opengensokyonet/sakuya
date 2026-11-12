/// The receiver of RFC 9000 resets: a reset abandons all data, and a later
/// reset changes nothing.
mod dialect {
    use super::model::{Event, Receiver, Violation};
    use sakuya_stream::connection_receive_flow::ConnectionReceiveFlowController;
    use sakuya_stream::receive::remote_reset::RemoteReset;
    use sakuya_wire::v1::frame::reset_stream::ResetStreamFrame;

    pub type Facts = RemoteReset;

    /// Whether the peer also sends resets that keep a prefix.
    pub const PARTIAL_RESETS: bool = false;

    /// No reset violates a rule beyond those of RFC 9000.
    #[derive(Clone, Copy, Debug)]
    pub enum Extra {}

    pub fn facts(code: u32, final_size: u64, owed: u64) -> Facts {
        assert_eq!(owed, 0, "a reset abandons all data");
        RemoteReset {
            code: super::model::code(code),
            final_size: super::model::v(final_size),
        }
    }

    /// A later reset with another error code is ignored.
    pub fn check_code(_known: u32, _stated: u32) -> Result<(), Extra> {
        Ok(())
    }

    /// The event of a later reset that lowers the owed prefix; there is none.
    pub fn lowered() -> Event {
        unreachable!("no reset lowers what the peer owes")
    }

    pub fn on_reset_stream(
        receiver: &mut Receiver,
        frame: ResetStreamFrame,
        connection: &mut ConnectionReceiveFlowController,
        expected: Result<(), Violation>,
    ) {
        let actual = receiver.on_reset_stream(frame, connection);
        assert_eq!(actual, expected.map_err(Violation::on_reset_stream));
    }

    pub fn on_partial_reset(
        _receiver: &mut Receiver,
        _frame: ResetStreamFrame,
        _owed: u64,
        _connection: &mut ConnectionReceiveFlowController,
        _expected: Result<(), Violation>,
    ) {
        unreachable!("no reset keeps a prefix")
    }
}

// The same model runs against each dialect.
#[allow(clippy::duplicate_mod)]
#[path = "model.rs"]
mod model;
