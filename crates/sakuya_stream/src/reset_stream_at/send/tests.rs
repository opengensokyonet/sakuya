//! The stream sender with [`LocalResetAt`] targets: `reset_at` and `reset`
//! in every order, the reliable prefix in the final size, the buffer and the
//! credit, the reset frames and the terminal states they lead to.
use super::{
    LocalResetAt, LocalResetAtFrame, PeerResetStreamAtSupport, PlainResetEffectiveError,
    ReliablePrefixNotPreparedError, ReliableSizeIncreaseError, ResetAtError,
    ResetAtWithFinalSizeError, ResetTarget,
};
use crate::connection::ConnectionClosedError;
use crate::connection_send_credit::ConnectionSendFlowController;
use crate::send::composition::DefaultSendComposition;
use crate::send::finish::{CloseError, ProtocolTerminalError, ResetError, ResetWithFinalSizeError};
use crate::send::local_reset::{LocalReset, LocalResetTarget};
use crate::send::termination::{
    FinalSizeRequest, SendTerminationContext, SendTerminationEvent, TerminationAction,
};
use crate::send::test_support::{
    Action, CODE, Connection, OTHER_CODE, TestSender, close_reason, completing_sender,
    due_end_frame, end_commits, expose, keep, new_connection, send_end, source, stream, v,
    write_all, written,
};
use crate::send::write::{FlushError, WriteError};
use crate::send::{
    EndSource, EnterTerminalStateError, SendEndState, SendTerminalState, StreamEndFrame,
    StreamResetError, StreamSender,
};
use crate::send_buffer::FinalSizeBeyondWrittenEndError;
use crate::send_buffer::visibility::FinalSizeBelowExposureError;
use crate::stream_end::{FinalSizeChangeError, ResetCodeChangeError};
use bytes::Bytes;
use sakuya_wire::reset_stream_at::{ReliableSizeError, ResetStreamAt};
use sakuya_wire::v1::application_error::ApplicationErrorCode;
use sakuya_wire::var_int::{VarInt, VarIntWidth};
use std::sync::Arc;

/// The peer of these tests advertised `reset_stream_at`.
const SUPPORT: PeerResetStreamAtSupport =
    PeerResetStreamAtSupport::from_peer_parameter(ResetStreamAt);

/// The state a policy of these senders decides on.
type Context = SendTerminationContext<LocalResetAt>;

/// A sender whose policy answers events with `script`.
fn scripted_sender<S>(
    connection: &Arc<Connection>,
    peer_stream_limit: u32,
    script: S,
) -> TestSender<S, LocalResetAt>
where
    S: FnMut(&SendTerminationEvent, &Context) -> Action<LocalResetAt>,
{
    crate::send::test_support::scripted_sender(connection, peer_stream_limit, script)
}

/// A sender whose policy never acts.
fn test_sender(
    connection: &Arc<Connection>,
    peer_stream_limit: u32,
) -> TestSender<impl FnMut(&SendTerminationEvent, &Context) -> Action<LocalResetAt>, LocalResetAt> {
    scripted_sender(connection, peer_stream_limit, keep)
}

/// A sender over the default composition.
fn default_sender(
    connection: &Arc<Connection>,
    peer_stream_limit: u32,
) -> StreamSender<DefaultSendComposition, Connection, LocalResetAt> {
    crate::send::test_support::default_sender(connection, peer_stream_limit)
}

fn reset_target(
    error_code: ApplicationErrorCode,
    reliable_size: u32,
    final_size: u32,
) -> ResetTarget {
    ResetTarget::new(SUPPORT, error_code, v(reliable_size), v(final_size)).unwrap()
}

/// The end state of a `reset_at` in effect.
fn reset_at_state(
    error_code: ApplicationErrorCode,
    reliable_size: u32,
    final_size: u32,
    source: EndSource,
) -> SendEndState<LocalResetAt> {
    SendEndState::Reset {
        target: LocalResetAt::ResetAt(reset_target(error_code, reliable_size, final_size)),
        source,
    }
}

/// The end state of a `reset` in effect.
fn reset_state(
    error_code: ApplicationErrorCode,
    final_size: u32,
    source: EndSource,
) -> SendEndState<LocalResetAt> {
    SendEndState::Reset {
        target: LocalResetAt::Reset(LocalReset {
            error_code,
            final_size: v(final_size),
        }),
        source,
    }
}

fn is_reset_stream(frame: StreamEndFrame<LocalResetAtFrame>) -> bool {
    matches!(
        frame,
        StreamEndFrame::Reset(LocalResetAtFrame::ResetStream(_))
    )
}

fn is_reset_stream_at(frame: StreamEndFrame<LocalResetAtFrame>) -> bool {
    matches!(
        frame,
        StreamEndFrame::Reset(LocalResetAtFrame::ResetStreamAt(_))
    )
}

// ---------------------------------------------------------------------------
// Targets

/// A reset target keeps its reliable size within its final size, and lowers
/// it but never raises it.
#[test]
fn a_reset_target_keeps_its_reliable_size_within_its_final_size() {
    assert_eq!(
        ResetTarget::new(SUPPORT, CODE, v(60), v(50)),
        Err(ReliableSizeError::check(v(50), v(60)).unwrap_err())
    );
    let target = reset_target(CODE, 50, 50);
    assert_eq!(
        (
            target.error_code(),
            target.reliable_size(),
            target.final_size()
        ),
        (CODE, v(50), v(50))
    );
    assert_eq!(target.lowered_to(v(20)), Ok(reset_target(CODE, 20, 50)));
    assert_eq!(
        target.lowered_to(v(51)),
        Err(ReliableSizeIncreaseError::check(v(50), v(51)).unwrap_err())
    );
    assert_eq!(target.without_reliable_prefix(), reset_target(CODE, 0, 50));

    let reset_at = LocalResetAt::ResetAt(target);
    assert_eq!(reset_at.reliable_size(), v(50));
    assert_eq!(reset_at.acknowledged_state(), SendTerminalState::DataRecvd);
    let reset = LocalResetAt::Reset(LocalReset {
        error_code: CODE,
        final_size: v(50),
    });
    assert_eq!(reset.reliable_size(), VarInt::ZERO);
    assert_eq!(reset.acknowledged_state(), SendTerminalState::ResetRecvd);
}

// ---------------------------------------------------------------------------
// Terminal states

/// A stream ended by `RESET_STREAM_AT` reaches Data Recvd, not Reset Recvd,
/// once the frame and the reliable prefix are acknowledged.
#[test]
fn reset_stream_at_reaches_data_recvd() {
    let connection = new_connection(1000);
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender
        .reset_at_with_final_size(SUPPORT, CODE, v(40), v(100))
        .unwrap();
    assert_eq!(
        sender.enter_terminal_state(SendTerminalState::DataRecvd),
        Err(EnterTerminalStateError::DataRecvdEndNotSent)
    );
    expose(&mut sender, 40);
    assert!(is_reset_stream_at(send_end(&mut sender)));
    assert_eq!(
        sender.enter_terminal_state(SendTerminalState::ResetRecvd),
        Err(EnterTerminalStateError::ResetStreamNotSent)
    );
    // Lowering the reliable size to zero keeps the stream on
    // RESET_STREAM_AT.
    sender.reset_at(SUPPORT, CODE, VarInt::ZERO).unwrap();
    assert!(is_reset_stream_at(send_end(&mut sender)));
    sender
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();
    assert_eq!(sender.terminal_state(), Some(SendTerminalState::DataRecvd));
}

/// `DataRecvd` after a `RESET_STREAM` needs the FIN; a `RESET_STREAM_AT`
/// that a `RESET_STREAM` followed does not suffice, while a
/// `RESET_STREAM_AT` alone does.
#[test]
fn data_recvd_needs_no_reset_stream_after_the_reset_stream_at() {
    let connection = new_connection(1000);

    // RESET_STREAM_AT, then RESET_STREAM: only Reset Recvd.
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.reset_at(SUPPORT, CODE, v(40)).unwrap();
    assert!(is_reset_stream_at(send_end(&mut sender)));
    sender.reset(CODE).unwrap();
    assert!(is_reset_stream(send_end(&mut sender)));
    assert_eq!(
        sender.enter_terminal_state(SendTerminalState::DataRecvd),
        Err(EnterTerminalStateError::DataRecvdEndNotSent)
    );
    assert_eq!(sender.terminal_state(), None);
    sender
        .enter_terminal_state(SendTerminalState::ResetRecvd)
        .unwrap();

    // FIN, RESET_STREAM_AT, then RESET_STREAM: the FIN allows Data Recvd.
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.close().unwrap();
    assert!(matches!(send_end(&mut sender), StreamEndFrame::Fin(_)));
    sender.reset_at(SUPPORT, CODE, v(40)).unwrap();
    assert!(is_reset_stream_at(send_end(&mut sender)));
    sender.reset(CODE).unwrap();
    assert!(is_reset_stream(send_end(&mut sender)));
    sender
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();

    // RESET_STREAM_AT lowered to zero, never a RESET_STREAM: Data Recvd.
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.reset_at(SUPPORT, CODE, v(40)).unwrap();
    send_end(&mut sender);
    sender.reset_at(SUPPORT, CODE, VarInt::ZERO).unwrap();
    send_end(&mut sender);
    sender
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();
}

// ---------------------------------------------------------------------------
// End frames

/// A reset gives its frame of the kind the application's call chose, in the
/// shortest encodings, and a new one each time the reliable size drops or
/// the kind changes.
#[test]
fn the_guard_gives_each_new_reset_frame() {
    let connection = new_connection(10_000);
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 1000);
    sender
        .reset_at_with_final_size(SUPPORT, CODE, v(600), v(900))
        .unwrap();

    let reset_stream_at_due = |sender: &mut _| match due_end_frame(sender) {
        Some(StreamEndFrame::Reset(LocalResetAtFrame::ResetStreamAt(frame))) => frame,
        frame => panic!("RESET_STREAM_AT is due, not {frame:?}"),
    };
    let frame = reset_stream_at_due(&mut sender);
    assert_eq!(frame.stream_id().get(), stream());
    assert_eq!(frame.application_error_code().get(), CODE);
    assert_eq!(frame.final_size().get(), v(900));
    assert_eq!(frame.reliable_size().get(), v(600));
    assert_eq!(frame.final_size().width(), VarIntWidth::Two);

    // The next reliable size supersedes one that was never exposed.
    sender.reset_at(SUPPORT, CODE, v(300)).unwrap();
    let frame = reset_stream_at_due(&mut sender);
    assert_eq!(frame.reliable_size().get(), v(300));
    assert_eq!(
        send_end(&mut sender),
        StreamEndFrame::Reset(LocalResetAtFrame::ResetStreamAt(frame))
    );
    assert!(due_end_frame(&mut sender).is_none());

    // The same target again gives nothing; a lower reliable size gives a
    // new frame.
    sender.reset_at(SUPPORT, CODE, v(300)).unwrap();
    assert!(due_end_frame(&mut sender).is_none());
    sender.reset_at(SUPPORT, CODE, v(100)).unwrap();
    let frame = reset_stream_at_due(&mut sender);
    assert_eq!(frame.reliable_size().get(), v(100));
    send_end(&mut sender);

    // `reset` after `reset_at` is a new kind: RESET_STREAM from then on.
    sender.reset(CODE).unwrap();
    let Some(StreamEndFrame::Reset(LocalResetAtFrame::ResetStream(frame))) =
        due_end_frame(&mut sender)
    else {
        panic!("RESET_STREAM is due");
    };
    assert_eq!(frame.application_error_code().get(), CODE);
    assert_eq!(frame.final_size().get(), v(900));
    send_end(&mut sender);
    assert!(due_end_frame(&mut sender).is_none());
}

// ---------------------------------------------------------------------------
// reset after reset_at, and reset_at after reset

#[test]
fn reset_at_after_a_plain_reset_is_an_error() {
    let connection = new_connection(1000);
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.reset(CODE).unwrap();
    let effective = sender.end_state();

    // Not even a reliable size of zero and the same code and final size.
    assert_eq!(
        sender.reset_at(SUPPORT, CODE, VarInt::ZERO),
        Err(ResetAtError::PlainResetEffective {
            source: PlainResetEffectiveError
        })
    );
    assert_eq!(
        sender.reset_at_with_final_size(SUPPORT, CODE, VarInt::ZERO, VarInt::ZERO),
        Err(ResetAtWithFinalSizeError::PlainResetEffective {
            source: PlainResetEffectiveError
        })
    );
    assert_eq!(sender.end_state(), effective);

    // The conflicts with the error code and the final size come first, and a
    // larger reliable size before the kind.
    assert!(matches!(
        sender.reset_at(SUPPORT, OTHER_CODE, VarInt::ZERO),
        Err(ResetAtError::ErrorCodeConflict { .. })
    ));
    assert!(matches!(
        sender.reset_at_with_final_size(SUPPORT, CODE, VarInt::ZERO, v(5)),
        Err(ResetAtWithFinalSizeError::FinalSizeConflictsWithReset { .. })
    ));
    assert!(matches!(
        sender.reset_at(SUPPORT, CODE, v(1)),
        Err(ResetAtError::ReliableSizeIncrease { .. })
    ));

    // The terminal state comes before what only this kind of target refuses.
    assert!(is_reset_stream(send_end(&mut sender)));
    sender
        .enter_terminal_state(SendTerminalState::ResetRecvd)
        .unwrap();
    assert!(matches!(
        sender.reset_at(SUPPORT, CODE, VarInt::ZERO),
        Err(ResetAtError::ProtocolTerminal { .. })
    ));
    assert!(matches!(
        sender.reset_at(SUPPORT, CODE, v(1)),
        Err(ResetAtError::ProtocolTerminal { .. })
    ));
    assert!(matches!(
        sender.reset_at(SUPPORT, OTHER_CODE, VarInt::ZERO),
        Err(ResetAtError::ErrorCodeConflict { .. })
    ));
}

/// The kind is part of the target: `reset` repeats as a no-op, `reset_at`
/// repeats as a no-op, and `reset` after `reset_at` changes the kind.
#[test]
fn the_kind_of_reset_is_part_of_the_target() {
    let connection = new_connection(1000);
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.reset_at(SUPPORT, CODE, VarInt::ZERO).unwrap();
    assert_eq!(end_commits(&sender), 1);
    sender.reset_at(SUPPORT, CODE, VarInt::ZERO).unwrap();
    assert_eq!(end_commits(&sender), 1);
    assert_eq!(
        sender.end_state(),
        reset_at_state(CODE, 0, 0, EndSource::Application)
    );

    // Same code and final size, reliable size already zero: a new kind.
    sender.reset(CODE).unwrap();
    assert_eq!(end_commits(&sender), 2);
    assert_eq!(
        sender.end_state(),
        reset_state(CODE, 0, EndSource::Application)
    );
    sender.reset(CODE).unwrap();
    assert_eq!(end_commits(&sender), 2);
}

/// On a sender that can end with `RESET_STREAM_AT`, `reset` alone behaves as
/// on a sender of RFC 9000.
#[test]
fn a_plain_reset_is_that_of_rfc_9000() {
    let connection = new_connection(1000);
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    expose(&mut sender, 30);
    sender.reset(CODE).unwrap();
    assert_eq!(
        sender.end_state(),
        reset_state(CODE, 30, EndSource::Application)
    );
    assert_eq!(sender.reliable_size(), VarInt::ZERO);
    assert_eq!(
        sender.reset(OTHER_CODE),
        Err(ResetError::ErrorCodeConflict {
            source: ResetCodeChangeError::check(CODE, OTHER_CODE).unwrap_err(),
        })
    );
    assert_eq!(
        sender.reset_with_final_size(CODE, v(40)),
        Err(ResetWithFinalSizeError::FinalSizeConflictsWithReset {
            source: FinalSizeChangeError::check(v(30), v(40)).unwrap_err(),
        })
    );
    sender.reset_with_final_size(CODE, v(30)).unwrap();
    assert!(is_reset_stream(send_end(&mut sender)));
    sender
        .enter_terminal_state(SendTerminalState::ResetRecvd)
        .unwrap();
}

/// A policy that follows a plain reset with a reset at a reliable size
/// violates the contract.
#[test]
#[should_panic(expected = "illegal reset")]
fn a_reset_at_decision_after_a_plain_reset_is_a_policy_violation() {
    let connection = new_connection(10_000);
    let mut sender = scripted_sender(&connection, 1000, |event, _| match event {
        SendTerminationEvent::StopSendingReceived { error_code } => {
            TerminationAction::Reset(LocalResetAt::ResetAt(reset_target(*error_code, 0, 0)))
        }
        _ => TerminationAction::Keep,
    });
    write_all(&mut sender, 10);
    sender.reset(CODE).unwrap();
    sender.on_stop_sending(CODE);
}

// ---------------------------------------------------------------------------
// Error check order

#[test]
fn reset_at_errors_follow_the_check_order() {
    let connection = new_connection(1000);

    // The terminal state before a plain reset in effect.
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.reset(CODE).unwrap();
    assert!(is_reset_stream(send_end(&mut sender)));
    sender
        .enter_terminal_state(SendTerminalState::ResetRecvd)
        .unwrap();
    assert_eq!(
        sender.reset_at(SUPPORT, CODE, VarInt::ZERO),
        Err(ResetAtError::ProtocolTerminal {
            source: ProtocolTerminalError::check(Some(SendTerminalState::ResetRecvd)).unwrap_err(),
        })
    );

    // The terminal state before a larger reliable size.
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.reset_at(SUPPORT, CODE, v(40)).unwrap();
    expose(&mut sender, 40);
    assert!(is_reset_stream_at(send_end(&mut sender)));
    sender
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();
    assert_eq!(
        sender.reset_at(SUPPORT, CODE, v(50)),
        Err(ResetAtError::ProtocolTerminal {
            source: ProtocolTerminalError::check(Some(SendTerminalState::DataRecvd)).unwrap_err(),
        })
    );

    // The terminal state before an unprepared prefix.
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.close().unwrap();
    assert!(matches!(send_end(&mut sender), StreamEndFrame::Fin(_)));
    sender
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();
    assert_eq!(
        sender.reset_at(SUPPORT, CODE, v(500)),
        Err(ResetAtError::ProtocolTerminal {
            source: ProtocolTerminalError::check(Some(SendTerminalState::DataRecvd)).unwrap_err(),
        })
    );

    // An unprepared prefix before an invalid final size.
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    assert_eq!(
        sender.reset_at_with_final_size(SUPPORT, CODE, v(500), v(2000)),
        Err(ResetAtWithFinalSizeError::ReliablePrefixNotPrepared {
            source: ReliablePrefixNotPreparedError::check(v(500), v(100)).unwrap_err(),
        })
    );
    assert_eq!(
        sender.reset_at_with_final_size(SUPPORT, CODE, v(50), v(2000)),
        Err(ResetAtWithFinalSizeError::FinalSizeBeyondWrittenEnd {
            source: FinalSizeBeyondWrittenEndError::check(v(2000), v(100)).unwrap_err(),
        })
    );
    // Failed requests change nothing and never reach the policy.
    assert_eq!(sender.end_state(), SendEndState::Open);
    assert!(sender.composition().termination.completions.is_empty());
    assert_eq!(end_commits(&sender), 0);
}

// ---------------------------------------------------------------------------
// State transitions, idempotence and conflicts

/// State transitions, idempotence and conflicts, row by row.
#[test]
fn state_transition_table() {
    let connection = new_connection(10_000);

    // Reset, then the identical target: a no-op, also in a terminal state.
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.reset_at(SUPPORT, CODE, v(60)).unwrap();
    let target = sender.end_state();
    sender.reset_at(SUPPORT, CODE, v(60)).unwrap();
    sender
        .reset_at_with_final_size(SUPPORT, CODE, v(60), v(60))
        .unwrap();
    assert!(is_reset_stream_at(send_end(&mut sender)));
    sender
        .enter_terminal_state(SendTerminalState::DataRecvd)
        .unwrap();
    sender.reset_at(SUPPORT, CODE, v(60)).unwrap();
    assert_eq!(sender.end_state(), target);
    assert_eq!(end_commits(&sender), 1);
    assert_eq!(sender.composition().termination.completions.len(), 1);

    // reset_at with the same code and final size and a smaller reliable size.
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.reset_at(SUPPORT, CODE, v(80)).unwrap();
    sender.reset_at(SUPPORT, CODE, v(30)).unwrap();
    assert_eq!(
        sender.end_state(),
        reset_at_state(CODE, 30, 80, EndSource::Application)
    );
    assert_eq!(end_commits(&sender), 2);

    // A larger reliable size conflicts.
    assert_eq!(
        sender.reset_at(SUPPORT, CODE, v(31)),
        Err(ResetAtError::ReliableSizeIncrease {
            source: ReliableSizeIncreaseError::check(v(30), v(31)).unwrap_err(),
        })
    );

    // A different error code or final size conflicts.
    assert_eq!(
        sender.reset_at(SUPPORT, OTHER_CODE, v(30)),
        Err(ResetAtError::ErrorCodeConflict {
            source: ResetCodeChangeError::check(CODE, OTHER_CODE).unwrap_err(),
        })
    );
    assert_eq!(
        sender.reset_at_with_final_size(SUPPORT, CODE, v(30), v(90)),
        Err(ResetAtWithFinalSizeError::FinalSizeConflictsWithReset {
            source: FinalSizeChangeError::check(v(80), v(90)).unwrap_err(),
        })
    );
    assert_eq!(
        sender.reset_with_final_size(CODE, v(90)),
        Err(ResetWithFinalSizeError::FinalSizeConflictsWithReset {
            source: FinalSizeChangeError::check(v(80), v(90)).unwrap_err(),
        }),
        "a plain reset with a final size meets the effective reset's"
    );

    // Close, then reset_at: legal, keeping the fixed final size.
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.close().unwrap();
    sender.reset_at(SUPPORT, CODE, v(40)).unwrap();
    assert_eq!(
        sender.end_state(),
        reset_at_state(CODE, 40, 100, EndSource::Application)
    );
    assert!(sender.composition().termination.completions.is_empty());
    let mut closed = test_sender(&connection, 1000);
    write_all(&mut closed, 100);
    closed.close().unwrap();
    assert_eq!(
        closed.reset_at_with_final_size(SUPPORT, CODE, v(40), v(90)),
        Err(ResetAtWithFinalSizeError::FinalSizeConflictsWithClose {
            source: FinalSizeChangeError::check(v(100), v(90)).unwrap_err(),
        })
    );

    // Reset, then close: an error.
    assert_eq!(
        sender.close(),
        Err(CloseError::AlreadyReset {
            source: StreamResetError
        })
    );

    // A closed connection fails every new call, ahead of no-ops and empty
    // input.
    sender.on_connection_closed(close_reason());
    assert_eq!(
        sender.reset_at(SUPPORT, CODE, v(40)),
        Err(ResetAtError::ConnectionClosed {
            source: ConnectionClosedError::new(close_reason())
        })
    );
    assert!(matches!(
        sender.write(&mut Bytes::new()),
        Err(WriteError::ConnectionClosed { .. })
    ));
    assert_eq!(
        sender.flush(),
        Err(FlushError::ConnectionClosed {
            source: ConnectionClosedError::new(close_reason())
        })
    );
}

/// Whether a request conflicts depends on the effective target, not on the
/// history of requests: 800 lowered to 400 makes 800 an increase.
#[test]
fn conflicts_follow_the_effective_target() {
    let connection = new_connection(10_000);
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 1000);
    sender.reset_at(SUPPORT, CODE, v(800)).unwrap();
    sender.reset_at(SUPPORT, CODE, v(400)).unwrap();
    assert!(matches!(
        sender.reset_at(SUPPORT, CODE, v(800)),
        Err(ResetAtError::ReliableSizeIncrease { .. })
    ));
}

/// An active reset_at of 600 that the policy then lowers to 400: a later
/// active request for 600 fails, one for 400 succeeds without effect.
#[test]
fn active_requests_meet_the_automatic_target_in_effect() {
    let connection = new_connection(10_000);
    let mut sender = scripted_sender(&connection, 1000, |event, context| {
        match (event, context.end_state) {
            (
                SendTerminationEvent::EndCommitted {
                    source: EndSource::Application,
                },
                SendEndState::Reset {
                    target: LocalResetAt::ResetAt(target),
                    ..
                },
            ) => {
                TerminationAction::Reset(LocalResetAt::ResetAt(target.lowered_to(v(400)).unwrap()))
            }
            _ => TerminationAction::Keep,
        }
    });
    write_all(&mut sender, 1000);
    sender.reset_at(SUPPORT, CODE, v(600)).unwrap();
    assert_eq!(
        sender.end_state(),
        reset_at_state(CODE, 400, 600, EndSource::Policy)
    );
    assert!(matches!(
        sender.reset_at(SUPPORT, CODE, v(600)),
        Err(ResetAtError::ReliableSizeIncrease { .. })
    ));
    sender.reset_at(SUPPORT, CODE, v(400)).unwrap();
    assert_eq!(
        sender.end_state(),
        reset_at_state(CODE, 400, 600, EndSource::Policy)
    );
}

// ---------------------------------------------------------------------------
// reset_at and the handed-over prefix

/// With 600 written, reset_at(800) fails without effect;
/// after writing 200 more it succeeds.
#[test]
fn reset_at_needs_the_prefix_written() {
    let connection = new_connection(10_000);
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 600);
    assert_eq!(
        sender.reset_at(SUPPORT, CODE, v(800)),
        Err(ResetAtError::ReliablePrefixNotPrepared {
            source: ReliablePrefixNotPreparedError::check(v(800), v(600)).unwrap_err(),
        })
    );
    assert_eq!(sender.end_state(), SendEndState::Open);
    write_all(&mut sender, 200);
    sender.reset_at(SUPPORT, CODE, v(800)).unwrap();
    assert_eq!(sender.reliable_size(), v(800));
}

/// A write limit of 700 makes reset_at(800) impossible; the request is
/// rejected, not shortened.
#[test]
fn reset_at_beyond_the_write_limit_cannot_be_prepared() {
    let connection = new_connection(10_000);
    let mut sender = scripted_sender(
        &connection,
        1000,
        crate::send::test_support::narrow_on_stop_sending(700),
    );
    write_all(&mut sender, 600);
    sender.on_stop_sending(CODE);
    let mut input = source(200);
    assert_eq!(sender.write(&mut input).unwrap(), written(100));
    assert!(matches!(
        sender.reset_at(SUPPORT, CODE, v(800)),
        Err(ResetAtError::ReliablePrefixNotPrepared { .. })
    ));
}

/// A write limit below the written end does not limit the reliable size of a
/// reset: it only restricts new input.
#[test]
fn write_limit_below_the_written_end_keeps_the_prefix() {
    let connection = new_connection(10_000);
    let mut sender = scripted_sender(
        &connection,
        1000,
        crate::send::test_support::narrow_on_stop_sending(300),
    );
    write_all(&mut sender, 600);
    sender.on_stop_sending(CODE);
    assert_eq!(sender.write_limit_end(), Some(v(300)));
    sender.reset_at(SUPPORT, CODE, v(400)).unwrap();
    assert_eq!(sender.reliable_size(), v(400));
}

// ---------------------------------------------------------------------------
// Final size range and credit retention

/// Written end 1000, exposure end 400, reliable size
/// 600; the final size ranges from 600 to 1000.
#[test]
fn reset_at_final_size_range() {
    let connection = new_connection(10_000);
    let prepare = || {
        let mut sender = test_sender(&connection, 1000);
        write_all(&mut sender, 1000);
        expose(&mut sender, 400);
        sender
    };

    let mut sender = prepare();
    sender.reset_at(SUPPORT, CODE, v(600)).unwrap();
    let [completion]: [FinalSizeRequest<LocalResetAt>; 1] = sender
        .composition()
        .termination
        .completions
        .clone()
        .try_into()
        .unwrap();
    assert!(completion.request.is_reset_at());
    assert_eq!(
        (
            completion.request.error_code(),
            completion.request.reliable_size(),
            completion.minimum,
            completion.maximum
        ),
        (CODE, v(600), v(600), v(1000))
    );

    for (final_size, expected) in [
        (
            399,
            Err(ResetAtWithFinalSizeError::FinalSizeBelowReliableSize {
                source: ReliableSizeError::check(v(399), v(600)).unwrap_err(),
            }),
        ),
        (
            599,
            Err(ResetAtWithFinalSizeError::FinalSizeBelowReliableSize {
                source: ReliableSizeError::check(v(599), v(600)).unwrap_err(),
            }),
        ),
        (600, Ok(())),
        (1000, Ok(())),
        (
            1001,
            Err(ResetAtWithFinalSizeError::FinalSizeBeyondWrittenEnd {
                source: FinalSizeBeyondWrittenEndError::check(v(1001), v(1000)).unwrap_err(),
            }),
        ),
    ] {
        let mut sender = prepare();
        let result = sender.reset_at_with_final_size(SUPPORT, CODE, v(600), v(final_size));
        assert_eq!(result, expected, "final size {final_size}");
        if expected.is_ok() {
            assert_eq!(sender.end_state().final_size(), Some(v(final_size)));
        }
        // An explicit final size never asks the policy.
        assert!(sender.composition().termination.completions.is_empty());
    }

    // Below both the reliable size and the exposure end: the reliable size
    // is reported first.
    let mut sender = prepare();
    assert!(matches!(
        sender.reset_at_with_final_size(SUPPORT, CODE, v(300), v(200)),
        Err(ResetAtWithFinalSizeError::FinalSizeBelowReliableSize { .. })
    ));

    // A reliable size below the exposure end: the exposure end bounds the
    // final size.
    let mut sender = prepare();
    assert_eq!(
        sender.reset_at_with_final_size(SUPPORT, CODE, v(300), v(399)),
        Err(ResetAtWithFinalSizeError::FinalSizeBelowExposure {
            source: FinalSizeBelowExposureError::check(v(399), v(400)).unwrap_err(),
        })
    );
    let mut sender = prepare();
    sender.reset_at(SUPPORT, CODE, v(300)).unwrap();
    assert_eq!(
        sender.composition().termination.completions[0].minimum,
        v(400)
    );
}

/// Final size 800 and reliable size 600 keep the coverage up to 800 and
/// cancel the 200 beyond; lowering the reliable size to 200 later returns
/// nothing of the coverage of 800.
#[test]
fn reset_at_keeps_coverage_up_to_the_final_size() {
    let connection = new_connection(10_000);
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 1000);
    expose(&mut sender, 400);
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(600), v(400))
    );

    sender
        .reset_at_with_final_size(SUPPORT, CODE, v(600), v(800))
        .unwrap();
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(400), v(400))
    );
    assert_eq!(connection.available(), v(10_000 - 800));

    sender.reset_at(SUPPORT, CODE, v(200)).unwrap();
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(400), v(400))
    );
    assert_eq!(sender.written_end(), v(1000));

    // Exposing the reset's final size commits the retained coverage.
    assert!(is_reset_stream_at(send_end(&mut sender)));
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(0), v(800))
    );
}

/// Close succeeded, FIN not yet exposed: a later reset_at keeps the final
/// size and its existing coverage, and needs no available credit.
#[test]
fn reset_at_after_close_before_the_fin_is_exposed() {
    let connection = new_connection(1000);
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 1000);
    expose(&mut sender, 300);
    sender.close().unwrap();
    assert_eq!(connection.available(), v(0));

    sender.reset_at(SUPPORT, CODE, v(200)).unwrap();
    assert_eq!(sender.end_state().final_size(), Some(v(1000)));
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(700), v(300))
    );
    // The reset frame replaces the FIN that was never exposed.
    assert!(is_reset_stream_at(send_end(&mut sender)));
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(0), v(1000))
    );
    assert!(sender.prepare_end_frame().is_none());
}

/// FIN possibly visible: the final size is committed; a later reset_at adds
/// no usage, works without available credit and returns nothing.
#[test]
fn reset_at_after_the_fin_is_exposed() {
    let connection = new_connection(1000);
    let mut sender = test_sender(&connection, 1000);
    write_all(&mut sender, 1000);
    sender.close().unwrap();
    let fin = sender.prepare_end_frame().unwrap();
    assert!(matches!(*fin, StreamEndFrame::Fin(_)));
    assert_eq!(fin.expose(), v(1000));
    assert_eq!(connection.available(), v(0));

    sender.reset_at(SUPPORT, CODE, v(200)).unwrap();
    assert_eq!(
        (connection.reserved(), connection.committed()),
        (v(0), v(1000))
    );
    // The reset frame adds no usage.
    let reset = sender.prepare_end_frame().unwrap();
    assert!(is_reset_stream_at(*reset));
    assert_eq!(reset.expose(), VarInt::ZERO);
    assert!(sender.prepare_end_frame().is_none());
}

// ---------------------------------------------------------------------------
// Policy violations

#[test]
#[should_panic(expected = "chose a final size the reset cannot end at")]
fn final_size_below_the_reliable_size_is_a_policy_violation() {
    let connection = new_connection(10_000);
    let mut sender = completing_sender::<LocalResetAt>(&connection, 1000, 500);
    write_all(&mut sender, 1000);
    expose(&mut sender, 400);
    let _ = sender.reset_at(SUPPORT, CODE, v(600));
}

#[test]
#[should_panic(expected = "chose a final size beyond the written end")]
fn final_size_beyond_the_written_end_is_a_policy_violation() {
    let connection = new_connection(10_000);
    let mut sender = completing_sender::<LocalResetAt>(&connection, 1000, 1200);
    write_all(&mut sender, 1000);
    expose(&mut sender, 400);
    let _ = sender.reset_at(SUPPORT, CODE, v(600));
}

// ---------------------------------------------------------------------------
// Default composition

#[test]
fn default_termination_chooses_the_smallest_final_size() {
    let connection = new_connection(10_000);
    let mut sender = default_sender(&connection, 1000);
    write_all(&mut sender, 1000);
    expose(&mut sender, 400);
    sender.reset_at(SUPPORT, CODE, v(600)).unwrap();
    assert_eq!(sender.end_state().final_size(), Some(v(600)));

    let mut sender = default_sender(&connection, 1000);
    write_all(&mut sender, 1000);
    expose(&mut sender, 400);
    sender.reset(CODE).unwrap();
    assert_eq!(sender.end_state().final_size(), Some(v(400)));
}

#[test]
fn default_termination_resets_on_stop_sending() {
    let connection = new_connection(10_000);

    // Open: reset at once with the request's error code, with RESET_STREAM.
    let mut sender = default_sender(&connection, 1000);
    write_all(&mut sender, 1000);
    expose(&mut sender, 250);
    sender.on_stop_sending(OTHER_CODE);
    assert_eq!(
        sender.end_state(),
        reset_state(OTHER_CODE, 250, EndSource::Policy)
    );

    // Closed: reset with the fixed final size.
    let mut sender = default_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.close().unwrap();
    sender.on_stop_sending(OTHER_CODE);
    assert_eq!(
        sender.end_state(),
        reset_state(OTHER_CODE, 100, EndSource::Policy)
    );

    // A plain reset already: nothing changes.
    let mut sender = default_sender(&connection, 1000);
    write_all(&mut sender, 1000);
    sender.reset(CODE).unwrap();
    sender.on_stop_sending(OTHER_CODE);
    assert_eq!(
        sender.end_state(),
        reset_state(CODE, 0, EndSource::Application)
    );

    // A reset_at already: it stays RESET_STREAM_AT, keeps the code and final
    // size, and its reliable size drops to zero.
    let mut sender = default_sender(&connection, 1000);
    write_all(&mut sender, 1000);
    sender.reset_at(SUPPORT, CODE, v(600)).unwrap();
    sender.on_stop_sending(OTHER_CODE);
    assert_eq!(
        sender.end_state(),
        reset_at_state(CODE, 0, 600, EndSource::Policy)
    );
    // Already zero: nothing changes.
    sender.on_stop_sending(OTHER_CODE);
    assert_eq!(
        sender.end_state(),
        reset_at_state(CODE, 0, 600, EndSource::Policy)
    );

    // An abandoned writer of an open stream: RESET_STREAM.
    let mut sender = default_sender(&connection, 1000);
    write_all(&mut sender, 100);
    sender.on_writer_abandoned();
    assert!(matches!(
        sender.end_state(),
        SendEndState::Reset {
            target: LocalResetAt::Reset(_),
            source: EndSource::Policy,
        }
    ));
}
