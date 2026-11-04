//! Limit actions of the receive termination policy.
use super::*;

/// A receiver whose policy answers `StopSent` with `on_stop` and everything
/// else with keep, with [0, 500) received and the STOP request sent.
fn stopped_with(
    on_stop: TerminationDecision<&'static str>,
    later: impl FnMut(TerminationEvent, &TerminationView) -> TerminationDecision<&'static str> + 'static,
) -> (
    Receiver<impl ReceiveTerminationPolicy<Reason = &'static str>>,
    ConnectionReceiveFlowController,
) {
    let mut on_stop = Some(on_stop);
    let mut later = later;
    let (mut receiver, mut connection) = new_receiver(scripted(move |event, view| {
        if event == TerminationEvent::StopSent {
            on_stop.take().unwrap()
        } else {
            later(event, view)
        }
    }));
    receiver
        .on_stream_frame(stream(0, 500, false), &mut connection)
        .unwrap();
    receiver.stop(c(1)).unwrap();
    receiver.on_stop_sent().unwrap();
    (receiver, connection)
}

fn delivery_limit(
    reason: &'static str,
    trigger: TerminationEvent,
    remote: Option<RemoteReset>,
) -> ChunkRead {
    Err(ReadError::DeliveryLimitReached {
        reason: SharedTerminationReason::new(reason),
        trigger,
        remote,
    })
}

fn acceptance_limit(
    reason: &'static str,
    trigger: TerminationEvent,
    remote: Option<RemoteReset>,
) -> ChunkRead {
    Err(ReadError::AcceptanceLimitReached {
        reason: SharedTerminationReason::new(reason),
        trigger,
        remote,
    })
}

fn destroyed(
    reason: &'static str,
    trigger: TerminationEvent,
    remote: Option<RemoteReset>,
) -> ChunkRead {
    Err(ReadError::BufferDestroyed {
        reason: SharedTerminationReason::new(reason),
        trigger,
        remote,
    })
}

#[test]
fn fixing_a_following_limit_is_a_change_even_at_the_same_value() {
    let (receiver, _connection) =
        stopped_with(fix_both(500, "stop"), |_, _| TerminationDecision::keep());
    assert_eq!(receiver.acceptance_limit(), BoundaryMode::Fixed(v(500)));
    assert_eq!(receiver.delivery_limit(), BoundaryMode::Fixed(v(500)));
    assert!(
        receiver
            .parts()
            .flow_events
            .contains(&ReceiveFlowEvent::BoundaryChanged)
    );
}

/// The same limits again keep the first reason.
#[test]
fn same_limits_are_idempotent() {
    let (mut receiver, mut connection) =
        stopped_with(fix_both(300, "first"), |event, _| match event {
            TerminationEvent::RemoteReset => fix_both(300, "second"),
            _ => TerminationDecision::keep(),
        });
    let changes = |receiver: &Receiver<_>| {
        receiver
            .parts()
            .flow_events
            .iter()
            .filter(|event| **event == ReceiveFlowEvent::BoundaryChanged)
            .count()
    };
    assert_eq!(changes(&receiver), 1);
    receiver
        .on_reset_stream(reset(4, 1000), &mut connection)
        .unwrap();
    assert_eq!(changes(&receiver), 1);
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read.len(), 300);
    let remote = receiver.remote_reset();
    assert_eq!(
        end,
        delivery_limit("first", TerminationEvent::StopSent, remote)
    );
}

/// A tighter limit records the new reason and trigger; the other limit
/// keeps its own.
#[test]
fn tightening_records_the_new_reason_per_limit() {
    let tighten_delivery_to = |limit: u32| {
        stopped_with(
            restrict(
                BoundaryUpdate::Fix(v(500)),
                BoundaryUpdate::Fix(v(800)),
                "first",
            ),
            move |event, _| match event {
                TerminationEvent::RemoteReset => restrict(
                    BoundaryUpdate::Keep,
                    BoundaryUpdate::Fix(v(limit)),
                    "second",
                ),
                _ => TerminationDecision::keep(),
            },
        )
    };
    // The reset promises the whole stream, so neither its gap rule nor its
    // prefix rule ends the read before the local limits do.
    let whole = reset_at(4, 1000, 1000);

    // Reading ends at the acceptance limit, which kept the first reason.
    let (mut receiver, mut connection) = tighten_delivery_to(700);
    receiver.on_reset_stream_at(whole, &mut connection).unwrap();
    assert_eq!(receiver.delivery_limit(), BoundaryMode::Fixed(v(700)));
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read.len(), 500);
    let remote = receiver.remote_reset();
    assert_eq!(
        end,
        acceptance_limit("first", TerminationEvent::StopSent, remote)
    );

    // Reading ends at the tightened delivery limit, with the second reason.
    let (mut receiver, mut connection) = tighten_delivery_to(400);
    receiver.on_reset_stream_at(whole, &mut connection).unwrap();
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read.len(), 400);
    let remote = receiver.remote_reset();
    assert_eq!(
        end,
        delivery_limit("second", TerminationEvent::RemoteReset, remote)
    );
}

#[test]
fn tightening_the_delivery_limit_releases_held_data() {
    let (mut receiver, mut connection) = stopped_with(
        restrict(BoundaryUpdate::Keep, BoundaryUpdate::Fix(v(200)), "stop"),
        |_, _| TerminationDecision::keep(),
    );
    assert_eq!(receiver.parts().buffer.held_len(), 200);
    // The acceptance limit still follows, but nothing beyond 200 is kept.
    receiver
        .on_stream_frame(stream(500, 100, false), &mut connection)
        .unwrap();
    assert_eq!(receiver.parts().buffer.held_len(), 200);
    assert_eq!(connection.used(), v(600));
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 200));
    assert_eq!(
        end,
        delivery_limit("stop", TerminationEvent::StopSent, None)
    );
}

/// With [0, 100) and [200, 300) held, an acceptance limit at 200 and a
/// delivery limit at 300: filling [100, 200) delivers up to 300, using the
/// range kept earlier, while new data at 300 and above is not kept.
#[test]
fn filling_a_gap_delivers_kept_data_up_to_the_delivery_limit() {
    let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::StopSent => restrict(
            BoundaryUpdate::Fix(v(200)),
            BoundaryUpdate::Fix(v(300)),
            "stop",
        ),
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver
        .on_stream_frame(stream(200, 100, false), &mut connection)
        .unwrap();
    receiver.stop(c(1)).unwrap();
    receiver.on_stop_sent().unwrap();
    receiver
        .on_stream_frame(stream(300, 100, false), &mut connection)
        .unwrap();
    receiver
        .on_stream_frame(stream(100, 100, false), &mut connection)
        .unwrap();
    assert_eq!(receiver.parts().buffer.held_len(), 300);
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 300));
    assert_eq!(
        end,
        delivery_limit("stop", TerminationEvent::StopSent, None)
    );
}

/// A limit below the read position does not take back delivered data.
#[test]
fn limit_below_the_read_position() {
    let mut out = Vec::new();
    let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::StopSent => fix_both(100, "stop"),
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 500, false), &mut connection)
        .unwrap();
    receiver.read_into(&mut (&mut out).limit(300)).unwrap();
    receiver.stop(c(1)).unwrap();
    receiver.on_stop_sent().unwrap();
    assert_eq!(receiver.parts().delivered_end(), v(300));
    assert_eq!(
        receiver.read_chunk(),
        delivery_limit("stop", TerminationEvent::StopSent, None)
    );
}

#[test]
fn policy_destroy_ends_reading_with_its_reason() {
    let (mut receiver, _connection) = stopped_with(destroy("first"), |event, _| match event {
        TerminationEvent::ReadResultCommitted => destroy("second"),
        _ => TerminationDecision::keep(),
    });
    assert!(receiver.parts().buffer.is_destroyed());
    let error = destroyed("first", TerminationEvent::StopSent, None);
    assert_eq!(receiver.read_chunk(), error);
    assert_eq!(receiver.read_chunk(), error);
}

/// A reason that is neither `Clone` nor `Debug`.
struct Unshared(u32);

/// Destroys the receive buffer on a remote reset, for an [`Unshared`] reason.
struct DestroyOnReset;

impl ReceiveTerminationPolicy for DestroyOnReset {
    type Reason = Unshared;

    fn on_termination_event(
        &mut self,
        event: TerminationEvent,
        _view: &TerminationView,
    ) -> TerminationDecision<Unshared> {
        match event {
            TerminationEvent::RemoteReset => TerminationDecision::new(BoundaryAction::Destroy {
                reason: Unshared(7),
            }),
            _ => TerminationDecision::keep(),
        }
    }
}

#[test]
fn repeated_reads_share_one_reason_that_needs_no_clone() {
    let (mut receiver, mut connection) = new_receiver(DestroyOnReset);
    receiver
        .on_reset_stream(reset(4, 1000), &mut connection)
        .unwrap();
    let reason = |receiver: &mut Receiver<DestroyOnReset>| {
        let Err(ReadError::BufferDestroyed { reason, .. }) = receiver.read_chunk() else {
            panic!("expected a destroyed buffer");
        };
        reason
    };
    let first = reason(&mut receiver);
    let second = reason(&mut receiver);
    assert_eq!(first.0, 7);
    assert!(core::ptr::eq(&*first, &*second));
}

#[test]
fn reader_drop_destroys_whatever_the_policy_says() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver.reader_dropped();
    receiver.reader_dropped();
    assert!(receiver.parts().buffer.is_destroyed());
    let events = &receiver.parts().events;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, TerminationEvent::ReaderDropped);
    assert!(events[0].1.destroyed && events[0].1.reader_dropped);
    assert!(events[0].1.stop_allowed);
    assert!(
        receiver
            .parts()
            .flow_events
            .contains(&ReceiveFlowEvent::ReaderDropped)
    );
}

#[test]
fn read_after_reader_drop_fails() {
    let (mut receiver, mut connection) = new_receiver(keep_all());
    receiver
        .on_stream_frame(stream(0, 100, true), &mut connection)
        .unwrap();
    receiver.reader_dropped();
    assert_eq!(receiver.read_chunk(), Err(ReadError::ReaderDropped));
    assert_eq!(
        receiver.read_into(&mut Vec::new()),
        Err(ReadError::ReaderDropped)
    );
    // A later connection close does not reopen reading.
    receiver.connection_closed(close_reason());
    assert_eq!(receiver.read_chunk(), Err(ReadError::ReaderDropped));
}

/// A sent STOP request is a local cancellation: the policy may then give up
/// a reliable prefix, and reading ends with the local reason.
#[test]
fn sent_stop_cancels_the_reliable_prefix() {
    let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::StopSent => fix_both(100, "stop"),
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 200, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
        .unwrap();
    receiver.stop(c(1)).unwrap();
    receiver.on_stop_sent().unwrap();
    assert_eq!(receiver.delivery_limit(), BoundaryMode::Fixed(v(100)));
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 100));
    let remote = receiver.remote_reset();
    assert_eq!(
        end,
        delivery_limit("stop", TerminationEvent::StopSent, remote)
    );
}

/// With the whole reliable prefix received and held, the acceptance limit
/// may drop below it.
#[test]
fn acceptance_below_a_received_prefix() {
    let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
        TerminationEvent::RemoteReset => restrict(
            BoundaryUpdate::Fix(VarInt::ZERO),
            BoundaryUpdate::Keep,
            "prefix complete",
        ),
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 800, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
        .unwrap();
    assert_eq!(
        receiver.acceptance_limit(),
        BoundaryMode::Fixed(VarInt::ZERO)
    );
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read.len(), 800);
    assert_eq!(end, reset_error(4, 1000, 800, false));
}

/// A reset gives a basis: the base-composition style of fixing both limits
/// at the final size keeps reading to the first gap.
#[test]
fn fixing_at_the_final_size_after_a_reset() {
    let (mut receiver, mut connection) = new_receiver(scripted(|event, view| match event {
        TerminationEvent::RemoteReset => fix_both(
            u32::try_from(view.final_size.unwrap().get()).unwrap(),
            "reset",
        ),
        _ => TerminationDecision::keep(),
    }));
    receiver
        .on_stream_frame(stream(0, 100, false), &mut connection)
        .unwrap();
    receiver
        .on_reset_stream_at(reset_at(4, 300, 200), &mut connection)
        .unwrap();
    receiver
        .on_stream_frame(stream(100, 200, false), &mut connection)
        .unwrap();
    let (read, end) = read_all(&mut receiver);
    assert_eq!(read, data(0, 300));
    assert_eq!(end, reset_error(4, 300, 200, true));
}

mod violations {
    use super::*;

    #[test]
    #[should_panic(expected = "raises the fixed delivery limit from 300 to 400")]
    fn raising_a_fixed_limit() {
        let (mut receiver, mut connection) =
            stopped_with(fix_both(300, "stop"), |event, _| match event {
                TerminationEvent::RemoteReset => {
                    restrict(BoundaryUpdate::Keep, BoundaryUpdate::Fix(v(400)), "again")
                }
                _ => TerminationDecision::keep(),
            });
        receiver
            .on_reset_stream(reset(4, 1000), &mut connection)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "without a reset, a sent STOP request or a dropped reader")]
    fn restricting_without_a_basis() {
        let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::DataComplete => fix_both(50, "complete"),
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_stream_frame(stream(0, 100, true), &mut connection)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "without a reset, a sent STOP request or a dropped reader")]
    fn restricting_on_the_stop_request_alone() {
        let (mut receiver, _connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::StopRequested => fix_both(0, "requested"),
            _ => TerminationDecision::keep(),
        }));
        receiver.stop(c(1)).unwrap();
    }

    #[test]
    #[should_panic(expected = "after delivery ended")]
    fn restricting_after_destruction() {
        let (mut receiver, mut connection) =
            stopped_with(destroy("stop"), |event, _| match event {
                TerminationEvent::RemoteReset => fix_both(0, "late"),
                _ => TerminationDecision::keep(),
            });
        receiver
            .on_reset_stream(reset(4, 1000), &mut connection)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "after delivery ended")]
    fn restricting_after_a_committed_result() {
        let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::ReadResultCommitted => fix_both(0, "late"),
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_reset_stream(reset(4, 100), &mut connection)
            .unwrap();
        let _ = receiver.read_chunk();
    }

    #[test]
    #[should_panic(expected = "beyond the final size 1000")]
    fn fixing_beyond_the_final_size() {
        let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::RemoteReset => fix_both(1001, "reset"),
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_reset_stream(reset(4, 1000), &mut connection)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "inside the undelivered reliable prefix 800")]
    fn delivery_inside_the_reliable_prefix() {
        let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::RemoteReset => {
                restrict(BoundaryUpdate::Keep, BoundaryUpdate::Fix(v(300)), "reset")
            }
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "inside the unreceived reliable prefix 800")]
    fn acceptance_inside_an_unreceived_prefix() {
        let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::RemoteReset => {
                restrict(BoundaryUpdate::Fix(v(300)), BoundaryUpdate::Keep, "reset")
            }
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_stream_frame(stream(0, 500, false), &mut connection)
            .unwrap();
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "while the reliable prefix is undelivered")]
    fn destroying_an_undelivered_prefix() {
        let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::RemoteReset => destroy("reset"),
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_reset_stream_at(reset_at(4, 1000, 800), &mut connection)
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "STOP request with code 0x2")]
    fn stop_request_the_protocol_does_not_allow() {
        let (mut receiver, mut connection) = new_receiver(scripted(|event, _| match event {
            TerminationEvent::DataComplete => TerminationDecision::keep().with_stop(c(2)),
            _ => TerminationDecision::keep(),
        }));
        receiver
            .on_stream_frame(stream(0, 100, true), &mut connection)
            .unwrap();
    }

    /// A violating decision changes nothing before the panic: the valid
    /// first limit is not applied when the second is invalid.
    #[test]
    fn no_partial_effect() {
        let (receiver, _connection) =
            stopped_with(fix_both(300, "stop"), |_, _| TerminationDecision::keep());
        let receiver = std::cell::RefCell::new(receiver);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut receiver = receiver.borrow_mut();
            let decision = restrict(
                BoundaryUpdate::Fix(v(200)),
                BoundaryUpdate::Fix(v(400)),
                "bad",
            );
            receiver.apply_decision(TerminationEvent::StopSent, decision);
        }));
        assert!(result.is_err());
        let receiver = receiver.into_inner();
        assert_eq!(receiver.acceptance_limit(), BoundaryMode::Fixed(v(300)));
        assert_eq!(receiver.delivery_limit(), BoundaryMode::Fixed(v(300)));
    }
}
