//! A frame of the peer that releases connection credit makes MAX_DATA due,
//! and the set publishes it with the frame, in both sets.
//!
//! The scenario goes through the operations of [`StreamSet`] only: the
//! peer's unidirectional stream 3 brings 10 bytes, the application accepts
//! it and drops its reader, and then a frame of the peer moves the stream's
//! end to 60 bytes. With the reader gone the data is released as it is
//! accounted, so the connection's released progress reaches 60, and the
//! sliding window of 100 makes the limit 160 due (RFC 9000 §4.2). No
//! operation of the application follows that would bring the intent up to
//! date, so a set that publishes it later leaves the peer without credit.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use core::task::{Context, Poll, Waker};
use sakuya_stream_sets::resets::{Rfc9000StreamResets, StreamResets};
use sakuya_stream_v1::send_options::{destination::AnyActiveLinkPath, urgency::Urgency};
use sakuya_var_int::{VarInt, VarIntField};
use sakuya_wire::parts::Coproduct;
use sakuya_wire_v1::{
    application_error::ApplicationErrorCode,
    encryption_level::EncryptionLevel,
    frame::{reset_stream::ResetStreamFrame, stream::StreamFrame},
    role::Role,
    stream_count::StreamCount,
    stream_id::{Directionality, StreamId},
    transport_parameters::integer::{
        InitialMaxData, InitialMaxStreamDataBidiLocal, InitialMaxStreamDataBidiRemote,
        InitialMaxStreamDataUni, InitialMaxStreamsBidi, InitialMaxStreamsUni,
    },
};

use super::{
    FlowControlParameters, StreamReaderCredential, StreamSet, StreamSetFacts,
    locked::{LockedStreamSet, LockedStreamSetConfig, tests::TestTypes},
    owned::{OwnedStreamSet, OwnedStreamSetConfig},
    send::{StreamIntent, StreamIntentKey},
    test_resets::{ExtensionTestResets, TestResetFrame},
};
use crate::{
    send_strategy::{
        IntentPublisher, IntentTicketResize, IntentTicketWithdraw, MinimumLengths,
        ranked::{KeyIntentTicket, PublisherChange, RankedSendPublisher},
    },
    v1::events::NoEvents,
};

/// The frame of the peer that follows the dropped reader.
#[derive(Clone, Copy, Debug)]
enum Then {
    /// 50 more bytes at offset 10.
    Data,
    /// RESET_STREAM with the final size 60.
    ResetStream,
    /// The extension's reset frame with the final size 60.
    ResetFrame,
}

fn v(value: u32) -> VarInt {
    VarInt::from_u32(value)
}

fn count(value: u64) -> StreamCount {
    StreamCount::new(value).expect("a small count")
}

/// The peer's unidirectional stream the scenario runs on.
fn stream() -> StreamId {
    StreamId::from(v(3))
}

fn stream_frame(offset: u32, len: usize) -> StreamFrame<Bytes> {
    let offset = (offset > 0).then(|| VarIntField::shortest(v(offset)));
    StreamFrame::new(
        VarIntField::shortest(stream()),
        offset,
        Bytes::from(vec![7; len]),
        false,
    )
    .expect("a short frame")
    .into_without_length()
    .into()
}

fn reset_stream(final_size: u32) -> ResetStreamFrame {
    ResetStreamFrame::new(
        VarIntField::shortest(stream()),
        VarIntField::shortest(ApplicationErrorCode::new(v(2))),
        VarIntField::shortest(v(final_size)),
    )
}

/// The facts of a client that grants the server 100 bytes of the
/// connection and 60 of each unidirectional stream.
fn facts<S>(peer_reset_support: S) -> StreamSetFacts<S> {
    let granted_to_peer = FlowControlParameters {
        initial_max_data: InitialMaxData::new(v(100)),
        initial_max_stream_data_bidi_local: InitialMaxStreamDataBidiLocal::new(v(60)),
        initial_max_stream_data_bidi_remote: InitialMaxStreamDataBidiRemote::new(v(60)),
        initial_max_stream_data_uni: InitialMaxStreamDataUni::new(v(60)),
        initial_max_streams_bidi: InitialMaxStreamsBidi::new(count(3)),
        initial_max_streams_uni: InitialMaxStreamsUni::new(count(3)),
    };
    StreamSetFacts {
        role: Role::Client,
        granted_to_peer,
        granted_by_peer: FlowControlParameters::default(),
        peer_reset_support,
    }
}

/// Run the scenario on `set` up to the dropped reader, then call `clear`,
/// and take the frame `then` of the peer, made by `reset_frame` when it is
/// the extension's.
fn run<X, Rs>(
    set: &mut X,
    publish: &mut RankedSendPublisher<TestTypes>,
    then: Then,
    reset_frame: impl FnOnce(ResetStreamFrame) -> Option<Rs::ResetFrame>,
    clear: impl FnOnce(&mut RankedSendPublisher<TestTypes>),
) where
    X: StreamSet<(), TestTypes, Rs, SendParameters = Urgency>,
    Rs: StreamResets,
{
    set.on_stream_frame(publish, EncryptionLevel::OneRtt, stream_frame(0, 10))
        .expect("within the limits");
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        set.poll_accept_held(&mut cx, Directionality::Unidirectional),
        Poll::Ready(Ok(accepted)) if accepted == stream()
    ));
    set.reclaim_reader(publish, StreamReaderCredential::new(stream()));
    clear(publish);
    match then {
        Then::Data => set.on_stream_frame(publish, EncryptionLevel::OneRtt, stream_frame(10, 50)),
        Then::ResetStream => set.on_reset_stream(publish, reset_stream(60)),
        Then::ResetFrame => set.on_reset_frame(
            publish,
            reset_frame(reset_stream(60)).expect("the kind has a frame"),
        ),
    }
    .expect("within the limits");
}

/// The keys of the intents the strategy's publisher took since the last
/// call.
fn published_through(publish: &mut RankedSendPublisher<TestTypes>) -> Vec<StreamIntentKey> {
    publish
        .take_changes()
        .into_iter()
        .filter_map(|change| match change {
            PublisherChange::Published { intent, .. } => Some(match intent {
                Coproduct::Inl(Coproduct::Inl(intent)) => intent.key(),
                Coproduct::Inl(Coproduct::Inr(never)) | Coproduct::Inr(never) => match never {},
            }),
            _ => None,
        })
        .collect()
}

// ---- the owned set, which publishes through the strategy's publisher ----

fn owned_publishes_max_data<Rs>(
    support: Rs::PeerSupport,
    then: Then,
    reset_frame: impl FnOnce(ResetStreamFrame) -> Option<Rs::ResetFrame>,
) where
    Rs: StreamResets,
    OwnedStreamSet<(), KeyIntentTicket, Rs>: StreamSet<
            (),
            TestTypes,
            Rs,
            SendParameters = Urgency,
            Config = OwnedStreamSetConfig,
            Events = NoEvents,
            Intake = (),
        >,
{
    let mut set = <OwnedStreamSet<(), KeyIntentTicket, Rs> as StreamSet<(), TestTypes, Rs>>::new(
        facts(support),
        OwnedStreamSetConfig::default(),
        NoEvents,
        (),
    );
    let mut publish = RankedSendPublisher::default();
    run(&mut set, &mut publish, then, reset_frame, |publish| {
        publish.take_changes();
    });
    let published = published_through(&mut publish);
    assert!(
        published.contains(&StreamIntentKey::MaxData),
        "the frame that released credit has MAX_DATA sent: {published:?}"
    );
}

#[test]
fn owned_data_released_by_a_stream_frame_has_max_data_sent() {
    owned_publishes_max_data::<Rfc9000StreamResets>((), Then::Data, |_| None);
}

#[test]
fn owned_data_released_by_a_reset_stream_has_max_data_sent() {
    owned_publishes_max_data::<Rfc9000StreamResets>((), Then::ResetStream, |_| None);
}

#[test]
fn owned_data_released_by_the_kinds_reset_frame_has_max_data_sent() {
    owned_publishes_max_data::<ExtensionTestResets>(true, Then::ResetFrame, |frame| {
        Some(TestResetFrame(frame))
    });
}

// ---- the locked set, which publishes through its own intake ----

/// A ticket that does nothing.
#[derive(Debug)]
struct Ticket;

impl IntentTicketResize for Ticket {
    fn resize(&mut self, _: MinimumLengths) {}
}

impl IntentTicketWithdraw for Ticket {
    type Report = ();

    fn withdraw(self) {}
}

/// An intake that records the keys of the intents published through it;
/// its clones share the record.
#[derive(Debug, Clone, Default)]
struct Intake {
    published: Arc<Mutex<Vec<StreamIntentKey>>>,
}

impl Intake {
    /// The keys published since the last call.
    fn published(&self) -> Vec<StreamIntentKey> {
        core::mem::take(&mut *self.published.lock().expect("not poisoned"))
    }
}

impl IntentPublisher<StreamIntent<Urgency>, AnyActiveLinkPath> for Intake {
    type Ticket = Ticket;

    fn publish_to(&mut self, intent: StreamIntent<Urgency>, _: AnyActiveLinkPath) -> Ticket {
        self.published
            .lock()
            .expect("not poisoned")
            .push(intent.key());
        Ticket
    }

    fn resize(&mut self, ticket: &mut Ticket, min: MinimumLengths) {
        ticket.resize(min);
    }

    fn withdraw(&mut self, ticket: Ticket) {
        ticket.withdraw();
    }

    fn release_written(&mut self, _: Ticket) {}

    fn waits_too_large(&self, _: &Ticket) -> bool {
        false
    }
}

fn locked_publishes_max_data<Rs>(
    support: Rs::PeerSupport,
    then: Then,
    reset_frame: impl FnOnce(ResetStreamFrame) -> Option<Rs::ResetFrame>,
) where
    Rs: StreamResets,
    LockedStreamSet<(), Ticket, Intake, Rs>: StreamSet<
            (),
            TestTypes,
            Rs,
            SendParameters = Urgency,
            Config = LockedStreamSetConfig,
            Events = NoEvents,
            Intake = Intake,
        >,
{
    let intake = Intake::default();
    let mut set = <LockedStreamSet<(), Ticket, Intake, Rs> as StreamSet<(), TestTypes, Rs>>::new(
        facts(support),
        LockedStreamSetConfig::default(),
        NoEvents,
        intake.clone(),
    );
    let mut publish = RankedSendPublisher::default();
    run(&mut set, &mut publish, then, reset_frame, |_| {
        intake.published();
    });
    let published = intake.published();
    assert!(
        published.contains(&StreamIntentKey::MaxData),
        "the frame that released credit has MAX_DATA sent: {published:?}"
    );
}

#[test]
fn locked_data_released_by_a_stream_frame_has_max_data_sent() {
    locked_publishes_max_data::<Rfc9000StreamResets>((), Then::Data, |_| None);
}

#[test]
fn locked_data_released_by_a_reset_stream_has_max_data_sent() {
    locked_publishes_max_data::<Rfc9000StreamResets>((), Then::ResetStream, |_| None);
}

#[test]
fn locked_data_released_by_the_kinds_reset_frame_has_max_data_sent() {
    locked_publishes_max_data::<ExtensionTestResets>(true, Then::ResetFrame, |frame| {
        Some(TestResetFrame(frame))
    });
}
