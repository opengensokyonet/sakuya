//! When a server's HANDSHAKE_DONE waits, is written and waits again, and
//! that a client's writes nothing.

use core::{marker::PhantomData, num::NonZeroUsize};

use bytes::BytesMut;
use sakuya_recovery_v1::send_journals::{DequeSendJournals, SendJournals as _};
use sakuya_wire::parts::{CNil, Coproduct, HList};
use sakuya_wire_v1::{
    frame::{FrameRun, set::Frames},
    role::Role,
};

use super::*;
use crate::v1::retry::{ClientRetryPolicy, ContinueOnRetry, ReceivedRetry, RetryDecision};
use crate::v1::{
    aead_usage::AeadUsage,
    datagram_batch::tests::{Accounts, Batch, one_rtt_keys},
    feedback::FeedbackSummary,
    receive::open_one_rtt,
};

const SPACE: PacketNumberSpaceKind = PacketNumberSpaceKind::ApplicationData;

#[test]
fn the_frame_waits_once_it_becomes_due() {
    let mut source = HandshakeDoneSource::NotDue;
    assert!(!source.is_waiting());
    assert!(source.due().is_some());
    assert!(source.is_waiting());
    source = HandshakeDoneSource::InFlight;
    assert!(source.due().is_none());
    assert_eq!(source, HandshakeDoneSource::InFlight, "due once only");
}

#[test]
fn a_lost_frame_waits_again_until_one_is_delivered() {
    let mut source = HandshakeDoneSource::Waiting;
    assert_eq!(frames_written(&mut source).0, ["HANDSHAKE_DONE"]);
    assert_eq!(source, HandshakeDoneSource::InFlight);
    FrameSource::lost(&mut source, SPACE, &HandshakeDoneSummary);
    assert!(source.is_waiting());
    assert_eq!(frames_written(&mut source).0, ["HANDSHAKE_DONE"]);
    FrameSource::delivered(&mut source, SPACE, HandshakeDoneSummary);
    assert_eq!(source, HandshakeDoneSource::Delivered);
    // another copy lost after one was delivered is not sent again
    FrameSource::lost(&mut source, SPACE, &HandshakeDoneSummary);
    assert_eq!(source, HandshakeDoneSource::Delivered);
}

#[test]
fn a_frame_that_does_not_wait_is_not_written() {
    for mut source in [
        HandshakeDoneSource::NotDue,
        HandshakeDoneSource::InFlight,
        HandshakeDoneSource::Delivered,
    ] {
        assert_eq!(frames_written(&mut source), (Vec::new(), 0));
    }
}

/// The frames `source` writes into a 1-RTT packet, as the peer reads them,
/// and the number of summaries the packet's record keeps of them.
fn frames_written<S>(source: &mut S) -> (Vec<String>, usize)
where
    S: for<'a> FrameSource<Item<'a> = (), Summary = HandshakeDoneSummary, Class = InFlightClass>,
{
    type Summary = Coproduct<FeedbackSummary<u64>, CNil>;
    let (keys, receiver) = one_rtt_keys();
    let mut journals = DequeSendJournals::<u64, Summary, ()>::new();
    let mut usage = AeadUsage::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, 1200, 1200, false);
        let packet = datagram
            .start_one_rtt_packet(
                journals.start_attempt(()),
                keys.send().unwrap(),
                &mut usage,
                None,
            )
            .unwrap();
        let _ = source.supply((), packet.open::<InFlightClass>());
    }
    let summaries = journals
        .take_link_path(&())
        .flat_map(|record| record.summaries)
        .filter(|summary| match summary {
            Coproduct::Inl(summary) => summary.get::<HandshakeDoneSummary, _>().is_some(),
            Coproduct::Inr(never) => match *never {},
        })
        .count();
    let Some(datagram) = batch.datagrams().next() else {
        return (Vec::new(), summaries);
    };
    let mut packet = BytesMut::from(datagram);
    let (opened, _) =
        open_one_rtt(receiver.receive().unwrap(), None, &mut packet, 9, None).unwrap();
    let payload = &packet[opened.payload.clone()];
    let frames = Frames::new(payload, PhantomData::<HList![sakuya_wire_v1::Part]>)
        .map(|run| match run.unwrap().extract() {
            FrameRun::HandshakeDone(_) => "HANDSHAKE_DONE".to_owned(),
            other => format!("{other:?}"),
        })
        .filter(|frame| !frame.starts_with("Padding"))
        .collect();
    (frames, summaries)
}

#[test]
fn a_server_writes_the_frame_it_is_given() {
    let mut source = HandshakeDoneSource::Waiting;
    assert_eq!(
        frames_written(&mut source),
        (vec!["HANDSHAKE_DONE".to_owned()], 1)
    );
}

fn client_own(sink: &RecordedTokens) -> ClientOnlyState<&RecordedTokens, ContinueOnRetry, ()> {
    ClientOnlyState {
        initial_token: Bytes::from_static(b"token"),
        sink,
        retry_policy: ContinueOnRetry,
        received: VecDeque::new(),
        connector: (),
    }
}

/// The tokens handed to the sink, in order.
#[derive(Debug, Default)]
struct RecordedTokens(core::cell::RefCell<Vec<Bytes>>);

impl AddressTokenSink for RecordedTokens {
    fn keep(&self, token: Bytes) {
        self.0.borrow_mut().push(token);
    }
}

#[test]
fn a_client_writes_nothing() {
    let sink = RecordedTokens::default();
    let mut own = client_own(&sink);
    assert_eq!(frames_written(&mut own), (Vec::new(), 0));
}

#[test]
fn a_client_hands_each_token_over_once() {
    let sink = RecordedTokens::default();
    let mut own = client_own(&sink);
    let token = |byte: u8| Bytes::from(vec![byte; 4]);
    own.new_token(token(1));
    own.new_token(token(2));
    // sent again after it was declared lost
    own.new_token(token(1));
    assert_eq!(*sink.0.borrow(), [token(1), token(2)]);
    // the token received last are remembered, not every one
    for byte in 3..=6 {
        own.new_token(token(byte));
    }
    own.new_token(token(1));
    assert_eq!(sink.0.borrow().len(), 7);
    // the Initial packets go on with the token they started with
    assert_eq!(own.initial_token(), &Bytes::from_static(b"token"));
}

/// Gives every Retry up.
struct AbandonOnRetry;

impl ClientRetryPolicy for AbandonOnRetry {
    fn decide(&mut self, _: &ReceivedRetry) -> RetryDecision {
        RetryDecision::Abandon
    }
}

#[test]
fn a_client_carries_the_token_of_a_retry_it_goes_on_after() {
    let sink = RecordedTokens::default();
    let retry = ReceivedRetry::new(
        sakuya_wire::connection_id::ConnectionId::new(&[9; 8]).unwrap(),
        5,
        None,
    );
    let mut own = client_own(&sink);
    assert_eq!(
        own.retry(&retry, Bytes::from_static(b"retry")),
        RetryDecision::Continue
    );
    assert_eq!(own.initial_token(), &Bytes::from_static(b"retry"));
    // the token of a Retry is not one to keep for later connections
    assert!(sink.0.borrow().is_empty());

    let mut given_up = ClientOnlyState {
        initial_token: Bytes::from_static(b"token"),
        sink: &sink,
        retry_policy: AbandonOnRetry,
        received: VecDeque::new(),
        connector: (),
    };
    assert_eq!(
        given_up.retry(&retry, Bytes::from_static(b"retry")),
        RetryDecision::Abandon
    );
    assert_eq!(given_up.initial_token(), &Bytes::from_static(b"token"));
}
