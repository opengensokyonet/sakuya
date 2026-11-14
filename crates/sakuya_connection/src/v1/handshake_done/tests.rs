//! When a server's HANDSHAKE_DONE is published, written and sent again,
//! and that a client's writes nothing.

use core::{marker::PhantomData, num::NonZeroUsize};

use bytes::BytesMut;
use sakuya_recovery::send_journals::{DequeSendJournals, SendJournals as _};
use sakuya_wire::{
    parts::{CNil, Coproduct, HList},
    v1::{
        frame::{FrameRun, set::Frames},
        role::Role,
    },
};

use super::*;
use crate::v1::{
    aead_usage::AeadUsage,
    datagram_batch::tests::{Accounts, Batch, one_rtt_keys},
    feedback::FeedbackSummary,
    receive::open_one_rtt,
};

/// What the frame source publishes, in order.
#[derive(Debug, Default)]
struct Published(Vec<HandshakeDoneIntent>);

impl PublishIntent<HandshakeDoneIntent, ()> for Published {
    fn publish(&mut self, intent: HandshakeDoneIntent) {
        self.0.push(intent);
    }
}

const SPACE: PacketNumberSpaceKind = PacketNumberSpaceKind::ApplicationData;

#[test]
fn the_frame_is_published_once_when_it_becomes_due() {
    let mut source = HandshakeDoneSource::NotDue;
    let mut published = Published::default();
    source.due::<_, ()>(&mut published);
    source.due::<_, ()>(&mut published);
    assert_eq!(source, HandshakeDoneSource::Due);
    assert_eq!(published.0, [HandshakeDoneIntent]);
}

#[test]
fn a_lost_frame_is_published_again_until_one_is_delivered() {
    let mut source = HandshakeDoneSource::Due;
    let mut published = Published::default();
    FrameSource::lost::<_, ()>(&mut source, &mut published, SPACE, &HandshakeDoneSummary);
    assert_eq!(published.0, [HandshakeDoneIntent]);
    FrameSource::delivered::<_, ()>(&mut source, &mut published, SPACE, HandshakeDoneSummary);
    assert_eq!(source, HandshakeDoneSource::Delivered);
    // another copy lost after one was delivered is not sent again
    FrameSource::lost::<_, ()>(&mut source, &mut published, SPACE, &HandshakeDoneSummary);
    assert_eq!(published.0, [HandshakeDoneIntent]);
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
    let frames = Frames::new(payload, PhantomData::<HList![sakuya_wire::v1::Part]>)
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
    let mut source = HandshakeDoneSource::Due;
    assert_eq!(
        frames_written(&mut source),
        (vec!["HANDSHAKE_DONE".to_owned()], 1)
    );
}

#[test]
fn a_client_writes_nothing() {
    let mut own = ClientOnlyState;
    assert_eq!(frames_written(&mut own), (Vec::new(), 0));
}
