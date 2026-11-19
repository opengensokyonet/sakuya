//! Which NEW_TOKEN tokens a server issues and writes, when they wait again,
//! and that a client's writes nothing.

use core::{cell::Cell, marker::PhantomData, num::NonZeroUsize};

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

const SPACE: PacketNumberSpaceKind = PacketNumberSpaceKind::ApplicationData;

/// Issues `token-n` for the n-th token asked, counted from 1, for the peer
/// `true`; nothing for the peer `false`, which it cannot bind a token to,
/// and nothing while it fails.
#[derive(Debug, Default)]
struct Counting {
    asked: Cell<u32>,
    failing: Cell<bool>,
}

impl ConnectionNewTokenIssuer<bool> for Counting {
    fn issue(&self, binds: &bool) -> Option<Bytes> {
        if !*binds || self.failing.get() {
            return None;
        }
        self.asked.set(self.asked.get() + 1);
        Some(Bytes::from(format!("token-{}", self.asked.get())))
    }
}

/// The tokens `source` writes into a 1-RTT packet of `room` bytes, as the
/// peer reads them, and the summaries the packet's record keeps of them.
fn written<S>(source: &mut S, room: usize) -> (Vec<Bytes>, Vec<NewTokenSummary>)
where
    S: for<'a> FrameSource<Item<'a> = (), Summary = NewTokenSummary, Class = InFlightClass>,
{
    type Summary = Coproduct<FeedbackSummary<u64>, CNil>;
    let (keys, receiver) = one_rtt_keys();
    let mut journals = DequeSendJournals::<u64, Summary, ()>::new();
    let mut usage = AeadUsage::new();
    let mut accounts = Accounts::new();
    let mut batch = Batch::new(NonZeroUsize::MIN);
    {
        let mut datagram = accounts.start(&mut batch, Role::Server, room, room, false);
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
        .filter_map(|summary| match summary {
            Coproduct::Inl(summary) => summary.get::<NewTokenSummary, _>().copied(),
            Coproduct::Inr(never) => match never {},
        })
        .collect();
    let Some(datagram) = batch.datagrams().next() else {
        return (Vec::new(), summaries);
    };
    let mut packet = BytesMut::from(datagram);
    let (opened, _) =
        open_one_rtt(receiver.receive().unwrap(), None, &mut packet, 9, None).unwrap();
    let payload = &packet[opened.payload.clone()];
    let tokens = Frames::new(payload, PhantomData::<HList![sakuya_wire::v1::Part]>)
        .filter_map(|run| match run.unwrap().extract() {
            FrameRun::NewToken(frame) => Some(Bytes::copy_from_slice(frame.token())),
            _ => None,
        })
        .collect();
    (tokens, summaries)
}

fn token(n: u32) -> Bytes {
    Bytes::from(format!("token-{n}"))
}

#[test]
fn an_issued_token_waits_and_is_written_once() {
    let mut source = NewTokenSource::new(Counting::default());
    assert_eq!(source.intent(), None);
    assert!(source.issue(&true).is_some());
    let intent = source.intent().expect("the token waits");
    assert_eq!(intent.frame_len(), 1 + 1 + token(1).len());
    let (tokens, summaries) = written(&mut source, 1200);
    assert_eq!(tokens, [token(1)]);
    assert_eq!(summaries, [NewTokenSummary { number: 0 }]);
    assert_eq!(source.intent(), None, "in flight, it does not wait");
    assert_eq!(written(&mut source, 1200).0, Vec::<Bytes>::new());
}

#[test]
fn a_lost_token_waits_again_until_it_is_delivered() {
    let mut source = NewTokenSource::new(Counting::default());
    let _ = source.issue(&true);
    let (_, summaries) = written(&mut source, 1200);
    FrameSource::lost(&mut source, SPACE, &summaries[0]);
    assert!(source.intent().is_some());
    assert_eq!(written(&mut source, 1200).0, [token(1)]);
    FrameSource::delivered(&mut source, SPACE, summaries[0]);
    assert_eq!(source.intent(), None);
    // a copy lost after one was delivered is not sent again
    FrameSource::lost(&mut source, SPACE, &summaries[0]);
    assert_eq!(source.intent(), None);
    assert_eq!(written(&mut source, 1200).0, Vec::<Bytes>::new());
}

#[test]
fn a_peer_the_issuer_cannot_bind_a_token_to_gets_none() {
    let mut source = NewTokenSource::new(Counting::default());
    assert!(source.issue(&false).is_none());
    assert_eq!(source.intent(), None);
    assert_eq!(written(&mut source, 1200).0, Vec::<Bytes>::new());
}

#[test]
fn no_token_is_sent_when_the_issuer_fails() {
    let issuer = Counting::default();
    issuer.failing.set(true);
    let mut source = NewTokenSource::new(issuer);
    assert!(source.issue(&true).is_none());
    assert_eq!(source.intent(), None);
    source.issuer().failing.set(false);
    assert!(source.issue(&true).is_some());
    assert_eq!(written(&mut source, 1200).0, [token(1)]);
}

#[test]
fn the_waiting_tokens_go_in_order_as_far_as_they_fit() {
    let mut source = NewTokenSource::new(Counting::default());
    let _ = source.issue(&true);
    let _ = source.issue(&true);
    let (tokens, summaries) = written(&mut source, 1200);
    assert_eq!(tokens, [token(1), token(2)]);
    assert_eq!(
        summaries,
        [NewTokenSummary { number: 0 }, NewTokenSummary { number: 1 }]
    );
    FrameSource::lost(&mut source, SPACE, &summaries[1]);
    assert_eq!(written(&mut source, 1200).0, [token(2)]);
}

#[test]
fn the_oldest_token_goes_once_more_are_kept() {
    let mut source = NewTokenSource::new(Counting::default());
    for _ in 0..=KEPT_TOKENS {
        let _ = source.issue(&true);
    }
    let (tokens, _) = written(&mut source, 1200);
    assert_eq!(tokens, (2..=5).map(token).collect::<Vec<_>>());
}

#[test]
fn a_client_writes_no_token() {
    let mut tokens = NoNewTokens;
    assert!(NewTokenIssuance::<bool>::issue_for(&mut tokens, &true).is_none());
    assert_eq!(written(&mut tokens, 1200), (Vec::new(), Vec::new()));
}
