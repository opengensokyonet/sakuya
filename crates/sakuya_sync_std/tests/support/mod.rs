//! A link and packets for the tests: only the link's identity takes part
//! in routing.

use std::convert::Infallible;
use std::future::Pending;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sakuya_link::{
    ArrivalFacts, BindingId, Link, LinkId, MIN_DATAGRAM_SIZE, OutgoingDatagram, ReceivedDatagram,
    SendAcceptance,
};

/// This side's end of a test link.
pub type Local = u32;
/// The peer's end of a test link.
pub type Peer = u32;
/// A datagram of the tests.
pub type Datagram = ReceivedDatagram<Vec<u8>, TestLink>;

/// A link of the tests, which never receives and whose sends never
/// complete.
#[derive(Clone, Debug)]
pub struct TestLink(LinkId<Local, Peer>);

impl Link for TestLink {
    type Local = Local;
    type Peer = Peer;
    type Payload = Vec<u8>;
    type Instant = Duration;
    type MaxDatagramSizeError = Infallible;
    type SendError = Infallible;
    type RecvError = Infallible;
    type Recv<'a>
        = Pending<Result<ReceivedDatagram<Self::Payload, Self>, Infallible>>
    where
        Self: 'a;
    type Ended = Pending<Infallible>;
    type Send<'a> = Pending<Result<SendAcceptance<Duration>, Infallible>>;
    type MaxDatagramSizeChanged = Pending<()>;

    fn id(&self) -> &LinkId<Local, Peer> {
        &self.0
    }

    fn may_mark_ecn(&self) -> bool {
        false
    }

    fn max_datagram_size(&self) -> Result<usize, Infallible> {
        Ok(MIN_DATAGRAM_SIZE)
    }

    fn recv(&self) -> Self::Recv<'_> {
        std::future::pending()
    }

    fn ended(&self) -> Self::Ended {
        std::future::pending()
    }

    fn send<'a>(&self, _batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        std::future::pending()
    }

    fn max_datagram_size_changed(&self) -> Pending<()> {
        std::future::pending()
    }
}

static NEXT_PEER: AtomicU32 = AtomicU32::new(1);

/// A new link from the local end `local`, with a peer end no other link of
/// this function has.
pub fn link(local: Local) -> TestLink {
    TestLink(LinkId::new::<TestLink>(
        local,
        NEXT_PEER.fetch_add(1, Ordering::Relaxed),
        &BindingId::new(),
    ))
}

/// `bytes` as they arrived on `link`.
pub fn datagram(bytes: Vec<u8>, link: &TestLink) -> Datagram {
    ReceivedDatagram::new(bytes, ArrivalFacts::new(link.clone(), Duration::ZERO, None))
}

/// A version 1 0-RTT packet with the eight-byte connection IDs `dcid` and
/// `scid`, a two-byte packet number and `payload` protected bytes.
pub fn zero_rtt(dcid: [u8; 8], scid: [u8; 8], payload: u8) -> Vec<u8> {
    // long header, fixed bit, 0-RTT, a two-byte packet number
    let mut packet = vec![0x80 | 0x40 | (0b01 << 4) | 0x01];
    packet.extend(1_u32.to_be_bytes());
    packet.push(8);
    packet.extend(dcid);
    packet.push(8);
    packet.extend(scid);
    let length = 2 + payload;
    assert!(
        length < 64,
        "the length fits a one-byte variable-length integer"
    );
    packet.push(length);
    packet.extend(std::iter::repeat_n(0xa5, usize::from(length)));
    packet
}
