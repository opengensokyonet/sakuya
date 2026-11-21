//! A link for tests: it never sends and never changes its limit.

use core::time::Duration;
use std::net::SocketAddr;

use sakuya_link::{BindingId, Link, LinkId, OutgoingDatagram, SendAcceptance};

/// A link whose local end is a port number and whose peer is an address.
#[derive(Clone, Debug)]
pub(crate) struct TestLink(LinkId<u16, SocketAddr>);

impl TestLink {
    pub(crate) fn new(local: u16, peer: SocketAddr, binding: &BindingId) -> Self {
        Self(LinkId::new::<Self>(local, peer, binding))
    }
}

impl Link for TestLink {
    type Local = u16;
    type Peer = SocketAddr;
    type Payload = Vec<u8>;
    type Instant = Duration;
    type MaxDatagramSizeError = ();
    type SendError = ();
    type RecvError = ();
    type Recv<'a> =
        core::future::Pending<Result<sakuya_link::ReceivedDatagram<Self::Payload, Self>, ()>>;
    type Ended = core::future::Pending<()>;
    type Send<'a> = core::future::Pending<Result<SendAcceptance<Duration>, ()>>;
    type MaxDatagramSizeChanged = core::future::Pending<()>;

    fn id(&self) -> &LinkId<u16, SocketAddr> {
        &self.0
    }

    fn may_mark_ecn(&self) -> bool {
        false
    }

    fn max_datagram_size(&self) -> Result<usize, ()> {
        Ok(1452)
    }

    fn recv(&self) -> Self::Recv<'_> {
        core::future::pending()
    }

    fn ended(&self) -> Self::Ended {
        core::future::pending()
    }

    fn send<'a>(&self, _batch: &'a [OutgoingDatagram]) -> Self::Send<'a> {
        core::future::pending()
    }

    fn max_datagram_size_changed(&self) -> Self::MaxDatagramSizeChanged {
        core::future::pending()
    }
}
