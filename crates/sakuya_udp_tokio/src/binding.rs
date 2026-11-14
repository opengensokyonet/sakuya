//! The binding: one UDP socket, with the links of its peers.

use core::{
    future::{Future, Ready},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::pin,
};
use std::{mem, sync::Arc};

use futures_util::future::{Either, select};
use sakuya_clock::MonotonicClock;
use sakuya_link::{AcceptingLinkBinding, BindingId, ConnectingLinkBinding, LinkBinding};
use snafu::{ResultExt, Snafu};

use crate::{
    SocketFailedError, UdpLink, UdpLocal,
    shared::{Shared, new_entry},
    sys::{self, BindError, RegisterSnafu},
};

/// How a [`UdpBinding`] binds and what it keeps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpBindingConfig {
    /// The address to bind. An IPv6 socket on the unspecified address takes
    /// IPv4 too, and each link's local address is the one its datagrams
    /// arrive at.
    pub address: SocketAddr,
    /// Whether datagrams from a peer with no link make a new link for
    /// [`accept`](AcceptingLinkBinding::accept). Without it, the binding
    /// only reaches the peers it is asked to connect to and drops the
    /// datagrams of any other. Default: `true`.
    pub accept_new_peers: bool,
    /// How many new links may wait to be accepted; datagrams from further
    /// new peers are dropped meanwhile. Default: 1024.
    pub max_unaccepted_links: usize,
    /// How many datagrams may wait in one link to be received; more are
    /// dropped. Default: 256.
    pub max_queued_datagrams: usize,
    /// The MTU of the interfaces, from which each link's datagram size
    /// limit is taken. Default: 1500.
    pub interface_mtu: usize,
}

impl UdpBindingConfig {
    /// The configuration that binds `address`, with the defaults for the
    /// rest.
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            accept_new_peers: true,
            max_unaccepted_links: 1024,
            max_queued_datagrams: 256,
            interface_mtu: 1500,
        }
    }
}

/// A link could not be set up by [`UdpBinding::connect`].
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ConnectError {
    /// The peer's IP version is one the socket cannot reach: an IPv6 peer
    /// on an IPv4 socket, or an IPv4 peer on an IPv6 socket bound to a
    /// specific address.
    #[snafu(display("the socket cannot reach {peer}"))]
    Unreachable {
        /// The peer.
        peer: SocketAddr,
    },
    /// The socket is on the unspecified address, and the local address the
    /// kernel would send to the peer from could not be found.
    #[snafu(display("no local address routes to {peer}"))]
    NoRoute {
        /// The peer.
        peer: SocketAddr,
        /// The error of the lookup.
        source: std::io::Error,
    },
    /// The socket failed.
    #[snafu(display("the binding has ended"), context(false))]
    Ended {
        /// Why the socket failed.
        source: SocketFailedError,
    },
}

/// A UDP socket as a link binding: each peer it exchanges datagrams with,
/// from each local address, is one [`UdpLink`].
///
/// Its links report instants on `C`, the clock the endpoint composed with
/// them uses as well.
///
/// The socket does not fragment: IPv4 datagrams carry DF and IPv6 ones are
/// not fragmented locally, and neither follows the path MTU the kernel
/// learns from ICMP. It reads the ECN codepoint of what arrives, marks what
/// it sends, and batches with GSO and GRO when the kernel can. Linux only.
pub struct UdpBinding<C: MonotonicClock + 'static> {
    shared: Arc<Shared<C>>,
}

impl<C: MonotonicClock + 'static> UdpBinding<C> {
    /// Binds a socket as `config` says; its links read `clock`.
    ///
    /// # Errors
    ///
    /// The socket could not be opened, set up, bound, or registered with
    /// the runtime.
    ///
    /// # Panics
    ///
    /// Panics outside a tokio runtime with its IO driver enabled, as
    /// [`tokio::net::UdpSocket::from_std`] does.
    pub fn bind(config: UdpBindingConfig, clock: C) -> Result<Self, BindError> {
        let opened = sys::open(config.address)?;
        let shared = Shared::new(opened, config, clock).context(RegisterSnafu)?;
        Ok(Self {
            shared: Arc::new(shared),
        })
    }

    /// The address the socket is bound to, with the port the kernel chose
    /// when the configuration asked for port 0.
    #[must_use]
    pub fn local_address(&self) -> SocketAddr {
        self.shared.bound
    }

    async fn take_link(&self) -> Result<UdpLink<C>, SocketFailedError> {
        let shared = &self.shared;
        loop {
            let new_link = pin!(shared.new_link.notified());
            if let Some(end) = shared.end.get() {
                return Err(end.clone());
            }
            if let Some(link) = shared.demux().unaccepted.pop_front() {
                return Ok(link);
            }
            let turn = pin!(shared.reader.acquire());
            if let Either::Right((Ok(permit), _)) = select(new_link, turn).await {
                shared.read(None).await;
                drop(permit);
            }
        }
    }

    fn connect_now(&self, peer: SocketAddr) -> Result<UdpLink<C>, ConnectError> {
        let shared = &self.shared;
        if let Some(end) = shared.end.get() {
            return Err(end.clone().into());
        }
        let peer = sys::canonical(peer);
        let bound = shared.bound;
        let reachable = match (bound, peer) {
            (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_)) => true,
            (SocketAddr::V6(_), SocketAddr::V4(_)) => bound.ip().is_unspecified(),
            (SocketAddr::V4(_), SocketAddr::V6(_)) => false,
        };
        if !reachable {
            return UnreachableSnafu { peer }.fail();
        }
        let local_ip = if shared.unspecified() {
            route_source(peer).context(NoRouteSnafu { peer })?
        } else {
            bound.ip()
        };
        let key = (local_ip, peer);
        let mut demux = shared.demux();
        let entry = match demux.links.get(&key) {
            Some(entry) => Arc::clone(entry),
            None => {
                let local =
                    UdpLocal::new(shared.id.clone(), SocketAddr::new(local_ip, bound.port()));
                let entry = new_entry::<C>(local, peer, &shared.id);
                demux.links.insert(key, Arc::clone(&entry));
                entry
            }
        };
        Ok(UdpLink::from_entry(entry, shared))
    }
}

/// The local address the kernel would send to `peer` from.
fn route_source(peer: SocketAddr) -> std::io::Result<IpAddr> {
    let any = match peer {
        SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    let probe = std::net::UdpSocket::bind(SocketAddr::new(any, 0))?;
    probe.connect(peer)?;
    Ok(probe.local_addr()?.ip())
}

impl<C: MonotonicClock + 'static> Drop for UdpBinding<C> {
    /// Takes no more new peers, and closes the links not yet accepted.
    fn drop(&mut self) {
        let unaccepted = {
            let mut demux = self.shared.demux();
            demux.accepting = false;
            mem::take(&mut demux.unaccepted)
        };
        drop(unaccepted);
    }
}

impl<C: MonotonicClock + 'static> LinkBinding for UdpBinding<C> {
    type Link = UdpLink<C>;

    fn id(&self) -> &BindingId {
        &self.shared.id
    }
}

impl<C: MonotonicClock + 'static> AcceptingLinkBinding for UdpBinding<C> {
    type AcceptError = SocketFailedError;
    type Accept<'a>
        = impl Future<Output = Result<UdpLink<C>, SocketFailedError>> + 'a
    where
        Self: 'a;

    /// The next link a new peer's datagram made, or the failure of the
    /// socket. A binding configured not to accept new peers never gives
    /// one.
    fn accept(&self) -> Self::Accept<'_> {
        self.take_link()
    }
}

impl<C: MonotonicClock + 'static> ConnectingLinkBinding for UdpBinding<C> {
    type Remote = SocketAddr;
    type ConnectError = ConnectError;
    type Connect<'a>
        = Ready<Result<UdpLink<C>, ConnectError>>
    where
        Self: 'a;

    /// The link to `remote`; it is ready at once. An IPv4 address mapped
    /// into IPv6 is taken as the IPv4 address it is.
    fn connect(&self, remote: SocketAddr) -> Self::Connect<'_> {
        core::future::ready(self.connect_now(remote))
    }
}
