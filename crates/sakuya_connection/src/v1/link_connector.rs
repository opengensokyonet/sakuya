//! What lets a client's connection take a link of its own: the
//! [`LinkConnector`] its [`Own`](super::Side::Own) data keeps.
//!
//! A connection's links otherwise come only from the datagrams that arrive.
//! A client that migrates to a server's preferred address (RFC 9000 §9.6)
//! needs a link from the local end it already uses to the new server
//! address; whoever makes the connection gives it a connector for that,
//! through the client's [`Start`](super::Side::Start), as it gives the sink
//! of the server's tokens.

use core::{
    convert::Infallible,
    fmt,
    future::{Future, Pending},
    net::SocketAddr,
};

use sakuya_link::Link;

/// Takes links of the type `L` for a connection: from this side's end of
/// a link the connection has, to another peer.
///
/// A link from the local end `x` comes only from a binding that
/// corresponds strictly to `x`, one whose own local end is `x`
/// ([`LinkBinding::local`](sakuya_link::LinkBinding::local)); without such
/// a binding there is no link to take. The connection only hands the
/// [`Error`](Self::Error) to its events.
pub trait LinkConnector<L: Link> {
    /// Why no link was taken.
    type Error: fmt::Display;
    /// The taking of one link, under way.
    type Connect: Future<Output = Result<L, Self::Error>>;

    /// Take a link from the local end of `beside` to `peer`, on the binding
    /// whose own local end is exactly that one.
    fn connect_beside(&self, beside: &L, peer: SocketAddr) -> Self::Connect;
}

/// Takes no link: whatever is asked never completes, so a client with it
/// stays on the links it has.
impl<L: Link> LinkConnector<L> for () {
    type Error = Infallible;
    type Connect = Pending<Result<L, Infallible>>;

    fn connect_beside(&self, _: &L, _: SocketAddr) -> Self::Connect {
        core::future::pending()
    }
}

/// The [`LinkConnector`] a side's [`Own`](super::Side::Own) data keeps, if
/// it keeps one: a client's, which migrates to a preferred address; never a
/// server's, which takes no link of its own (RFC 9000 §9).
pub trait OwnLinkConnector<L: Link> {
    /// The connector.
    type Connector: LinkConnector<L>;

    /// The connector, when this side has one.
    fn link_connector(&self) -> Option<&Self::Connector>;
}
