//! The link binding: what a link driver's bind produces, and the two ways
//! it gives links.

use core::future::Future;

use crate::{BindingId, Link};

/// A link binding: the object a transport produces when it binds, and from
/// which links come.
///
/// A binding gives links in one or both of two ways, each a trait of its
/// own: it takes new links as peers appear ([`AcceptingLinkBinding`]), or
/// it sets up a link to a peer when asked ([`ConnectingLinkBinding`]). UDP
/// does both.
///
/// For the same two ends, as long as one link is alive, both ways give that
/// link, as clones of it; a caller that receives the same link from both
/// tells them apart by [`LinkId`](crate::LinkId).
///
/// A binding, its links and the driver that bound it have lifetimes of
/// their own. Dropping the binding does not close the links it gave, which
/// keep receiving whether or not anyone still takes new links from it; a
/// transport implementation keeps whatever they need to make progress.
pub trait LinkBinding {
    /// The links this binding gives.
    type Link: Link;

    /// The identity of this binding, which every link it gives carries in
    /// its [`LinkId::binding`](crate::LinkId::binding).
    ///
    /// The transport takes it with [`BindingId::new`] when it binds and
    /// keeps it for the binding's life.
    fn id(&self) -> &BindingId;
}

/// A link binding that takes new links as peers appear.
///
/// Taking a link is not a transport handshake and not the start of a QUIC
/// connection: a link is a channel to a peer, and what arrives on it is
/// examined later.
pub trait AcceptingLinkBinding: LinkBinding {
    /// Why the binding gives no more new links.
    ///
    /// Transient failures are not reported through it: the transport
    /// handles them itself.
    type AcceptError;
    /// The future of one [`accept`](Self::accept): it borrows the binding.
    type Accept<'a>: Future<Output = Result<Self::Link, Self::AcceptError>> + 'a
    where
        Self: 'a;

    /// Take the next new link.
    ///
    /// - `Ok` gives a link the binding produced, as a rule because a
    ///   datagram arrived from a peer with no live link; it may be a link
    ///   that [`ConnectingLinkBinding::connect`] gave too. The datagram that
    ///   made the binding produce it is delivered by a [`recv`](Link::recv)
    ///   of the link, not by `accept`.
    /// - `Err` means the binding gives no more new links. The links it gave
    ///   keep working.
    ///
    /// While nobody takes new links, the binding holds back the ones not
    /// yet taken up to a bound of its own, and drops datagrams from further
    /// new peers once that bound is reached.
    fn accept(&self) -> Self::Accept<'_>;
}

/// A link binding that sets up a link to a peer when asked.
pub trait ConnectingLinkBinding: LinkBinding {
    /// Where to connect to, in the form the binding chooses: for UDP, for
    /// example, the peer's address.
    type Remote;
    /// Why a link could not be set up. A binding whose
    /// [`connect`](Self::connect) cannot fail uses
    /// [`Infallible`](core::convert::Infallible).
    type ConnectError;
    /// The future of one [`connect`](Self::connect): it borrows the binding.
    type Connect<'a>: Future<Output = Result<Self::Link, Self::ConnectError>> + 'a
    where
        Self: 'a;

    /// Set up a link to `remote`.
    ///
    /// On success, every datagram from that peer on this binding is
    /// delivered by the link given, as long as it is alive; when a link to
    /// it is alive already, that link is given.
    ///
    /// # Errors
    ///
    /// The link could not be set up, for the reason the binding gives.
    fn connect(&self, remote: Self::Remote) -> Self::Connect<'_>;
}
