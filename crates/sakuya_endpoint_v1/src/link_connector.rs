//! What a client connection of the endpoint takes its own links with: the
//! endpoint's [`LinkConnector`].
//!
//! Each client connection's [`EndpointLinkConnector`] keeps the binding the
//! connection was started on, as one of the types the endpoint's choices
//! list ([`EndpointChoices::Bindings`]): nothing is erased, so whether the
//! connector, its errors and the taking of a link are `Send` is checked
//! where the endpoint is composed. Asked for a link from the local end of a
//! link to a peer, it connects that binding to the peer and admits the
//! link as the binding handle does, when the binding corresponds strictly
//! to that local end ([`LinkBinding::local`](sakuya_link::LinkBinding::local));
//! otherwise it takes no link. A binding on a wildcard address never
//! corresponds strictly to the local end of a link it gives.
//!
//! A peer address is a remote of the binding when it converts into one
//! (`B::Remote: TryFrom<SocketAddr>`); a binding of another kind of remote
//! has a conversion that always fails.

use alloc::sync::Arc;
use core::{
    error::Error,
    fmt,
    future::Future,
    net::SocketAddr,
    sync::atomic::{AtomicBool, Ordering},
};

use sakuya_connection::v1::link_connector::LinkConnector;
use sakuya_link::Link as _;
use sakuya_wire::parts::ErrorCoproduct;

use self::sum::{ConnectingBindingSum, DisplayCoproduct};
use crate::{
    choices::{EndpointChoices, LinkOf, SharedBindingOf},
    endpoint::EndpointClosedError,
};

/// Why an [`EndpointLinkConnector`] of an endpoint of the choices `E` took
/// no link.
pub type EndpointLinkConnectErrorOf<E> = EndpointLinkConnectError<
    <SharedBindingOf<E> as ConnectingBindingSum<<E as EndpointChoices>::Links>>::ConnectError,
>;

/// The link connector of a client connection of an endpoint of the choices
/// `E`: it connects the binding the connection was started on, when that
/// binding corresponds strictly to the local end of the link it is given,
/// as the [module documentation](self) says.
pub struct EndpointLinkConnector<E: EndpointChoices> {
    /// The binding the connection was started on.
    binding: SharedBindingOf<E>,
    /// Whether the endpoint has been closed.
    closed: Arc<AtomicBool>,
}

impl<E: EndpointChoices> EndpointLinkConnector<E> {
    pub(crate) fn new(binding: SharedBindingOf<E>, closed: Arc<AtomicBool>) -> Self {
        Self { binding, closed }
    }
}

impl<E: EndpointChoices> fmt::Debug for EndpointLinkConnector<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointLinkConnector")
            .field("closed", &self.closed.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl<E> LinkConnector<LinkOf<E>> for EndpointLinkConnector<E>
where
    E: EndpointChoices,
    SharedBindingOf<E>: ConnectingBindingSum<E::Links>,
{
    type Error = EndpointLinkConnectErrorOf<E>;
    type Connect = impl Future<Output = Result<LinkOf<E>, EndpointLinkConnectErrorOf<E>>>;

    /// Fails at once once the endpoint has been closed, when the binding
    /// does not correspond strictly to the local end of `beside`, and when
    /// `peer` is no remote of the binding; then as the binding's connect
    /// does.
    fn connect_beside(&self, beside: &LinkOf<E>, peer: SocketAddr) -> Self::Connect {
        let connect = (!self.closed.load(Ordering::Acquire))
            .then(|| self.binding.connect_beside(&beside.id().local, peer));
        async move {
            match connect {
                Some(connect) => connect.await,
                None => Err(EndpointLinkConnectError::EndpointClosed(
                    EndpointClosedError,
                )),
            }
        }
    }
}

/// An [`EndpointLinkConnector`] took no link; `Es` is the sum of the
/// reasons of the endpoint's bindings, one member for each binding type.
#[derive(Debug)]
pub enum EndpointLinkConnectError<Es> {
    /// The binding of the connection does not correspond strictly to the
    /// local end of the link the new one was to be beside.
    NoBinding,
    /// The peer's address is no remote the binding connects to.
    UnaddressablePeer,
    /// The endpoint has been closed.
    EndpointClosed(EndpointClosedError),
    /// The binding could not set up the link, for its own reason: it shows
    /// as that reason.
    Binding(Es),
}

impl<Es> EndpointLinkConnectError<Es> {
    /// The same failure, with the binding's reason put into another sum.
    fn map_binding<Fs>(self, map: impl FnOnce(Es) -> Fs) -> EndpointLinkConnectError<Fs> {
        match self {
            Self::NoBinding => EndpointLinkConnectError::NoBinding,
            Self::UnaddressablePeer => EndpointLinkConnectError::UnaddressablePeer,
            Self::EndpointClosed(source) => EndpointLinkConnectError::EndpointClosed(source),
            Self::Binding(reason) => EndpointLinkConnectError::Binding(map(reason)),
        }
    }
}

impl<Es: DisplayCoproduct> fmt::Display for EndpointLinkConnectError<Es> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBinding => f.write_str("no binding has the local end of the link"),
            Self::UnaddressablePeer => f.write_str("the binding does not connect to the peer"),
            Self::EndpointClosed(_) => f.write_str("connecting on a closed endpoint"),
            Self::Binding(reason) => reason.fmt_member(f),
        }
    }
}

impl<Es: DisplayCoproduct + ErrorCoproduct + fmt::Debug> Error for EndpointLinkConnectError<Es> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NoBinding | Self::UnaddressablePeer => None,
            Self::EndpointClosed(source) => Some(source),
            Self::Binding(reason) => reason.as_error().source(),
        }
    }
}

/// The sums an endpoint link connector works with: of the bindings it may
/// keep, and of their reasons for taking no link.
pub(crate) mod sum {
    use alloc::sync::Arc;
    use core::{fmt, future::Future, net::SocketAddr};

    use frunk_core::coproduct::{CNil, Coproduct};
    use sakuya_link::ConnectingLinkBinding;

    use super::EndpointLinkConnectError;
    use crate::{
        binding::shared::BindingShared,
        link::{EndpointLink, sum::LinkSum},
        synchronization::EndpointSynchronization,
    };

    /// A sum of the shared states of bindings that connect, whose links are
    /// in the sum `M`: a `Coproduct` of them that ends in `CNil`.
    pub trait ConnectingBindingSum<M: LinkSum> {
        /// The sum of the members' reasons for taking no link.
        type ConnectError: DisplayCoproduct;
        /// The taking of one link, under way.
        type Connect: Future<
            Output = Result<EndpointLink<M>, EndpointLinkConnectError<Self::ConnectError>>,
        >;

        /// The taking of a link from `local` to `peer` on the member's
        /// binding, which fails at once when the binding does not
        /// correspond strictly to `local` or `peer` is no remote of it.
        fn connect_beside(&self, local: &M::Local, peer: SocketAddr) -> Self::Connect;
    }

    /// The sum of no binding, which holds nothing.
    impl<M: LinkSum> ConnectingBindingSum<M> for CNil {
        type ConnectError = CNil;
        type Connect =
            core::future::Pending<Result<EndpointLink<M>, EndpointLinkConnectError<CNil>>>;

        fn connect_beside(&self, _: &M::Local, _: SocketAddr) -> Self::Connect {
            match *self {}
        }
    }

    /// The sum of a binding type that connects and further ones.
    impl<M, B, T, Y> ConnectingBindingSum<M> for Coproduct<Arc<BindingShared<B, M, Y>>, T>
    where
        M: LinkSum,
        Y: EndpointSynchronization,
        B: ConnectingLinkBinding,
        B::Remote: TryFrom<SocketAddr>,
        B::ConnectError: fmt::Display,
        T: ConnectingBindingSum<M>,
    {
        type ConnectError = Coproduct<B::ConnectError, T::ConnectError>;
        type Connect = impl Future<
            Output = Result<EndpointLink<M>, EndpointLinkConnectError<Self::ConnectError>>,
        >;

        fn connect_beside(&self, local: &M::Local, peer: SocketAddr) -> Self::Connect {
            let connect = match self {
                Coproduct::Inl(shared) => Coproduct::Inl(connect_member(shared, local, peer)),
                Coproduct::Inr(rest) => Coproduct::Inr(rest.connect_beside(local, peer)),
            };
            async move {
                match connect {
                    Coproduct::Inl(connect) => connect
                        .await
                        .map_err(|error| error.map_binding(Coproduct::Inl)),
                    Coproduct::Inr(connect) => connect
                        .await
                        .map_err(|error| error.map_binding(Coproduct::Inr)),
                }
            }
        }
    }

    /// The taking of a link from `local` to `peer` on the binding of
    /// `shared`.
    fn connect_member<B, M, Y>(
        shared: &Arc<BindingShared<B, M, Y>>,
        local: &M::Local,
        peer: SocketAddr,
    ) -> impl Future<Output = Result<EndpointLink<M>, EndpointLinkConnectError<B::ConnectError>>>
    + use<B, M, Y>
    where
        M: LinkSum,
        Y: EndpointSynchronization,
        B: ConnectingLinkBinding,
        B::Remote: TryFrom<SocketAddr>,
    {
        let remote = if shared.local() == local {
            B::Remote::try_from(peer).map_err(|_| EndpointLinkConnectError::UnaddressablePeer)
        } else {
            Err(EndpointLinkConnectError::NoBinding)
        };
        let shared = Arc::clone(shared);
        async move {
            let remote = remote?;
            let member = shared
                .binding()
                .connect(remote)
                .await
                .map_err(EndpointLinkConnectError::Binding)?;
            Ok(shared.admit_connected(member))
        }
    }

    /// A sum of reasons that show: a `Coproduct` of them that ends in
    /// `CNil`.
    pub trait DisplayCoproduct {
        /// Shows the reason this sum holds, as it shows.
        fn fmt_member(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;
    }

    impl DisplayCoproduct for CNil {
        fn fmt_member(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
            match *self {}
        }
    }

    impl<H: fmt::Display, T: DisplayCoproduct> DisplayCoproduct for Coproduct<H, T> {
        fn fmt_member(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Inl(reason) => fmt::Display::fmt(reason, f),
                Self::Inr(rest) => rest.fmt_member(f),
            }
        }
    }
}
