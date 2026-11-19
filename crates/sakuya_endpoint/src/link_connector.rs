//! What a client connection of the endpoint takes its own links with: the
//! endpoint's [`LinkConnector`].
//!
//! A binding handle's [`connect`](crate::endpoint::BindingHandle::connect)
//! registers its binding with the endpoint the first time a link it gives
//! has the binding's own local end
//! ([`LinkBinding::local`](sakuya_link::LinkBinding::local)): the binding
//! corresponds strictly to that local end. A binding on a wildcard address
//! gives no link with its own local end and is never registered. Asked for
//! a link from the local end of a link to a peer, the
//! [`EndpointLinkConnector`] finds the binding registered for that local
//! end, connects it to the peer and admits the link as the binding handle
//! does; without such a binding, it takes no link.

use core::{
    error::Error,
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use sakuya_connection::v1::link_connector::LinkConnector;
use sakuya_link::{ConnectingLinkBinding, Link as _};

use crate::{
    binding::shared::BindingShared,
    choices::{EndpointChoices, LinkOf, LocalOf},
    endpoint::EndpointClosedError,
};

/// The taking of one link by an [`EndpointLinkConnector`], under way.
pub type EndpointLinkConnect<E> =
    Pin<Box<dyn Future<Output = Result<LinkOf<E>, EndpointLinkConnectError>> + Send>>;

/// The link connector of the client connections of an endpoint of the
/// choices `E`: it connects the binding that corresponds strictly to the
/// local end of the link it is given, as the [module documentation](self)
/// says.
pub struct EndpointLinkConnector<E: EndpointChoices> {
    // only the bindings, not the whole domain: the connector is in every
    // client connection, whose auto traits are checked through it
    bindings: Arc<LinkConnectors<E>>,
}

impl<E: EndpointChoices> EndpointLinkConnector<E> {
    pub(crate) fn new(bindings: Arc<LinkConnectors<E>>) -> Self {
        Self { bindings }
    }
}

impl<E: EndpointChoices> fmt::Debug for EndpointLinkConnector<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointLinkConnector")
            .finish_non_exhaustive()
    }
}

impl<E: EndpointChoices> LinkConnector<LinkOf<E>> for EndpointLinkConnector<E> {
    type Error = EndpointLinkConnectError;
    type Connect = EndpointLinkConnect<E>;

    /// Fails at once once the endpoint has been closed, without a binding
    /// registered for the local end of `beside`, and when `peer` is no
    /// remote of that binding; then as the binding's connect does.
    fn connect_beside(&self, beside: &LinkOf<E>, peer: SocketAddr) -> EndpointLinkConnect<E> {
        let connect = self.bindings.connect(&beside.id().local, peer);
        // an async block holds only the error, whatever the link's type
        connect.unwrap_or_else(|error| Box::pin(async move { Err(error) }))
    }
}

/// An [`EndpointLinkConnector`] took no link.
#[derive(Debug)]
pub enum EndpointLinkConnectError {
    /// No binding of the endpoint corresponds strictly to the local end of
    /// the link the new one was to be beside.
    NoBinding,
    /// The peer's address is no remote the binding connects to.
    UnaddressablePeer,
    /// The endpoint has been closed.
    EndpointClosed(EndpointClosedError),
    /// The binding could not set up the link, for its own reason.
    Binding(Box<dyn Error + Send + Sync>),
}

impl fmt::Display for EndpointLinkConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBinding => f.write_str("no binding has the local end of the link"),
            Self::UnaddressablePeer => f.write_str("the binding does not connect to the peer"),
            Self::EndpointClosed(_) => f.write_str("connecting on a closed endpoint"),
            Self::Binding(_) => f.write_str("the binding did not set up the link"),
        }
    }
}

impl Error for EndpointLinkConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::NoBinding | Self::UnaddressablePeer => None,
            Self::EndpointClosed(source) => Some(source),
            Self::Binding(source) => Some(source.as_ref()),
        }
    }
}

/// The bindings registered with an endpoint, by the local end each
/// corresponds to strictly.
pub(crate) struct LinkConnectors<E: EndpointChoices> {
    /// Whether the endpoint has been closed.
    closed: AtomicBool,
    bindings: Mutex<Vec<Registered<E>>>,
}

/// A binding registered for the local end it corresponds to strictly.
type Registered<E> = (LocalOf<E>, Box<dyn ConnectBeside<E>>);

impl<E: EndpointChoices> LinkConnectors<E> {
    pub(crate) fn new() -> Self {
        Self {
            closed: AtomicBool::new(false),
            bindings: Mutex::new(Vec::new()),
        }
    }

    /// The endpoint has been closed: no link is taken any more, and the
    /// bindings are forgotten.
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        let forgotten = core::mem::take(&mut *self.bindings());
        drop(forgotten);
    }

    fn bindings(&self) -> MutexGuard<'_, Vec<Registered<E>>> {
        self.bindings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `shared`'s binding corresponds strictly to `local`, of a link it
    /// gave. A binding that is gone is forgotten.
    pub(crate) fn register<B>(&self, local: LocalOf<E>, shared: &Arc<BindingShared<B, E::Links>>)
    where
        BindingConnect<B, E::Links>: ConnectBeside<E>,
        B: sakuya_link::LinkBinding + 'static,
    {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        let mut bindings = self.bindings();
        bindings.retain(|(_, binding)| binding.alive());
        bindings.push((
            local,
            Box::new(BindingConnect {
                shared: Arc::downgrade(shared),
            }),
        ));
    }

    /// The taking of a link from `local` to `peer`, on the binding
    /// registered for `local`.
    fn connect(
        &self,
        local: &LocalOf<E>,
        peer: SocketAddr,
    ) -> Result<EndpointLinkConnect<E>, EndpointLinkConnectError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(EndpointLinkConnectError::EndpointClosed(
                EndpointClosedError,
            ));
        }
        let bindings = self.bindings();
        bindings
            .iter()
            .filter(|(registered, binding)| registered == local && binding.alive())
            .find_map(|(_, binding)| binding.connect(peer))
            .unwrap_or(Err(EndpointLinkConnectError::NoBinding))
    }
}

impl<E: EndpointChoices> fmt::Debug for LinkConnectors<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkConnectors")
            .field("bindings", &self.bindings().len())
            .finish()
    }
}

/// One registered binding, with its type erased.
pub(crate) trait ConnectBeside<E: EndpointChoices>: Send + Sync {
    /// Whether the binding is still there.
    fn alive(&self) -> bool;

    /// The taking of a link to `peer`; `None` when the binding is gone.
    fn connect(
        &self,
        peer: SocketAddr,
    ) -> Option<Result<EndpointLinkConnect<E>, EndpointLinkConnectError>>;
}

/// A registered binding `B` of an endpoint whose links are the sum `M`: it
/// does not keep the binding.
pub(crate) struct BindingConnect<B: sakuya_link::LinkBinding, M: crate::link::sum::LinkSum> {
    shared: Weak<BindingShared<B, M>>,
}

impl<E, B> ConnectBeside<E> for BindingConnect<B, E::Links>
where
    E: EndpointChoices,
    B: ConnectingLinkBinding + Send + Sync + 'static,
    B::Remote: TryFrom<SocketAddr> + Send,
    B::ConnectError: Error + Send + Sync + 'static,
    for<'a> B::Connect<'a>: Send,
    BindingShared<B, E::Links>: Send + Sync,
{
    fn alive(&self) -> bool {
        self.shared.strong_count() > 0
    }

    fn connect(
        &self,
        peer: SocketAddr,
    ) -> Option<Result<EndpointLinkConnect<E>, EndpointLinkConnectError>> {
        let shared = self.shared.upgrade()?;
        let Ok(remote) = B::Remote::try_from(peer) else {
            return Some(Err(EndpointLinkConnectError::UnaddressablePeer));
        };
        let connect: EndpointLinkConnect<E> = Box::pin(async move {
            let member = shared
                .binding()
                .connect(remote)
                .await
                .map_err(|error| EndpointLinkConnectError::Binding(Box::new(error)))?;
            Ok(shared.admit_connected(member))
        });
        Some(Ok(connect))
    }
}
