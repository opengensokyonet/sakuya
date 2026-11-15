//! The endpoint: one routing domain, its bindings, and its two roles.

use core::{fmt, num::NonZeroUsize};
use std::sync::Arc;

use frunk_core::coproduct::CoprodInjector;
use sakuya_datagram_routing::{
    claim::queue::DatagramDeliveryQueue,
    route::{acceptance::InitialAcceptance, router::DatagramRouter},
};
use sakuya_link::{AcceptingLinkBinding, ConnectingLinkBinding, LinkBinding};
use snafu::{ResultExt as _, Snafu};

use crate::{
    binding::{Accepting, BindingDriver, ConnectOnly, shared::BindingShared},
    choices::{EndpointChoices, LinkOf, ResetTokensOf},
    config::{
        BindingDeclarations, EndpointConfig, InvalidEndpointConfigError, OfferedVersionsError,
        OfferedVersionsSnafu, check_offered_versions,
    },
    domain::{BirthFactory, Births, Domain, DomainParts},
    dropped_input::DroppedInputCounts,
    handshake::ClientHandshakeConfig,
    incoming::IncomingStream,
    outgoing::Outgoing,
    reflow::{ReflowDriver, ReflowQueues},
    role::{AcceptingServerRole, ClientRole, ConnectingClientRole, ServerRole},
    version_negotiation::NegotiatingVersionService,
    zero_length::{ZeroLengthLocalRecognizer, ZeroLengthLocals},
};

/// An endpoint: the owner of one datagram routing domain, with the server
/// role `S` and the client role `C`, composed with the choices `E`.
///
/// It is made together with its [`ReflowDriver`]; each binding the host adds
/// gives a [`BindingHandle`] and a [`BindingDriver`]. The host spawns the
/// drivers; the endpoint spawns nothing. Dropping the endpoint does nothing
/// to its drivers or connections.
pub struct Endpoint<E: EndpointChoices, S: ServerRole<E>, C: ClientRole<E>> {
    domain: Arc<Domain<E>>,
    server: S::Kept,
    client: C::Kept,
}

/// The binding driver of a binding `B` of an endpoint of the choices `E`,
/// which runs the binding's accept loop when `A` is [`Accepting`].
pub type EndpointBindingDriver<E, B, A> =
    BindingDriver<B, <E as EndpointChoices>::Links, Arc<Domain<E>>, Arc<Domain<E>>, A>;

impl<E: EndpointChoices, S: ServerRole<E>, C: ClientRole<E>> Endpoint<E, S, C> {
    /// An endpoint made with `config`, and its reflow driver, which the host
    /// spawns.
    ///
    /// # Errors
    ///
    /// [`InvalidEndpointConfigError`] when values of the configuration do
    /// not agree: the versions the server offers, or the thresholds of loss
    /// detection and the clock.
    pub fn new(
        config: EndpointConfig<E, S, C>,
    ) -> Result<(Self, ReflowDriver<E, S>), InvalidEndpointConfigError> {
        let settings = S::domain_settings(&config.server);
        check_offered_versions(&settings.offered_versions).context(OfferedVersionsSnafu)?;
        let (versions, version_negotiation) =
            NegotiatingVersionService::new(settings.version_negotiation_queue_capacity);
        let unclaimed =
            DatagramDeliveryQueue::new(queue_capacity(settings.unclaimed_queue_capacity));
        // invariant: the capacity is at most the largest a queue can have.
        let unclaimed = unclaimed.expect("the capacity is within the bound");
        let births = Arc::new(Births::new(queue_capacity(settings.receive_queue_capacity)));
        let zero_length = Arc::new(ZeroLengthLocals::new());
        let reset_tokens: ResetTokensOf<E> =
            sakuya_datagram_routing::route::reset::StatelessResetTokens::new();
        let router = DatagramRouter::new(
            sakuya_datagram_routing::route::index::RouteIndex::new(),
            ZeroLengthLocalRecognizer::new(config.recognizer, Arc::clone(&zero_length)),
        )
        .with_stateless_reset(Arc::clone(&reset_tokens))
        .with_version_service(versions)
        .with_initial_acceptance(InitialAcceptance::new(
            BirthFactory::new(Arc::clone(&births)),
            Arc::new(unclaimed.poster()),
        ));
        let domain = Arc::new(Domain::new(
            router,
            births,
            DomainParts {
                reset_tokens,
                zero_length,
                connection_ids: config.connection_ids,
                crypto: config.crypto,
                random: config.random,
                clock: config.clock,
                wall_clock: config.wall_clock,
                offered_versions: settings.offered_versions,
            },
        ));
        let (server, steps) = S::start(
            config.server,
            &domain,
            ReflowQueues {
                unclaimed,
                version_negotiation,
            },
        )?;
        let client = C::start(config.client, &domain)?;
        let reflow = ReflowDriver::new(Arc::clone(&domain), steps);
        Ok((
            Self {
                domain,
                server,
                client,
            },
            reflow,
        ))
    }

    /// Closes the endpoint; it does nothing more when called again.
    ///
    /// From now on the endpoint offers no new connection: incoming streams
    /// end and the incoming connections not taken yet are dropped,
    /// `accept`, `start`, adding a binding and a binding handle's `connect`
    /// fail with [`EndpointClosedError`]. Connections already made go on
    /// and end by themselves; the drivers end once they all have.
    pub fn close(&self) {
        self.domain.close();
        S::close(&self.server);
    }

    /// How many inputs the endpoint dropped, by the bound that was reached.
    pub fn dropped_input_counts(&self) -> DroppedInputCounts {
        S::dropped_input_counts(&self.server)
    }

    /// Adds `binding`, whose new links the endpoint takes, with what the
    /// host declares about it; gives its handle, and its driver, which the
    /// host spawns.
    ///
    /// # Errors
    ///
    /// [`AddBindingError`] when the declarations offer versions they should
    /// not, or once the endpoint has been closed.
    #[expect(clippy::type_complexity, reason = "the driver's type names its parts")]
    pub fn add_accepting_binding<B, I>(
        &self,
        binding: B,
        declarations: BindingDeclarations,
    ) -> Result<
        (
            BindingHandle<B, E, C>,
            EndpointBindingDriver<E, B, Accepting>,
        ),
        AddBindingError,
    >
    where
        B: AcceptingLinkBinding,
        E::Links: CoprodInjector<B::Link, I>,
    {
        let shared = self.add_binding::<B, I>(binding, declarations)?;
        let driver = BindingDriver::new(
            Arc::clone(&shared),
            Arc::clone(&self.domain),
            Arc::clone(&self.domain),
        );
        Ok((self.handle(shared), driver))
    }

    /// Adds `binding`, on which the endpoint only connects: its driver takes
    /// no new links from peers, though a peer can still start a connection
    /// on a link the endpoint connected.
    ///
    /// # Errors
    ///
    /// [`AddBindingError`] when the declarations offer versions they should
    /// not, or once the endpoint has been closed.
    #[expect(clippy::type_complexity, reason = "the driver's type names its parts")]
    pub fn add_connect_only_binding<B, I>(
        &self,
        binding: B,
        declarations: BindingDeclarations,
    ) -> Result<
        (
            BindingHandle<B, E, C>,
            EndpointBindingDriver<E, B, ConnectOnly>,
        ),
        AddBindingError,
    >
    where
        B: ConnectingLinkBinding,
        E::Links: CoprodInjector<B::Link, I>,
    {
        let shared = self.add_binding::<B, I>(binding, declarations)?;
        let driver = BindingDriver::new(
            Arc::clone(&shared),
            Arc::clone(&self.domain),
            Arc::clone(&self.domain),
        );
        Ok((self.handle(shared), driver))
    }

    fn add_binding<B, I>(
        &self,
        binding: B,
        declarations: BindingDeclarations,
    ) -> Result<Arc<BindingShared<B, E::Links>>, AddBindingError>
    where
        B: LinkBinding,
        E::Links: CoprodInjector<B::Link, I>,
    {
        if self.domain.is_closed() {
            return Err(EndpointClosedError).context(AddBindingClosedSnafu);
        }
        if let Some(offered) = &declarations.offered_versions {
            check_offered_versions(offered).context(BindingOfferedVersionsSnafu)?;
        }
        self.domain.declare(binding.id().clone(), declarations);
        Ok(Arc::new(BindingShared::new::<I>(binding)))
    }

    fn handle<B: LinkBinding>(
        &self,
        shared: Arc<BindingShared<B, E::Links>>,
    ) -> BindingHandle<B, E, C> {
        BindingHandle {
            shared,
            domain: Arc::clone(&self.domain),
            client: self.client.clone(),
        }
    }
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>, C: ClientRole<E>> Endpoint<E, S, C> {
    /// The incoming connections, for one receiver: each call registers one
    /// more.
    ///
    /// While no receiver exists, the endpoint offers no new connection.
    pub fn incoming(&self) -> IncomingStream<E, S> {
        IncomingStream::new(Arc::clone(&self.server))
    }
}

impl<E: EndpointChoices, S: ServerRole<E>, C: ClientRole<E>> fmt::Debug for Endpoint<E, S, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Endpoint")
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
}

/// The capacity of a queue the endpoint makes, within what a queue can have.
fn queue_capacity(capacity: NonZeroUsize) -> NonZeroUsize {
    let bounded = capacity
        .get()
        .min(DatagramDeliveryQueue::<()>::MAX_CAPACITY);
    // invariant: both bounds are above zero.
    NonZeroUsize::new(bounded).expect("a capacity above zero")
}

/// What the endpoint gives for each binding the host adds: where
/// connections on the binding are started.
pub struct BindingHandle<B: LinkBinding, E: EndpointChoices, C: ClientRole<E>> {
    shared: Arc<BindingShared<B, E::Links>>,
    domain: Arc<Domain<E>>,
    client: C::Kept,
}

impl<B, E, C> BindingHandle<B, E, C>
where
    B: LinkBinding,
    E: EndpointChoices,
    C: ConnectingClientRole<E, Kept = Arc<<C as ClientRole<E>>::Config>>,
    C::Config: Clone,
{
    /// Takes a link to `remote` on the binding and gives the outgoing
    /// connection over it to the server `server_name`, with a clone of the
    /// client configuration; the connection starts with
    /// [`Outgoing::start`].
    ///
    /// The link is taken here, on the caller's task. Dropping the future
    /// cancels it.
    ///
    /// # Errors
    ///
    /// [`BindingHandleConnectError::EndpointClosed`] once the endpoint has
    /// been closed, before any link is taken;
    /// [`BindingHandleConnectError::Binding`] when the binding could not set
    /// up the link.
    pub async fn connect(
        &self,
        remote: B::Remote,
        server_name: <C::Handshake as ClientHandshakeConfig>::ServerName,
    ) -> Result<Outgoing<E, C>, BindingHandleConnectError<B::ConnectError>>
    where
        B: ConnectingLinkBinding,
    {
        if self.domain.is_closed() {
            return Err(BindingHandleConnectError::EndpointClosed(
                EndpointClosedError,
            ));
        }
        let member = self
            .shared
            .binding()
            .connect(remote)
            .await
            .map_err(BindingHandleConnectError::Binding)?;
        let link = self.shared.admit(member);
        Ok(Outgoing::new(
            Arc::clone(&self.domain),
            (*self.client).clone(),
            link,
            server_name,
        ))
    }

    /// Gives the outgoing connection to the server `server_name` over the
    /// link `id` of this binding, which another connection uses: it takes no
    /// new link.
    ///
    /// # Errors
    ///
    /// [`LinkNotDispatchedError`] when the link is not one the binding
    /// receives on now: it ended, or nobody used it any more.
    pub fn connect_on(
        &self,
        id: &sakuya_link::LinkId<crate::choices::LocalOf<E>, crate::choices::PeerOf<E>>,
        server_name: <C::Handshake as ClientHandshakeConfig>::ServerName,
    ) -> Result<Outgoing<E, C>, LinkNotDispatchedError> {
        let link: LinkOf<E> = self
            .shared
            .dispatched_link(id)
            .ok_or(LinkNotDispatchedError)?;
        Ok(Outgoing::new(
            Arc::clone(&self.domain),
            (*self.client).clone(),
            link,
            server_name,
        ))
    }
}

impl<B: LinkBinding, E: EndpointChoices, C: ClientRole<E>> fmt::Debug for BindingHandle<B, E, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindingHandle")
            .field("binding", &self.shared)
            .finish_non_exhaustive()
    }
}

/// The endpoint has been closed: it makes no new connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("the endpoint is closed"))]
pub struct EndpointClosedError;

/// A binding could not be added.
#[derive(Debug, Snafu)]
pub enum AddBindingError {
    /// The binding's declarations offer versions they should not.
    #[snafu(
        display("versions the binding offers"),
        context(name(BindingOfferedVersionsSnafu))
    )]
    OfferedVersions {
        /// Which version does not belong.
        source: OfferedVersionsError,
    },
    /// The endpoint has been closed.
    #[snafu(display("adding a binding"), context(name(AddBindingClosedSnafu)))]
    EndpointClosed {
        /// The endpoint is closed.
        source: EndpointClosedError,
    },
}

/// A binding handle could not give an outgoing connection.
#[derive(Debug)]
pub enum BindingHandleConnectError<B> {
    /// The endpoint has been closed; no link was taken.
    EndpointClosed(EndpointClosedError),
    /// The binding could not set up the link, for its own reason.
    Binding(B),
}

impl<B> fmt::Display for BindingHandleConnectError<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointClosed(_) => f.write_str("connecting on a closed endpoint"),
            Self::Binding(_) => f.write_str("the binding did not set up the link"),
        }
    }
}

impl<B: core::error::Error + 'static> core::error::Error for BindingHandleConnectError<B> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::EndpointClosed(source) => Some(source),
            Self::Binding(source) => Some(source),
        }
    }
}

/// The link to connect on is not one the binding receives on now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display("the link is not dispatched by the binding"))]
pub struct LinkNotDispatchedError;
