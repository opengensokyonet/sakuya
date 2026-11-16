//! The incoming connections a server endpoint gives the application.
//!
//! When a datagram that may start a connection passes the reflow driver's
//! stateless checks, routing publishes a receiver for it and the endpoint
//! puts an incoming connection in a queue: the datagram, its link, the
//! receiver that already takes the client's later datagrams, the facts of
//! the attempt and a clone of the server configuration. The application
//! takes incoming connections from [`Endpoint::incoming`](crate::endpoint::Endpoint::incoming),
//! may replace parts of their configuration, and accepts, retries, refuses
//! or drops each; dropping one refuses it silently and revokes its
//! registration.

use core::{
    convert::Infallible,
    fmt,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicU64, Ordering},
    },
};

use core::future::poll_fn;
use futures_util::Stream;
use nitori_crypto::RandomError;
use sakuya_clock::MonotonicClock as _;
use sakuya_connection::v1::input::LogicalPathDatagramReceiver as _;
use sakuya_connection::{
    call::{CallPositions, TreeCalls},
    driver::ConnectionDriver,
    error::ConnectionErrorsOf,
    send_strategy::{AnyActiveLinkPath, SendStrategy},
    share::{ConnectionArgsOf, LineageLists},
    v1::{
        self as connection, ConnectionArgs,
        advancing::HandshakeStart,
        amplification::AddressValidation,
        application_handles::connection::{ConnectionHandle, ConnectionHandleCellOf},
        close_request::CloseRequestCell,
        first_flight::FirstFlight,
        input::InitialPathReceiver,
        link::LinkFacts,
        send::SendTypes,
        send_planning::{IntakePublishOutcome, SendStrategyOf},
        streams::send::StreamIntent,
    },
};
use sakuya_datagram_routing::claim::{
    candidate::{DatagramClaimAttempt, DatagramClaimOutcome},
    delivery::DatagramDelivery,
};
use sakuya_link::MIN_DATAGRAM_SIZE;
use sakuya_link::{EcnMarking, Link, OutgoingDatagram};
use sakuya_recovery::loss::GranularityBelowClockError;
use sakuya_stream::connection::TransportImmediateClose;
use sakuya_tls::clock::Clock as _;
use sakuya_wire::header::codec::ReadLongHeaderHostExt as _;
use sakuya_wire::{connection_id::ConnectionId, parts::Selector, version::Version};

use crate::{
    address_token::{AddressTokens as _, NewTokenAddress, TokenPeerAddress as _},
    choices::{ConnectionDatagramReceiver, DatagramOf, EndpointChoices, LinkOf, PeerOf},
    config::thresholds_against_clock,
    connection::{make_connection, register_first_local},
    domain::{Born, Domain},
    dropped_input::DroppedInputCounts,
    endpoint::EndpointClosedError,
    handshake::ServerHandshakeConfig as _,
    invalid_token::encode_initial_close,
    late_initial::LateInitials,
    make::MakeConnection,
    part::CoreFacts,
    reflow,
    retry::{EncodeStatelessRetryError, encode_stateless_retry, generate_stateless_scid},
    role::AcceptingServerRole,
    stateless_check::{AdmittedDatagram, IncomingLoad, ReturnedToken},
    zero_length::{ZeroLengthLocalCidInUseError, ZeroLengthLocalOccupancy},
};

/// What [`Endpoint::incoming`](crate::endpoint::Endpoint::incoming) gives: a
/// new connection before it is accepted, of a version the server can
/// terminate (`T`) or only parse (`P`).
///
/// An endpoint without versions it only parses has `P` = [`Infallible`],
/// so the item is taken apart with an irrefutable pattern:
/// `let Incoming::Terminable(half) = item;`.
#[derive(Debug)]
pub enum Incoming<T, P = Infallible> {
    /// A connection of a version the server terminates.
    Terminable(T),
    /// A connection of a version the server only parses.
    ParseOnly(P),
}

/// What an incoming connection is known by before it is accepted, from the
/// datagram that started it; nothing in it is authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingFacts<Peer> {
    /// The peer's end of the link the datagram arrived on.
    pub peer: Peer,
    /// The version of the datagram's first packet.
    pub version: Version,
    /// The address validation token the client's Initial returned.
    pub token: ReturnedToken,
    /// Whether the datagram's first packet was 0-RTT rather than Initial.
    pub born_from_zero_rtt: bool,
}

/// A new connection of a version the server terminates, before the
/// application accepts it, retries it, refuses it or drops it.
///
/// Its registration under the client's first destination connection ID is
/// published already: the client's later datagrams for it queue in its
/// receiver, and make no other incoming connection.
pub struct TerminableIncoming<E: EndpointChoices, S: AcceptingServerRole<E>> {
    domain: Arc<Domain<E>>,
    config: S::Config,
    receiver: ConnectionDatagramReceiver<E>,
    first: DatagramOf<E>,
    facts: IncomingFacts<PeerOf<E>>,
    client_dcid: ConnectionId,
    client_scid: ConnectionId,
    transport_validated: bool,
    zero_length: Option<ZeroLengthLocalOccupancy<crate::choices::LocalOf<E>>>,
    /// The datagrams taken from the receiver after the first, before the
    /// connection is made: they follow it in the first flight.
    later: Vec<DatagramOf<E>>,
    /// Whether a datagram whose first packet is an Initial is in the first
    /// flight.
    has_initial: bool,
    late: Arc<LateInitials<E>>,
    /// The endpoint's token component, which issues the token of a Retry
    /// sent for this connection; the endpoint validates the token the
    /// client returns with the same component, so the one in `config` is
    /// not used.
    tokens: S::Tokens,
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> TerminableIncoming<E, S> {
    /// The incoming connection of what routing published, with a clone of
    /// the server configuration `config`.
    pub(crate) fn born(
        domain: &Arc<Domain<E>>,
        config: &S::Config,
        late: &Arc<LateInitials<E>>,
        born: Born<E>,
        admitted: AdmittedDatagram,
    ) -> Self {
        let link = born.datagram.link().id();
        let facts = IncomingFacts {
            peer: link.peer.clone(),
            version: born.initial.version(),
            token: admitted.token,
            born_from_zero_rtt: admitted.born_from_zero_rtt,
        };
        Self {
            transport_validated: domain.transport_validated(&link.binding),
            domain: Arc::clone(domain),
            config: config.clone(),
            receiver: born.receiver,
            client_dcid: *born.initial.dcid(),
            client_scid: *born.initial.scid(),
            first: born.datagram,
            has_initial: !admitted.born_from_zero_rtt,
            facts,
            zero_length: None,
            later: Vec::new(),
            late: Arc::clone(late),
            tokens: config.tokens.clone(),
        }
    }

    /// What the incoming connection is known by.
    pub fn facts(&self) -> &IncomingFacts<PeerOf<E>> {
        &self.facts
    }

    /// The configuration the connection will be made with: a clone of the
    /// server configuration, which the application may change.
    pub fn config(&self) -> &S::Config {
        &self.config
    }

    /// The configuration the connection will be made with, to change.
    pub fn config_mut(&mut self) -> &mut S::Config {
        &mut self.config
    }

    /// Makes the connection use zero-length local connection IDs on the
    /// local end of its link, which it then occupies until it ends or this
    /// incoming connection is dropped.
    ///
    /// # Errors
    ///
    /// [`ZeroLengthLocalCidInUseError`] when another connection occupies
    /// that local end.
    pub fn use_zero_length_local_cid(&mut self) -> Result<(), ZeroLengthLocalCidInUseError> {
        if self.zero_length.is_none() {
            let local = self.first.link().id().local.clone();
            self.zero_length = Some(self.domain.zero_length.occupy(local)?);
        }
        Ok(())
    }

    /// Accepts the connection: generates and registers its first local
    /// connection ID, then makes the connection, whose future the host
    /// spawns, and its handle.
    ///
    /// # Errors
    ///
    /// [`AcceptIncomingError`], which gives the incoming connection back as
    /// it was: once the endpoint has been closed, when it may still be
    /// refused; when the timer granularity of its loss detection thresholds
    /// is finer than the endpoint's clock, as it may be after its
    /// configuration was replaced.
    #[expect(clippy::type_complexity, reason = "the driver's inferred positions")]
    #[expect(
        clippy::result_large_err,
        reason = "the error gives the incoming connection back by value"
    )]
    pub fn accept<P, W, Bw, I>(
        mut self,
    ) -> Result<
        (
            ConnectionDriver<S::Choices, S::Parts, P, W, Bw>,
            ConnectionHandle<S::Choices, S::Parts>,
        ),
        AcceptIncomingError<Self>,
    >
    where
        S::Parts: TreeCalls<S::Choices, P>,
        for<'v> S::Parts: LineageLists<'v, S::Choices>,
        P: CallPositions,
        ConnectionDriver<S::Choices, S::Parts, P, W, Bw>: MakeConnection<S::Choices, S::Parts>,
        ConnectionArgsOf<S::Choices, S::Parts>: Selector<ConnectionArgs<S::Choices, S::Parts>, I>,
        S::Parts: ConnectionErrorsOf,
        SendTypes<S::Choices, S::Parts>: IntakePublishOutcome<
                StreamIntent<<S::Choices as connection::Choices>::SendParameters>,
                AnyActiveLinkPath,
            >,
        SendStrategyOf<S::Choices, S::Parts>: SendStrategy<SendTypes<S::Choices, S::Parts>>,
        ConnectionHandleCellOf<S::Choices, S::Parts>: Send + Sync + 'static,
    {
        if self.domain.is_closed() {
            return Err(AcceptIncomingError::EndpointClosed {
                half: self,
                source: EndpointClosedError,
            });
        }
        let loss_thresholds = match thresholds_against_clock(
            self.config.loss_thresholds(),
            self.domain.clock.timer_granularity(),
        ) {
            Ok(thresholds) => thresholds,
            Err(source) => {
                return Err(AcceptIncomingError::TimerGranularity { half: self, source });
            }
        };
        let link = self.first.link().clone();
        let first_local_connection_id = match register_first_local(
            &self.domain,
            &mut self.receiver,
            &link,
            &mut self.zero_length,
        ) {
            Ok(id) => id,
            Err(source) => return Err(AcceptIncomingError::EndpointClosed { half: self, source }),
        };
        let Self {
            domain,
            config,
            receiver,
            first,
            facts,
            client_dcid,
            client_scid: _,
            transport_validated,
            zero_length: _,
            later,
            has_initial: _,
            late: _,
            tokens: _,
        } = self;
        let (validation, original_destination_connection_id) = match facts.token {
            ReturnedToken::Retry { original_dcid, .. } => {
                (AddressValidation::Validated, Some(original_dcid))
            }
            ReturnedToken::NewToken(NewTokenAddress::Validated) => {
                (AddressValidation::Validated, None)
            }
            _ if transport_validated => (AddressValidation::Validated, None),
            _ => (AddressValidation::NotValidated, None),
        };
        let handshake = config.handshake();
        let core = CoreFacts {
            crypto: domain.crypto.clone(),
            handshake: HandshakeStart::new(handshake.start(), handshake.limits()),
            client_dcid,
            original_destination_connection_id,
            first_link: LinkFacts { validation },
            crypto_receive: config.checked_crypto_receive(),
            loss_thresholds,
            first_flight: FirstFlight::Datagrams(core::iter::once(first).chain(later).collect()),
            initial_receiver: InitialPathReceiver::new(receiver),
            reset_token_registry: domain.reset_tokens.clone(),
            first_local_connection_id,
            close_request: CloseRequestCell::new(),
        };
        let (driver, handle) = make_connection::<S::Choices, S::Parts, _, I>(
            domain.clock.clone(),
            config.parts,
            core,
            link,
        );
        Ok((driver, handle))
    }

    /// Waits until a datagram whose first packet is an Initial arrives for
    /// an incoming connection born from 0-RTT, and gives the incoming
    /// connection back; at once for any other incoming connection.
    ///
    /// The datagram must be at least 1200 bytes (RFC 9000 §14.1), come from
    /// the client's address and carry the client's source connection ID of
    /// the first 0-RTT packet. The endpoint checks its token as it checks
    /// the first datagram of every other incoming connection; one that
    /// fails is dropped, and the wait goes on. Only the packet type is read:
    /// whether the Initial is valid is the connection's to find. How long
    /// to wait is the application's: dropping the future drops the
    /// incoming connection.
    pub async fn initial_arrived(mut self) -> Self {
        while !self.has_initial {
            let delivery = poll_fn(|cx| self.receiver.poll_next(cx)).await;
            let link = self.first.link().id().clone();
            let scid = self.client_scid;
            let ours = move |datagram: &DatagramOf<E>| {
                datagram.link().id() == &link
                    && initial_scid(datagram.payload().as_ref()) == Some(scid)
            };
            let datagram = match delivery {
                DatagramDelivery::Exclusive(delivery) => delivery.consume().0.into_inner(),
                DatagramDelivery::Competing(candidate) => {
                    let attempt = candidate
                        .try_exclusive(|access, _| {
                            if ours(access.datagram()) {
                                DatagramClaimOutcome::Claimed(access.into_exclusive(), ())
                            } else {
                                DatagramClaimOutcome::Abandoned(())
                            }
                        })
                        .await;
                    match attempt {
                        DatagramClaimAttempt::Claimed(delivery, ())
                        | DatagramClaimAttempt::Exclusive(delivery) => {
                            delivery.consume().0.into_inner()
                        }
                        _ => continue,
                    }
                }
            };
            if initial_scid(datagram.payload().as_ref()).is_none() {
                // More of the client's 0-RTT, before its Initial.
                self.later.push(datagram);
                continue;
            }
            if datagram.payload().as_ref().len() < MIN_DATAGRAM_SIZE {
                continue;
            }
            if let Some((token, datagram)) = self.late.check(datagram).await {
                self.facts.token = token;
                self.later.push(datagram);
                self.has_initial = true;
            }
        }
        self
    }

    /// Retries the connection: sends a Retry packet with an address
    /// validation token, without keeping any state, and waits until the link
    /// took it (RFC 9000 §8.1.2).
    ///
    /// The client answers with a new Initial that carries the token. The
    /// endpoint validates it as it does after a stateless Retry and gives
    /// another incoming connection, whose [`facts`](Self::facts) hold
    /// [`ReturnedToken::Retry`]; the connection made from it states the
    /// `original_destination_connection_id` and `retry_source_connection_id`
    /// transport parameters from it (RFC 9000 §7.3). This incoming connection
    /// is dropped once the Retry is sent, and its registration revoked.
    ///
    /// # Errors
    ///
    /// [`RetryError`], which gives the incoming connection back as it was,
    /// its registration kept, when no Retry was sent:
    ///
    /// - [`RetryError::PeerNotSocketAddr`] when the peer is not a socket
    ///   address, against which a token cannot be checked;
    /// - [`RetryError::AlreadyRetried`] when the client's Initial already
    ///   returned a valid Retry token: a client accepts one Retry per
    ///   connection attempt (RFC 9000 §17.2.5.2);
    /// - [`RetryError::Random`] when the random source failed to issue the
    ///   token;
    /// - [`RetryError::Encode`] when the Retry cannot be encoded;
    /// - [`RetryError::AmplificationLimited`] when the Retry is more than
    ///   three times the bytes received from the client, as it may be for a
    ///   connection born from 0-RTT before its Initial arrived;
    /// - [`RetryError::EndpointClosed`] once the endpoint has been closed;
    /// - [`RetryError::Send`] when the link failed to send.
    #[expect(
        clippy::result_large_err,
        reason = "the error gives the incoming connection back by value"
    )]
    pub async fn retry(self) -> Result<(), RetryError<Self, <LinkOf<E> as Link>::SendError>> {
        let Some(&peer) = self.tokens.peer_socket_addr(&self.facts.peer) else {
            return Err(RetryError::PeerNotSocketAddr(self));
        };
        if matches!(self.facts.token, ReturnedToken::Retry { .. }) {
            return Err(RetryError::AlreadyRetried(self));
        }
        let token =
            match self
                .tokens
                .issue_retry(&peer, &self.client_dcid, self.domain.wall_clock.now())
            {
                Ok(token) => token,
                Err(source) => return Err(RetryError::Random { half: self, source }),
            };
        let scid = generate_stateless_scid::<E::ConnectionIds>(&self.domain.connection_ids);
        let packet = match encode_stateless_retry(
            &self.domain.crypto,
            &self.client_dcid,
            &self.client_scid,
            &scid,
            &token,
        ) {
            Ok(packet) => packet,
            Err(source) => return Err(RetryError::Encode { half: self, source }),
        };
        if packet.len() > self.received_bytes().saturating_mul(3) {
            return Err(RetryError::AmplificationLimited(self));
        }
        if self.domain.is_closed() {
            return Err(RetryError::EndpointClosed {
                half: self,
                source: EndpointClosedError,
            });
        }
        let batch = [OutgoingDatagram {
            payload: packet,
            ecn: EcnMarking::NotEct,
        }];
        let link = self.first.link().clone();
        match link.send(&batch).await {
            Ok(_) => Ok(()),
            Err(source) => Err(RetryError::Send { half: self, source }),
        }
    }

    /// Refuses the connection: sends an Initial packet that closes the
    /// attempt with `close`, without keeping any state, and waits until the
    /// link took it (RFC 9000 §5.2.2).
    ///
    /// Only a transport close can be sent in an Initial packet (RFC 9000
    /// §12.4); its reason phrase is cut so that the packet is at most three
    /// times the bytes received from the client, whose address is not
    /// validated (RFC 9000 §8.1).
    ///
    /// # Errors
    ///
    /// [`RefuseError`] when the link failed to send; it gives the incoming
    /// connection back, which can still be accepted or refused.
    #[expect(
        clippy::result_large_err,
        reason = "the error gives the incoming connection back by value"
    )]
    pub async fn refuse(
        self,
        close: TransportImmediateClose,
    ) -> Result<(), RefuseError<Self, <LinkOf<E> as Link>::SendError>> {
        let scid = generate_stateless_scid::<E::ConnectionIds>(&self.domain.connection_ids);
        let limit = self.received_bytes().saturating_mul(3);
        let packet = encode_initial_close(
            &self.domain.crypto,
            &self.client_dcid,
            &self.client_scid,
            &scid,
            &close,
            limit,
        );
        let batch = [OutgoingDatagram {
            payload: packet,
            ecn: EcnMarking::NotEct,
        }];
        let link = self.first.link().clone();
        match link.send(&batch).await {
            Ok(_) => Ok(()),
            Err(source) => Err(RefuseError { half: self, source }),
        }
    }

    /// How many bytes arrived from the client's address for this
    /// connection: the datagrams taken on the link of the first. Before the
    /// address is validated, what the server sends there is at most three
    /// times as much (RFC 9000 §8.1).
    fn received_bytes(&self) -> usize {
        let link = self.first.link().id();
        core::iter::once(&self.first)
            .chain(
                self.later
                    .iter()
                    .filter(|datagram| datagram.link().id() == link),
            )
            .map(|datagram| datagram.payload().as_ref().len())
            .sum()
    }
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> fmt::Debug for TerminableIncoming<E, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TerminableIncoming")
            .field("version", &self.facts.version)
            .field("token", &self.facts.token)
            .field("born_from_zero_rtt", &self.facts.born_from_zero_rtt)
            .finish_non_exhaustive()
    }
}

/// The incoming connection `H` could not be accepted. It is given back as it
/// was, its registration kept, for the application to refuse, change or
/// drop.
pub enum AcceptIncomingError<H> {
    /// The endpoint has been closed. The connection can still be refused.
    EndpointClosed {
        /// The incoming connection, as it was.
        half: H,
        /// The endpoint's closing.
        source: EndpointClosedError,
    },
    /// The timer granularity of the loss detection thresholds in the
    /// configuration is finer than the endpoint's clock (RFC 9002 §6.1.2).
    TimerGranularity {
        /// The incoming connection, as it was.
        half: H,
        /// The granularity and the clock's.
        source: GranularityBelowClockError,
    },
}

impl<H> fmt::Debug for AcceptIncomingError<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndpointClosed { source, .. } => f
                .debug_struct("EndpointClosed")
                .field("source", source)
                .finish_non_exhaustive(),
            Self::TimerGranularity { source, .. } => f
                .debug_struct("TimerGranularity")
                .field("source", source)
                .finish_non_exhaustive(),
        }
    }
}

impl<H> fmt::Display for AcceptIncomingError<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the incoming connection was not accepted")
    }
}

impl<H> core::error::Error for AcceptIncomingError<H> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::EndpointClosed { source, .. } => Some(source),
            Self::TimerGranularity { source, .. } => Some(source),
        }
    }
}

/// The incoming connection could not be refused: the link failed to send
/// the close.
pub struct RefuseError<H, S> {
    /// The incoming connection, as it was.
    pub half: H,
    /// Why the link did not send.
    pub source: S,
}

impl<H, S: fmt::Debug> fmt::Debug for RefuseError<H, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefuseError")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl<H, S> fmt::Display for RefuseError<H, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the link did not send the close that refuses the connection")
    }
}

impl<H, S: core::error::Error + 'static> core::error::Error for RefuseError<H, S> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// The incoming connection `H` was not retried: no Retry was sent. It is
/// given back as it was, its registration kept, for the application to
/// accept, refuse, change or drop.
pub enum RetryError<H, S> {
    /// The peer is not a socket address, against which a token cannot be
    /// checked.
    PeerNotSocketAddr(H),
    /// The client's Initial already returned a valid Retry token.
    AlreadyRetried(H),
    /// The Retry is more than three times the bytes received from the
    /// client, whose address is not validated (RFC 9000 §8.1).
    AmplificationLimited(H),
    /// The endpoint has been closed.
    EndpointClosed {
        /// The incoming connection, as it was.
        half: H,
        /// The endpoint's closing.
        source: EndpointClosedError,
    },
    /// The random source failed to issue the token.
    Random {
        /// The incoming connection, as it was.
        half: H,
        /// The random source's failure.
        source: RandomError,
    },
    /// The Retry cannot be encoded.
    Encode {
        /// The incoming connection, as it was.
        half: H,
        /// Why the packet cannot be encoded.
        source: EncodeStatelessRetryError,
    },
    /// The link failed to send the Retry.
    Send {
        /// The incoming connection, as it was.
        half: H,
        /// Why the link did not send.
        source: S,
    },
}

impl<H, S: fmt::Debug> fmt::Debug for RetryError<H, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerNotSocketAddr(_) => {
                f.debug_tuple("PeerNotSocketAddr").finish_non_exhaustive()
            }
            Self::AlreadyRetried(_) => f.debug_tuple("AlreadyRetried").finish_non_exhaustive(),
            Self::AmplificationLimited(_) => f
                .debug_tuple("AmplificationLimited")
                .finish_non_exhaustive(),
            Self::EndpointClosed { source, .. } => f
                .debug_struct("EndpointClosed")
                .field("source", source)
                .finish_non_exhaustive(),
            Self::Random { source, .. } => f
                .debug_struct("Random")
                .field("source", source)
                .finish_non_exhaustive(),
            Self::Encode { source, .. } => f
                .debug_struct("Encode")
                .field("source", source)
                .finish_non_exhaustive(),
            Self::Send { source, .. } => f
                .debug_struct("Send")
                .field("source", source)
                .finish_non_exhaustive(),
        }
    }
}

impl<H, S> fmt::Display for RetryError<H, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PeerNotSocketAddr(_) => {
                "the Retry was not sent: the peer is not a socket address"
            }
            Self::AlreadyRetried(_) => "the Retry was not sent: the client was already retried",
            Self::AmplificationLimited(_) => {
                "the Retry was not sent: it exceeds the amplification limit"
            }
            Self::EndpointClosed { .. }
            | Self::Random { .. }
            | Self::Encode { .. }
            | Self::Send { .. } => "the Retry was not sent",
        })
    }
}

impl<H, S: core::error::Error + 'static> core::error::Error for RetryError<H, S> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::PeerNotSocketAddr(_)
            | Self::AlreadyRetried(_)
            | Self::AmplificationLimited(_) => None,
            Self::EndpointClosed { source, .. } => Some(source),
            Self::Random { source, .. } => Some(source),
            Self::Encode { source, .. } => Some(source),
            Self::Send { source, .. } => Some(source),
        }
    }
}

/// The queue of incoming connections of a server endpoint, which the reflow
/// driver fills and the application's incoming streams take from.
#[doc(hidden)]
pub struct IncomingShared<E: EndpointChoices, S: AcceptingServerRole<E>> {
    config: S::Config,
    domain: Arc<Domain<E>>,
    capacity: NonZeroUsize,
    state: Mutex<IncomingState<E, S>>,
    counts: DropCounts,
    late: Arc<LateInitials<E>>,
}

struct IncomingState<E: EndpointChoices, S: AcceptingServerRole<E>> {
    queue: VecDeque<TerminableIncoming<E, S>>,
    waiting_born_from_zero_rtt: usize,
    receivers: usize,
    next_receiver: u64,
    wakers: Vec<(u64, Waker)>,
    /// No more incoming connections: the endpoint was closed or its reflow
    /// driver dropped.
    ended: bool,
}

#[derive(Default)]
struct DropCounts {
    incoming_queue_full: AtomicU64,
    zero_rtt_incoming_limit_reached: AtomicU64,
    version_negotiation_queue_full: AtomicU64,
    version_negotiation_send_set_full: AtomicU64,
    retry_send_set_full: AtomicU64,
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> IncomingShared<E, S> {
    pub(crate) fn new(config: S::Config, domain: &Arc<Domain<E>>) -> Self {
        let config_late_capacity = config.quotas.late_initial_queue_capacity;
        Self {
            capacity: config.quotas.incoming_queue_capacity,
            config,
            domain: Arc::clone(domain),
            state: Mutex::new(IncomingState {
                queue: VecDeque::new(),
                waiting_born_from_zero_rtt: 0,
                receivers: 0,
                next_receiver: 0,
                wakers: Vec::new(),
                ended: false,
            }),
            counts: DropCounts::default(),
            late: Arc::new(LateInitials::new(config_late_capacity)),
        }
    }

    pub(crate) fn late(&self) -> &Arc<LateInitials<E>> {
        &self.late
    }

    pub(crate) fn config(&self) -> &S::Config {
        &self.config
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity.get()
    }

    fn lock(&self) -> MutexGuard<'_, IncomingState<E, S>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the domain offers new connections, given `state`: someone
    /// takes them, and the endpoint neither was closed nor lost its reflow
    /// driver.
    fn refresh_offering(&self, state: &IncomingState<E, S>) {
        let offering = state.receivers > 0 && !state.ended && !self.domain.is_closed();
        self.domain.births.set_offering(offering);
    }

    /// The incoming connections waiting for the application.
    pub(crate) fn load(&self) -> IncomingLoad {
        let state = self.lock();
        reflow::load(state.queue.len(), state.waiting_born_from_zero_rtt)
    }

    /// Queues `half` for the application, and wakes the streams waiting.
    pub(crate) fn push(&self, half: TerminableIncoming<E, S>) {
        let wakers = {
            let mut state = self.lock();
            if state.ended || state.receivers == 0 {
                return;
            }
            if half.facts.born_from_zero_rtt {
                state.waiting_born_from_zero_rtt += 1;
            }
            state.queue.push_back(half);
            core::mem::take(&mut state.wakers)
        };
        for (_, waker) in wakers {
            waker.wake();
        }
    }

    /// Ends the incoming connections: queued ones are dropped, and every
    /// stream ends.
    pub(crate) fn end(&self) {
        let (queue, wakers) = {
            let mut state = self.lock();
            state.ended = true;
            state.waiting_born_from_zero_rtt = 0;
            self.refresh_offering(&state);
            (
                core::mem::take(&mut state.queue),
                core::mem::take(&mut state.wakers),
            )
        };
        drop(queue);
        for (_, waker) in wakers {
            waker.wake();
        }
    }

    fn register_receiver(&self) -> u64 {
        let mut state = self.lock();
        state.receivers += 1;
        let id = state.next_receiver;
        state.next_receiver += 1;
        self.refresh_offering(&state);
        id
    }

    fn deregister_receiver(&self, id: u64) {
        let mut state = self.lock();
        state.receivers -= 1;
        state.wakers.retain(|(receiver, _)| *receiver != id);
        self.refresh_offering(&state);
    }

    fn poll_next(&self, id: u64, cx: &mut Context<'_>) -> Poll<Option<TerminableIncoming<E, S>>> {
        let mut state = self.lock();
        if let Some(half) = state.queue.pop_front() {
            if half.facts.born_from_zero_rtt {
                state.waiting_born_from_zero_rtt -= 1;
            }
            return Poll::Ready(Some(half));
        }
        if state.ended || self.domain.is_closed() {
            return Poll::Ready(None);
        }
        match state
            .wakers
            .iter_mut()
            .find(|(receiver, _)| *receiver == id)
        {
            Some((_, waker)) => waker.clone_from(cx.waker()),
            None => state.wakers.push((id, cx.waker().clone())),
        }
        Poll::Pending
    }

    pub(crate) fn count_incoming_queue_full(&self) {
        self.counts
            .incoming_queue_full
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_retry_send_set_full(&self) {
        self.counts
            .retry_send_set_full
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn count_version_negotiation_send_set_full(&self) {
        self.counts
            .version_negotiation_send_set_full
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn set_version_negotiation_queue_dropped(&self, dropped: u64) {
        self.counts
            .version_negotiation_queue_full
            .store(dropped, Ordering::Relaxed);
    }

    pub(crate) fn dropped_input_counts(&self) -> DroppedInputCounts {
        let read = |count: &AtomicU64| count.load(Ordering::Relaxed);
        DroppedInputCounts {
            incoming_queue_full: read(&self.counts.incoming_queue_full),
            zero_rtt_incoming_limit_reached: read(&self.counts.zero_rtt_incoming_limit_reached),
            late_initial_queue_full: self.late.dropped(),
            version_negotiation_queue_full: read(&self.counts.version_negotiation_queue_full),
            version_negotiation_send_set_full: read(&self.counts.version_negotiation_send_set_full),
            retry_send_set_full: read(&self.counts.retry_send_set_full),
        }
    }

    pub(crate) fn count_zero_rtt_incoming_limit_reached(&self) {
        self.counts
            .zero_rtt_incoming_limit_reached
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> fmt::Debug for IncomingShared<E, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        f.debug_struct("IncomingShared")
            .field("waiting", &state.queue.len())
            .field("receivers", &state.receivers)
            .field("ended", &state.ended)
            .finish_non_exhaustive()
    }
}

/// The incoming connections of a server endpoint, as the application takes
/// them: one receiver of them.
///
/// Each incoming connection goes to one receiver; with several, whichever
/// polls first takes the next. While no receiver exists, the endpoint offers
/// no new connection. The stream ends once the endpoint is closed or its
/// reflow driver is dropped.
pub struct IncomingStream<E: EndpointChoices, S: AcceptingServerRole<E>> {
    shared: Arc<IncomingShared<E, S>>,
    id: u64,
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> IncomingStream<E, S> {
    pub(crate) fn new(shared: Arc<IncomingShared<E, S>>) -> Self {
        let id = shared.register_receiver();
        Self { shared, id }
    }
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> Stream for IncomingStream<E, S> {
    type Item = Incoming<TerminableIncoming<E, S>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.shared
            .poll_next(self.id, cx)
            .map(|half| half.map(Incoming::Terminable))
    }
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> Drop for IncomingStream<E, S> {
    fn drop(&mut self) {
        self.shared.deregister_receiver(self.id);
    }
}

impl<E: EndpointChoices, S: AcceptingServerRole<E>> fmt::Debug for IncomingStream<E, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingStream")
            .field("shared", &self.shared)
            .finish()
    }
}

/// The source connection ID of the first packet of the datagram `bytes`
/// when it is a QUIC version 1 Initial.
fn initial_scid(mut bytes: &[u8]) -> Option<ConnectionId> {
    let first = *bytes.first()?;
    // A long header with the packet type of a version 1 Initial (RFC 9000
    // §17.2.2).
    if first & 0x80 == 0 || (first >> 4) & 0b11 != 0 {
        return None;
    }
    let header = bytes.sync_read_long_header_unpin().ok()?;
    if header.version() != Version::V1 {
        return None;
    }
    ConnectionId::try_from(*header.scid()).ok()
}
