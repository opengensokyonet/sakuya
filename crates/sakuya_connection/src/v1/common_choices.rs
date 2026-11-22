//! What every part of version 1 reads of a composition's choices: the two
//! slots of the choices of version 1 ([`V1Choices`]), the side and the
//! host, with what the host picks for all of them
//! ([`CommonHostChoices`]) and what every side has ([`CommonSide`]), and
//! the markers of the two sides ([`Server`], [`Client`]).
//!
//! The other parts each have a trait of their own for the slots: the
//! connection's state its host's choices and its side
//! ([`StateHostChoices`](super::state_choices::StateHostChoices),
//! [`StateSide`](super::state_choices::StateSide)), version 1 its side
//! ([`Side`](super::Side)); each implements its side for [`Server`] and
//! [`Client`].

use core::{fmt::Debug, marker::PhantomData};

use bytes::Bytes;
use kasen_handshake::{
    alert::CallsForAlert,
    client::engine::ClientHandshakeSteps,
    engine::HandshakeError,
    extension::alpn::ProtocolName,
    schedule::Exporter,
    server::{engine::ServerHandshakeSteps, targets::SelectedTarget},
};
use sakuya_link::Link;
use sakuya_wire_v1::{role::Role, transport_parameters::TransportParameterSlots};

use super::{
    application_handles::{
        self,
        connection::{ClientHandshakeFacts, ServerHandshakeFacts},
    },
    close::{self, ApplicationClose, LocalCloseCause},
    events,
    parameters::{ResumedParametersPolicy, UseConfiguredParameters},
    streams::{self, StreamSetFamily},
};
use crate::{
    clock::{ConnectionChoices, InstantOf},
    error::ConnectionErrorOf,
    send_strategy::SendStrategyTypes,
};

/// The choices of version 1 of a composition: the side of the connection
/// and the host's type, which picks the rest. The parts read each slot
/// through a trait of their own besides.
pub trait V1Choices: ConnectionChoices {
    /// Which side of the connection this side is.
    type Side: CommonSide;
    /// The host's type, which picks the rest.
    type Host: CommonHostChoices<Self>;
}

/// What the host picks for every part of version 1, for the connections
/// whose choices are `T`. What has one implementation in sakuya has it as
/// its default.
pub trait CommonHostChoices<T: ConnectionChoices + ?Sized>: 'static {
    /// The application's own error type for closing the connection.
    type ApplicationError: ApplicationClose + 'static;
    /// What adjusts the close this endpoint sends at each encryption level:
    /// an [`ImmediateClosePolicy`](close::ImmediateClosePolicy) of this
    /// endpoint's reason for closing, [`CloseCauseOf`] for the composition's
    /// list of parts. The connection keeps the one it was made with.
    // defaults: 5b
    type ImmediateClosePolicy: Clone + 'static = close::PassThroughImmediateClosePolicy;
    /// What decides, for a connection a server resumes, how version 1's
    /// transport parameters go: reject 0-RTT, send those remembered, or
    /// send those configured ([`ResumedParametersPolicy`]). The connection
    /// keeps the one it was made with; the default sends those configured.
    // defaults: 5b
    type ResumedParametersPolicy: ResumedParametersPolicy<TransportParameterSlots> + Clone + 'static =
        UseConfiguredParameters;
    /// The core of the send strategy, for the types `I` the composition
    /// gives it; it starts as its default makes it.
    // defaults: 5b
    type SendStrategy<I: SendStrategyTypes>: Default =
        crate::send_strategy::ranked::RankedSendStrategy<I>;
    /// The kind of the connection's stream set in the established layer
    /// ([`streams`]), which gives the set's configuration and the
    /// parameters application data is sent with; the send strategy
    /// constrains the parameters with a trait of its own.
    // defaults: 5b
    type Streams: StreamSetFamily = streams::owned::OwnedStreamSetFamily;
    /// What receives the connection's events ([`events`]), one for each
    /// connection, kept in the connection node; `L` is the composition's
    /// list of parts. The events that carry packets need
    /// [`PacketEvents`](events::PacketEvents) for that list besides, which
    /// the composition proves; the default records nothing, for any list. A
    /// receiver that writes the parts' own events names the list it writes
    /// them for, as qlog's does ([`SharedEvents::PartEvents`](events::SharedEvents::PartEvents)).
    // defaults: 5b
    type Events<L>: events::ConnectionEvents<InstantOf<T>> = events::NoEvents;
}

/// What every part of version 1 reads of the side of the connection.
pub trait CommonSide: 'static {
    /// The role of this side.
    const ROLE: Role;

    /// The exporter this side's handshake gives when it completes, which
    /// the connection node keeps until the connection closes.
    type Exporter: 'static;

    /// What this side knows of its handshake once it completed, which the
    /// connection handle gives
    /// ([`ClientHandshakeFacts`], [`ServerHandshakeFacts`]).
    type HandshakeFacts: 'static;

    /// What an established layer of this side runs with of the handshake's
    /// selection, which the layer's handle gives: the application protocol,
    /// on a server together with the selected target.
    type LayerSelection: application_handles::established_layer::LayerSelection + 'static;

    /// How this side's handshake engine fails with an alert: the failure
    /// that [`HandshakeError`] holds for it.
    type AlertError: CallsForAlert + 'static;
}

/// The host's choices of the choices `T`, as every part reads them.
type CommonHostOf<T> = <T as V1Choices>::Host;
/// The application's error type of the choices `T`.
pub type ApplicationErrorOf<T> = <CommonHostOf<T> as CommonHostChoices<T>>::ApplicationError;
/// The close policy of the choices `T`.
pub type ImmediateClosePolicyOf<T> =
    <CommonHostOf<T> as CommonHostChoices<T>>::ImmediateClosePolicy;
/// The policy of version 1's transport parameters on resumption, of the
/// choices `T`.
pub type ResumedParametersPolicyOf<T> =
    <CommonHostOf<T> as CommonHostChoices<T>>::ResumedParametersPolicy;
/// The kind of stream set of the choices `T`.
pub type StreamSetFamilyOf<T> = <CommonHostOf<T> as CommonHostChoices<T>>::Streams;
/// The parameters application data is sent with, of the choices `T`.
pub type SendParametersOf<T> = <StreamSetFamilyOf<T> as StreamSetFamily>::SendParameters;
/// The configuration of the stream set of the choices `T`.
pub type StreamSetConfigOf<T> = <StreamSetFamilyOf<T> as StreamSetFamily>::Config;
/// The receiver of the connection's events, of the choices `T` and the list
/// of parts `L`.
pub type EventsOf<T, L> = <CommonHostOf<T> as CommonHostChoices<T>>::Events<L>;
/// What the receiver of the connection's events is made from, of the
/// choices `T` and the list of parts `L`.
pub type EventsConfigOf<T, L> = <EventsOf<T, L> as events::ConnectionEvents<InstantOf<T>>>::Config;

/// The handle the application's threads give the connection's events
/// through, of the choices `T` and the list of parts `L`.
pub type SharedEventsOf<T, L> = <EventsOf<T, L> as events::ConnectionEvents<InstantOf<T>>>::Shared;

/// This endpoint's reason for closing a connection of the choices `T` and
/// the list of parts `L`: the connection's error, the handshake's error,
/// which holds the alert failure of the side's handshake engine, the
/// application's error, or why the choices' link ended.
pub type CloseCauseOf<T, L> = LocalCloseCause<
    ConnectionErrorOf<L>,
    HandshakeError<<<T as V1Choices>::Side as CommonSide>::AlertError, ConnectionErrorOf<L>>,
    ApplicationErrorOf<T>,
    <<T as ConnectionChoices>::Link as Link>::RecvError,
>;

/// The server's side, with the handshake engine whose start state is
/// `Tls` and the issuer `Ti` of the tokens of its NEW_TOKEN frames
/// ([`ConnectionNewTokenIssuer`](super::address_token::ConnectionNewTokenIssuer)).
pub struct Server<Tls, Ti>(Marker<(Tls, Ti)>);

impl<Tls, Ti> Debug for Server<Tls, Ti> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Server")
    }
}

impl<Tls, Ti> CommonSide for Server<Tls, Ti>
where
    Tls: ServerHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    Tls::Target: 'static,
    Ti: 'static,
{
    const ROLE: Role = Role::Server;
    type Exporter = Exporter<Tls::Crypto>;
    type HandshakeFacts = ServerHandshakeFacts<Tls::Target>;
    type LayerSelection = SelectedTarget<Tls::Target>;
    type AlertError = Tls::AlertError;
}

/// The client's side, with the handshake engine whose start state is
/// `Tls`, the sink `Tk` of the address validation tokens its server gives
/// it, the Retry policy `Rp` and the connector `Lc` of the links it
/// migrates to ([`LinkConnector`](super::link_connector::LinkConnector)).
pub struct Client<Tls, Tk, Rp, Lc>(Marker<(Tls, Tk, Rp, Lc)>);

/// What a side type holds of its parameters: nothing.
type Marker<T> = PhantomData<fn() -> T>;

impl<Tls, Tk, Rp, Lc> Debug for Client<Tls, Tk, Rp, Lc> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Client")
    }
}

impl<Tls, Tk, Rp, Lc> CommonSide for Client<Tls, Tk, Rp, Lc>
where
    Tls: ClientHandshakeSteps + 'static,
    Tls::AlertError: 'static,
    Tk: 'static,
    Rp: 'static,
    Lc: 'static,
{
    const ROLE: Role = Role::Client;
    type Exporter = Exporter<Tls::Crypto>;
    type HandshakeFacts = ClientHandshakeFacts;
    type LayerSelection = Option<ProtocolName<Bytes>>;
    type AlertError = Tls::AlertError;
}
