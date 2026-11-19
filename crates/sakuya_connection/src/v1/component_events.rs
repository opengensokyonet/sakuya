//! The component events of version 1: what happens in the nodes of a
//! connection, published by whoever makes it happen and handed to what
//! subscribes to it ([`component_event`](crate::component_event)).
//!
//! Each is a type without contents, of the layer of the node it happens in.
//! The keys of one encryption level are told apart by a marker of the level
//! ([`level`]). A method of version 1 that changes a component returns what
//! happened as a [`Happened`](crate::component_event::Happened), which its
//! caller publishes in its lend; where version 1 wraps a policy of the
//! host, it publishes once the policy reports that its queries changed.
//! What the driver's content has to send is published both when it grows
//! and when it shrinks.
//!
//! These are not the events of the connection's records, such as qlog's:
//! those are [`events`](super::events).

use core::marker::PhantomData;

use crate::{
    component_event::ComponentEvent,
    layer::{Connection, LinkEntry, LinkPath, LogicalPath, Recovery},
};

/// The encryption levels whose keys the key events tell apart.
pub mod level {
    /// The Initial keys.
    #[derive(Debug)]
    pub struct Initial;
    /// The Handshake keys.
    #[derive(Debug)]
    pub struct Handshake;
    /// The 0-RTT keys.
    #[derive(Debug)]
    pub struct ZeroRtt;
    /// The 1-RTT keys.
    #[derive(Debug)]
    pub struct OneRtt;

    mod sealed {
        pub trait Sealed {}
        impl Sealed for super::Initial {}
        impl Sealed for super::Handshake {}
        impl Sealed for super::ZeroRtt {}
        impl Sealed for super::OneRtt {}
    }

    /// An encryption level of version 1, as a marker of the key events.
    pub trait KeyLevel: sealed::Sealed + 'static {}
    impl KeyLevel for Initial {}
    impl KeyLevel for Handshake {}
    impl KeyLevel for ZeroRtt {}
    impl KeyLevel for OneRtt {}
}

use self::level::KeyLevel;

macro_rules! component_events {
    ($($(#[$doc:meta])* $name:ident: $layer:ident;)*) => {$(
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name;
        impl ComponentEvent for $name {
            type Layer = $layer;
        }
    )*};
}

macro_rules! level_events {
    ($($(#[$doc:meta])* $name:ident: $layer:ident;)*) => {$(
        $(#[$doc])*
        pub struct $name<Lv>(PhantomData<fn() -> Lv>);
        impl<Lv: KeyLevel> ComponentEvent for $name<Lv> {
            type Layer = $layer;
        }
    )*};
}

level_events! {
    /// The keys of the level `Lv` were installed: the advancing call
    /// installed them, or a client that received a Retry derived its
    /// Initial keys anew.
    KeysInstalled: Connection;
    /// The keys of the level `Lv` were discarded, or kept only their
    /// receiving half: the Handshake keys when the handshake is confirmed,
    /// the Initial keys when a server processed its first Handshake packet
    /// or a client sealed its first, a server's 0-RTT keys when they are
    /// discarded, and the keys of every level as the connection closes.
    KeysDiscarded: Connection;
    /// The keys of the level `Lv` started to retire: a server processed its
    /// first 1-RTT packet, and its 0-RTT keys are kept a while longer.
    KeysRetiring: Connection;
}

component_events! {
    /// The 1-RTT keys moved to their next key phase: a packet of the next
    /// phase was received, or this side updated its keys.
    KeyPhaseChanged: Connection;
    /// The handshake was confirmed: the advancing call confirmed it, or a
    /// client received HANDSHAKE_DONE.
    HandshakeConfirmed: Connection;
    /// The advancing call read the peer's transport parameters.
    PeerTransportParametersKnown: Connection;
    /// The advancing call wrote this side's transport parameters.
    LocalTransportParametersSent: Connection;
    /// What was published through the send strategy's publisher, resized
    /// or withdrawn there may change the plan of a link path: the
    /// publisher compared it with the room the link path left there as it
    /// took it.
    SendIntentsChanged: Connection;
    /// The reason for closing was first written into the record of why the
    /// connection closed: this side found an error, the application closed
    /// it, the idle timeout came, or a stateless reset was received.
    CloseReasonWritten: Connection;
    /// What the CRYPTO frames have to send changed: CRYPTO data to send was
    /// written, was put into a packet, was lost, or went with its level.
    CryptoOutputChanged: Connection;
    /// A server's HANDSHAKE_DONE became due, or was sent.
    HandshakeDonePendingChanged: Connection;
    /// The NEW_TOKEN frames a server has to send changed: a token was
    /// issued, or was sent.
    NewTokenPendingChanged: Connection;
    /// A client accepted a Retry.
    RetryReceived: Connection;

    /// The link reported that the datagram size ceiling of the logical
    /// link changed.
    LinkCeilingChanged: LinkEntry;
    /// The anti-amplification credit of the logical link changed: a
    /// datagram was received or sent before the address was validated, or
    /// the address was validated.
    AmplificationCreditChanged: LinkEntry;

    /// An ACK frame was processed.
    AckReceived: LogicalPath;
    /// What ACK frames have to send changed: an ACK became due now, a
    /// delayed acknowledgment came due, or an ACK was written, acknowledged
    /// or lost.
    AckPendingChanged: LogicalPath;
    /// The destination connection IDs changed: the strategy for them
    /// reported that its queries changed, the first Initial packet set the
    /// handshake's connection ID, or a Retry did.
    DestinationConnectionIdsChanged: LogicalPath;
    /// The local connection IDs changed: the strategy for them reported
    /// that its queries changed, or one of its frames was written or lost.
    LocalConnectionIdsChanged: LogicalPath;
    /// A packet number space was retired.
    SpaceRetired: LogicalPath;

    /// The link path's role changed: it entered `Closing` or `Draining`,
    /// including when the peer's close or a stateless reset puts every link
    /// path into `Draining`.
    LinkPathRoleChanged: LinkPath;
    /// The sending call settled a batch of packets sent on the link path.
    PacketsSent: LinkPath;
    /// The PINGs to send changed: the probe timeout came and asked for
    /// PINGs, or a PING was written.
    ProbePingsChanged: LinkPath;
    /// The response to a PATH_CHALLENGE to send changed: a PATH_CHALLENGE
    /// was received, or the response was written.
    PathResponsePendingChanged: LinkPath;
    /// Whether a PATH_CHALLENGE is to be sent changed: one became due, or
    /// was written.
    PathChallengePendingChanged: LinkPath;
    /// The link path's path validation concluded, validated or failed, and
    /// the conclusion waits for the rules of connection migration.
    PathValidationConcluded: LinkPath;
    /// The close packet changed: it was sealed, or a datagram was received
    /// after it was sealed.
    ClosePacketChanged: LinkPath;
    /// The datagram size probe to send changed: the sending call wrote its
    /// PING, or the start of a datagram set it anew.
    PmtuProbePendingChanged: LinkPath;

    /// What congestion control allows changed: an ACK was processed,
    /// packets were sent, taken out of flight or declared lost, the probe
    /// timeout came, a packet number space was retired, or a Retry was
    /// received; or pacing reported a change once it was refilled.
    CongestionChanged: Recovery;
    /// The RTT estimates changed: an ACK brought a sample, or a Retry was
    /// received.
    RttSampled: Recovery;
    /// Packets were declared lost by the time threshold or when the probe
    /// timeout came.
    PacketsLost: Recovery;
    /// The datagram size probing policy reported that its conclusion
    /// changed.
    PmtuConcluded: Recovery;
}
