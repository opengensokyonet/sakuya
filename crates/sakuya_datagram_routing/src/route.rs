//! Datagram routing: from a received datagram to its claim candidates
//!
//! A link's datagram dispatcher receives each complete UDP datagram and passes
//! it, with the link, to [`DatagramRouter::route`] as a [`ReceivedDatagram`].
//! Routing keeps the receive registrations of one routing domain in a
//! [`RouteIndex`], recognizes the first packet of the datagram, finds every
//! route entry that applies, and delivers one claim candidate per entry
//! through the [claim mechanism](crate::claim). Delivery completing means only
//! that routing handed the candidates over; it does not mean that anything
//! was claimed, authenticated, accepted or processed. Routing never advances
//! TLS and never updates acknowledgements, packet numbers, flow control or
//! path validation.
//!
//! # Associations and the index
//!
//! A route entry is found under a [`MatchAssociation`]: a local connection ID,
//! an Initial destination connection ID, or the zero-length connection ID on
//! this side's end of the arrival link. Every kind holds any number of entries; each registration is
//! its own [`DatagramRouteEntry`] with its own identity, published together
//! with its [`RouteMatcher`] and its erased deliverer. The datagram receiver
//! holds the [`RouteEntryRegistration`] and revokes exactly its entry by
//! dropping it. Revoking stops new lookups from finding the entry; candidates
//! already delivered keep the original deliverer.
//!
//! # Interpretations
//!
//! A [`FirstPacketInterpretation`] states how a candidate reads the first
//! packet. Long headers state their connection IDs; for short headers a
//! [`ConnectionIdRecognizer`] yields every applicable destination connection
//! ID length, zero included only when it says so. The same entry under two
//! interpretations is two chances; the same entry and interpretation found
//! twice is one.
//!
//! # One round
//!
//! All recognition and lookup happen while the router still owns the
//! datagram. The complete set of entries is frozen, the index is left, the
//! light candidate objects are built, and only then is each deliverer called.
//! Entries registered after the freeze do not join the round. A supported
//! Initial the domain may accept uses the on-unclaimed finish policy; every
//! other datagram uses last takes.
//!
//! # Accepting new Initials
//!
//! When every candidate of an acceptable Initial exits, the last exit hands an
//! [`UnclaimedWork`] to the configured [`ReflowProvider`] through the domain's
//! [`ReflowHandoff`], without continuing on that call stack. The outer layer
//! later passes it to [`DatagramRouter::resume`], which prepares a receiver,
//! rechecks the Initial's key within one entry access, and either offers the
//! datagram to entries that had no chance yet, publishes the prepared
//! receiver, or releases the datagram. See [`InitialAcceptance`].
//!
//! # Stateless resets
//!
//! Before any of this, the last 16 bytes of every datagram are checked by the
//! configured [`StatelessResetDetector`]; a hit ends ordinary routing.
//!
//! Sending a stateless reset is a separate matter: a short header datagram
//! whose lookups found no entry, read with a non-empty destination connection
//! ID, goes to the configured [`StatelessResetService`] instead of being
//! released.
//!
//! [`DatagramRouter::route`]: router::DatagramRouter::route
//! [`DatagramRouter::resume`]: router::DatagramRouter::resume
//! [`ReceivedDatagram`]: datagram::ReceivedDatagram
//! [`RouteIndex`]: index::RouteIndex
//! [`MatchAssociation`]: association::MatchAssociation
//! [`DatagramRouteEntry`]: index::DatagramRouteEntry
//! [`RouteMatcher`]: association::RouteMatcher
//! [`RouteEntryRegistration`]: index::RouteEntryRegistration
//! [`FirstPacketInterpretation`]: interpretation::FirstPacketInterpretation
//! [`ConnectionIdRecognizer`]: recognizer::ConnectionIdRecognizer
//! [`UnclaimedWork`]: acceptance::UnclaimedWork
//! [`ReflowProvider`]: acceptance::ReflowProvider
//! [`ReflowHandoff`]: acceptance::ReflowHandoff
//! [`InitialAcceptance`]: acceptance::InitialAcceptance
//! [`StatelessResetDetector`]: reset::StatelessResetDetector
//! [`StatelessResetService`]: router::StatelessResetService

pub mod acceptance;
pub mod association;
pub mod datagram;
pub mod index;
pub mod interpretation;
pub mod recognizer;
pub mod reset;
pub mod router;

#[cfg(test)]
mod tests;
