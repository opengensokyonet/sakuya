//! Datagram routing and claim delivery for sakuya
//!
//! A received UDP datagram is routed to a frozen set of route entries. Each
//! entry's [`DatagramDeliverer`](claim::DatagramDeliverer) receives a claim
//! candidate for the datagram, and the candidates compete for the single
//! original datagram. The [`claim`] module implements that competition: how a
//! candidate attempts to take the datagram, how the winner gains exclusive
//! ownership, and how the deliverer's private per-datagram state is created,
//! kept and handed over. The [`route`] module builds on it: the route index,
//! registrations, first-packet recognition, stateless reset detection, and the
//! reflow through which a routing domain accepts new Initial receivers.
#![feature(type_alias_impl_trait)]
#![deny(missing_docs)]

pub mod claim;
pub mod route;
