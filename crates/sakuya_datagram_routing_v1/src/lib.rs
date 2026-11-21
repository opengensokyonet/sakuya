//! Datagram routing and claim delivery for sakuya
//!
//! A received UDP datagram is routed to a frozen set of route entries. Each
//! entry's [`DatagramDeliverer`](claim::deliverer::DatagramDeliverer) receives a claim
//! candidate for the datagram, and the candidates compete for the single
//! original datagram. The [`claim`] module implements that competition: how
//! whoever holds a candidate attempts to take the datagram with its own
//! judgment, and how the winner gains exclusive ownership. The [`route`]
//! module builds on it: the route index,
//! registrations, first-packet recognition, stateless reset detection, and the
//! reflow through which a routing domain accepts new Initial receivers.
//!
//! The index is keyed by connection ID: the entries of one non-empty
//! connection ID, whether found by a local connection ID or by an Initial
//! destination connection ID, share a bucket; the entries of zero-length
//! connection IDs are kept by this side's end of the link
//! ([`route::index`]). A registration is revoked by dropping its handle
//! ([`route`]). The reflow does not run on the stack of the call that found
//! no one claiming the datagram: the outer layer resumes it later, rechecks
//! the Initial's key and publishes the prepared receiver, offers the datagram
//! to entries that had no chance yet, or releases it
//! ([`route::acceptance`]).
#![feature(associated_type_defaults)]
#![feature(type_alias_impl_trait)]
#![deny(missing_docs)]

extern crate alloc;

pub mod claim;
pub mod route;
