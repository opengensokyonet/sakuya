#![feature(impl_trait_in_assoc_type)]
#![forbid(unsafe_code)]
//! QUIC endpoints for sakuya.
//!
//! An endpoint owns one datagram routing domain: its link bindings, the
//! reception on the logical links of those bindings, and the birth of new
//! connections. [`endpoint::Endpoint`] is made with its
//! [`reflow::ReflowDriver`] from an [`config::EndpointConfig`]; each binding
//! added gives an [`endpoint::BindingHandle`] and a
//! [`binding::BindingDriver`]. A server takes [`incoming::Incoming`]
//! connections and accepts or refuses them; a client connects through a
//! binding handle and starts the [`outgoing::Outgoing`] connection. Both give
//! the connection's future, which the host spawns, and its
//! [`ConnectionHandle`](sakuya_connection::v1::application_handles::connection::ConnectionHandle).
//!
//! - [`choices`]: what an endpoint is composed with, and the types of its
//!   routing domain, among them the datagram receiver of its connections.
//! - [`role`]: the server and client roles.
//! - [`config`]: the configuration of the endpoint and its roles, and the
//!   checks it passes.
//! - [`handshake`]: what makes the start state of each connection's
//!   handshake engine.
//! - [`part`]: the configuration of each part of a connection, and how the
//!   connection's start values are made from it; [`v1`] is QUIC version 1's.
//! - [`endpoint`], [`reflow`], [`incoming`], [`outgoing`]: the endpoint,
//!   its reflow driver, and the incoming and outgoing connections.
//! - [`domain`]: what the bindings, the reflow driver and the connections of
//!   one endpoint share.
//! - [`address_token`]: address validation tokens, issued in Retry packets and
//!   NEW_TOKEN frames and validated when a client returns them
//!   ([RFC 9000 §8.1]).
//! - [`retry`]: the Retry packet a server sends before it keeps any state, and
//!   the policy that decides when to send one.
//! - [`stateless_check`]: what the reflow driver decides about a datagram
//!   that may start a connection, before any state for it exists.
//! - [`invalid_token`]: the Initial packet that closes a connection attempt
//!   with INVALID_TOKEN when a client returns a Retry token that does not
//!   validate.
//! - [`version_negotiation`]: the Version Negotiation packet a server sends
//!   for a version it does not support ([RFC 9000 §6]).
//! - [`send_set`]: the bounded set of sends in progress that an endpoint keeps
//!   for each kind of response it sends without a connection.
//! - [`quota`]: the bounds an endpoint applies to work that arrives without a
//!   connection.
//! - [`dropped_input`]: what an endpoint dropped of that work, counted by
//!   the bound that was reached.
//! - [`zero_length`]: the local ends on which a connection uses
//!   zero-length local connection IDs, and the recognizer that reads short
//!   headers there accordingly.
//! - [`client_token`]: where a client keeps the tokens servers gave it for
//!   later connections.
//! - [`link`]: the endpoint's link, the sum of the links of its bindings.
//! - [`binding`]: the driver of each link binding, which takes the binding's
//!   new links and receives on each of them.
//!
//! [RFC 9000 §6]: https://www.rfc-editor.org/rfc/rfc9000.html#section-6
//! [RFC 9000 §8.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1

pub mod address_token;
pub mod binding;
pub mod choices;
pub mod client_token;
pub mod config;
mod connection;
pub mod domain;
pub mod dropped_input;
pub mod endpoint;
pub mod handshake;
pub mod incoming;
pub mod invalid_token;
mod late_initial;
pub mod link;
mod make;
pub mod outgoing;
pub mod part;
pub mod quota;
pub mod reflow;
pub mod retry;
pub mod role;
pub mod send_set;
pub mod stateless_check;
pub mod v1;
pub mod version_negotiation;
pub mod zero_length;

#[cfg(test)]
mod memory_link;
#[cfg(test)]
mod test_link;
