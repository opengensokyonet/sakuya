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
//! the connection only: the host puts it in a wrapper
//! ([`SharedConnection`](sakuya_connection::shared::SharedConnection)),
//! spawns the future that drives it there
//! ([`SharedConnectionDriver`](sakuya_connection::shared::SharedConnectionDriver)),
//! and takes the application's
//! [`ConnectionHandle`](sakuya_connection::v1::application_handles::connection::ConnectionHandle)
//! from the wrapper.
//!
//! The server and client roles are each a type parameter of the endpoint, so
//! an endpoint may accept new links, or only connect ([`role`]). The
//! binding drivers and the reflow driver are futures the host spawns. A
//! binding driver receives on each link of its binding and hands the
//! datagrams to routing; a link no one uses any more stops
//! ([`binding`]). The reflow driver takes the datagrams no connection claims:
//! it validates address validation tokens, answers with a stateless Retry, an
//! INVALID_TOKEN close or a Version Negotiation packet where it should, each
//! in a bounded set of sends, and otherwise gives the application an incoming
//! connection, which it accepts, refuses or drops, after reading the
//! client's first ClientHello if it chooses to ([`incoming`]). Accepting and
//! starting register the first local connection ID and make the connection
//! from each part's configuration ([`part`]). Closing the endpoint
//! ([`endpoint::Endpoint::close`]) ends the incoming connections not taken
//! yet; the connections already made go on and end by themselves, and the
//! drivers end once they all have.
//!
//! - [`choices`]: what an endpoint is composed with, and the types of its
//!   routing domain, among them the datagram receiver of its connections.
//! - [`role`]: the server and client roles.
//! - [`synchronization`]: how the endpoint's state is synchronized, a
//!   family the host chooses, and the wrapper of its state.
//! - [`config`]: the configuration of the endpoint and its roles, and the
//!   checks it passes.
//! - [`handshake`]: what makes the start state of each connection's
//!   handshake engine.
//! - [`part`]: the parts of an endpoint, standing for the parts of its
//!   connections, the configuration of each, and how the connection's start
//!   values are made from it; [`v1`] is QUIC version 1's.
//! - [`endpoint`], [`reflow`], [`incoming`], [`outgoing`]: the endpoint,
//!   its reflow driver, and the incoming and outgoing connections.
//! - [`passthrough`]: what an incoming connection hands off when the server
//!   forwards its datagrams to another server instead of accepting it: what
//!   it takes to build the first flight again for the other server, and a
//!   receiver of the client's later datagrams. The proof of concept, a Relay
//!   that serves one name and forwards another from the same socket, is the
//!   test `forwarding`, which needs the package's feature
//!   `passthrough_experiment`.
//! - [`domain`]: what the bindings, the reflow driver and the connections of
//!   one endpoint share.
//! - [`address_token`]: address validation tokens, issued in Retry packets and
//!   NEW_TOKEN frames and validated when a client returns them
//!   ([RFC 9000 §8.1]); [`address_token::AeadAddressTokens`] seals them with
//!   an AEAD under a key derived for each token.
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
//! - [`link_connector`]: what a client connection takes links of its own
//!   with, to migrate to a server's preferred address.
//! - [`binding`]: the driver of each link binding, which takes the binding's
//!   new links and receives on each of them.
//!
//! [RFC 9000 §6]: https://www.rfc-editor.org/rfc/rfc9000.html#section-6
//! [RFC 9000 §8.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1

extern crate alloc;

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
pub mod issuer;
mod late_initial;
pub mod link;
pub mod link_connector;
pub mod outgoing;
pub mod part;
pub mod passthrough;
pub mod quota;
pub mod reflow;
pub mod retry;
pub mod role;
pub mod send_set;
pub mod stateless_check;
pub mod synchronization;
pub mod v1;
pub mod version_negotiation;
pub mod zero_length;

#[cfg(test)]
mod memory_link;
#[cfg(test)]
mod test_link;
