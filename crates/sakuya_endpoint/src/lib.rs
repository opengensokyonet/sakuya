#![forbid(unsafe_code)]
//! QUIC endpoints for sakuya.
//!
//! An endpoint owns one datagram routing domain: its link bindings, the
//! reception on the logical links of those bindings, and the birth of new
//! connections. This crate holds the parts of an endpoint that do not depend
//! on how a connection is built:
//!
//! - [`address_token`]: address validation tokens, issued in Retry packets and
//!   NEW_TOKEN frames and validated when a client returns them
//!   ([RFC 9000 §8.1]).
//! - [`retry`]: the Retry packet a server sends before it keeps any state, and
//!   the policy that decides when to send one.
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
//!
//! [RFC 9000 §6]: https://www.rfc-editor.org/rfc/rfc9000.html#section-6
//! [RFC 9000 §8.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1

pub mod address_token;
pub mod client_token;
pub mod dropped_input;
pub mod invalid_token;
pub mod quota;
pub mod retry;
pub mod send_set;
pub mod version_negotiation;
pub mod zero_length;

#[cfg(test)]
mod test_link;
