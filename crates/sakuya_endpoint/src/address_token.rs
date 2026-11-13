//! Address validation tokens ([RFC 9000 §8.1]).
//!
//! A server gives a client a token in a Retry packet or a NEW_TOKEN frame; a
//! client that returns it in an Initial packet proves it receives packets at
//! its address, so the server need not limit what it sends there before the
//! handshake validates the address. The token component issues and validates
//! them: [`AddressTokens`] on the endpoint's side, where Initial packets
//! arrive and Retry packets leave, and [`NewTokenIssuer`] on a connection's
//! side, where NEW_TOKEN frames leave.
//!
//! A Retry token is accepted only for a short time; a NEW_TOKEN token is
//! accepted for longer, and at most once, which [`UsedNewTokens`] records
//! ([RFC 9000 §8.1.4]). [`AeadAddressTokens`] is the component the endpoint
//! uses unless it is given another.
//!
//! [RFC 9000 §8.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1
//! [RFC 9000 §8.1.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4

use std::{net::SocketAddr, time::Duration};

use bytes::Bytes;
use nitori_crypto::RandomError;
use sakuya_wire::connection_id::ConnectionId;
use time::UtcDateTime;

mod aead;
mod used;

pub use aead::{
    AddressTokenKey, AddressTokenLifetimes, AeadAddressTokens, AeadAddressTokensError,
    AeadNewTokenIssuer,
};
pub use used::UsedNewTokens;

/// How long a Retry token is accepted after it is issued unless the
/// endpoint is configured otherwise: 15 seconds.
pub const DEFAULT_RETRY_TOKEN_LIFETIME: Duration = Duration::from_secs(15);

/// How long a NEW_TOKEN token is accepted after it is issued unless the
/// endpoint is configured otherwise: two weeks.
pub const DEFAULT_NEW_TOKEN_LIFETIME: Duration = Duration::from_secs(14 * 24 * 60 * 60);

/// The token component on the endpoint's side.
///
/// Issuing and validating are synchronous: the endpoint calls them while it
/// decides what to do with an Initial packet, before any connection state
/// exists.
pub trait AddressTokens {
    /// What a connection holds to issue NEW_TOKEN tokens.
    type NewTokenIssuer: NewTokenIssuer;

    /// The issuer a new connection holds.
    fn new_token_issuer(&self) -> Self::NewTokenIssuer;

    /// A token for a Retry packet sent to `peer` in response to an Initial
    /// packet whose Destination Connection ID was `original_dcid`.
    ///
    /// The token carries `original_dcid`, which the server states in its
    /// transport parameters when the client returns the token
    /// ([RFC 9000 §7.3]).
    ///
    /// # Errors
    ///
    /// Fails when the random source fails; no Retry is sent then.
    ///
    /// [RFC 9000 §7.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-7.3
    fn issue_retry(
        &self,
        peer: &SocketAddr,
        original_dcid: &ConnectionId,
        now: UtcDateTime,
    ) -> Result<Bytes, RandomError>;

    /// What the token in an Initial packet from `peer` is.
    ///
    /// `token` is the non-empty Token field of the packet.
    fn validate(&self, token: &[u8], peer: &SocketAddr, now: UtcDateTime) -> TokenOutcome;
}

/// The token component on a connection's side: it issues the tokens a
/// server sends in NEW_TOKEN frames.
pub trait NewTokenIssuer {
    /// A token for a NEW_TOKEN frame sent to `peer`.
    ///
    /// # Errors
    ///
    /// Fails when the random source fails; no NEW_TOKEN frame is sent then.
    fn issue(&self, peer: &SocketAddr, now: UtcDateTime) -> Result<Bytes, RandomError>;
}

/// What the token in an Initial packet is.
///
/// Which kind of token a client returned is visible on the wire; what the
/// token holds is not ([RFC 9000 §8.1.3]).
///
/// [RFC 9000 §8.1.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.3
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenOutcome {
    /// A valid Retry token: the client's address is validated.
    Retry {
        /// The Destination Connection ID of the Initial packet the Retry
        /// responded to.
        original_dcid: ConnectionId,
    },
    /// A NEW_TOKEN token that is authentic and not expired.
    NewToken(ValidNewToken),
    /// A Retry token that is not authentic, expired, or issued to another
    /// address. The client will not accept another Retry, so the server
    /// closes the attempt with INVALID_TOKEN ([RFC 9000 §8.1.2]).
    ///
    /// [RFC 9000 §8.1.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.2
    InvalidRetry,
    /// A token that is not a valid NEW_TOKEN token and not recognized as a
    /// Retry token. The server proceeds as if the packet had no token
    /// ([RFC 9000 §8.1.3]).
    ///
    /// [RFC 9000 §8.1.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.3
    InvalidNewToken,
}

/// A NEW_TOKEN token that is authentic and not expired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidNewToken {
    /// How the address it was issued to compares with the client's address.
    pub address: NewTokenAddress,
    /// What tells this token apart from every other token, for accepting it
    /// only once.
    pub id: NewTokenId,
    /// When the token stops being accepted.
    pub expires_at: UtcDateTime,
}

/// How the address a NEW_TOKEN token was issued to compares with the address
/// of the client that returned it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NewTokenAddress {
    /// The address policy accepts the client's address and the IP address is
    /// the one the token was issued to: the client's address is validated.
    Validated,
    /// The address policy accepts the client's address but the IP address
    /// changed. The address is not validated, since a server must then keep
    /// to the amplification limit ([RFC 9000 §8.1.4]); the endpoint may still
    /// weigh the match when it decides whether to send a Retry.
    ///
    /// [RFC 9000 §8.1.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4
    LooselyMatched,
}

/// What tells one NEW_TOKEN token apart from every other one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NewTokenId(pub [u8; 16]);

/// The two kinds of address validation token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenKind {
    /// A token sent in a Retry packet.
    Retry,
    /// A token sent in a NEW_TOKEN frame.
    NewToken,
}

/// Decides whether the address a token was issued to matches the address of
/// the client that returned it.
///
/// For a NEW_TOKEN token, a match with a different IP address never counts
/// as a validated address: [`NewTokenAddress::LooselyMatched`] reports it.
pub trait TokenAddressPolicy {
    /// Whether `current` matches `issued` for a token of `kind`.
    fn matches(&self, kind: TokenKind, issued: &SocketAddr, current: &SocketAddr) -> bool;
}

/// Matches the IP address and port for a Retry token and the IP address for
/// a NEW_TOKEN token, the checks [RFC 9000 §8.1.4] describes.
///
/// [RFC 9000 §8.1.4]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ExactTokenAddressPolicy;

impl TokenAddressPolicy for ExactTokenAddressPolicy {
    fn matches(&self, kind: TokenKind, issued: &SocketAddr, current: &SocketAddr) -> bool {
        match kind {
            TokenKind::Retry => issued == current,
            TokenKind::NewToken => issued.ip() == current.ip(),
        }
    }
}

impl<P: TokenAddressPolicy + ?Sized> TokenAddressPolicy for &P {
    fn matches(&self, kind: TokenKind, issued: &SocketAddr, current: &SocketAddr) -> bool {
        (**self).matches(kind, issued, current)
    }
}
