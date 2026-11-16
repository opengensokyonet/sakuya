//! Where a client connection puts the address validation tokens the server
//! gives it in NEW_TOKEN frames (RFC 9000 §8.1.3, §19.7).
//!
//! The client returns such a token when it next connects to the same
//! server, so that the server can count its address as validated before
//! the handshake. The connection only hands each token over, once, as it
//! arrives: whoever made the connection decides where it is kept and for
//! which server, so the connection knows neither the store nor the key.

use bytes::Bytes;

/// Where a client connection puts the tokens its server gives it.
pub trait AddressTokenSink {
    /// Keep `token`, which the server of this connection gave.
    fn keep(&self, token: Bytes);
}

/// Keeps nothing: a client that wants no continuity with its servers
/// across connections uses it (RFC 9000 §8.1.3).
impl AddressTokenSink for () {
    fn keep(&self, _: Bytes) {}
}

impl<S: AddressTokenSink + ?Sized> AddressTokenSink for &S {
    fn keep(&self, token: Bytes) {
        (**self).keep(token);
    }
}
