//! The address validation tokens of NEW_TOKEN frames (RFC 9000 §8.1.3,
//! §19.7) on a connection's side: what a server connection issues them with
//! ([`NewTokenIssuer`]), and where a client connection puts the ones its
//! server gives it ([`AddressTokenSink`]).
//!
//! The client returns such a token when it next connects to the same
//! server, so that the server can count its address as validated before
//! the handshake. The client connection only hands each token over, once,
//! as it arrives: whoever made the connection decides where it is kept and
//! for which server, so the connection knows neither the store nor the key.
//! The server connection holds only the issuer, which the endpoint's token
//! component gives it; validating tokens stays on the endpoint's side.

use bytes::Bytes;
use nitori_crypto::RandomError;
use sakuya_link::MIN_DATAGRAM_SIZE;
use sakuya_packet_protection::backend::AEAD_TAG_LEN;
use sakuya_wire::var_int::{VarInt, VarIntWidth};
use time::UtcDateTime;

/// The token component on a connection's side: it issues the tokens a
/// server sends in NEW_TOKEN frames.
pub trait NewTokenIssuer<Peer> {
    /// A token for a NEW_TOKEN frame sent to `peer`.
    ///
    /// # Errors
    ///
    /// Fails when the random source fails; no NEW_TOKEN frame is sent then.
    fn issue(&self, peer: &Peer, now: UtcDateTime) -> Result<Bytes, RandomError>;
}

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

/// Whether an Initial packet of the smallest datagram a client sends one in
/// ([`MIN_DATAGRAM_SIZE`]) still has room for a byte of CRYPTO data with a
/// token of `token_len` bytes, a Destination Connection ID of `dcid_len`
/// bytes and a Source Connection ID of `scid_len` bytes, the Length and
/// Packet Number fields counted at their widest for such a packet.
///
/// A client leaves out a token that does not fit: sending one is a SHOULD
/// (RFC 9000 §8.1.3), and the server then treats the address as not
/// validated.
pub fn fits_initial_packet(token_len: usize, dcid_len: usize, scid_len: usize) -> bool {
    // the first byte, the Version, and the two connection ID lengths
    const FIXED: usize = 1 + 4 + 1 + 1;
    // the Length field, two bytes for a packet below 16384 bytes
    const LENGTH: usize = 2;
    const PACKET_NUMBER: usize = 4;
    // a CRYPTO frame at offset 0 with one byte: type, offset, length, data
    const CRYPTO: usize = 1 + 1 + 1 + 1;
    let Ok(length) = VarInt::try_from(token_len) else {
        return false;
    };
    let token = VarIntWidth::shortest(length).encoded_len() + token_len;
    FIXED + dcid_len + scid_len + token + LENGTH + PACKET_NUMBER + CRYPTO + AEAD_TAG_LEN
        <= MIN_DATAGRAM_SIZE
}

#[cfg(test)]
mod tests {
    use super::fits_initial_packet;

    #[test]
    fn a_token_fits_while_a_byte_of_crypto_data_does() {
        // 7 + 8 + 8 + 2 + 4 + 4 + 16 = 49 bytes without the token and
        // the two bytes of its length
        assert!(fits_initial_packet(1200 - 49 - 2, 8, 8));
        assert!(!fits_initial_packet(1200 - 49 - 1, 8, 8));
        assert!(fits_initial_packet(0, 20, 20));
        assert!(!fits_initial_packet(usize::MAX, 0, 0));
    }
}
