//! The layers of a ClientHello a server opens before it handles it.
//!
//! A ClientHello can carry encrypted layers, such as an inner ClientHello
//! of ECH. [`HelloLayers::open`] takes the ClientHello as received and
//! hands over the one the handshake continues with, as an
//! [`AcceptedHello`], with what the layers leave for the reply: the value
//! that confirms an accepted layer in the ServerHello, and the retry
//! configurations of a rejected one for EncryptedExtensions.
//!
//! [`PassThroughLayers`] opens nothing and hands the ClientHello over as it
//! came. Its confirmation and retry configurations are of a type with no
//! values, so the handshake's code for them is never reached.

use crate::message::{HandshakeMessage, client_hello::ClientHello};
use bytes::Bytes;
use core::{
    convert::Infallible,
    future::{Future, Ready, ready},
};

/// The ClientHello a handshake continues with, after its layers.
pub trait AcceptedHello {
    /// What confirms an accepted layer in the ServerHello.
    type Confirmation;

    /// The retry configurations of a rejected layer, for
    /// EncryptedExtensions.
    type RetryConfigs;

    /// The encoding of the ClientHello, which goes into the transcript.
    fn encoded(&self) -> &HandshakeMessage;

    /// The ClientHello.
    fn client_hello(&self) -> &ClientHello<Bytes>;

    /// The confirmation of an accepted layer, if a layer was accepted.
    fn confirmation(&self) -> Option<&Self::Confirmation>;

    /// The retry configurations of a rejected layer, if a layer was
    /// rejected.
    fn retry_configs(&self) -> Option<&Self::RetryConfigs>;
}

/// How a server opens the layers of a ClientHello.
pub trait HelloLayers {
    /// The ClientHello after its layers.
    type Accepted: AcceptedHello;

    /// A failure to open.
    type Error;

    /// Opening in progress.
    type Opening<'a>: Future<Output = Result<Self::Accepted, Self::Error>> + 'a
    where
        Self: 'a;

    /// Opens `hello`, received as `encoded`.
    fn open(&self, encoded: HandshakeMessage, hello: ClientHello<Bytes>) -> Self::Opening<'_>;
}

/// Layers that open nothing: the ClientHello is handed over as it came.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PassThroughLayers;

/// A ClientHello handed over as it came, by [`PassThroughLayers`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassThroughHello {
    encoded: HandshakeMessage,
    hello: ClientHello<Bytes>,
}

impl AcceptedHello for PassThroughHello {
    type Confirmation = Infallible;
    type RetryConfigs = Infallible;

    fn encoded(&self) -> &HandshakeMessage {
        &self.encoded
    }

    fn client_hello(&self) -> &ClientHello<Bytes> {
        &self.hello
    }

    fn confirmation(&self) -> Option<&Infallible> {
        None
    }

    fn retry_configs(&self) -> Option<&Infallible> {
        None
    }
}

impl HelloLayers for PassThroughLayers {
    type Accepted = PassThroughHello;
    type Error = Infallible;
    type Opening<'a> = Ready<Result<PassThroughHello, Infallible>>;

    fn open(&self, encoded: HandshakeMessage, hello: ClientHello<Bytes>) -> Self::Opening<'_> {
        ready(Ok(PassThroughHello { encoded, hello }))
    }
}

#[cfg(test)]
mod tests {
    use super::{AcceptedHello, HelloLayers, PassThroughLayers};
    use crate::test_support::{
        VERSIONS, client_hello, extension, ready_now, received_client_hello,
    };

    #[test]
    fn the_hello_passes_through_as_it_came() {
        let bytes = client_hello(&extension(43, VERSIONS));
        let (encoded, hello) = received_client_hello(&bytes);
        let Ok(accepted) = ready_now(PassThroughLayers.open(encoded, hello.clone()));
        assert_eq!(accepted.encoded().encoded().as_ref(), &bytes[..]);
        assert_eq!(accepted.client_hello(), &hello);
        assert!(accepted.confirmation().is_none());
        assert!(accepted.retry_configs().is_none());
    }
}
