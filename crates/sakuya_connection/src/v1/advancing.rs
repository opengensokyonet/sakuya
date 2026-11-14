//! The advancing call: the handshake of version 1, run as one call of the
//! connection node.

use sakuya_tls::message::MessageLimits;

/// What a connection's handshake starts from, given once when the
/// connection is made: the start state `E` of the side's handshake engine,
/// and the limits on the first ClientHello a server reads in the tree,
/// which a client does not use. The advancing call takes it when it
/// starts.
pub struct HandshakeStart<E> {
    start: Option<(E, MessageLimits)>,
}

impl<E> HandshakeStart<E> {
    /// The handshake of the engine whose start state is `engine`; a server
    /// reads its first ClientHello within `first_client_hello_limits`,
    /// unless the connection is made with a first flight read before.
    pub fn new(engine: E, first_client_hello_limits: MessageLimits) -> Self {
        Self {
            start: Some((engine, first_client_hello_limits)),
        }
    }

    /// The start state and the limits, the first time they are asked for.
    pub(crate) fn take(&mut self) -> Option<(E, MessageLimits)> {
        self.start.take()
    }
}

impl<E> core::fmt::Debug for HandshakeStart<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HandshakeStart")
            .field("taken", &self.start.is_none())
            .finish_non_exhaustive()
    }
}
