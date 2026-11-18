//! What makes the start state of a connection's handshake engine.
//!
//! A connection's handshake starts from the start state of its side's
//! handshake engine, which the connection takes by value. Each connection
//! needs a new one, made when the application accepts or starts the
//! connection, since by then it may have replaced the configuration it
//! came with. The configuration of each role holds a value of one of these
//! traits, written by the host: it keeps the pieces connections share, such
//! as the certificate and the ticket store, and makes a start state from
//! them each time it is asked.

use nitori_tls::{
    client::engine::ClientHandshakeSteps, message::MessageLimits,
    server::engine::ServerHandshakeSteps,
};

/// What makes the start state of a server connection's handshake engine.
pub trait ServerHandshakeConfig: Clone {
    /// The start state it makes.
    type Start: ServerHandshakeSteps<AlertError: 'static> + 'static;

    /// The start state of one connection's handshake, made when the
    /// application accepts the connection.
    fn start(&self) -> Self::Start;

    /// The limits on the handshake messages the engines it makes receive,
    /// the first ClientHello included.
    ///
    /// The endpoint checks the capacities of the CRYPTO data a connection
    /// receives against them, and gives them to the connection for the first
    /// ClientHello; they must be the limits the engine reads with.
    fn limits(&self) -> MessageLimits;

    /// Whether the engines it makes may ask the client for a certificate,
    /// for any target: the client then sends its Certificate, empty or
    /// not, and with a certificate its CertificateVerify, before its
    /// Finished at the Handshake level (RFC 8446 §4.4.2, §4.4.3).
    ///
    /// It is the same whether the certificate is optional or required:
    /// what the server does with an empty Certificate is its engine's
    /// peer authentication's, not this. It must agree with the peer
    /// authentication its engines are made with, as [`limits`](Self::limits)
    /// with their limits: an engine that asks when this says it does not
    /// leaves the Handshake level too little room for the client's
    /// Certificate, and the connection closes with CRYPTO_BUFFER_EXCEEDED.
    fn requests_client_certificate(&self) -> bool;
}

/// What makes the start state of a client connection's handshake engine.
pub trait ClientHandshakeConfig: Clone {
    /// The name of the server a connection is made to, which the
    /// application gives each time it connects; it is also the key the
    /// client keeps the server's address validation tokens under, which
    /// each token is put into the store with.
    type ServerName: Clone + 'static;
    /// The start state it makes.
    type Start: ClientHandshakeSteps<AlertError: 'static> + 'static;

    /// The start state of one connection's handshake to `server_name`,
    /// made when the application starts the connection.
    fn start(&self, server_name: &Self::ServerName) -> Self::Start;

    /// The limits on the handshake messages the engines it makes receive.
    ///
    /// The endpoint checks the capacities of the CRYPTO data a connection
    /// receives against them; they must be the limits the engine reads with.
    fn limits(&self) -> MessageLimits;
}
