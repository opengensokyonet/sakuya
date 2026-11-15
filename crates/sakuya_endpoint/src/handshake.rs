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

use sakuya_tls::{
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

    /// Whether the engines it makes ask the client for a certificate, which
    /// then arrives with the client's Finished at the Handshake level.
    fn requests_client_certificate(&self) -> bool;
}

/// What makes the start state of a client connection's handshake engine.
pub trait ClientHandshakeConfig: Clone {
    /// The name of the server a connection is made to, which the
    /// application gives each time it connects; it is also the key the
    /// client keeps the server's address validation tokens under.
    type ServerName;
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
