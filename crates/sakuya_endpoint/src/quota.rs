//! The bounds an endpoint applies to work that arrives without a connection.
//!
//! Anyone can send an endpoint datagrams from forged addresses, and each one
//! that arrives without a connection can make the endpoint queue work or
//! send a response. The endpoint bounds each kind of such work separately,
//! so that a flood of one kind only crowds out that kind: past a bound it
//! drops the new input and counts the drop.

use core::num::NonZeroUsize;

/// The endpoint's bounds for its server role.
///
/// Connections the application has accepted are the application's to count;
/// the endpoint does not bound them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServerQuotas {
    /// How many incoming connections can wait for the application to take
    /// them. When the queue is full, a new one is treated as if no one were
    /// taking incoming connections.
    pub incoming_queue_capacity: NonZeroUsize,
    /// How many of the waiting incoming connections can be ones born from a
    /// datagram whose first packet is 0-RTT. Past it, the endpoint drops such
    /// a datagram; zero drops all of them. The count only covers the queue:
    /// once the application takes one, it is the application's to count.
    pub zero_rtt_incoming_limit: usize,
    /// How many Version Negotiation responses can wait to be sent.
    pub version_negotiation_queue_capacity: NonZeroUsize,
    /// How many stateless Retry packets and Initial packets that close an
    /// attempt with INVALID_TOKEN can be in the course of sending at a time.
    pub retry_send_set_capacity: NonZeroUsize,
    /// How many accepted NEW_TOKEN tokens the endpoint records so that it
    /// accepts each only once.
    pub used_new_tokens_capacity: NonZeroUsize,
}
