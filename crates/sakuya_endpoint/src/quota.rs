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
/// The bounds apply to the endpoint's own queues, not to each connection.
/// Connections the application has accepted are the application's to count;
/// the endpoint does not bound them. The defaults are estimates from the
/// structure, not measurements.
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
    /// How many Initial datagrams that arrive late for an incoming
    /// connection born from 0-RTT can wait to be checked by the endpoint
    /// before they reach that connection.
    pub late_initial_queue_capacity: NonZeroUsize,
    /// How many Version Negotiation responses can wait to be sent.
    pub version_negotiation_queue_capacity: NonZeroUsize,
    /// How many Version Negotiation responses can be in the course of
    /// sending at a time.
    pub version_negotiation_send_set_capacity: NonZeroUsize,
    /// How many stateless Retry packets and Initial packets that close an
    /// attempt with INVALID_TOKEN can be in the course of sending at a time.
    pub retry_send_set_capacity: NonZeroUsize,
    /// How many accepted NEW_TOKEN tokens the endpoint records so that it
    /// accepts each only once.
    pub used_new_tokens_capacity: NonZeroUsize,
}

impl Default for ServerQuotas {
    /// An incoming queue of 1024, at most 64 incoming connections born from
    /// 0-RTT, a late Initial queue of 64, a Version Negotiation queue of 64
    /// with 16 sends in progress, 64 Retry and INVALID_TOKEN sends in
    /// progress, and a record of 65536 accepted NEW_TOKEN tokens.
    fn default() -> Self {
        Self {
            incoming_queue_capacity: NonZeroUsize::new(1024).unwrap(),
            zero_rtt_incoming_limit: 64,
            late_initial_queue_capacity: NonZeroUsize::new(64).unwrap(),
            version_negotiation_queue_capacity: NonZeroUsize::new(64).unwrap(),
            version_negotiation_send_set_capacity: NonZeroUsize::new(16).unwrap(),
            retry_send_set_capacity: NonZeroUsize::new(64).unwrap(),
            used_new_tokens_capacity: NonZeroUsize::new(65536).unwrap(),
        }
    }
}
