//! What an endpoint dropped of the work that arrives without a connection.
//!
//! An endpoint bounds each kind of such work ([`ServerQuotas`]); past a
//! bound it drops the new input and counts the drop by its reason. The
//! counts only grow. The application reads them as a
//! [`DroppedInputCounts`]; sakuya does not log the drops.
//!
//! [`ServerQuotas`]: crate::quota::ServerQuotas

/// How many inputs an endpoint dropped, by the bound that was reached.
///
/// Each count only grows. A difference of two readings tells how many were
/// dropped between them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DroppedInputCounts {
    /// Incoming connections dropped because the queue of those waiting for
    /// the application was full.
    pub incoming_queue_full: u64,
    /// Datagrams whose first packet is 0-RTT dropped because as many
    /// incoming connections born from 0-RTT were waiting as allowed.
    pub zero_rtt_incoming_limit_reached: u64,
    /// Initial datagrams for an incoming connection born from 0-RTT dropped
    /// because the queue of those waiting to be checked was full.
    pub late_initial_queue_full: u64,
    /// Version Negotiation responses not sent because the queue of those
    /// waiting was full.
    pub version_negotiation_queue_full: u64,
    /// Version Negotiation responses not sent because the set of those being
    /// sent was full.
    pub version_negotiation_send_set_full: u64,
    /// Stateless Retry packets and Initial packets that close an attempt
    /// with INVALID_TOKEN not sent because the set of those being sent was
    /// full.
    pub retry_send_set_full: u64,
}
