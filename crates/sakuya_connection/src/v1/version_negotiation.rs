//! A client's handling of a Version Negotiation packet (RFC 9000 §6.2).
//!
//! A server that does not support the version of the client's first
//! Initial packet answers with a Version Negotiation packet listing the
//! versions it supports. A client that supports only version 1 abandons
//! the connection attempt when a valid one arrives: the connection ends
//! without sending anything, for
//! [`CloseReason::VersionNegotiation`](sakuya_stream_v1::connection::CloseReason::VersionNegotiation)
//! with the versions listed, which nothing authenticates. Whoever made the
//! connection decides whether to connect again with another version.
//!
//! [`check_version_negotiation`] tells a valid one from one to drop.

use core::ops::Range;
use std::sync::Arc;

use sakuya_wire::{
    header::{
        VersionNegotiation,
        codec::{read_long_header, read_version_negotiation},
    },
    version::Version,
};
use sakuya_wire_v1::connection_id::ConnectionId;
use sakuya_wire_v1::header::VERSION;
use snafu::Snafu;

/// Why a client dropped a Version Negotiation packet.
#[derive(Debug, Snafu)]
pub enum VersionNegotiationDropReason {
    /// The client has already processed a packet from the server (RFC 9000
    /// §6.2).
    #[snafu(display("a packet from the server was already processed"))]
    AfterServerPacket,
    /// The Source Connection ID is not the Destination Connection ID of the
    /// client's first Initial packet, which the server echoes (RFC 9000
    /// §17.2.1): the packet does not answer this connection attempt.
    #[snafu(display("the Source Connection ID is not the one the client sent to"))]
    OtherSourceConnectionId,
    /// The list has no versions (RFC 8999 §6).
    #[snafu(display("the list of supported versions is empty"))]
    NoVersions,
    /// The list has version 1, which the client chose (RFC 9000 §6.2).
    #[snafu(display("the list of supported versions has the client's version"))]
    ListsOwnVersion,
}

/// Check, as a client that supports only version 1, the Version
/// Negotiation packet `packet`, whose bytes are `packet_bytes`, against
/// `first_destination`, the Destination Connection ID of the client's
/// first Initial packet. `answered` is whether the client has already
/// processed a packet from the server. Gives the versions the server
/// listed, in order.
///
/// # Errors
///
/// The [`VersionNegotiationDropReason`] the packet is dropped for.
pub fn check_version_negotiation(
    packet: &VersionNegotiation<Range<usize>>,
    packet_bytes: &[u8],
    first_destination: &ConnectionId,
    answered: bool,
) -> Result<Arc<[Version]>, VersionNegotiationDropReason> {
    if answered {
        return Err(VersionNegotiationDropReason::AfterServerPacket);
    }
    if packet.scid().as_bytes() != first_destination.as_bytes() {
        return Err(VersionNegotiationDropReason::OtherSourceConnectionId);
    }
    // the packet was read once when the datagram was cut; reading it again
    // from its own bytes gives the list as a chunk to read versions from
    let mut input = packet_bytes;
    let read = read_long_header(&mut input)
        .ok()
        .and_then(|header| read_version_negotiation(&mut input, header).ok());
    let Some(read) = read else {
        unreachable!("a Version Negotiation packet already cut reads again")
    };
    let versions: Arc<[Version]> = read.supported_versions().collect();
    if versions.is_empty() {
        return Err(VersionNegotiationDropReason::NoVersions);
    }
    if versions.contains(&VERSION) {
        return Err(VersionNegotiationDropReason::ListsOwnVersion);
    }
    Ok(versions)
}

#[cfg(test)]
mod tests;
