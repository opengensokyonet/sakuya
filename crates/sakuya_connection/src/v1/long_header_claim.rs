//! Whether a datagram whose first packet has a long header, offered to a
//! connection as one of the candidates for it, belongs to the connection.
//!
//! Routing gives a long header datagram sent to one of this side's
//! connection IDs to the connections it was issued for, with no other
//! candidate (sakuya_datagram_routing's `InitialAcceptance`); the receiving
//! of each packet drops one from another Source Connection ID. A long
//! header becomes a candidate to judge only when it was found otherwise: by
//! the first Destination Connection ID a client chose, under which another
//! connection attempt can send too, a client that starts again with the
//! same one; or among the connections a colliding connection ID was issued
//! for. What tells the attempts apart is the Source Connection ID the peer
//! chose for the handshake (RFC 9000 §7.2): every long header packet from
//! the peer carries it, and once a packet from the peer opened the
//! connection keeps it
//! ([`PeerHandshakeConnectionId`](super::connection_ids::PeerHandshakeConnectionId)).
//!
//! [`long_header_belongs`] judges by it: a version 1 long header from the
//! peer's handshake connection ID belongs to the connection. Before one is
//! known, a client takes any version 1 long header sent to its own
//! connection ID, which only the server it connects to can know; a server
//! leaves the datagram to the other candidates, as it knows the client's
//! Source Connection ID from the first datagrams it was made with.

use sakuya_wire::{connection_id::ConnectionId, header::codec::read_long_header};
use sakuya_wire_v1::{header::VERSION, role::Role};

/// Whether `datagram`, whose first packet has a long header, belongs to a
/// connection of `role` whose peer chose `peer_handshake` for the
/// handshake, `None` while no packet from the peer opened.
pub fn long_header_belongs(
    datagram: &[u8],
    peer_handshake: Option<&ConnectionId>,
    role: Role,
) -> bool {
    let mut input = datagram;
    let Ok(header) = read_long_header(&mut input) else {
        return false;
    };
    if header.version() != VERSION {
        return false;
    }
    match peer_handshake {
        Some(peer) => header.scid().as_bytes() == peer.as_bytes(),
        None => role == Role::Client,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The start of a version 1 Initial packet from `scid` to `dcid`.
    fn initial(dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0xc0, 0, 0, 0, 1, dcid.len() as u8];
        bytes.extend_from_slice(dcid);
        bytes.push(scid.len() as u8);
        bytes.extend_from_slice(scid);
        bytes.extend_from_slice(&[0, 0x41, 0x00]);
        bytes
    }

    fn id(bytes: &[u8]) -> ConnectionId {
        ConnectionId::new(bytes).unwrap()
    }

    #[test]
    fn a_long_header_from_the_peers_handshake_connection_id_belongs() {
        let client = id(&[7; 8]);
        let datagram = initial(&[1; 8], &[7; 8]);
        assert!(long_header_belongs(&datagram, Some(&client), Role::Server));
        assert!(long_header_belongs(&datagram, Some(&client), Role::Client));
    }

    #[test]
    fn a_long_header_from_another_attempt_does_not() {
        let client = id(&[7; 8]);
        let datagram = initial(&[1; 8], &[6; 8]);
        assert!(!long_header_belongs(&datagram, Some(&client), Role::Server));
    }

    #[test]
    fn before_the_peer_is_known_only_a_client_takes_one() {
        let datagram = initial(&[1; 8], &[6; 8]);
        assert!(long_header_belongs(&datagram, None, Role::Client));
        assert!(!long_header_belongs(&datagram, None, Role::Server));
    }

    #[test]
    fn another_version_or_a_short_header_does_not_belong() {
        let mut other = initial(&[1; 8], &[7; 8]);
        other[4] = 2;
        assert!(!long_header_belongs(
            &other,
            Some(&id(&[7; 8])),
            Role::Client
        ));
        assert!(!long_header_belongs(&[0x40, 1, 2, 3], None, Role::Client));
    }
}
