//! Retry packets sent before a server keeps any state, and the policy that
//! decides when to send one.
//!
//! A stateless Retry ([RFC 9000 §8.1.2]) answers a client Initial with a
//! token the client returns in its next Initial. Its source connection ID
//! becomes the destination connection ID of the client's later packets, so
//! it comes from the endpoint's connection ID generator
//! ([`generate_stateless_scid`]) and follows the endpoint's conventions for
//! recognizing connection IDs.
//!
//! [RFC 9000 §8.1.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.2

mod policy;

pub use policy::{
    CapacityFraction, CapacityFractionAboveOneError, LoadStatelessRetryPolicy, PresentedToken,
    StatelessRetryDecision, StatelessRetryInput, StatelessRetryPolicy,
};

use bytes::Bytes;
use sakuya_datagram_routing::route::recognizer::ConnectionIdGenerator;
use sakuya_packet_protection::{backend::CryptoBackend, retry::compute_retry_integrity_tag};
use sakuya_wire::{
    connection_id::ConnectionId, v1::header::codec::WriteRetryPacketWithoutTagHostExt as _,
};
use snafu::{Snafu, ensure};

/// The Unused field of the Retry packets this module encodes: all four bits
/// set. [RFC 9000 §17.2.5] lets the server choose any value; this is the one
/// of the example in [RFC 9001 Appendix A.4].
///
/// [RFC 9000 §17.2.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5
/// [RFC 9001 Appendix A.4]: https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A.4
const RETRY_UNUSED: u8 = 0x0f;

/// Encodes a Retry packet, Retry Integrity Tag included, that answers a
/// client Initial whose destination connection ID was `original_dcid` and
/// whose source connection ID was `client_scid` ([RFC 9000 §17.2.5]).
///
/// The packet's destination connection ID is `client_scid` and its source
/// connection ID `scid`, usually from [`generate_stateless_scid`]; it carries
/// `token`. The tag is computed with `backend` over the packet and
/// `original_dcid` ([RFC 9001 §5.8]).
///
/// # Errors
///
/// - [`EncodeStatelessRetryError::ScidMatchesOriginalDcid`] if `scid` equals
///   `original_dcid`, which [RFC 9000 §17.2.5.1] forbids and for which the
///   client discards the packet;
/// - [`EncodeStatelessRetryError::EmptyToken`] if `token` is empty, for which
///   the client discards the packet ([RFC 9000 §17.2.5.2]).
///
/// [RFC 9000 §17.2.5]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5
/// [RFC 9000 §17.2.5.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5.1
/// [RFC 9000 §17.2.5.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.5.2
/// [RFC 9001 §5.8]: https://www.rfc-editor.org/rfc/rfc9001.html#section-5.8
pub fn encode_stateless_retry<B: CryptoBackend>(
    backend: &B,
    original_dcid: &ConnectionId,
    client_scid: &ConnectionId,
    scid: &ConnectionId,
    token: &[u8],
) -> Result<Bytes, EncodeStatelessRetryError> {
    ensure!(
        scid != original_dcid,
        encode_stateless_retry_error::ScidMatchesOriginalDcidSnafu
    );
    ensure!(
        !token.is_empty(),
        encode_stateless_retry_error::EmptyTokenSnafu
    );
    let mut packet = Vec::new();
    // invariant: a `Vec` accepts every byte written to it.
    packet
        .sync_write_retry_packet_without_tag_unpin(RETRY_UNUSED, *client_scid, *scid, token)
        .expect("a Vec accepts every byte");
    let tag = compute_retry_integrity_tag(backend, original_dcid, &packet);
    packet.extend_from_slice(&tag);
    Ok(Bytes::from(packet))
}

/// Failures that [`encode_stateless_retry`] can produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(module(encode_stateless_retry_error))]
pub enum EncodeStatelessRetryError {
    /// The source connection ID equals the destination connection ID of the
    /// client's Initial.
    #[snafu(display("Retry source connection ID equals the original destination connection ID"))]
    ScidMatchesOriginalDcid,
    /// The Retry Token is empty.
    #[snafu(display("Retry token is empty"))]
    EmptyToken,
}

/// Generates the source connection ID of a packet the endpoint sends without
/// connection state: a stateless Retry, or an Initial that closes a
/// connection attempt with INVALID_TOKEN.
///
/// A generator of type `G` is made from `config` and generates one
/// connection ID; the stateless reset token issued with it is not used. The
/// client puts the connection ID in the destination connection ID of the
/// packets it sends next, so the endpoint's routing recognizes them
/// ([RFC 9000 §8.1.2]).
///
/// [RFC 9000 §8.1.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.2
pub fn generate_stateless_scid<G: ConnectionIdGenerator>(config: &G::Config) -> ConnectionId {
    let (scid, _) = G::new(config).generate();
    scid
}

#[cfg(test)]
mod tests {
    use super::{EncodeStatelessRetryError, encode_stateless_retry, generate_stateless_scid};
    use sakuya_datagram_routing::route::recognizer::ConnectionIdGenerator;
    use sakuya_packet_protection::{
        backend::ring::RingBackend,
        retry::{compute_retry_integrity_tag, verify_retry_integrity_tag},
    };
    use sakuya_wire::{
        connection_id::{ConnectionId, StatelessResetToken},
        header::codec::ReadLongHeaderHostExt as _,
        v1::header::{
            LongPacketType, RETRY_INTEGRITY_TAG_LEN, TypeFields,
            codec::{ReadLongPacketHostExt as _, WriteRetryPacketWithoutTagHostExt as _},
        },
    };

    /// The destination connection ID of the client Initial of RFC 9001
    /// Appendix A.2.
    const RFC_ODCID: [u8; 8] = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];

    /// The source connection ID of the Retry of RFC 9001 Appendix A.4.
    const RFC_SCID: [u8; 8] = [0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5];

    /// The Retry packet of RFC 9001 Appendix A.4.
    const RFC_RETRY: [u8; 36] = [
        0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5,
        0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba, 0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58,
        0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
    ];

    fn cid(bytes: &[u8]) -> ConnectionId {
        ConnectionId::new(bytes).unwrap()
    }

    #[test]
    fn the_written_packet_and_its_tag_are_the_appendix_packet() {
        let mut packet = Vec::new();
        packet
            .sync_write_retry_packet_without_tag_unpin(
                0x0f,
                ConnectionId::EMPTY,
                cid(&RFC_SCID),
                b"token",
            )
            .unwrap();
        let tag = compute_retry_integrity_tag(&RingBackend, &cid(&RFC_ODCID), &packet);
        packet.extend_from_slice(&tag);
        assert_eq!(packet, RFC_RETRY);
    }

    #[test]
    fn encodes_the_appendix_packet() {
        let packet = encode_stateless_retry(
            &RingBackend,
            &cid(&RFC_ODCID),
            &ConnectionId::EMPTY,
            &cid(&RFC_SCID),
            b"token",
        )
        .unwrap();
        assert_eq!(packet[..], RFC_RETRY);
    }

    #[test]
    fn the_packet_verifies_and_reads_back() {
        let original_dcid = cid(&[1; 20]);
        let client_scid = cid(&[2, 3, 4, 5]);
        let scid = cid(&[6; 12]);
        let token = [0xab; 90];
        let packet =
            encode_stateless_retry(&RingBackend, &original_dcid, &client_scid, &scid, &token)
                .unwrap();
        verify_retry_integrity_tag(&RingBackend, &original_dcid, &packet).unwrap();
        // The tag binds the original destination connection ID.
        assert!(verify_retry_integrity_tag(&RingBackend, &client_scid, &packet).is_err());

        let mut input = &packet[..];
        let header = input.sync_read_long_header_unpin().unwrap();
        let read = input.sync_read_long_packet_unpin(header).unwrap();
        assert_eq!(read.packet_type(), LongPacketType::Retry);
        assert_eq!(read.dcid(), &client_scid);
        assert_eq!(read.scid(), &scid);
        let TypeFields::Retry {
            token: read_token,
            integrity_tag,
            end,
        } = read.fields()
        else {
            panic!("expected Retry fields, got {:?}", read.fields());
        };
        assert_eq!(read_token[..], token);
        assert_eq!(
            integrity_tag[..],
            packet[packet.len() - RETRY_INTEGRITY_TAG_LEN..]
        );
        assert_eq!(*end, packet.len());
    }

    #[test]
    fn refuses_packets_the_client_discards() {
        let original_dcid = cid(&[1; 8]);
        assert_eq!(
            encode_stateless_retry(
                &RingBackend,
                &original_dcid,
                &ConnectionId::EMPTY,
                &original_dcid,
                b"token",
            ),
            Err(EncodeStatelessRetryError::ScidMatchesOriginalDcid)
        );
        assert_eq!(
            encode_stateless_retry(
                &RingBackend,
                &original_dcid,
                &ConnectionId::EMPTY,
                &cid(&[2; 8]),
                b"",
            ),
            Err(EncodeStatelessRetryError::EmptyToken)
        );
    }

    /// A generator that issues connection IDs of one repeated byte, counting
    /// up from the configured byte.
    struct CountingGenerator(u8);

    impl ConnectionIdGenerator for CountingGenerator {
        type Config = u8;

        fn new(config: &u8) -> Self {
            Self(*config)
        }

        fn generate(&mut self) -> (ConnectionId, StatelessResetToken) {
            let byte = self.0;
            self.0 = self.0.wrapping_add(1);
            (cid(&[byte; 8]), StatelessResetToken::new([byte; 16]))
        }

        fn stateless_reset_token(_: &u8, _: &ConnectionId) -> Option<StatelessResetToken> {
            None
        }
    }

    #[test]
    fn the_scid_is_the_first_of_a_new_generator() {
        assert_eq!(
            generate_stateless_scid::<CountingGenerator>(&9),
            cid(&[9; 8])
        );
        assert_eq!(
            generate_stateless_scid::<CountingGenerator>(&9),
            cid(&[9; 8])
        );
    }
}
