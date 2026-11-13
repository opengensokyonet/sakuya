//! The Version Negotiation packet a server sends in response to a client
//! packet of a version it does not support ([RFC 9000 §6.1]).
//!
//! The response echoes the client's connection IDs with their places swapped
//! ([RFC 9000 §17.2.1]), lists the versions the binding offers, and adds one
//! reserved version so that clients keep handling versions they do not know
//! ([RFC 9000 §6.3]). Whether a datagram is large enough to be answered
//! ([RFC 9000 §5.2.2]) is decided before the response is encoded.
//!
//! [RFC 9000 §5.2.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-5.2.2
//! [RFC 9000 §6.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-6.1
//! [RFC 9000 §6.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-6.3
//! [RFC 9000 §17.2.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.1

use bytes::Bytes;
use nitori_crypto::{Random, RandomError};
use sakuya_wire::{
    connection_id::RawConnectionId, header::codec::WriteVersionNegotiationHostExt as _,
    version::Version,
};

/// The `0x40` bit of the Unused field, set so that the packet appears to have
/// the Fixed Bit ([RFC 9000 §17.2.1]).
///
/// [RFC 9000 §17.2.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.1
const FIXED_BIT: u8 = 0x40;

/// The bits of the Unused field below [`FIXED_BIT`], drawn at random.
const RANDOM_UNUSED_MASK: u8 = 0x3f;

/// The low four bits of every byte of a reserved version, `0xa`
/// ([RFC 9000 §15]).
///
/// [RFC 9000 §15]: https://www.rfc-editor.org/rfc/rfc9000.html#section-15
const RESERVED_LOW_BITS: u32 = 0x0a0a_0a0a;

/// The high four bits of every byte of a version, which a reserved version
/// takes at random.
const RESERVED_RANDOM_MASK: u32 = 0xf0f0_f0f0;

/// Encodes the Version Negotiation packet that answers a client packet with
/// the destination connection ID `client_dcid`, the source connection ID
/// `client_scid` and the unsupported version `client_version`.
///
/// The packet's destination connection ID is `client_scid` and its source
/// connection ID is `client_dcid` ([RFC 9000 §17.2.1]). The first byte has
/// the Header Form and the `0x40` bit of the Unused field set, as
/// [RFC 9000 §17.2.1] asks of a server, and the other six bits drawn from
/// `random`. The supported version list is `offered`, in order, followed by
/// one reserved version of the form `0x?a?a?a?a` whose high nibbles are drawn
/// from `random` ([RFC 9000 §6.3]). The reserved version is never
/// `client_version`: a client discards a Version Negotiation packet that
/// lists the version it used ([RFC 9000 §6.2]).
///
/// `offered` is the list of the binding the packet arrived on; it holds the
/// versions the server accepts and no reserved version.
///
/// # Errors
///
/// [`RandomError`] if `random` cannot produce the bytes.
///
/// [RFC 9000 §6.2]: https://www.rfc-editor.org/rfc/rfc9000.html#section-6.2
/// [RFC 9000 §6.3]: https://www.rfc-editor.org/rfc/rfc9000.html#section-6.3
/// [RFC 9000 §17.2.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.1
pub fn encode_version_negotiation<R: Random + ?Sized>(
    client_dcid: &RawConnectionId,
    client_scid: &RawConnectionId,
    client_version: Version,
    offered: &[Version],
    random: &R,
) -> Result<Bytes, RandomError> {
    let [unused, reserved @ ..] = random.random::<5>()?;
    let unused = FIXED_BIT | (unused & RANDOM_UNUSED_MASK);
    let reserved = reserved_version(u32::from_be_bytes(reserved), client_version);
    let mut versions = Vec::with_capacity(offered.len() + 1);
    versions.extend_from_slice(offered);
    versions.push(reserved);
    let mut packet = Vec::new();
    // invariant: a `Vec` accepts every byte written to it.
    packet
        .sync_write_version_negotiation_unpin(unused, client_scid, client_dcid, &versions)
        .expect("a Vec accepts every byte");
    Ok(Bytes::from(packet))
}

/// The reserved version whose high nibbles are those of `random`, other than
/// `avoid`.
fn reserved_version(random: u32, avoid: Version) -> Version {
    let version = Version::new(random & RESERVED_RANDOM_MASK | RESERVED_LOW_BITS);
    if version == avoid {
        // Flipping one high bit keeps the form and leaves the other version.
        Version::new(version.get() ^ 0x1000_0000)
    } else {
        version
    }
}

#[cfg(test)]
mod tests {
    use super::encode_version_negotiation;
    use nitori_crypto::{Random, RandomError};
    use sakuya_wire::{
        connection_id::RawConnectionId,
        header::codec::{ReadLongHeaderHostExt as _, ReadVersionNegotiationHostExt as _},
        version::Version,
    };

    /// A random source that repeats one byte.
    struct RepeatedByte(u8);

    impl Random for RepeatedByte {
        fn random<const N: usize>(&self) -> Result<[u8; N], RandomError> {
            Ok([self.0; N])
        }
    }

    /// A random source that always fails.
    struct FailingRandom;

    impl Random for FailingRandom {
        fn random<const N: usize>(&self) -> Result<[u8; N], RandomError> {
            Err(RandomError)
        }
    }

    /// Reads `packet` as a Version Negotiation packet and returns its first
    /// byte, connection IDs and versions.
    fn read(packet: &[u8]) -> (u8, RawConnectionId, RawConnectionId, Vec<Version>) {
        let mut input = packet;
        let header = input.sync_read_long_header_unpin().unwrap();
        assert_eq!(header.version(), Version::NEGOTIATION);
        let negotiation = input.sync_read_version_negotiation_unpin(header).unwrap();
        assert!(input.is_empty());
        (
            header.first_byte(),
            *negotiation.dcid(),
            *negotiation.scid(),
            negotiation.supported_versions().collect(),
        )
    }

    #[test]
    fn swaps_the_connection_ids_and_adds_a_reserved_version() {
        let client_dcid = RawConnectionId::new(&[7; 255]).unwrap();
        let client_scid = RawConnectionId::new(&[1, 2, 3]).unwrap();
        let client_version = Version::new(0x6b33_43cf);
        let packet = encode_version_negotiation(
            &client_dcid,
            &client_scid,
            client_version,
            &[Version::V1],
            &RepeatedByte(0x35),
        )
        .unwrap();
        let (first_byte, dcid, scid, versions) = read(&packet);
        // 0x80 | 0x40 | (0x35 & 0x3f).
        assert_eq!(first_byte, 0xf5);
        assert_eq!(dcid, client_scid);
        assert_eq!(scid, client_dcid);
        assert_eq!(versions, [Version::V1, Version::new(0x3a3a_3a3a)]);
        assert!(versions[1].is_reserved());
        assert_ne!(versions[1], client_version);
    }

    #[test]
    fn sets_the_fixed_bit_whatever_the_random_bits() {
        for byte in [0x00, 0x3f, 0x40, 0x80, 0xff] {
            let packet = encode_version_negotiation(
                &RawConnectionId::EMPTY,
                &RawConnectionId::EMPTY,
                Version::new(2),
                &[],
                &RepeatedByte(byte),
            )
            .unwrap();
            let (first_byte, _, _, versions) = read(&packet);
            assert_eq!(first_byte & 0xc0, 0xc0, "{byte:#x}");
            assert_eq!(first_byte & 0x3f, byte & 0x3f, "{byte:#x}");
            assert_eq!(versions.len(), 1);
            assert!(versions[0].is_reserved());
            assert_eq!(
                versions[0].get() & 0xf0f0_f0f0,
                u32::from(byte & 0xf0) * 0x0101_0101
            );
        }
    }

    #[test]
    fn the_reserved_version_avoids_the_client_version() {
        // The random bytes would give 0x5a5a5a5a, which the client used.
        let client_version = Version::new(0x5a5a_5a5a);
        let packet = encode_version_negotiation(
            &RawConnectionId::new(&[1; 8]).unwrap(),
            &RawConnectionId::EMPTY,
            client_version,
            &[Version::V1],
            &RepeatedByte(0x55),
        )
        .unwrap();
        let (_, _, _, versions) = read(&packet);
        assert_eq!(versions[0], Version::V1);
        assert!(versions[1].is_reserved());
        assert_ne!(versions[1], client_version);
    }

    #[test]
    fn a_random_failure_is_returned() {
        let result = encode_version_negotiation(
            &RawConnectionId::EMPTY,
            &RawConnectionId::EMPTY,
            Version::new(2),
            &[Version::V1],
            &FailingRandom,
        );
        assert!(result.is_err());
    }
}
