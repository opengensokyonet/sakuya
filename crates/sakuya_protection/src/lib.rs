//! QUIC version 1 packet protection primitives from RFC 9001.
//!
//! - [`initial`]: the Initial secrets derived from the client's Destination
//!   Connection ID ([`initial::InitialSecrets`]).
//! - [`secret`]: traffic secrets and the key update derivation
//!   ([`secret::TrafficSecret`]).
//! - [`packet_key`]: opening and sealing packet payloads
//!   ([`packet_key::PacketKey`]).
//! - [`header_protection`]: removing and applying header protection
//!   ([`header_protection::HeaderProtectionKey`]).
//! - [`packet_number`]: packet numbers ([`packet_number::PacketNumber`]) and
//!   their truncation in the Packet Number field from RFC 9000 Appendix A
//!   ([`packet_number::TruncatedPacketNumber`]), which header protection
//!   covers.
//! - [`retry`]: the Retry integrity tag.
//! - [`backend`]: the cryptographic operations all of the above use
//!   ([`backend::CryptoBackend`]). The `backend::ring::RingBackend`
//!   implementation is available with the `ring` feature, which is enabled
//!   by default.
//!
//! The crate holds no key state. Which keys exist, when they are discarded,
//! and which key phase is current belong to the caller, as does parsing the
//! packet header: operations take the packet number offset and the header
//! length as arguments.
//!
//! # Buffers
//!
//! Operations on a packet work in place on a mutable slice that starts at the
//! packet's first byte and ends at the packet's last byte. Removing header
//! protection rewrites the first byte and the packet number field; opening the
//! payload rewrites the payload. When a step fails after it has started
//! writing, the buffer is not restored. A caller that wants to try other keys
//! rebuilds the rewritten regions from a read-only copy of the received
//! datagram; this crate keeps no backup.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "ring")] {
//! use sakuya_protection::backend::ring::RingBackend;
//! use sakuya_protection::header_protection::HeaderProtectionKey;
//! use sakuya_protection::initial::{INITIAL_AEAD, InitialSecrets};
//! use sakuya_protection::packet_key::PacketKey;
//! use sakuya_protection::packet_number::{PacketNumber, TruncatedPacketNumber};
//! use sakuya_wire::connection_id::ConnectionId;
//!
//! let backend = RingBackend;
//! let client_dcid = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08])?;
//! let secrets = InitialSecrets::derive(&backend, &client_dcid);
//! let key = PacketKey::derive(&backend, INITIAL_AEAD, &secrets.client);
//! let hp = HeaderProtectionKey::derive(&backend, INITIAL_AEAD, &secrets.client);
//!
//! // The client protects an Initial packet: empty Source Connection ID and
//! // token, a 2-byte Length of 37, packet number 2, and a PING frame padded
//! // to 20 bytes of payload.
//! let packet_number = PacketNumber::new(2)?;
//! let pn = TruncatedPacketNumber::encode(packet_number, None)?;
//! let mut packet = vec![0xc0 | pn.encoded_len().first_byte_bits(), 0, 0, 0, 1, 8];
//! packet.extend_from_slice(client_dcid.as_bytes());
//! packet.extend_from_slice(&[0, 0, 0x40, 37]);
//! let pn_offset = packet.len();
//! packet.extend_from_slice(pn.as_bytes());
//! let header_len = packet.len();
//! packet.push(0x01);
//! packet.resize(header_len + 20 + 16, 0);
//! key.seal(packet_number, &mut packet, header_len)?;
//! hp.apply(&mut packet, pn_offset)?;
//!
//! // The server works on a private copy; the received datagram stays intact
//! // in case the copy has to be rebuilt for another attempt.
//! let received: &[u8] = &packet;
//! let mut private = received.to_vec();
//! let truncated = hp.remove(&mut private, pn_offset)?;
//! let decoded = truncated.decode(None);
//! let payload = key.open(decoded, &mut private, pn_offset + truncated.encoded_len().get())?;
//! assert_eq!(decoded, packet_number);
//! assert_eq!(payload[0], 0x01);
//! # }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![warn(missing_docs)]

pub mod backend;
pub mod header_protection;
pub mod initial;
pub mod packet_key;
pub mod packet_number;
pub mod retry;
pub mod secret;
mod wipe;
