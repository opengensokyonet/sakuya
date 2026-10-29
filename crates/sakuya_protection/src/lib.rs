//! QUIC version 1 packet protection primitives from RFC 9001.
//!
//! This crate derives Initial secrets and packet protection keys, removes and
//! applies header protection, opens and seals packet payloads, derives the
//! secrets of a key update, and computes the Retry integrity tag. Packet
//! number encoding and decoding from RFC 9000 Appendix A sits beside header
//! protection, which yields the truncated packet number.
//!
//! All cryptography goes through the [`backend::CryptoBackend`] trait. The
//! `backend::ring::RingBackend` implementation is available with the `ring`
//! feature, which is enabled by default.
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
//! use sakuya_protection::packet_number::TruncatedPacketNumber;
//!
//! let backend = RingBackend;
//! let client_dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
//! let secrets = InitialSecrets::derive(&backend, &client_dcid);
//! let key = PacketKey::derive(&backend, INITIAL_AEAD, &secrets.client);
//! let hp = HeaderProtectionKey::derive(&backend, INITIAL_AEAD, &secrets.client);
//!
//! // The client protects an Initial packet: empty Source Connection ID and
//! // token, a 2-byte Length of 37, packet number 2, and a PING frame padded
//! // to 20 bytes of payload.
//! let pn = TruncatedPacketNumber::encode(2, None)?;
//! let mut packet = vec![0xc0 | (pn.encoded_len() as u8 - 1), 0, 0, 0, 1, 8];
//! packet.extend_from_slice(&client_dcid);
//! packet.extend_from_slice(&[0, 0, 0x40, 37]);
//! let pn_offset = packet.len();
//! packet.extend_from_slice(pn.as_bytes());
//! let header_len = packet.len();
//! packet.push(0x01);
//! packet.resize(header_len + 20 + 16, 0);
//! key.seal(2, &mut packet, header_len)?;
//! hp.apply(&mut packet, pn_offset)?;
//!
//! // The server works on a private copy; the received datagram stays intact
//! // in case the copy has to be rebuilt for another attempt.
//! let received: &[u8] = &packet;
//! let mut private = received.to_vec();
//! let truncated = hp.remove(&mut private, pn_offset)?;
//! let packet_number = truncated.decode(0);
//! let payload = key.open(packet_number, &mut private, pn_offset + truncated.encoded_len())?;
//! assert_eq!(packet_number, 2);
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
