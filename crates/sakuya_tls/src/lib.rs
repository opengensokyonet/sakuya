//! TLS 1.3 handshake messages, extensions and key schedule for QUIC in
//! sakuya.
//!
//! The baseline is TLS 1.3 ([RFC 8446]) as QUIC version 1 uses it
//! ([RFC 9001]): handshake messages travel in CRYPTO frames, without the
//! TLS record layer, and the handshake hands traffic secrets to packet
//! protection.
//!
//! - [`message`]: handshake messages, collected whole from the byte stream
//!   of an encryption level, with a reader and a writer for each type.
//! - [`extension`]: the extensions of those messages.
//! - [`code_point`]: code point lists, such as cipher suites and groups.
//! - [`cipher_suite`], [`version`], [`alert`]: cipher suites, protocol
//!   versions and alert descriptions.
//! - [`vector`]: failures shared by the length-prefixed fields.
//!
//! Every wire format is read and written through `nitori_call` operations,
//! in the `codec` module of its type. The readers run on the bytes of a
//! whole message, `&[u8]` or `Bytes`, and their variable-length fields are
//! chunks of those bytes, without copying. `encoded_len` methods compute
//! lengths without writing. Each read failure answers the TLS alert it calls
//! for through `alert`.
//!
//! [RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446.html
//! [RFC 9001]: https://www.rfc-editor.org/rfc/rfc9001.html
#![feature(impl_trait_in_assoc_type)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod alert;
pub mod cipher_suite;
pub mod code_point;
pub mod extension;
pub mod message;
#[cfg(test)]
mod test_support;
pub mod vector;
pub mod version;
mod width;
