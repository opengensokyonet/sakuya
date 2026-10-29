//! Stream IDs ([RFC 9000 §2.1]).
//!
//! A [`StreamId`] is a [`VarInt`]. Its least significant bit names the
//! endpoint that initiated the stream ([`Initiator`]), the next bit tells
//! whether the stream carries data in both directions or one
//! ([`Directionality`]), and the remaining bits number the streams of each
//! of the four resulting types from zero ([`StreamId::index`]).
//!
//! [RFC 9000 §2.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1
use crate::var_int::VarInt;
use core::fmt;

/// A QUIC stream ID.
///
/// Every [`VarInt`] is a stream ID. Equality, ordering and hashing are those
/// of the numeric value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(VarInt);

impl StreamId {
    /// The largest stream index of each stream type, 2<sup>60</sup> − 1.
    pub const MAX_INDEX: u64 = VarInt::MAX.get() >> 2;

    /// Composes the stream ID of the `index`-th stream of a type.
    ///
    /// Returns `None` if `index` exceeds [`StreamId::MAX_INDEX`].
    pub const fn new(
        initiator: Initiator,
        directionality: Directionality,
        index: u64,
    ) -> Option<Self> {
        if index > Self::MAX_INDEX {
            return None;
        }
        let value = index << 2 | directionality.bit() | initiator.bit();
        match VarInt::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// The endpoint that initiated the stream.
    pub const fn initiator(self) -> Initiator {
        if self.0.get() & Initiator::Server.bit() == 0 {
            Initiator::Client
        } else {
            Initiator::Server
        }
    }

    /// Whether the stream is bidirectional or unidirectional.
    pub const fn directionality(self) -> Directionality {
        if self.0.get() & Directionality::Unidirectional.bit() == 0 {
            Directionality::Bidirectional
        } else {
            Directionality::Unidirectional
        }
    }

    /// The position of the stream among the streams of its type, counting
    /// from zero: the stream ID shifted right by two bits.
    pub const fn index(self) -> u64 {
        self.0.get() >> 2
    }

    /// The stream ID as a variable-length integer.
    pub const fn get(self) -> VarInt {
        self.0
    }
}

impl From<VarInt> for StreamId {
    fn from(value: VarInt) -> Self {
        Self(value)
    }
}

impl From<StreamId> for VarInt {
    fn from(id: StreamId) -> Self {
        id.0
    }
}

/// Formats the numeric value.
impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// The endpoint that initiated a stream: bit `0x01` of its stream ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Initiator {
    /// Initiated by the client; the bit is 0.
    Client,
    /// Initiated by the server; the bit is 1.
    Server,
}

impl Initiator {
    const fn bit(self) -> u64 {
        match self {
            Self::Client => 0,
            Self::Server => 0x01,
        }
    }
}

/// Whether a stream carries data in both directions: bit `0x02` of its
/// stream ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Directionality {
    /// Data flows in both directions; the bit is 0.
    Bidirectional,
    /// Data flows only from the initiator to its peer; the bit is 1.
    Unidirectional,
}

impl Directionality {
    const fn bit(self) -> u64 {
        match self {
            Self::Bidirectional => 0,
            Self::Unidirectional => 0x02,
        }
    }
}

#[cfg(test)]
mod tests;
