//! The three packet number spaces of QUIC version 1 (RFC 9000 §12.3).
//!
//! Packet numbers, acknowledgments and loss detection are per space; the
//! keys and the order of writing are per encryption level, which is a
//! different division (0-RTT and 1-RTT share the Application Data space).

/// One of the three packet number spaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PacketNumberSpaceKind {
    /// The space of Initial packets.
    Initial,
    /// The space of Handshake packets.
    Handshake,
    /// The space of 0-RTT and 1-RTT packets.
    ApplicationData,
}

impl PacketNumberSpaceKind {
    /// All three, in the order Initial, Handshake, Application Data.
    pub const ALL: [Self; 3] = [Self::Initial, Self::Handshake, Self::ApplicationData];

    const fn bit(self) -> u8 {
        match self {
            Self::Initial => 1,
            Self::Handshake => 2,
            Self::ApplicationData => 4,
        }
    }
}

/// A set of packet number spaces.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PacketNumberSpaceSet {
    bits: u8,
}

impl PacketNumberSpaceSet {
    /// The empty set.
    pub const EMPTY: Self = Self { bits: 0 };

    /// Whether `space` is in the set.
    pub const fn contains(self, space: PacketNumberSpaceKind) -> bool {
        self.bits & space.bit() != 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }

    /// The set with `space` added.
    #[must_use]
    pub const fn with(self, space: PacketNumberSpaceKind) -> Self {
        Self {
            bits: self.bits | space.bit(),
        }
    }

    /// Adds `space`.
    pub fn insert(&mut self, space: PacketNumberSpaceKind) {
        *self = self.with(space);
    }

    /// The spaces in the set, in the order Initial, Handshake, Application
    /// Data.
    pub fn iter(self) -> impl Iterator<Item = PacketNumberSpaceKind> {
        PacketNumberSpaceKind::ALL
            .into_iter()
            .filter(move |space| self.contains(*space))
    }
}

impl FromIterator<PacketNumberSpaceKind> for PacketNumberSpaceSet {
    fn from_iter<T: IntoIterator<Item = PacketNumberSpaceKind>>(iter: T) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

#[cfg(test)]
mod tests;
