//! The three packet number spaces of QUIC version 1 (RFC 9000 §12.3).
//!
//! Packet numbers, acknowledgments and loss detection are per space; the
//! keys and the order of writing are per encryption level, which is a
//! different division (0-RTT and 1-RTT share the Application Data space).
use sakuya_link::EcnMarking;
use sakuya_wire::v1::packet_number::PacketNumber;

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

/// One value for each packet number space a logical path has: the
/// Application Data space always, the Initial and Handshake spaces until
/// they are discarded.
///
/// A component of the logical path or of the recovery layer that keeps
/// state for each space is one value of this type: the value for a space
/// does not know which space it is. Discarding the Initial or Handshake
/// keys sets that field to `None`, and the state of the space is dropped.
/// A logical path other than the connection's first has the Application
/// Data space only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketNumberSpaces<X> {
    /// The Initial space, until its keys are discarded.
    pub initial: Option<X>,
    /// The Handshake space, until its keys are discarded.
    pub handshake: Option<X>,
    /// The Application Data space.
    pub application_data: X,
}

impl<X> PacketNumberSpaces<X> {
    /// The value of `space`; `None` if that space is gone or the logical
    /// path never had it.
    pub fn get(&self, space: PacketNumberSpaceKind) -> Option<&X> {
        match space {
            PacketNumberSpaceKind::Initial => self.initial.as_ref(),
            PacketNumberSpaceKind::Handshake => self.handshake.as_ref(),
            PacketNumberSpaceKind::ApplicationData => Some(&self.application_data),
        }
    }

    /// The value of `space`, mutably; `None` if that space is gone or the
    /// logical path never had it.
    pub fn get_mut(&mut self, space: PacketNumberSpaceKind) -> Option<&mut X> {
        match space {
            PacketNumberSpaceKind::Initial => self.initial.as_mut(),
            PacketNumberSpaceKind::Handshake => self.handshake.as_mut(),
            PacketNumberSpaceKind::ApplicationData => Some(&mut self.application_data),
        }
    }

    /// The spaces there are, with their values, in the order Initial,
    /// Handshake, Application Data.
    pub fn iter(&self) -> impl Iterator<Item = (PacketNumberSpaceKind, &X)> {
        let Self {
            initial,
            handshake,
            application_data,
        } = self;
        let initial = initial
            .as_ref()
            .map(|x| (PacketNumberSpaceKind::Initial, x));
        let handshake = handshake
            .as_ref()
            .map(|x| (PacketNumberSpaceKind::Handshake, x));
        initial
            .into_iter()
            .chain(handshake)
            .chain([(PacketNumberSpaceKind::ApplicationData, application_data)])
    }

    /// The spaces there are, with their values mutably, in the order
    /// Initial, Handshake, Application Data.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (PacketNumberSpaceKind, &mut X)> {
        let Self {
            initial,
            handshake,
            application_data,
        } = self;
        let initial = initial
            .as_mut()
            .map(|x| (PacketNumberSpaceKind::Initial, x));
        let handshake = handshake
            .as_mut()
            .map(|x| (PacketNumberSpaceKind::Handshake, x));
        initial
            .into_iter()
            .chain(handshake)
            .chain([(PacketNumberSpaceKind::ApplicationData, application_data)])
    }

    /// A value for every space there is, made from the value of each.
    pub fn map<Y>(self, mut f: impl FnMut(PacketNumberSpaceKind, X) -> Y) -> PacketNumberSpaces<Y> {
        PacketNumberSpaces {
            initial: self.initial.map(|x| f(PacketNumberSpaceKind::Initial, x)),
            handshake: self
                .handshake
                .map(|x| f(PacketNumberSpaceKind::Handshake, x)),
            application_data: f(
                PacketNumberSpaceKind::ApplicationData,
                self.application_data,
            ),
        }
    }
}

/// What a logical path keeps about the packet numbers of one space, besides
/// its send and receive journals.
///
/// The largest acknowledged packet number truncates the packet numbers this
/// side writes (RFC 9000 §17.1) and lets the time threshold apply to every
/// packet sent before it (RFC 9002 §6.1). The smallest acknowledged packet
/// number bounds the losses that may be ignored for congestion because the
/// peer may not have had the keys yet (RFC 9002 §7.4). The ECN counts of
/// packets sent are compared with those the peer reports (RFC 9000
/// §13.4.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PacketNumberSpaceState {
    largest_acked: Option<PacketNumber>,
    smallest_acked: Option<PacketNumber>,
    ect0_sent: u64,
    ect1_sent: u64,
}

impl PacketNumberSpaceState {
    /// Nothing sent or acknowledged yet.
    pub const fn new() -> Self {
        Self {
            largest_acked: None,
            smallest_acked: None,
            ect0_sent: 0,
            ect1_sent: 0,
        }
    }

    /// The largest packet number acknowledged in this space.
    pub const fn largest_acked(&self) -> Option<PacketNumber> {
        self.largest_acked
    }

    /// The smallest packet number acknowledged in this space.
    pub const fn smallest_acked(&self) -> Option<PacketNumber> {
        self.smallest_acked
    }

    /// An ACK frame acknowledged packets from `smallest` to `largest`:
    /// both bounds move outward only.
    pub fn on_ack(&mut self, smallest: PacketNumber, largest: PacketNumber) {
        self.largest_acked = Some(self.largest_acked.map_or(largest, |l| l.max(largest)));
        self.smallest_acked = Some(self.smallest_acked.map_or(smallest, |s| s.min(smallest)));
    }

    /// Whether the loss of the packet `number` may be ignored for
    /// congestion control: it is below every packet number acknowledged so
    /// far, or nothing was acknowledged yet (RFC 9002 §7.4, MAY; the
    /// caller applies it to the Handshake and Application Data spaces
    /// only).
    pub fn loss_may_ignore_congestion(&self, number: PacketNumber) -> bool {
        self.smallest_acked.is_none_or(|smallest| number < smallest)
    }

    /// A packet marked `marking` was sent in this space.
    pub fn marked_sent(&mut self, marking: EcnMarking) {
        match marking {
            EcnMarking::NotEct => {}
            EcnMarking::Ect0 => self.ect0_sent = self.ect0_sent.saturating_add(1),
            EcnMarking::Ect1 => self.ect1_sent = self.ect1_sent.saturating_add(1),
        }
    }

    /// How many packets marked ECT(0) were sent in this space.
    pub const fn ect0_sent(&self) -> u64 {
        self.ect0_sent
    }

    /// How many packets marked ECT(1) were sent in this space.
    pub const fn ect1_sent(&self) -> u64 {
        self.ect1_sent
    }
}

#[cfg(test)]
mod tests;
