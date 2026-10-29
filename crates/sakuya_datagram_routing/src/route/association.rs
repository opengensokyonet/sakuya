//! Match associations and the conditions of a route entry

use std::fmt;
use std::ops::BitOr;

use sakuya_link::BindingId;
use sakuya_wire::connection_id::NonEmptyCid;
use sakuya_wire::header::v1::LongPacketType;
use sakuya_wire::version::Version;

use super::interpretation::FirstPacketInterpretation;

/// The key under which a route entry is found.
///
/// All three kinds hold any number of entries: several connections may use
/// the same non-empty connection ID, and one link binding may carry several
/// zero-length connection ID receivers. A collision is a case for connection
/// ID generation to avoid, never a reason to refuse a registration.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MatchAssociation {
    /// A non-empty connection ID this side issued for receiving.
    LocalCid(NonEmptyCid),
    /// A non-empty destination connection ID under which this side receives
    /// Initial packets, and the 0-RTT packets that use the same value. After a
    /// Retry it differs from the client's original destination connection ID.
    InitialDcid(NonEmptyCid),
    /// Receiving with the zero-length connection ID on the link binding that
    /// produced the arrival link. Only an explicit zero-length interpretation
    /// looks it up; it is never a fallback for a failed lookup.
    ZeroCid(BindingId),
}

/// A set of packet forms a route entry applies to.
///
/// Routing offers a datagram to an entry only when the entry's forms contain
/// the form of the candidate's first-packet interpretation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PacketForms(u8);

impl PacketForms {
    /// No form.
    pub const NONE: Self = Self(0);
    /// Initial packets of a supported version.
    pub const INITIAL: Self = Self(1);
    /// 0-RTT packets of a supported version.
    pub const ZERO_RTT: Self = Self(1 << 1);
    /// Handshake packets of a supported version.
    pub const HANDSHAKE: Self = Self(1 << 2);
    /// Retry packets of a supported version.
    pub const RETRY: Self = Self(1 << 3);
    /// Version Negotiation packets.
    pub const VERSION_NEGOTIATION: Self = Self(1 << 4);
    /// Short header packets.
    pub const SHORT: Self = Self(1 << 5);
    /// Every form.
    pub const ALL: Self = Self((1 << 6) - 1);

    /// The form of a long header packet of a supported version.
    pub const fn long(packet_type: LongPacketType) -> Self {
        match packet_type {
            LongPacketType::Initial => Self::INITIAL,
            LongPacketType::ZeroRtt => Self::ZERO_RTT,
            LongPacketType::Handshake => Self::HANDSHAKE,
            LongPacketType::Retry => Self::RETRY,
        }
    }

    /// The forms in either set.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every form of `other` is in this set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for PacketForms {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        self.union(other)
    }
}

impl fmt::Debug for PacketForms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [(PacketForms, &str); 6] = [
            (PacketForms::INITIAL, "INITIAL"),
            (PacketForms::ZERO_RTT, "ZERO_RTT"),
            (PacketForms::HANDSHAKE, "HANDSHAKE"),
            (PacketForms::RETRY, "RETRY"),
            (PacketForms::VERSION_NEGOTIATION, "VERSION_NEGOTIATION"),
            (PacketForms::SHORT, "SHORT"),
        ];
        let mut set = f.debug_set();
        for (form, name) in NAMES {
            if self.contains(form) {
                set.entry(&format_args!("{name}"));
            }
        }
        set.finish()
    }
}

/// What one route entry matches: its association and the packets it applies
/// to.
///
/// An entry applies to a candidate interpretation when the interpretation's
/// form is in [`forms`](Self::forms) and, for a long header of a supported
/// version, the version equals [`version`](Self::version). Version
/// Negotiation and short headers carry no version to compare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteMatcher {
    association: MatchAssociation,
    forms: PacketForms,
    version: Version,
}

impl RouteMatcher {
    /// Matches `association` for the packets in `forms` of `version`.
    pub fn new(association: MatchAssociation, forms: PacketForms, version: Version) -> Self {
        Self {
            association,
            forms,
            version,
        }
    }

    /// The association the entry is registered under.
    pub fn association(&self) -> &MatchAssociation {
        &self.association
    }

    /// The packet forms the entry applies to.
    pub fn forms(&self) -> PacketForms {
        self.forms
    }

    /// The version the entry applies to for long headers.
    pub fn version(&self) -> Version {
        self.version
    }

    /// Whether the entry applies to a candidate with this interpretation.
    pub fn applies(&self, interpretation: &FirstPacketInterpretation) -> bool {
        if !self.forms.contains(interpretation.form()) {
            return false;
        }
        match interpretation {
            FirstPacketInterpretation::Long { version, .. } => *version == self.version,
            FirstPacketInterpretation::VersionNegotiation
            | FirstPacketInterpretation::Short { .. } => true,
        }
    }
}
