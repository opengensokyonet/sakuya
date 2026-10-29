//! First-packet interpretations and the Initial context routing recognized

use sakuya_link::BindingId;
use sakuya_wire::connection_id::{ConnectionId, NonEmptyCid};
use sakuya_wire::header::v1::LongPacketType;

use super::association::{MatchAssociation, PacketForms};
use super::recognizer::ConnectionIdLength;
use crate::version::Version;

/// How a candidate reads the first packet of a datagram.
///
/// It answers "under which layout does this candidate read the first packet",
/// not "whom does the packet belong to". A short header carries no connection
/// ID length, so a zero-length and an eight-byte reading put the packet number
/// at different offsets; both are separate interpretations, and the same entry
/// under two interpretations has two separate chances. Protected fields, such
/// as the packet number length, are not read here.
///
/// Two equal interpretations mean the same routing to the author of a
/// deliverer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FirstPacketInterpretation {
    /// A long header of a supported version.
    Long {
        /// The version field.
        version: Version,
        /// The packet type the version defines.
        packet_type: LongPacketType,
    },
    /// A Version Negotiation packet, read with the version-independent fields
    /// only.
    VersionNegotiation,
    /// A short header whose destination connection ID has this length.
    Short {
        /// The length of the destination connection ID after the first byte.
        dcid_len: ConnectionIdLength,
    },
}

impl FirstPacketInterpretation {
    /// The packet form of this interpretation.
    pub fn form(&self) -> PacketForms {
        match self {
            Self::Long { packet_type, .. } => PacketForms::long(*packet_type),
            Self::VersionNegotiation => PacketForms::VERSION_NEGOTIATION,
            Self::Short { .. } => PacketForms::SHORT,
        }
    }
}

/// What routing recognized about a supported Initial packet.
///
/// It is kept across reflow rounds, so that a later round looks up the same
/// key and offers the same entries without guessing the first packet again.
/// It states the header fields as they arrived; nothing in it is
/// authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecognizedInitial {
    version: Version,
    dcid: ConnectionId,
    scid: ConnectionId,
    binding: BindingId,
}

impl RecognizedInitial {
    pub(crate) fn new(
        version: Version,
        dcid: ConnectionId,
        scid: ConnectionId,
        binding: BindingId,
    ) -> Self {
        Self {
            version,
            dcid,
            scid,
            binding,
        }
    }

    /// The version of the Initial packet.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The destination connection ID of the Initial packet.
    pub fn dcid(&self) -> &ConnectionId {
        &self.dcid
    }

    /// The source connection ID of the Initial packet.
    pub fn scid(&self) -> &ConnectionId {
        &self.scid
    }

    /// The link binding that produced the arrival link.
    pub fn binding(&self) -> &BindingId {
        &self.binding
    }

    /// The interpretation of the Initial packet.
    pub fn interpretation(&self) -> FirstPacketInterpretation {
        FirstPacketInterpretation::Long {
            version: self.version,
            packet_type: LongPacketType::Initial,
        }
    }

    /// The association under which a receiver for this Initial is published:
    /// the destination connection ID, or the link binding when it is empty.
    pub fn association(&self) -> MatchAssociation {
        match self.key() {
            InitialKey::Dcid(dcid) => MatchAssociation::InitialDcid(dcid),
            InitialKey::Binding(binding) => MatchAssociation::ZeroCid(binding),
        }
    }

    /// The index key of [`association`](Self::association).
    pub(crate) fn key(&self) -> InitialKey {
        match NonEmptyCid::new(self.dcid) {
            Ok(dcid) => InitialKey::Dcid(dcid),
            Err(_) => InitialKey::Binding(self.binding.clone()),
        }
    }
}

/// The index key under which a receiver for an Initial is published.
pub(crate) enum InitialKey {
    /// A non-empty destination connection ID, under the Initial association.
    Dcid(NonEmptyCid),
    /// The link binding of a zero-length destination connection ID.
    Binding(BindingId),
}
