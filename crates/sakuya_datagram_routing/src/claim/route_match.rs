//! What routing recorded about one candidate's match

use crate::route::association::MatchAssociation;
use crate::route::interpretation::FirstPacketInterpretation;

/// What routing recorded about why one route entry matched a datagram.
///
/// Routing produces one value per candidate: the match association it looked
/// up and the first-packet interpretation under which the entry applied. The
/// mechanism keeps it with the candidate, lends it to every judgment, and
/// hands it over with the datagram from
/// [`ExclusiveDatagramDelivery::consume`](super::delivery::ExclusiveDatagramDelivery::consume).
/// It keeps values, never borrows of the datagram. It is not evidence of
/// authentication or acceptance: a match only says under which reading the
/// entry was offered the datagram.
///
/// Only routing creates it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatagramRouteMatchInfo {
    association: MatchAssociation,
    interpretation: FirstPacketInterpretation,
}

impl DatagramRouteMatchInfo {
    pub(crate) fn new(
        association: MatchAssociation,
        interpretation: FirstPacketInterpretation,
    ) -> Self {
        Self {
            association,
            interpretation,
        }
    }

    /// The association under which routing found the entry.
    pub fn association(&self) -> &MatchAssociation {
        &self.association
    }

    /// How the candidate reads the first packet of the datagram.
    pub fn interpretation(&self) -> FirstPacketInterpretation {
        self.interpretation
    }
}
