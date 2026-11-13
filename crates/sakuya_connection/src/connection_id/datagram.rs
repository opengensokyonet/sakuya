//! The destination connection ID one datagram is written with.

use core::{fmt, marker::PhantomData};

use sakuya_wire::connection_id::ConnectionId;

use super::{DestinationConnectionIdStrategy, OfferedConnectionId, ResetTokenRegistrar};
use crate::v1::datagram_batch::ConnectionIdUse;

/// The connection ID chosen for one datagram, borrowing the strategy that
/// offered it and the registrar of the link path it is sent on.
///
/// It tells the strategy of its use when the datagram is sealed with
/// content ([`ConnectionIdUse::used`]); dropped without that, nothing
/// happened, and the strategy never learns it was chosen.
pub struct DatagramConnectionId<'a, D, R, Id, I> {
    strategy: &'a mut D,
    registrar: &'a mut R,
    link_path: &'a Id,
    offered: OfferedConnectionId,
    instant: PhantomData<fn() -> I>,
}

impl<'a, D, R, Id, I> DatagramConnectionId<'a, D, R, Id, I>
where
    D: DestinationConnectionIdStrategy<Id, I, R>,
    R: ResetTokenRegistrar,
{
    /// The first connection ID in `strategy`'s offer for `link_path`, in
    /// the strategy's order, for which `fits` holds; `None` when there is
    /// none.
    ///
    /// The offer is used up before the choice borrows the strategy, so it
    /// holds for this one choice only.
    pub fn choose_first(
        strategy: &'a mut D,
        registrar: &'a mut R,
        link_path: &'a Id,
        mut fits: impl FnMut(&OfferedConnectionId) -> bool,
    ) -> Option<Self> {
        let offered = strategy.offer(link_path).find(|offered| fits(offered))?;
        Some(Self {
            strategy,
            registrar,
            link_path,
            offered,
            instant: PhantomData,
        })
    }

    /// The chosen connection ID and its sequence number.
    pub fn offered(&self) -> OfferedConnectionId {
        self.offered
    }
}

impl<D, R, Id, I> ConnectionIdUse for DatagramConnectionId<'_, D, R, Id, I>
where
    D: DestinationConnectionIdStrategy<Id, I, R>,
    R: ResetTokenRegistrar,
{
    fn connection_id(&self) -> ConnectionId {
        self.offered.id
    }

    fn used(self, datagram_len: usize) {
        self.strategy.on_used(
            self.registrar,
            self.offered.sequence,
            self.link_path,
            datagram_len,
        );
    }
}

impl<D, R, Id, I> fmt::Debug for DatagramConnectionId<'_, D, R, Id, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramConnectionId")
            .field("offered", &self.offered)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
