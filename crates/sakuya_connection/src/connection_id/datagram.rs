//! The destination connection ID one datagram is written with.

use core::{fmt, marker::PhantomData};

use sakuya_wire::connection_id::ConnectionId;

use super::{DestinationConnectionIdStrategy, OfferedConnectionId, ResetTokenRegistrar};

/// The connection ID chosen for one datagram from the offer of a
/// destination connection ID strategy `D`, which registers reset tokens
/// through `R`, for a link path identified by `Id`, with instants `I`.
///
/// It is made only by a choice ([`choose_first`](Self::choose_first)),
/// which reads the strategy without changing it, and it holds no borrow:
/// the strategy can be told of other events while the datagram is
/// written. Once the datagram is sealed with content, it is given back to
/// the strategy with the datagram's size ([`used`](Self::used)), which
/// consumes it, so a use is reported at most once. Dropped without that,
/// nothing happened, and the strategy never learns it was chosen.
#[must_use = "a datagram sealed with content reports its connection ID as used"]
pub struct DatagramConnectionId<D, R, Id, I> {
    offered: OfferedConnectionId,
    strategy: PhantomData<fn(&mut D, &mut R, &Id) -> I>,
}

impl<D, R, Id, I> DatagramConnectionId<D, R, Id, I>
where
    D: DestinationConnectionIdStrategy<Id, I, R>,
    R: ResetTokenRegistrar,
{
    /// The first connection ID in `strategy`'s offer for `link_path`, in
    /// the strategy's order, for which `fits` holds; `None` when there is
    /// none.
    ///
    /// The offer holds for this one choice only.
    pub fn choose_first(
        strategy: &D,
        link_path: &Id,
        mut fits: impl FnMut(&OfferedConnectionId) -> bool,
    ) -> Option<Self> {
        let offered = strategy.offer(link_path).find(|offered| fits(offered))?;
        Some(Self {
            offered,
            strategy: PhantomData,
        })
    }

    /// The chosen connection ID and its sequence number.
    pub fn offered(&self) -> OfferedConnectionId {
        self.offered
    }

    /// The chosen connection ID: every packet of the datagram carries it
    /// (RFC 9000 §12.2).
    pub fn connection_id(&self) -> ConnectionId {
        self.offered.id
    }

    /// A datagram of `datagram_len` bytes with content was sealed on
    /// `link_path` with the connection ID: `strategy`, the one that offered
    /// it, is told so, with `registrar`, the registrar of the link path
    /// ([`DestinationConnectionIdStrategy::on_used`]).
    pub fn used(self, strategy: &mut D, registrar: &mut R, link_path: &Id, datagram_len: usize) {
        strategy.on_used(registrar, self.offered.sequence, link_path, datagram_len);
    }
}

impl<D, R, Id, I> fmt::Debug for DatagramConnectionId<D, R, Id, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramConnectionId")
            .field("offered", &self.offered)
            .finish()
    }
}

#[cfg(test)]
mod tests;
