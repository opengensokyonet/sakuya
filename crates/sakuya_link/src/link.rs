//! The link: a channel that keeps message boundaries.

use core::{future::Future, num::NonZeroUsize, ops::Add, time::Duration};

use bytes::Bytes;

use crate::LinkId;

/// The smallest maximum datagram size QUIC allows, in bytes (RFC 9000
/// §14): the default of a link's datagram size conclusion and its floor.
pub const MIN_DATAGRAM_SIZE: usize = 1200;

/// A link: sends and receives whole messages between this side and one
/// peer, one UDP datagram per message.
///
/// A clone is another handle to the same link, with the same [`LinkId`];
/// cloning is cheap, and dropping a clone does not close the link. Each
/// clone has a wait state of its own.
///
/// Besides carrying messages, a link states a few facts about itself, each
/// through its own method because each changes by its own rule: whether it
/// may mark ECN, its datagram size limit and when that limit may have
/// changed, and the datagram size its clones have concluded works.
///
/// The futures its methods return borrow nothing of the link: a caller may
/// keep one while it holds no borrow of the clone it came from. Several
/// futures from one clone wait each on its own, without affecting one
/// another.
///
/// The method that receives messages is not part of this trait yet.
pub trait Link: Clone {
    /// The type of a received message's payload.
    ///
    /// Code that cuts, reads or rewrites payloads states what it needs as
    /// bounds where it does so.
    type Payload;
    /// The type of the instants a link reports: when a datagram arrived,
    /// and when the link accepted datagrams to send.
    ///
    /// A connection requires it to be the instant of its clock; that both
    /// read the same clock is for whoever composes them to ensure.
    type Instant: Ord + Copy + Add<Duration, Output = Self::Instant>;
    /// Why [`max_datagram_size`](Self::max_datagram_size) cannot be told.
    type MaxDatagramSizeError;
    /// Why the first datagram not yet accepted by [`send`](Self::send) was
    /// given up. It is not classified: the caller handles every error the
    /// same way.
    type SendError;
    /// The future of one [`send`](Self::send): it borrows only the batch.
    type Send<'a>: Future<Output = Result<SendAcceptance<Self::Instant>, Self::SendError>> + 'a;
    /// The future of one
    /// [`max_datagram_size_changed`](Self::max_datagram_size_changed); it
    /// borrows nothing.
    ///
    /// A link that cannot detect a change uses
    /// [`core::future::Pending<()>`], which is never ready.
    type MaxDatagramSizeChanged: Future<Output = ()>;

    /// The identity of this link, the same for all its clones.
    fn id(&self) -> &LinkId;

    /// Whether this link can write ECN codepoints into the IP headers of
    /// what it sends.
    ///
    /// It may change from `true` to `false`, for example when a platform
    /// reveals that it cannot after a send, and never from `false` to
    /// `true`. A link that cannot set a codepoint sends Not-ECT without
    /// failing.
    fn may_mark_ecn(&self) -> bool;

    /// The largest UDP payload this link can send without fragmenting at
    /// its own layer, as far as it knows locally.
    ///
    /// It is the upper bound of datagram size probing, not a size proven
    /// to reach the peer. It may become smaller or larger. A link never
    /// fragments at the IP layer; a UDP link whose limit is below
    /// [`MIN_DATAGRAM_SIZE`] reports it as it is, and a link that can split
    /// datagrams at its own layer accepts datagrams of at least
    /// [`MIN_DATAGRAM_SIZE`] whatever its limit.
    ///
    /// # Errors
    ///
    /// The limit cannot be told for now, or the link has failed.
    fn max_datagram_size(&self) -> Result<usize, Self::MaxDatagramSizeError>;

    /// Hand `batch` to the link to send, in order.
    ///
    /// The future ends when the link has accepted some of the batch, or has
    /// given one up:
    ///
    /// - `Ok` means the first [`count`](SendAcceptance::count) datagrams
    ///   are accepted, at [`at`](SendAcceptance::at); the rest are not, and
    ///   the caller sends them again. Accepted means taken by the link, not
    ///   that they reached the network.
    /// - `Err` means the first of them is given up and the rest are not
    ///   touched: the caller handles the packets in that datagram as lost
    ///   and sends the rest again.
    ///
    /// Dropping the future before it ends leaves the batch neither sent nor
    /// unsent: some of it may have gone out. The caller handles the packets
    /// in it as lost.
    ///
    /// `batch` is not empty.
    fn send<'a>(&self, batch: &'a [OutgoingDatagram]) -> Self::Send<'a>;

    /// A future that is ready when the result of
    /// [`max_datagram_size`](Self::max_datagram_size) may have changed
    /// since the future was made.
    ///
    /// It may report a change that did not happen, and never misses one; a
    /// change between `Ok` and an error counts. It carries no value: the
    /// limit is read again with `max_datagram_size`. A caller that watches
    /// the limit makes the next future before it reads the limit, so a
    /// change after the read is reported by that future:
    ///
    /// ```ignore
    /// loop {
    ///     let changed = link.max_datagram_size_changed();
    ///     let limit = link.max_datagram_size();
    ///     // use the limit
    ///     changed.await;
    /// }
    /// ```
    fn max_datagram_size_changed(&self) -> Self::MaxDatagramSizeChanged;

    /// The datagram size the probing over this link has concluded works,
    /// shared by all its clones, never below [`MIN_DATAGRAM_SIZE`].
    ///
    /// By default it is [`MIN_DATAGRAM_SIZE`]: a link that keeps no
    /// conclusion shares none.
    fn datagram_size_conclusion(&self) -> usize {
        MIN_DATAGRAM_SIZE
    }

    /// Probing has proven that datagrams of `size` bytes get through: the
    /// conclusion becomes the larger of it and `size`.
    ///
    /// By default the conclusion is not kept.
    fn record_datagram_size_confirmed(&self, size: usize) {
        let _ = size;
    }

    /// Probing has found that datagrams above `size` bytes are lost: the
    /// conclusion becomes the smaller of it and `size`, and a `size` below
    /// [`MIN_DATAGRAM_SIZE`] counts as [`MIN_DATAGRAM_SIZE`].
    ///
    /// By default the conclusion is not kept.
    fn record_datagram_size_lowered(&self, size: usize) {
        let _ = size;
    }
}

/// A datagram handed to [`Link::send`]: its UDP payload and the ECN marking
/// to set in its IP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutgoingDatagram {
    /// The UDP payload.
    pub payload: Bytes,
    /// The ECN marking. A link that cannot set it sends Not-ECT without
    /// failing (see [`Link::may_mark_ecn`]).
    pub ecn: EcnMarking,
}

/// The ECN marking set on a datagram sent: Not-ECT, ECT(0) or ECT(1)
/// (RFC 9000 §13.4).
///
/// It has no CE: this side never sends CE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcnMarking {
    /// Not ECN-Capable Transport.
    NotEct,
    /// ECN-Capable Transport, codepoint 0.
    Ect0,
    /// ECN-Capable Transport, codepoint 1.
    Ect1,
}

/// How much of a batch [`Link::send`] accepted, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendAcceptance<I> {
    /// How many datagrams from the start of the batch were accepted.
    pub count: NonZeroUsize,
    /// The instant the link accepted them; the connection records it as
    /// their send time.
    pub at: I,
}
