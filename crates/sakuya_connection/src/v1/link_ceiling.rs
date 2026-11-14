//! The call that follows the datagram size limit of a logical link.
//!
//! [`link_ceiling_watching`] is the call of each entry of a logical link.
//! The link's limit ([`Link::max_datagram_size`]) is otherwise read only
//! because something else happened: a link path's planner reads it when
//! another component it reads changes, and the sending call where a
//! datagram starts to be filled, which happens only when the send strategy
//! plans one. No read happens because the limit itself changed, and
//! content held back by the limit can be the last thing left to send. So
//! the call waits on the link's own report that the limit may have changed
//! ([`Link::max_datagram_size_changed`]), and each time it is woken it
//! takes the entry's clone of the link: the planner of every link path over
//! the logical link reads the clone, and is read again after the call's
//! lend, telling its strategy what the link path can send with the limit
//! as it is now. A limit that grew lets held content go; one below the
//! least size every path supports stops the link path's ordinary content
//! at once, without waiting for the next datagram.
//!
//! The call makes the next future before the planners read the limit, so a
//! change after that read is reported by the future it awaits. It starts
//! woken, and its first poll is the same as a wake: a change between the
//! planners' first read and that poll is not missed.
//!
//! [`link_ceiling_watching`] is also the operation struct
//! [`LinkCeilingWatching`], with `LinkCeilingWatchingExt` on receiver
//! accesses.
// `#[call]` generates a constructor and an extension trait without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use core::{future::Future, pin::Pin};

use nitori_call::{LentAccess, LentCall, ReceiverFamily, call};
use sakuya_link::Link;

use super::{Choices, link::LinkClone};
use crate::{
    call::{CallBundle, CallKind, NodeCallFamily, NodeLoan},
    component::ArgsOf,
    layer::LinkEntry,
    share::{LineageLists, LineagePartList},
    take::GetAt,
};

/// What the call of an entry of a logical link does with its view:
/// everything but waiting.
pub trait LinkCeilingWatchingCapability: ReceiverFamily {
    /// What is ready when the link's datagram size limit may have changed.
    type CeilingChanged: Future<Output = ()>;

    /// Make the future of the next change of the limit of the entry's link,
    /// and take the entry's clone of the link, so that whoever reads the
    /// clone reads the limit again after this lend.
    fn watch_ceiling<'v>(view: Pin<&mut Self::ReceiverView<'v>>) -> Self::CeilingChanged
    where
        Self: 'v;
}

impl<T, L, K, B, I> LinkCeilingWatchingCapability for NodeCallFamily<T, L, LinkEntry, K, I, B>
where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'x> <L as LineageLists<'x, T>>::LinkEntry: GetAt<LinkClone<T::Link>, I>,
{
    type CeilingChanged = <T::Link as Link>::MaxDatagramSizeChanged;

    fn watch_ceiling<'v>(view: Pin<&mut NodeLoan<'v, T, L, LinkEntry, B>>) -> Self::CeilingChanged
    where
        Self: 'v,
    {
        view.get_mut()
            .lineage
            .get_mut::<LinkClone<T::Link>, I>()
            .0
            .max_datagram_size_changed()
    }
}

/// The call of an entry of a logical link; what it does is in the
/// [module documentation](self).
#[call]
pub async fn link_ceiling_watching<W: LinkCeilingWatchingCapability>(
    host: &mut impl LentAccess<Family = W>,
) {
    loop {
        let changed = host.with(|mut view| W::watch_ceiling(view.as_pin()));
        changed.await;
    }
}

/// The kind of the call of an entry of a logical link. It reads nothing:
/// only the link wakes it.
#[derive(Debug)]
pub struct LinkCeilingWatchingKind;

impl<T, L, I> CallKind<T, L, LinkEntry, I> for LinkCeilingWatchingKind
where
    T: Choices,
    L: LineagePartList<T>,
    for<'x> <L as LineageLists<'x, T>>::LinkEntry: GetAt<LinkClone<T::Link>, I>,
    I: 'static,
{
    type Call<B: CallBundle> = LentCall<
        NodeCallFamily<T, L, LinkEntry, LinkCeilingWatchingKind, I, B>,
        LinkCeilingWatching,
    >;
    fn start<B: CallBundle>(_: &mut ArgsOf<T, L, LinkEntry>) -> Self::Call<B> {
        LentCall::new(LinkCeilingWatching::new())
    }
}
