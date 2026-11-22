//! The call that follows the end of a logical link.
//!
//! [`link_end_watching`] is the second call of each entry of a logical
//! link, beside the one that follows its datagram size limit. It waits for
//! the link's end ([`Link::ended`]) on the entry's clone of the link, and
//! then ends what ran over it, one request after the other:
//!
//! - while another link path is left over another link, it asks for the
//!   end of each link path over this one; the connection goes on, and the
//!   entry ends with the last of them;
//! - when none is left and the record of why the connection closed is
//!   empty, it writes this endpoint's reason, the end of the link with the
//!   link's reason ([`LocalCloseCause::LinkEnded`]), and asks for the
//!   connection to end at once: no close is sealed, and the connection
//!   enters neither closing nor draining;
//! - when the record has a reason already, that reason stays, and the call
//!   asks for the end of each link path over this link; the record then
//!   asks for the connection's end once no link path is left.
//!
//! A link path ended this way ends as any link path does: what it has in
//! flight is handed back to the frame sources as lost.
//!
//! [`link_end_watching`] is also the operation struct [`LinkEndWatching`],
//! with `LinkEndWatchingExt` on receiver accesses.
// `#[call]` generates a constructor and an extension trait without
// documentation comments; the module documentation above describes them.
#![allow(missing_docs)]

use crate::v1::state_choices::StateChoices;
use core::{future::Future, pin::Pin};
use std::sync::Arc;

use nitori_call::{LentAccess, LentCall, ReceiverFamily, call};
use sakuya_link::Link;
use sakuya_stream_v1::connection::CloseReason;

use super::{
    CloseCauseOf, EventsOf,
    close::{CloseReasonRecord, LocalCloseCause, TransportClose},
    events::{ConnectionEventSink, ConnectionEvents},
    link::LinkClone,
};
use crate::{
    call::{CallBundle, CallKind, NodeCallFamily, NodeLoan},
    clock::InstantOf,
    component::{ArgsOf, RequestOf},
    error::{ConnectionErrorOf, ConnectionErrorsOf},
    layer::{LinkEntry, NodeKey},
    request::StructureRequest,
    share::{LineageLists, LineagePartList},
    take::GetAt,
};

/// What the call that follows the end of a logical link does with its
/// view: everything but waiting.
pub trait LinkEndWatchingCapability: ReceiverFamily {
    /// Why the link ended: its `RecvError`.
    type RecvError;
    /// What is ready, with the reason, once the link ended.
    type Ended: Future<Output = Self::RecvError>;
    /// A request of the connection's structure.
    type Request;

    /// Make the future of the end of the entry's link.
    fn watch_end<'v>(view: Pin<&mut Self::ReceiverView<'v>>) -> Self::Ended
    where
        Self: 'v;

    /// The entry's link ended for `reason`: the next request that ends
    /// what ran over it, as the [module documentation](self) says, or
    /// `None` once nothing is left to end.
    fn link_ended<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        reason: &Self::RecvError,
    ) -> Option<Self::Request>
    where
        Self: 'v;
}

impl<T, L, K, B, Il, Ir, Iev> LinkEndWatchingCapability
    for NodeCallFamily<T, L, LinkEntry, K, (Il, Ir, Iev), B>
where
    T: StateChoices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    ConnectionErrorOf<L>: TransportClose,
    B: CallBundle,
    for<'x> <L as LineageLists<'x, T>>::LinkEntry: GetAt<LinkClone<T::Link>, Il>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
{
    type RecvError = <T::Link as Link>::RecvError;
    type Ended = <T::Link as Link>::Ended;
    type Request = RequestOf<T, L>;

    fn watch_end<'v>(view: Pin<&mut NodeLoan<'v, T, L, LinkEntry, B>>) -> Self::Ended
    where
        Self: 'v,
    {
        view.get_mut()
            .lineage
            .get::<LinkClone<T::Link>, Il>()
            .0
            .ended()
    }

    fn link_ended<'v>(
        view: Pin<&mut NodeLoan<'v, T, L, LinkEntry, B>>,
        reason: &Self::RecvError,
    ) -> Option<Self::Request>
    where
        Self: 'v,
    {
        let loan = view.get_mut();
        let NodeKey::LinkEntry(link) = loan.others.here().clone() else {
            unreachable!("an entry's lend carries its key")
        };
        let mut over_this = None;
        let mut elsewhere = false;
        for key in loan.others.link_path_keys() {
            if let NodeKey::LinkPath(path, over) = key {
                if *over == link {
                    over_this.get_or_insert_with(|| path.clone());
                } else {
                    elsewhere = true;
                }
            }
        }
        let path = over_this?;
        if !elsewhere
            && !loan
                .lineage
                .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
                .is_written()
        {
            let written = loan
                .lineage
                .get_mut::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
                .record(CloseReason::Local(Arc::new(LocalCloseCause::LinkEnded(
                    reason.clone(),
                ))));
            if let Some(written) = written {
                loan.lineage.publish(written);
            }
            // the connection ends at once, before the record's handler runs
            if <EventsOf<T, L> as ConnectionEvents<InstantOf<T>>>::ENABLED {
                let closed = loan
                    .lineage
                    .get::<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>()
                    .reason()
                    .map(super::connection_closed_event);
                if let Some(closed) = closed {
                    let now = loan.others.now();
                    loan.lineage
                        .get_mut::<ConnectionEventSink<EventsOf<T, L>>, Iev>()
                        .record_written(now, || closed);
                }
            }
            return Some(StructureRequest::EndConnection);
        }
        Some(StructureRequest::EndLinkPath { path, link })
    }
}

/// The call that follows the end of a logical link; what it does is in the
/// [module documentation](self).
#[call(yields = W::Request)]
pub async fn link_end_watching<W: LinkEndWatchingCapability>(
    host: &mut impl LentAccess<Family = W>,
) {
    let ended = host.with(|mut view| W::watch_end(view.as_pin()));
    let reason = ended.await;
    while let Some(request) = host.with(|mut view| W::link_ended(view.as_pin(), &reason)) {
        yield request;
    }
    // the entry ends with the last link path over its link
    core::future::pending::<()>().await;
}

/// The kind of the call that follows the end of a logical link. It
/// subscribes to nothing: only the link wakes it.
#[derive(Debug)]
pub struct LinkEndWatchingKind;

impl<T, L, Il, Ir, Iev> CallKind<T, L, LinkEntry, (Il, Ir, Iev)> for LinkEndWatchingKind
where
    T: StateChoices,
    L: LineagePartList<T> + ConnectionErrorsOf,
    ConnectionErrorOf<L>: TransportClose,
    for<'x> <L as LineageLists<'x, T>>::LinkEntry: GetAt<LinkClone<T::Link>, Il>
        + GetAt<CloseReasonRecord<CloseCauseOf<T, L>>, Ir>
        + GetAt<ConnectionEventSink<EventsOf<T, L>>, Iev>,
    Il: 'static,
    Ir: 'static,
    Iev: 'static,
{
    type Call<B: CallBundle> = LentCall<
        NodeCallFamily<T, L, LinkEntry, LinkEndWatchingKind, (Il, Ir, Iev), B>,
        LinkEndWatching,
    >;
    fn start<B: CallBundle>(_: &mut ArgsOf<T, L, LinkEntry>) -> Self::Call<B> {
        LentCall::new(LinkEndWatching::new())
    }
}
