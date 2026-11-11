//! Stand-in parts: just enough state for the driver's rules to show.
//!
//! `a::Part` keeps a close record in the connection, a role with an end
//! time in each link path, a group of recovery components built together,
//! and streams in the established layer. `b::Part` keeps one component in
//! the connection that reads `a`'s record, to compose two parts in either
//! order.
#![allow(dead_code)]
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    future::poll_fn,
    pin::Pin,
    task::{Poll, Waker},
    time::Duration,
};

use frunk_core::{hlist, hlist_pat};
use nitori_call::{LentAccess, LentCall, ReceiverFamily, call};
use sakuya_connection::{
    call::{CallBundle, CallKind, NodeCallFamily, NodeLoan},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, ReadSet, RequestOf},
    layer::{self, NodeKey},
    others::OtherNodes,
    request::StructureRequest,
    share::{LayerShare, LineageLists, LogicalPathKeyShare, LogicalPathKeys, SoleLogicalPath},
    take::{GetAt, Take, TakeEach},
};
use sakuya_wire::parts::{HList, HNil};

use super::{Mine, log, ms};

thread_local! {
    pub static COMMANDS: RefCell<VecDeque<Command>> = const { RefCell::new(VecDeque::new()) };
    pub static WATCH_WAKER: RefCell<Option<Waker>> = const { RefCell::new(None) };
    pub static SEND_WAKERS: RefCell<Vec<Waker>> = const { RefCell::new(Vec::new()) };
    pub static IDLE_AT: Cell<Option<Duration>> = const { Cell::new(None) };
    pub static FACTORY_CALLS: Cell<usize> = const { Cell::new(0) };
}

/// What the watch call does at its next turn.
pub enum Command {
    /// Hand over a request.
    Ask(StructureRequest<SoleLogicalPath>),
    /// Write the close record.
    Close(&'static str),
    /// Write the close record and wake itself in the same lend.
    CloseAndWakeSelf(&'static str),
}

/// Give the watch call a command and wake it, as another thread would.
pub fn command(command: Command) {
    COMMANDS.with(|c| c.borrow_mut().push_back(command));
    if let Some(waker) = WATCH_WAKER.with(|w| w.borrow_mut().take()) {
        waker.wake();
    }
}

/// Wake every send call, as their links would.
pub fn wake_sends() {
    for waker in SEND_WAKERS.with(|w| std::mem::take(&mut *w.borrow_mut())) {
        waker.wake();
    }
}

macro_rules! plain {
    ($lv:ident: $($t:ty),*) => {$(
        impl<L> DataComponent<Mine, L, layer::$lv, ()> for $t where for<'v> L: LineageLists<'v, Mine> {}
        impl<L> Build<Mine, L, layer::$lv, ()> for $t where for<'v> L: LineageLists<'v, Mine> {
            fn build<'v>(_: &mut ParentsOf<'v, Mine, L, layer::$lv>, _: &ArgsOf<L, layer::$lv>) -> Self {
                Default::default()
            }
        }
    )*};
}

macro_rules! no_share {
    ($part:ty: $($lv:ident),*) => {$(
        impl<L> LayerShare<Mine, L, layer::$lv> for $part {
            type Data = HNil;
            type Calls = HNil;
        }
    )*};
}

pub mod a {
    use super::*;

    /// The stand-in part.
    pub struct Part;
    impl LogicalPathKeyShare for Part {
        type Fields = HNil;
    }

    /// Why the connection closes; only the first reason stays.
    #[derive(Debug, Default)]
    pub struct Record(pub Option<&'static str>);
    plain!(Connection: Record);

    /// The idle timeout: when it expires the reason is written and the
    /// connection ends at once.
    #[derive(Debug)]
    pub struct Idle(pub Option<Duration>);
    impl<L> Build<Mine, L, layer::Connection, ()> for Idle
    where
        for<'v> L: LineageLists<'v, Mine>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, L, layer::Connection>,
            _: &ArgsOf<L, layer::Connection>,
        ) -> Self {
            Idle(IDLE_AT.with(Cell::get))
        }
    }
    impl<L, I, J> DataComponent<Mine, L, layer::Connection, (I, J)> for Idle
    where
        for<'v> L: LineageLists<'v, Mine>,
        for<'v> <L as LineageLists<'v, Mine>>::Connection:
            GetAt<Idle, I> + TakeEach<'v, HList![Idle, Record], J>,
    {
        fn deadline<'v>(lineage: &LineageOf<'v, Mine, L, layer::Connection>) -> Option<Duration> {
            lineage.get::<Idle, I>().0
        }
        fn expire<'v, B: CallBundle>(
            lineage: LineageOf<'v, Mine, L, layer::Connection>,
            _: &mut OtherNodes<'v, Mine, L, B>,
            now: Duration,
        ) -> Option<RequestOf<L>> {
            let (hlist_pat![idle, record], _) = Take::<HList![Idle, Record], J>::take(lineage);
            idle.0 = None;
            record.0.get_or_insert("idle");
            log(format!("idle expired at {now:?}"));
            Some(StructureRequest::EndConnection)
        }
    }

    /// Ends the established layer once the record is written, and the
    /// connection once the record is written and no link path is left.
    #[derive(Debug, Default)]
    pub struct Closer;
    impl<L> Build<Mine, L, layer::Connection, ()> for Closer
    where
        for<'v> L: LineageLists<'v, Mine>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, L, layer::Connection>,
            _: &ArgsOf<L, layer::Connection>,
        ) -> Self {
            Closer
        }
    }
    impl<L, I> DataComponent<Mine, L, layer::Connection, I> for Closer
    where
        for<'v> L: LineageLists<'v, Mine>,
        for<'v> <L as LineageLists<'v, Mine>>::Connection: GetAt<Record, I>,
    {
        fn reads(reads: &mut ReadSet) {
            reads.add::<Record>().add::<Role>();
        }
        fn reread<'v, B: CallBundle>(
            lineage: LineageOf<'v, Mine, L, layer::Connection>,
            others: &mut OtherNodes<'v, Mine, L, B>,
            _: Duration,
        ) -> Option<RequestOf<L>> {
            lineage.get::<Record, I>().0?;
            if others.has_established() {
                Some(StructureRequest::EndEstablished)
            } else if others.link_path_keys().next().is_none() {
                Some(StructureRequest::EndConnection)
            } else {
                None
            }
        }
    }

    /// What a link path does: active, or draining until its end time.
    #[derive(Debug, Clone, Copy, PartialEq, Default)]
    pub enum Role {
        #[default]
        Active,
        Draining(Duration),
    }
    impl<L> Build<Mine, L, layer::LinkPath, ()> for Role
    where
        for<'v> L: LineageLists<'v, Mine>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, L, layer::LinkPath>,
            _: &ArgsOf<L, layer::LinkPath>,
        ) -> Self {
            Role::Active
        }
    }
    impl<L, I, J, K> DataComponent<Mine, L, layer::LinkPath, (I, J, K)> for Role
    where
        for<'v> L: LineageLists<'v, Mine>,
        for<'v> <L as LineageLists<'v, Mine>>::LinkPath:
            GetAt<Role, I> + GetAt<Record, J> + TakeEach<'v, HList![Role], K>,
    {
        fn reads(reads: &mut ReadSet) {
            reads.add::<Record>();
        }
        fn deadline<'v>(lineage: &LineageOf<'v, Mine, L, layer::LinkPath>) -> Option<Duration> {
            match lineage.get::<Role, I>() {
                Role::Active => None,
                Role::Draining(end) => Some(*end),
            }
        }
        fn expire<'v, B: CallBundle>(
            _: LineageOf<'v, Mine, L, layer::LinkPath>,
            others: &mut OtherNodes<'v, Mine, L, B>,
            now: Duration,
        ) -> Option<RequestOf<L>> {
            let NodeKey::LinkPath(path, link) = others.here().clone() else {
                unreachable!()
            };
            log(format!("link path ends at {now:?}"));
            Some(StructureRequest::EndLinkPath { path, link })
        }
        fn reread<'v, B: CallBundle>(
            lineage: LineageOf<'v, Mine, L, layer::LinkPath>,
            others: &mut OtherNodes<'v, Mine, L, B>,
            now: Duration,
        ) -> Option<RequestOf<L>> {
            if lineage.get::<Record, J>().0.is_none() || *lineage.get::<Role, I>() != Role::Active {
                return None;
            }
            let (hlist_pat![role], _) = Take::<HList![Role], K>::take(lineage);
            *role = Role::Draining(now + ms(30));
            let NodeKey::LinkPath(path, link) = others.here().clone() else {
                unreachable!()
            };
            Some(StructureRequest::EndRecovery { path, link })
        }
    }

    /// The round-trip time and the window of a link path, made together by
    /// one factory call.
    #[derive(Debug, Clone, PartialEq)]
    pub struct Rtt(pub Duration);
    #[derive(Debug, Clone, PartialEq)]
    pub struct Window(pub u32);
    impl<L> DataComponent<Mine, L, layer::Recovery, ()> for Rtt where for<'v> L: LineageLists<'v, Mine> {}
    impl<L> DataComponent<Mine, L, layer::Recovery, ()> for Window where
        for<'v> L: LineageLists<'v, Mine>
    {
    }
    impl<L> Build<Mine, L, layer::Recovery, ()> for HList![Rtt, Window]
    where
        for<'v> L: LineageLists<'v, Mine>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, L, layer::Recovery>,
            _: &ArgsOf<L, layer::Recovery>,
        ) -> Self {
            let n = FACTORY_CALLS.with(|c| {
                c.set(c.get() + 1);
                c.get()
            });
            hlist![Rtt(ms(10 * n as u64)), Window(1000 * n as u32)]
        }
        fn end<'v>(self, _: &mut ParentsOf<'v, Mine, L, layer::Recovery>) {
            log(format!("recovery ended with {:?}", self));
        }
    }

    /// Streams: only in the established layer; at their end they read the
    /// close record.
    #[derive(Debug, Default)]
    pub struct Streams(pub u32);
    impl<L> DataComponent<Mine, L, layer::Established, ()> for Streams where
        for<'v> L: LineageLists<'v, Mine>
    {
    }
    impl<L, I> Build<Mine, L, layer::Established, I> for Streams
    where
        for<'v> L: LineageLists<'v, Mine>,
        for<'v> <L as LineageLists<'v, Mine>>::Connection: GetAt<Record, I>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, L, layer::Established>,
            _: &ArgsOf<L, layer::Established>,
        ) -> Self {
            Streams(3)
        }
        fn end<'v>(self, parents: &mut ParentsOf<'v, Mine, L, layer::Established>) {
            log(format!(
                "streams ended with {} open, the record says {:?}",
                self.0,
                parents.get::<Record, I>().0
            ));
        }
    }

    /// The credit of a logical link entry.
    #[derive(Debug, Default)]
    pub struct Credit(pub u32);
    impl<L> DataComponent<Mine, L, layer::LinkEntry, ()> for Credit where
        for<'v> L: LineageLists<'v, Mine>
    {
    }
    impl<L> Build<Mine, L, layer::LinkEntry, ()> for Credit
    where
        for<'v> L: LineageLists<'v, Mine>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, L, layer::LinkEntry>,
            _: &ArgsOf<L, layer::LinkEntry>,
        ) -> Self {
            log("entry built");
            Credit(0)
        }
        fn end<'v>(self, _: &mut ParentsOf<'v, Mine, L, layer::LinkEntry>) {
            log("entry ended");
        }
    }

    impl<L> LayerShare<Mine, L, layer::Connection> for Part {
        type Data = HList![Record, Idle, Closer];
        type Calls = HList![WatchKind];
    }
    impl<L> LayerShare<Mine, L, layer::LinkEntry> for Part {
        type Data = HList![Credit];
        type Calls = HNil;
    }
    no_share!(Part: LogicalPath);
    impl<L> LayerShare<Mine, L, layer::LinkPath> for Part {
        type Data = HList![Role];
        type Calls = HList![SendKind];
    }
    impl<L> LayerShare<Mine, L, layer::Established> for Part {
        type Data = HList![Streams];
        type Calls = HNil;
    }
    impl<L> LayerShare<Mine, L, layer::Recovery> for Part {
        type Data = HList![Rtt, Window];
        type Units = HList![HList![Rtt, Window]];
        type Calls = HNil;
    }

    // ---- the watch call: does what the test commands ----

    /// What the watch call can do with its view.
    pub trait WatchCapability: ReceiverFamily {
        /// Write the close record.
        fn close<'v>(view: Pin<&mut Self::ReceiverView<'v>>, reason: &'static str)
        where
            Self: 'v;
    }
    impl<L, K: 'static, I: 'static, B: CallBundle> WatchCapability
        for NodeCallFamily<Mine, L, layer::Connection, K, I, B>
    where
        for<'v> L: LineageLists<'v, Mine>,
        for<'v> <L as LineageLists<'v, Mine>>::Connection: GetAt<Record, I>,
    {
        fn close<'v>(
            view: Pin<&mut NodeLoan<'v, Mine, L, layer::Connection, B>>,
            reason: &'static str,
        ) where
            Self: 'v,
        {
            view.get_mut()
                .lineage
                .get_mut::<Record, I>()
                .0
                .get_or_insert(reason);
        }
    }

    #[call(yields = StructureRequest<SoleLogicalPath>)]
    pub async fn watch<W: WatchCapability>(host: &mut impl LentAccess<Family = W>) {
        loop {
            let next = poll_fn(|cx| {
                log("watch polled");
                match COMMANDS.with(|c| c.borrow_mut().pop_front()) {
                    Some(command) => Poll::Ready(command),
                    None => {
                        WATCH_WAKER.with(|w| *w.borrow_mut() = Some(cx.waker().clone()));
                        Poll::Pending
                    }
                }
            })
            .await;
            match next {
                Command::Ask(request) => yield request,
                Command::Close(reason) => host.with(|mut a| W::close(a.as_pin(), reason)),
                Command::CloseAndWakeSelf(reason) => {
                    host.with(|mut a| W::close(a.as_pin(), reason));
                    poll_fn(|cx| {
                        cx.waker().wake_by_ref();
                        Poll::Ready(())
                    })
                    .await;
                }
            }
        }
    }

    /// The kind of the watch call; it reads the record.
    pub struct WatchKind;
    impl<L, I: 'static> CallKind<Mine, L, layer::Connection, I> for WatchKind
    where
        for<'v> L: LineageLists<'v, Mine>,
        L: LogicalPathKeys<Key = SoleLogicalPath>,
        for<'v> <L as LineageLists<'v, Mine>>::Connection: GetAt<Record, I>,
    {
        type Call<B: CallBundle> =
            LentCall<NodeCallFamily<Mine, L, layer::Connection, WatchKind, I, B>, Watch>;
        fn start<B: CallBundle>(_: &ArgsOf<L, layer::Connection>) -> Self::Call<B> {
            LentCall::new(Watch::new())
        }
        fn reads(reads: &mut ReadSet) {
            reads.add::<Record>();
        }
    }

    // ---- the send call: waits for its link ----

    #[call]
    pub async fn send_loop<W: ReceiverFamily>(_host: &mut impl LentAccess<Family = W>) {
        loop {
            poll_fn(|cx| {
                log("send polled");
                SEND_WAKERS.with(|w| w.borrow_mut().push(cx.waker().clone()));
                Poll::<()>::Pending
            })
            .await;
        }
    }

    /// The kind of the send call: not needed once its link path drains.
    pub struct SendKind;
    impl<L, I: 'static> CallKind<Mine, L, layer::LinkPath, I> for SendKind
    where
        for<'v> L: LineageLists<'v, Mine>,
        for<'v> <L as LineageLists<'v, Mine>>::LinkPath: GetAt<Role, I>,
    {
        type Call<B: CallBundle> =
            LentCall<NodeCallFamily<Mine, L, layer::LinkPath, SendKind, I, B>, SendLoop>;
        fn start<B: CallBundle>(_: &ArgsOf<L, layer::LinkPath>) -> Self::Call<B> {
            LentCall::new(SendLoop::new())
        }
        fn reads(reads: &mut ReadSet) {
            reads.add::<Role>();
        }
        fn no_longer_needed<'v>(lineage: &LineageOf<'v, Mine, L, layer::LinkPath>) -> bool {
            matches!(lineage.get::<Role, I>(), Role::Draining(_))
        }
    }
}

pub mod b {
    use super::*;

    /// The second stand-in part.
    pub struct Part;
    impl LogicalPathKeyShare for Part {
        type Fields = HNil;
    }

    /// Counts how often it saw `a`'s record change.
    #[derive(Debug, Default)]
    pub struct Seen(pub u32);
    impl<L> Build<Mine, L, layer::Connection, ()> for Seen
    where
        for<'v> L: LineageLists<'v, Mine>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, L, layer::Connection>,
            _: &ArgsOf<L, layer::Connection>,
        ) -> Self {
            Seen(0)
        }
    }
    impl<L, I, J> DataComponent<Mine, L, layer::Connection, (I, J)> for Seen
    where
        for<'v> L: LineageLists<'v, Mine>,
        for<'v> <L as LineageLists<'v, Mine>>::Connection:
            GetAt<super::a::Record, I> + TakeEach<'v, HList![Seen], J>,
    {
        fn reads(reads: &mut ReadSet) {
            reads.add::<super::a::Record>();
        }
        fn reread<'v, B: CallBundle>(
            lineage: LineageOf<'v, Mine, L, layer::Connection>,
            _: &mut OtherNodes<'v, Mine, L, B>,
            _: Duration,
        ) -> Option<RequestOf<L>> {
            let reason = lineage.get::<super::a::Record, I>().0;
            let (hlist_pat![seen], _) = Take::<HList![Seen], J>::take(lineage);
            seen.0 += 1;
            log(format!("b saw the record: {reason:?}"));
            None
        }
    }

    impl<L> LayerShare<Mine, L, layer::Connection> for Part {
        type Data = HList![Seen];
        type Calls = HNil;
    }
    no_share!(Part: LinkEntry, LogicalPath, LinkPath, Established, Recovery);
}

pub mod c {
    //! Two components that change each other forever: rereads never settle.
    use super::*;

    pub struct Part;
    impl LogicalPathKeyShare for Part {
        type Fields = HNil;
    }

    #[derive(Debug, Default)]
    pub struct Ping(pub u32);
    #[derive(Debug, Default)]
    pub struct Pong(pub u32);
    impl<L> Build<Mine, L, layer::Connection, ()> for Ping
    where
        for<'v> L: LineageLists<'v, Mine>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, L, layer::Connection>,
            _: &ArgsOf<L, layer::Connection>,
        ) -> Self {
            Ping(0)
        }
    }
    impl<L> Build<Mine, L, layer::Connection, ()> for Pong
    where
        for<'v> L: LineageLists<'v, Mine>,
    {
        fn build<'v>(
            _: &mut ParentsOf<'v, Mine, L, layer::Connection>,
            _: &ArgsOf<L, layer::Connection>,
        ) -> Self {
            Pong(0)
        }
    }
    impl<L, J> DataComponent<Mine, L, layer::Connection, J> for Ping
    where
        for<'v> L: LineageLists<'v, Mine>,
        for<'v> <L as LineageLists<'v, Mine>>::Connection: TakeEach<'v, HList![Ping], J>,
    {
        fn reads(reads: &mut ReadSet) {
            reads.add::<Pong>();
        }
        fn reread<'v, B: CallBundle>(
            lineage: LineageOf<'v, Mine, L, layer::Connection>,
            _: &mut OtherNodes<'v, Mine, L, B>,
            _: Duration,
        ) -> Option<RequestOf<L>> {
            let (hlist_pat![ping], _) = Take::<HList![Ping], J>::take(lineage);
            ping.0 += 1;
            None
        }
    }
    impl<L, J> DataComponent<Mine, L, layer::Connection, J> for Pong
    where
        for<'v> L: LineageLists<'v, Mine>,
        for<'v> <L as LineageLists<'v, Mine>>::Connection: TakeEach<'v, HList![Pong], J>,
    {
        fn reads(reads: &mut ReadSet) {
            reads.add::<Ping>();
        }
        fn reread<'v, B: CallBundle>(
            lineage: LineageOf<'v, Mine, L, layer::Connection>,
            _: &mut OtherNodes<'v, Mine, L, B>,
            _: Duration,
        ) -> Option<RequestOf<L>> {
            let (hlist_pat![pong], _) = Take::<HList![Pong], J>::take(lineage);
            pong.0 += 1;
            None
        }
    }
    impl<L> LayerShare<Mine, L, layer::Connection> for Part {
        type Data = HList![Ping, Pong];
        type Calls = HNil;
    }
    no_share!(Part: LinkEntry, LogicalPath, LinkPath, Established, Recovery);
}
