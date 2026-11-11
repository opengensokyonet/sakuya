//! The calls of a connection: how a part declares them, how they are lent
//! the tree and polled, and the types that tie them together.
//!
//! A part lists the kinds of its calls in each layer's share. A kind of call
//! is a `#[call]` function on a [`NodeCallFamily`], whose view is the lent
//! node's lineage and the other nodes ([`NodeLoan`]), and a [`CallKind`]
//! impl that starts it. The types of all calls follow from the list of
//! parts: each layer's calls are a generic type of a bundle
//! ([`CallBundle`]), and one named bundle per composition
//! ([`PartsCallBundle`]) puts every layer's calls in, so that a view can
//! hold the other nodes with their real types.
use core::{marker::PhantomData, ops::ControlFlow, pin::Pin, task::Context};
use std::task::Poll;

use nitori_call::{LentCall, LentSlot, Operation, ReceiverFamily, Start};
use sakuya_wire::parts::{HCons, HNil};

use crate::{
    clock::ConnectionChoices,
    component::{ArgsOf, LineageOf, ReadSet, RequestOf},
    layer::{Connection, Established, LinkEntry, LinkPath, LogicalPath, Recovery},
    others::OtherNodes,
    share::{LayerLineage, LayerShare, LineageLists, PartList},
};

/// The types of the calls of each layer.
pub trait CallBundle: 'static {
    /// The calls of the connection node.
    type Connection;
    /// The calls of a logical link entry.
    type LinkEntry;
    /// The calls of a logical path.
    type LogicalPath;
    /// The calls of a link path.
    type LinkPath;
    /// The calls of the established layer.
    type Established;
    /// The calls of a recovery layer.
    type Recovery;
}

/// What a call of a node of the layer `Lv` is lent on each poll: the
/// node's lineage and the other nodes.
pub struct NodeLoan<
    'v,
    T: ConnectionChoices,
    L: LineageLists<'v, T>,
    Lv: LayerLineage,
    B: CallBundle,
> {
    /// The lent node's data and the data of the nodes above it.
    pub lineage: LineageOf<'v, T, L, Lv>,
    /// The other nodes.
    pub others: OtherNodes<'v, T, L, B>,
}

// A loan holds borrows only; nothing in it is pinned structurally.
impl<'v, T: ConnectionChoices, L: LineageLists<'v, T>, Lv: LayerLineage, B: CallBundle> Unpin
    for NodeLoan<'v, T, L, Lv, B>
{
}

/// The receiver family of a call of the kind `K` in a node of the layer
/// `Lv`; `H` is what the kind's impl infers its takes by, `B` the bundle.
#[allow(clippy::type_complexity)] // a marker of six type parameters
pub struct NodeCallFamily<T, L, Lv, K, H, B>(PhantomData<fn() -> (T, L, Lv, K, H, B)>);

impl<T: ConnectionChoices, L, Lv: LayerLineage, K, H, B: CallBundle> ReceiverFamily
    for NodeCallFamily<T, L, Lv, K, H, B>
where
    for<'v> L: LineageLists<'v, T>,
{
    type ReceiverView<'v>
        = NodeLoan<'v, T, L, Lv, B>
    where
        Self: 'v;
}

/// What one poll of a call came to.
#[derive(Debug)]
pub enum CallStep<R> {
    /// The call waits.
    Pending,
    /// The call is over.
    Finished,
    /// The call handed over a request; it goes on at the next poll.
    Requested(R),
}

/// A call the driver polls at a position of a node of the layer `Lv`.
pub trait NodeCall<T: ConnectionChoices, L, Lv: LayerLineage, B: CallBundle>
where
    for<'v> L: LineageLists<'v, T>,
{
    /// Poll the call with the lent node.
    fn poll_lent<'v>(
        self: Pin<&mut Self>,
        loan: NodeLoan<'v, T, L, Lv, B>,
        cx: &mut Context<'_>,
    ) -> CallStep<RequestOf<L>>;
    /// Whether the call is not needed any more; see
    /// [`CallKind::no_longer_needed`].
    fn no_longer_needed<'v>(lineage: &LineageOf<'v, T, L, Lv>) -> bool;
}

impl<T, L, Lv, K, H, B, Op> NodeCall<T, L, Lv, B>
    for LentCall<NodeCallFamily<T, L, Lv, K, H, B>, Op>
where
    T: ConnectionChoices,
    for<'v> L: LineageLists<'v, T>,
    Lv: LayerLineage,
    K: CallKind<T, L, Lv, H> + 'static,
    H: 'static,
    B: CallBundle,
    Op: Operation<NodeCallFamily<T, L, Lv, K, H, B>, Output = ()>
        + for<'s> Start<'s, LentSlot<'s, NodeCallFamily<T, L, Lv, K, H, B>>>,
    <Op as Operation<NodeCallFamily<T, L, Lv, K, H, B>>>::Yield: Into<RequestOf<L>>,
{
    #[inline]
    fn poll_lent<'v>(
        self: Pin<&mut Self>,
        loan: NodeLoan<'v, T, L, Lv, B>,
        cx: &mut Context<'_>,
    ) -> CallStep<RequestOf<L>> {
        let mut loan = loan;
        match self.poll_with_views(Pin::new(&mut loan), cx) {
            Poll::Ready(ControlFlow::Break(())) => CallStep::Finished,
            Poll::Ready(ControlFlow::Continue(item)) => CallStep::Requested(item.into()),
            Poll::Pending => CallStep::Pending,
        }
    }
    #[inline]
    fn no_longer_needed<'v>(lineage: &LineageOf<'v, T, L, Lv>) -> bool {
        K::no_longer_needed(lineage)
    }
}

/// A kind of call of a node of the layer `Lv`.
///
/// `H` is what the impl infers its takes by: the impl carries the bounds of
/// the data its call takes, so the call's type holds for every bundle.
pub trait CallKind<T: ConnectionChoices, L, Lv: LayerLineage, H>
where
    for<'v> L: LineageLists<'v, T>,
{
    /// The call, for the bundle `B`.
    type Call<B: CallBundle>: NodeCall<T, L, Lv, B>;
    /// Start the call of a new node; it starts woken.
    fn start<B: CallBundle>(args: &ArgsOf<L, Lv>) -> Self::Call<B>;
    /// The component types the call reads: after one was taken mutably by
    /// anything but this call's own lend, the call is woken.
    fn reads(_reads: &mut ReadSet) {}
    /// Whether the call is not needed any more, looking only at what it
    /// reads. The driver asks before it polls a woken call and drops a call
    /// that is not needed; its position is not polled again. By default the
    /// call is always needed.
    fn no_longer_needed<'v>(_lineage: &LineageOf<'v, T, L, Lv>) -> bool {
        false
    }
}

/// A call at its position: running, over, or dropped because it was not
/// needed any more.
pub struct CallSlot<X> {
    call: Option<Pin<Box<X>>>,
}

/// Polling the call at a position counted from the end of a part's calls.
pub trait PollAt<T: ConnectionChoices, L, Lv: LayerLineage, B: CallBundle>
where
    for<'v> L: LineageLists<'v, T>,
{
    /// Poll the call at `r` from the end when it is here; `after` is how
    /// many calls follow. The loan comes back when it is not here.
    // The loan moves through the dispatch by value; the dispatch is inlined.
    #[allow(clippy::type_complexity, clippy::result_large_err)]
    fn try_poll<'v>(
        &mut self,
        r: usize,
        after: usize,
        loan: NodeLoan<'v, T, L, Lv, B>,
        cx: &mut Context<'_>,
    ) -> Result<CallStep<RequestOf<L>>, NodeLoan<'v, T, L, Lv, B>>;
}
impl<T: ConnectionChoices, L, Lv: LayerLineage, B: CallBundle> PollAt<T, L, Lv, B> for HNil
where
    for<'v> L: LineageLists<'v, T>,
{
    #[inline(always)]
    fn try_poll<'v>(
        &mut self,
        _: usize,
        _: usize,
        loan: NodeLoan<'v, T, L, Lv, B>,
        _: &mut Context<'_>,
    ) -> Result<CallStep<RequestOf<L>>, NodeLoan<'v, T, L, Lv, B>> {
        Err(loan)
    }
}
impl<T, L, Lv, B, X, Xs> PollAt<T, L, Lv, B> for HCons<CallSlot<X>, Xs>
where
    T: ConnectionChoices,
    for<'v> L: LineageLists<'v, T>,
    Lv: LayerLineage,
    B: CallBundle,
    X: NodeCall<T, L, Lv, B>,
    Xs: PollAt<T, L, Lv, B> + CallCount,
{
    #[inline(always)]
    fn try_poll<'v>(
        &mut self,
        r: usize,
        after: usize,
        loan: NodeLoan<'v, T, L, Lv, B>,
        cx: &mut Context<'_>,
    ) -> Result<CallStep<RequestOf<L>>, NodeLoan<'v, T, L, Lv, B>> {
        if r != Xs::COUNT + after {
            return self.tail.try_poll(r, after, loan, cx);
        }
        let Some(call) = self.head.call.as_mut() else {
            return Ok(CallStep::Finished);
        };
        if X::no_longer_needed(&loan.lineage) {
            self.head.call = None;
            return Ok(CallStep::Finished);
        }
        let step = call.as_mut().poll_lent(loan, cx);
        if let CallStep::Finished = step {
            self.head.call = None;
        }
        Ok(step)
    }
}

/// The number of calls in a list of call slots.
pub trait CallCount {
    /// How many.
    const COUNT: usize;
}
impl CallCount for HNil {
    const COUNT: usize = 0;
}
impl<X, Xs: CallCount> CallCount for HCons<CallSlot<X>, Xs> {
    const COUNT: usize = 1 + Xs::COUNT;
}

/// Starting a part's calls in a new node of the layer `Lv`.
pub trait PartCalls<T: ConnectionChoices, L, Lv: LayerLineage, Hs>
where
    for<'v> L: LineageLists<'v, T>,
{
    /// The calls, for the bundle `B`.
    type Calls<B: CallBundle>: PollAt<T, L, Lv, B> + CallCount;
    /// How many calls.
    const LEN: usize;
    /// Start every call.
    fn start_all<B: CallBundle>(args: &ArgsOf<L, Lv>) -> Self::Calls<B>;
    /// What each call reads, in order.
    fn reads(out: &mut Vec<ReadSet>);
}
impl<T: ConnectionChoices, L, Lv: LayerLineage> PartCalls<T, L, Lv, HNil> for HNil
where
    for<'v> L: LineageLists<'v, T>,
{
    type Calls<B: CallBundle> = HNil;
    const LEN: usize = 0;
    fn start_all<B: CallBundle>(_: &ArgsOf<L, Lv>) -> HNil {
        HNil
    }
    fn reads(_: &mut Vec<ReadSet>) {}
}
impl<T: ConnectionChoices, L, Lv: LayerLineage, K, Ks, H, Hs> PartCalls<T, L, Lv, HCons<H, Hs>>
    for HCons<K, Ks>
where
    for<'v> L: LineageLists<'v, T>,
    K: CallKind<T, L, Lv, H>,
    Ks: PartCalls<T, L, Lv, Hs>,
{
    type Calls<B: CallBundle> = HCons<CallSlot<K::Call<B>>, Ks::Calls<B>>;
    const LEN: usize = 1 + Ks::LEN;
    fn start_all<B: CallBundle>(args: &ArgsOf<L, Lv>) -> Self::Calls<B> {
        HCons {
            head: CallSlot {
                call: Some(Box::pin(K::start::<B>(args))),
            },
            tail: Ks::start_all::<B>(args),
        }
    }
    fn reads(out: &mut Vec<ReadSet>) {
        let mut reads = ReadSet::default();
        K::reads(&mut reads);
        out.push(reads);
        Ks::reads(out);
    }
}

/// The calls of a node of the layer `Lv`: every part's, in the order of the
/// list.
pub trait NodeCalls<T: ConnectionChoices, L, Lv: LayerLineage, Hss>
where
    for<'v> L: LineageLists<'v, T>,
{
    /// The calls, for the bundle `B`.
    type Calls<B: CallBundle>;
    /// How many calls a node has.
    const LEN: usize;
    /// Start every call.
    fn start_all<B: CallBundle>(args: &ArgsOf<L, Lv>) -> Self::Calls<B>;
    /// What each call reads, in order.
    fn reads(out: &mut Vec<ReadSet>);
    /// Poll the call at `r` from the end.
    fn poll_from_end<'v, B: CallBundle>(
        calls: &mut Self::Calls<B>,
        r: usize,
        loan: NodeLoan<'v, T, L, Lv, B>,
        cx: &mut Context<'_>,
    ) -> CallStep<RequestOf<L>>;
}
impl<T: ConnectionChoices, L, Lv: LayerLineage> NodeCalls<T, L, Lv, HNil> for HNil
where
    for<'v> L: LineageLists<'v, T>,
{
    type Calls<B: CallBundle> = HNil;
    const LEN: usize = 0;
    fn start_all<B: CallBundle>(_: &ArgsOf<L, Lv>) -> HNil {
        HNil
    }
    fn reads(_: &mut Vec<ReadSet>) {}
    #[inline(always)]
    fn poll_from_end<'v, B: CallBundle>(
        _: &mut HNil,
        _: usize,
        _: NodeLoan<'v, T, L, Lv, B>,
        _: &mut Context<'_>,
    ) -> CallStep<RequestOf<L>> {
        unreachable!("a position beyond the node's calls")
    }
}
impl<T: ConnectionChoices, L, Lv: LayerLineage, P, Ps, Hs, Hss> NodeCalls<T, L, Lv, HCons<Hs, Hss>>
    for HCons<P, Ps>
where
    for<'v> L: LineageLists<'v, T>,
    P: LayerShare<T, L, Lv>,
    P::Calls: PartCalls<T, L, Lv, Hs>,
    Ps: NodeCalls<T, L, Lv, Hss>,
{
    type Calls<B: CallBundle> =
        HCons<<P::Calls as PartCalls<T, L, Lv, Hs>>::Calls<B>, Ps::Calls<B>>;
    const LEN: usize = <P::Calls as PartCalls<T, L, Lv, Hs>>::LEN + Ps::LEN;
    fn start_all<B: CallBundle>(args: &ArgsOf<L, Lv>) -> Self::Calls<B> {
        HCons {
            head: <P::Calls as PartCalls<T, L, Lv, Hs>>::start_all::<B>(args),
            tail: Ps::start_all::<B>(args),
        }
    }
    fn reads(out: &mut Vec<ReadSet>) {
        <P::Calls as PartCalls<T, L, Lv, Hs>>::reads(out);
        Ps::reads(out);
    }
    #[inline(always)]
    fn poll_from_end<'v, B: CallBundle>(
        calls: &mut Self::Calls<B>,
        r: usize,
        loan: NodeLoan<'v, T, L, Lv, B>,
        cx: &mut Context<'_>,
    ) -> CallStep<RequestOf<L>> {
        match calls.head.try_poll(r, Ps::LEN, loan, cx) {
            Ok(step) => step,
            Err(loan) => Ps::poll_from_end::<B>(&mut calls.tail, r, loan, cx),
        }
    }
}

/// What the calls of each layer infer their takes by, as one type with a
/// member for each layer.
pub trait CallPositions: 'static {
    /// The connection's calls.
    type Connection;
    /// An entry's calls.
    type LinkEntry;
    /// A logical path's calls.
    type LogicalPath;
    /// A link path's calls.
    type LinkPath;
    /// The established layer's calls.
    type Established;
    /// A recovery layer's calls.
    type Recovery;
}
impl<A: 'static, E: 'static, G: 'static, K: 'static, S: 'static, R: 'static> CallPositions
    for (A, E, G, K, S, R)
{
    type Connection = A;
    type LinkEntry = E;
    type LogicalPath = G;
    type LinkPath = K;
    type Established = S;
    type Recovery = R;
}

/// A list of parts with calls in every layer.
pub trait TreeCalls<T: ConnectionChoices, P: CallPositions>:
    PartList<T>
    + NodeCalls<T, Self, Connection, P::Connection>
    + NodeCalls<T, Self, LinkEntry, P::LinkEntry>
    + NodeCalls<T, Self, LogicalPath, P::LogicalPath>
    + NodeCalls<T, Self, LinkPath, P::LinkPath>
    + NodeCalls<T, Self, Established, P::Established>
    + NodeCalls<T, Self, Recovery, P::Recovery>
where
    for<'v> Self: LineageLists<'v, T>,
{
}
impl<T: ConnectionChoices, P: CallPositions, L> TreeCalls<T, P> for L
where
    for<'v> L: LineageLists<'v, T>,
    L: PartList<T>
        + NodeCalls<T, L, Connection, P::Connection>
        + NodeCalls<T, L, LinkEntry, P::LinkEntry>
        + NodeCalls<T, L, LogicalPath, P::LogicalPath>
        + NodeCalls<T, L, LinkPath, P::LinkPath>
        + NodeCalls<T, L, Established, P::Established>
        + NodeCalls<T, L, Recovery, P::Recovery>,
{
}

macro_rules! layer_calls {
    ($($(#[$doc:meta])* $name:ident: $layer:ident;)*) => {$(
        $(#[$doc])*
        pub struct $name<T: ConnectionChoices, L: TreeCalls<T, P>, P: CallPositions>(
            pub(crate) <L as NodeCalls<T, L, $layer, P::$layer>>::Calls<PartsCallBundle<T, L, P>>,
        )
        where
            for<'v> L: LineageLists<'v, T>;
    )*};
}
layer_calls! {
    /// The calls of the connection node of a composition.
    ConnectionCalls: Connection;
    /// The calls of a logical link entry of a composition.
    LinkEntryCalls: LinkEntry;
    /// The calls of a logical path of a composition.
    LogicalPathCalls: LogicalPath;
    /// The calls of a link path of a composition.
    LinkPathCalls: LinkPath;
    /// The calls of the established layer of a composition.
    EstablishedCalls: Established;
    /// The calls of a recovery layer of a composition.
    RecoveryCalls: Recovery;
}

/// The bundle of a composition: the calls of each layer, from the list of
/// parts.
#[allow(clippy::type_complexity)] // a marker of three type parameters
pub struct PartsCallBundle<T, L, P>(PhantomData<fn() -> (T, L, P)>);

impl<T: ConnectionChoices, L: TreeCalls<T, P>, P: CallPositions> CallBundle
    for PartsCallBundle<T, L, P>
where
    for<'v> L: LineageLists<'v, T>,
{
    type Connection = ConnectionCalls<T, L, P>;
    type LinkEntry = LinkEntryCalls<T, L, P>;
    type LogicalPath = LogicalPathCalls<T, L, P>;
    type LinkPath = LinkPathCalls<T, L, P>;
    type Established = EstablishedCalls<T, L, P>;
    type Recovery = RecoveryCalls<T, L, P>;
}
