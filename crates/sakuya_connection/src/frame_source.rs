//! Frame sources: what writes the planned content into a packet and takes
//! back what comes of it, and how the parts' frame sources make up the
//! sets each kind of packet carries.
//!
//! A frame source ([`FrameSource`]) gets one planned item at a time, with
//! an open packet of its class, and hands back what it holds afterwards;
//! each frame it writes leaves a summary in the packet's record, which
//! comes back to it when the packet is delivered or lost. An intent of it
//! that was refused, or that the strategy ended, comes back to it as
//! unfulfilled.
//!
//! What the driver's own components have to send is not published: each
//! part says what its components in a lineage have to send now
//! ([`DriverContentPart`]), and the list of parts gathers it
//! ([`DriverContentOf`]).
//!
//! A part lists the kinds of its frame sources ([`FrameSourceKind`], in
//! [`SendIntentPart::FrameSources`]); each kind says how its source is
//! found in a lineage ([`FindFrameSource`]). The items, the summaries and
//! the handing of an item or a summary to its source follow from the list
//! ([`FrameSourceKinds`], [`SupplyFrameSources`], [`FeedFrameSources`]).
//! Each part says, for each kind of packet ([`PacketKind`]), which of its
//! intents that packet may carry and as what item ([`FrameSourcePart`]);
//! the set of a composition is the sum of its parts' ([`PartsFrameSources`]),
//! with a part that has nothing for a kind of packet giving no items. The
//! filling hands an item to the part it belongs to
//! ([`PartsFrameSourceDispatch`]), which finds the frame source in the view
//! it is given and sets the packet's class to that source's.

use core::marker::PhantomData;
use sakuya_wire_v1::frame::write::FlightClassType;

use sakuya_recovery_v1::packet_number_space::PacketNumberSpaceKind;
use sakuya_stream_v1::send_options::destination::Unfulfilled;
use sakuya_wire::parts::{CNil, Coproduct, HCons, HNil};

use crate::{
    clock::{ConnectionChoices, InstantOf},
    feedback::InjectSummary,
    send_strategy::{
        DriverContent, FrameSourceSet, PlannedPacketKind, SendIntentPart, SendIntentsOf,
    },
    share::{LinkPathIdentifierOf, LogicalPathKeys},
    take::{AppendEach, Lineage, OptionalRefs},
    write::{ClassOfSource, OpenPacket, PacketPosition, PacketWriting, SummaryOf, Supplied},
};

/// What writes one kind of content into packets, and takes back what comes
/// of it.
pub trait FrameSource {
    /// What it hands back with each frame, for when the frame is
    /// acknowledged or declared lost.
    type Summary;
    /// Whether its content counts in the bytes in flight.
    type Class: FlightClassType;
    /// One planned item of it: which of its intents to supply.
    type Item<'a>;

    /// Write content for `item` into `packet` and hand back what it holds
    /// afterwards.
    ///
    /// It is called only when the item's least room fits. Having written
    /// nothing, it has already updated or withdrawn the intent, or changed
    /// its own state for content the driver gathers, so that the plan does
    /// not give it the same item again.
    ///
    /// `Idx` is the place of [`Self::Summary`](FrameSource::Summary) in the
    /// composition's sum of summaries; the compiler infers it.
    fn supply<W, P, Idx>(
        &mut self,
        item: Self::Item<'_>,
        packet: OpenPacket<W, Self::Class, P>,
    ) -> Supplied<W, Self::Class, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<Self::Summary, Idx>,
        P: PacketPosition;

    /// The packet of `space` that a frame of `summary` was written into was
    /// acknowledged.
    fn delivered(&mut self, space: PacketNumberSpaceKind, summary: Self::Summary);

    /// The packet of `space` that a frame of `summary` was written into was
    /// declared lost, or its send result is unknown, or its link path ended
    /// before it was settled. `summary` stays in the packet's record while
    /// it is kept, for a late acknowledgment.
    fn lost(&mut self, space: PacketNumberSpaceKind, summary: &Self::Summary);

    /// An intent of this source, the one `item` stands for, was not
    /// fulfilled for `cause`: its publishing was refused, or the strategy
    /// ended it after taking it. The end of the layer the source lives on is
    /// not one; the source learns of it otherwise.
    fn unfulfilled(&mut self, item: Self::Item<'_>, cause: Unfulfilled);
}

/// A frame source borrowed is that frame source: what a kind of frame
/// source finds inside a component is borrowed from it.
impl<S: FrameSource + ?Sized> FrameSource for &mut S {
    type Summary = S::Summary;
    type Class = S::Class;
    type Item<'a> = S::Item<'a>;

    fn supply<W, P, Idx>(
        &mut self,
        item: Self::Item<'_>,
        packet: OpenPacket<W, Self::Class, P>,
    ) -> Supplied<W, Self::Class, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<Self::Summary, Idx>,
        P: PacketPosition,
    {
        (**self).supply::<W, P, Idx>(item, packet)
    }

    fn delivered(&mut self, space: PacketNumberSpaceKind, summary: Self::Summary) {
        (**self).delivered(space, summary);
    }

    fn lost(&mut self, space: PacketNumberSpaceKind, summary: &Self::Summary) {
        (**self).lost(space, summary);
    }

    fn unfulfilled(&mut self, item: Self::Item<'_>, cause: Unfulfilled) {
        (**self).unfulfilled(item, cause);
    }
}

// ---- kinds of frame sources ----

/// A kind of frame source, as a type: what a part lists for each of its
/// frame sources. It gives the types of the source's items and summaries,
/// apart from where the source is.
///
/// `I` in the summary is the type of instants of the composition's
/// choices, so that a summary can hold a deadline.
pub trait FrameSourceKind {
    /// One planned item of the source.
    type Item<'a>;
    /// The summary of one frame of the source.
    type Summary<I>;
    /// The kind whose source the summaries and the unfulfilled intents of
    /// this kind go back to ([`FeedFrameSources`]): by default the kind
    /// itself. A kind whose source is found only in the lineages it writes
    /// in, and whose frames need nothing when they come back, names
    /// [`IgnoredFeedback`] of itself, which is found in any lineage.
    type Feedback: FrameSourceKind + ?Sized = Self;
}

/// The kind whose source takes the summaries and unfulfilled intents of
/// the kind `K` and does nothing with them (`IgnoredFeedback`): the
/// [`Feedback`](FrameSourceKind::Feedback) of a kind whose frames need
/// nothing when they are acknowledged or lost, such as a probe's PING.
#[derive(Debug)]
pub struct IgnoredFeedback<K>(PhantomData<fn() -> K>);

impl<K: FrameSourceKind> FrameSourceKind for IgnoredFeedback<K> {
    type Item<'a> = K::Item<'a>;
    type Summary<I> = K::Summary<I>;
}

/// The source of [`IgnoredFeedback`]: it writes nothing, and nothing is
/// done when a frame of its kind comes back.
#[derive(Debug)]
pub struct IgnoringFrameSource<K, I>(PhantomData<fn() -> (K, I)>);

impl<K: FrameSourceKind, I> FrameSource for IgnoringFrameSource<K, I> {
    type Summary = K::Summary<I>;
    type Class = sakuya_wire_v1::frame::write::InFlightClass;
    type Item<'a> = K::Item<'a>;

    fn supply<W, P, Idx>(
        &mut self,
        _: Self::Item<'_>,
        packet: OpenPacket<W, Self::Class, P>,
    ) -> Supplied<W, Self::Class, P>
    where
        W: PacketWriting,
        SummaryOf<W>: InjectSummary<Self::Summary, Idx>,
        P: PacketPosition,
    {
        Supplied::Open(packet)
    }

    fn delivered(&mut self, _: PacketNumberSpaceKind, _: Self::Summary) {}

    fn lost(&mut self, _: PacketNumberSpaceKind, _: &Self::Summary) {}

    fn unfulfilled(&mut self, _: Self::Item<'_>, _: Unfulfilled) {}
}

impl<T: ConnectionChoices, L, V, K: FrameSourceKind> FindFrameSource<T, L, V, ()>
    for IgnoredFeedback<K>
{
    type Source<'l, 'r>
        = IgnoringFrameSource<K, InstantOf<T>>
    where
        V: 'l,
        'r: 'l;

    fn find<'l, 'r>(_: &'l mut Lineage<'r, V>, _: InstantOf<T>) -> Self::Source<'l, 'r> {
        IgnoringFrameSource(PhantomData)
    }
}

/// How a frame source of this kind is found in a lineage: implemented by
/// the marker type of the kind.
///
/// `T` is the choices, `L` the composition's list of parts, `V` the list
/// of the lineage and `H` what the impl infers the positions of what it
/// finds by.
pub trait FindFrameSource<T: ConnectionChoices, L, V, H>: FrameSourceKind {
    /// The source, borrowing what it is made of from the lineage.
    type Source<'l, 'r>: for<'a> FrameSource<Item<'a> = Self::Item<'a>, Summary = Self::Summary<InstantOf<T>>>
    where
        V: 'l,
        'r: 'l;

    /// The source in `lineage` at `now`.
    fn find<'l, 'r>(lineage: &'l mut Lineage<'r, V>, now: InstantOf<T>) -> Self::Source<'l, 'r>;
}

/// The kinds of frame sources a part lists: a list of
/// [`FrameSourceKind`]s, `HNil` when it has none.
pub trait FrameSourceKinds {
    /// One item of any of the sources: the sum of their items, in the order
    /// of the list.
    type Items<'a>;
    /// The summary of one frame of any of the sources: the sum of their
    /// summaries, in the order of the list.
    type Summaries<I>;
}

impl FrameSourceKinds for HNil {
    type Items<'a> = CNil;
    type Summaries<I> = CNil;
}

impl<K: FrameSourceKind, Ks: FrameSourceKinds> FrameSourceKinds for HCons<K, Ks> {
    type Items<'a> = Coproduct<K::Item<'a>, Ks::Items<'a>>;
    type Summaries<I> = Coproduct<K::Summary<I>, Ks::Summaries<I>>;
}

/// The items of the frame sources the part `P` lists.
pub type FrameSourceItemsOf<'a, P> =
    <<P as SendIntentPart>::FrameSources as FrameSourceKinds>::Items<'a>;

/// Handing an item to the frame source of its kind: implemented for every
/// list of kinds that implement [`FindFrameSource`].
///
/// `S` is the summary of the composition's send attempts, which takes the
/// summary of every kind; `Hs` holds, for each kind, the positions of its
/// impl and the place of its summary in `S`.
pub trait SupplyFrameSources<T: ConnectionChoices, L, V, S, Hs>: FrameSourceKinds {
    /// Give `item` to its frame source in `lineage` at `now`, setting the
    /// packet's class to that source's, and hand back what the source
    /// handed back.
    fn supply<W, P>(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        item: Self::Items<'_>,
        packet: OpenPacket<W, ClassOfSource, P>,
    ) -> Supplied<W, ClassOfSource, P>
    where
        W: PacketWriting,
        W::Attempt: sakuya_recovery_v1::send_journals::PacketSendAttempt<Summary = S>,
        P: PacketPosition;
}

impl<T: ConnectionChoices, L, V, S> SupplyFrameSources<T, L, V, S, HNil> for HNil {
    fn supply<W, P>(
        _: &mut Lineage<'_, V>,
        _: InstantOf<T>,
        item: CNil,
        _: OpenPacket<W, ClassOfSource, P>,
    ) -> Supplied<W, ClassOfSource, P>
    where
        W: PacketWriting,
        W::Attempt: sakuya_recovery_v1::send_journals::PacketSendAttempt<Summary = S>,
        P: PacketPosition,
    {
        match item {}
    }
}

impl<T, L, V, S, K, Ks, H, Ix, Hs> SupplyFrameSources<T, L, V, S, HCons<(H, Ix), Hs>>
    for HCons<K, Ks>
where
    T: ConnectionChoices,
    K: FindFrameSource<T, L, V, H>,
    Ks: SupplyFrameSources<T, L, V, S, Hs>,
    S: InjectSummary<K::Summary<InstantOf<T>>, Ix>,
{
    fn supply<W, P>(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        item: Self::Items<'_>,
        packet: OpenPacket<W, ClassOfSource, P>,
    ) -> Supplied<W, ClassOfSource, P>
    where
        W: PacketWriting,
        W::Attempt: sakuya_recovery_v1::send_journals::PacketSendAttempt<Summary = S>,
        P: PacketPosition,
    {
        match item {
            Coproduct::Inl(item) => K::find(lineage, now)
                .supply::<_, _, Ix>(item, packet.into_source_class())
                .into_class_of_source(),
            Coproduct::Inr(rest) => Ks::supply(lineage, now, rest, packet),
        }
    }
}

/// Handing a summary back to the frame source of its kind: implemented for
/// every list of kinds that implement [`FindFrameSource`].
///
/// `Hs` holds, for each kind, the positions of its impl.
pub trait FeedFrameSources<T: ConnectionChoices, L, V, Hs>: FrameSourceKinds {
    /// The packet of `space` that the frame of `summary` was written into
    /// was acknowledged; see [`FrameSource::delivered`].
    fn delivered(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: Self::Summaries<InstantOf<T>>,
    );

    /// The packet of `space` that the frame of `summary` was written into
    /// was declared lost; see [`FrameSource::lost`].
    fn lost(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: &Self::Summaries<InstantOf<T>>,
    );

    /// The intent that `item` stands for was not fulfilled for `cause`;
    /// see [`FrameSource::unfulfilled`].
    fn unfulfilled(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        item: Self::Items<'_>,
        cause: Unfulfilled,
    );
}

impl<T: ConnectionChoices, L, V> FeedFrameSources<T, L, V, HNil> for HNil {
    fn delivered(_: &mut Lineage<'_, V>, _: InstantOf<T>, _: PacketNumberSpaceKind, summary: CNil) {
        match summary {}
    }

    fn lost(_: &mut Lineage<'_, V>, _: InstantOf<T>, _: PacketNumberSpaceKind, summary: &CNil) {
        match *summary {}
    }

    fn unfulfilled(_: &mut Lineage<'_, V>, _: InstantOf<T>, item: CNil, _: Unfulfilled) {
        match item {}
    }
}

impl<T, L, V, K, Ks, H, Hs> FeedFrameSources<T, L, V, HCons<H, Hs>> for HCons<K, Ks>
where
    T: ConnectionChoices,
    K: FrameSourceKind,
    K::Feedback: for<'a> FindFrameSource<
            T,
            L,
            V,
            H,
            Item<'a> = K::Item<'a>,
            Summary<InstantOf<T>> = K::Summary<InstantOf<T>>,
        >,
    Ks: FeedFrameSources<T, L, V, Hs>,
{
    fn delivered(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: Self::Summaries<InstantOf<T>>,
    ) {
        match summary {
            Coproduct::Inl(summary) => {
                K::Feedback::find(lineage, now).delivered(space, summary);
            }
            Coproduct::Inr(rest) => Ks::delivered(lineage, now, space, rest),
        }
    }

    fn lost(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: &Self::Summaries<InstantOf<T>>,
    ) {
        match summary {
            Coproduct::Inl(summary) => {
                K::Feedback::find(lineage, now).lost(space, summary);
            }
            Coproduct::Inr(rest) => Ks::lost(lineage, now, space, rest),
        }
    }

    fn unfulfilled(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        item: Self::Items<'_>,
        cause: Unfulfilled,
    ) {
        match item {
            Coproduct::Inl(item) => K::Feedback::find(lineage, now).unfulfilled(item, cause),
            Coproduct::Inr(rest) => Ks::unfulfilled(lineage, now, rest, cause),
        }
    }
}

// ---- what the driver's own components have to send ----

/// What one part's own components have to send on a link path at this
/// moment (`DriverContentPart`), read from a lineage: implemented by the
/// marker type of the part. A part whose content is all published through
/// the intake has none.
///
/// `T` is the choices, `L` the composition's list of parts, `V` the list
/// of the lineage and `H` what the impl infers the positions of what it
/// reads by.
pub trait DriverContentPart<T: ConnectionChoices, L: LogicalPathKeys, V, H>:
    SendIntentPart
{
    /// Put what the part's components in `lineage` have to send on
    /// `link_path` now into `out`: each intent made a value of the
    /// composition's sum by `inject`, and the facts of the link path's
    /// sealed close packet if the part keeps it.
    fn pending<J>(
        lineage: &Lineage<'_, V>,
        link_path: &LinkPathIdentifierOf<T, L>,
        out: &mut DriverContent<J>,
        inject: impl Fn(Self::SendIntents) -> J,
    );
}

/// What the own components of a list of parts have to send on a link path
/// at this moment, part by part ([`DriverContentPart`]); `Hs` holds, for
/// each part, the positions of its impl.
pub trait DriverContentOf<T: ConnectionChoices, L: LogicalPathKeys, V, Hs>: SendIntentsOf {
    /// Put what every part's components in `lineage` have to send on
    /// `link_path` now into `out`, each intent made a value of `J` by
    /// `inject`.
    fn pending<J>(
        lineage: &Lineage<'_, V>,
        link_path: &LinkPathIdentifierOf<T, L>,
        out: &mut DriverContent<J>,
        inject: impl Fn(Self::SendIntents) -> J,
    );
}

impl<T: ConnectionChoices, L: LogicalPathKeys, V> DriverContentOf<T, L, V, HNil> for HNil {
    fn pending<J>(
        _: &Lineage<'_, V>,
        _: &LinkPathIdentifierOf<T, L>,
        _: &mut DriverContent<J>,
        _: impl Fn(CNil) -> J,
    ) {
    }
}

impl<T, L, V, P, Ps, H, Hs> DriverContentOf<T, L, V, HCons<H, Hs>> for HCons<P, Ps>
where
    T: ConnectionChoices,
    L: LogicalPathKeys,
    P: DriverContentPart<T, L, V, H>,
    Ps: DriverContentOf<T, L, V, Hs>,
{
    fn pending<J>(
        lineage: &Lineage<'_, V>,
        link_path: &LinkPathIdentifierOf<T, L>,
        out: &mut DriverContent<J>,
        inject: impl Fn(Self::SendIntents) -> J,
    ) {
        P::pending(lineage, link_path, out, |intent| {
            inject(Coproduct::Inl(intent))
        });
        Ps::pending(lineage, link_path, out, |rest| inject(Coproduct::Inr(rest)));
    }
}

// ---- what the frame sources find of the established layer ----

/// The components of the established layer the part's frame sources find in
/// a lineage (`EstablishedSourceComponentsPart`): a list of component
/// types, `HNil` when they find none there.
///
/// The established layer is no node of a link path's or a logical path's
/// lineage; a lend that hands frames or their summaries to frame sources
/// borrows the components of the whole composition from it and appends
/// them to the lineage, each as a borrow that is `None` while there is no
/// such layer ([`OptionalRefs`]).
///
/// `T` is the choices of the composition, `L` the full list of parts.
pub trait EstablishedSourceComponentsPart<T, L> {
    /// The component types, in the order they are appended.
    type Components;
}

/// The components of the established layer the frame sources of a list of
/// parts find in a lineage: each part's, joined in the order of the list
/// ([`EstablishedSourceComponentsPart`]). `L` is the full list of parts.
///
/// It is implemented for `HNil` and for `HCons<P, Ps>` of a part `P` and a
/// list of parts `Ps`.
pub trait EstablishedSourceComponentsOf<T, L> {
    /// The component types, in the order they are appended.
    type Components: OptionalRefs;
}

impl<T, L> EstablishedSourceComponentsOf<T, L> for HNil {
    type Components = HNil;
}

impl<T, L, P, Ps> EstablishedSourceComponentsOf<T, L> for HCons<P, Ps>
where
    P: EstablishedSourceComponentsPart<T, L>,
    Ps: EstablishedSourceComponentsOf<T, L>,
    P::Components: AppendEach<Ps::Components>,
    <P::Components as AppendEach<Ps::Components>>::Out: OptionalRefs,
{
    type Components = <P::Components as AppendEach<Ps::Components>>::Out;
}

/// The components of the established layer the frame sources of the list
/// of parts `L` of the choices `T` find in a lineage.
pub type EstablishedSourceComponentsOfParts<T, L> =
    <L as EstablishedSourceComponentsOf<T, L>>::Components;

// ---- kinds of packets ----

/// A kind of packet, as a type.
pub trait PacketKind: 'static {
    /// The kind.
    const KIND: PlannedPacketKind;
}

macro_rules! packet_kinds {
    ($($(#[$doc:meta])* $name:ident => $kind:ident;)*) => {$(
        $(#[$doc])*
        #[derive(Debug)]
        pub enum $name {}

        impl PacketKind for $name {
            const KIND: PlannedPacketKind = PlannedPacketKind::$kind;
        }
    )*};
}

packet_kinds! {
    /// [`PlannedPacketKind::Initial`] as a type.
    InitialPacket => Initial;
    /// [`PlannedPacketKind::Handshake`] as a type.
    HandshakePacket => Handshake;
    /// [`PlannedPacketKind::ZeroRtt`] as a type.
    ZeroRttPacket => ZeroRtt;
    /// [`PlannedPacketKind::OneRtt`] as a type.
    OneRttPacket => OneRtt;
    /// [`PlannedPacketKind::OneRttProbe`] as a type.
    OneRttProbePacket => OneRttProbe;
    /// [`PlannedPacketKind::SettlingProbe`] as a type.
    SettlingProbePacket => SettlingProbe;
}

// ---- one part's sources for a kind of packet ----

/// Which of one part's intents a packet of kind `K` may carry, and as what
/// item of the part's frame sources. Implemented by the marker type of the
/// part; a part with nothing for `K` gives no items.
pub trait FrameSourcePart<K: PacketKind>: SendIntentPart {
    /// The item for `intent`, if `K` may carry it.
    fn item(intent: &Self::SendIntents) -> Option<FrameSourceItemsOf<'_, Self>>;

    /// The frame source of `item`.
    fn source(item: &FrameSourceItemsOf<'_, Self>) -> Self::FrameSourceId;
}

/// The frame sources of the parts `L` for packets of kind `K`.
#[derive(Debug)]
pub struct PartsFrameSources<K, L>(PhantomData<fn() -> (K, L)>);

impl<K: PacketKind> FrameSourceSet for PartsFrameSources<K, HNil> {
    type Intents = CNil;
    type FrameSourceId = CNil;
    type Item<'a> = CNil;

    fn item(intent: &CNil) -> Option<CNil> {
        match *intent {}
    }

    fn source(item: &CNil) -> CNil {
        match *item {}
    }
}

impl<K: PacketKind, P, Ps> FrameSourceSet for PartsFrameSources<K, HCons<P, Ps>>
where
    P: FrameSourcePart<K>,
    PartsFrameSources<K, Ps>: FrameSourceSet,
{
    type Intents = Coproduct<P::SendIntents, <PartsFrameSources<K, Ps> as FrameSourceSet>::Intents>;
    type FrameSourceId =
        Coproduct<P::FrameSourceId, <PartsFrameSources<K, Ps> as FrameSourceSet>::FrameSourceId>;
    type Item<'a> = Coproduct<
        FrameSourceItemsOf<'a, P>,
        <PartsFrameSources<K, Ps> as FrameSourceSet>::Item<'a>,
    >;

    fn item(intent: &Self::Intents) -> Option<Self::Item<'_>> {
        match intent {
            Coproduct::Inl(intent) => P::item(intent).map(Coproduct::Inl),
            Coproduct::Inr(rest) => {
                <PartsFrameSources<K, Ps> as FrameSourceSet>::item(rest).map(Coproduct::Inr)
            }
        }
    }

    fn source(item: &Self::Item<'_>) -> Self::FrameSourceId {
        match item {
            Coproduct::Inl(item) => Coproduct::Inl(P::source(item)),
            Coproduct::Inr(rest) => {
                Coproduct::Inr(<PartsFrameSources<K, Ps> as FrameSourceSet>::source(rest))
            }
        }
    }
}

// ---- handing an item to its part ----

/// Handing an item of a list of parts to the frame source it belongs to,
/// among those its part lists.
///
/// It is implemented for every list whose parts' lists of frame sources
/// implement [`SupplyFrameSources`]; `T` is the choices, `L` the whole
/// composition, `V` the list of the lineage the sending call finds the
/// frame sources in, `S` the summary of the composition's send attempts,
/// and `Hs` the positions of each part's impl.
pub trait PartsFrameSourceDispatch<T: ConnectionChoices, L, K: PacketKind, V, S, Hs>:
    Sized
where
    PartsFrameSources<K, Self>: FrameSourceSet,
{
    /// Give `item` to its frame source in `lineage` at `now`, setting the
    /// packet's class to that source's, and hand back what the source
    /// handed back.
    fn supply<W, P>(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        item: <PartsFrameSources<K, Self> as FrameSourceSet>::Item<'_>,
        packet: OpenPacket<W, ClassOfSource, P>,
    ) -> Supplied<W, ClassOfSource, P>
    where
        W: PacketWriting,
        W::Attempt: sakuya_recovery_v1::send_journals::PacketSendAttempt<Summary = S>,
        P: PacketPosition;
}

impl<T: ConnectionChoices, L, K: PacketKind, V, S> PartsFrameSourceDispatch<T, L, K, V, S, HNil>
    for HNil
{
    fn supply<W, P>(
        _: &mut Lineage<'_, V>,
        _: InstantOf<T>,
        item: CNil,
        _: OpenPacket<W, ClassOfSource, P>,
    ) -> Supplied<W, ClassOfSource, P>
    where
        W: PacketWriting,
        W::Attempt: sakuya_recovery_v1::send_journals::PacketSendAttempt<Summary = S>,
        P: PacketPosition,
    {
        match item {}
    }
}

impl<T: ConnectionChoices, L, K: PacketKind, V, S, P, Ps, H, Hs>
    PartsFrameSourceDispatch<T, L, K, V, S, HCons<H, Hs>> for HCons<P, Ps>
where
    P: FrameSourcePart<K>,
    P::FrameSources: SupplyFrameSources<T, L, V, S, H>,
    Ps: PartsFrameSourceDispatch<T, L, K, V, S, Hs>,
    PartsFrameSources<K, Ps>: FrameSourceSet,
{
    fn supply<W, Q>(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        item: <PartsFrameSources<K, Self> as FrameSourceSet>::Item<'_>,
        packet: OpenPacket<W, ClassOfSource, Q>,
    ) -> Supplied<W, ClassOfSource, Q>
    where
        W: PacketWriting,
        W::Attempt: sakuya_recovery_v1::send_journals::PacketSendAttempt<Summary = S>,
        Q: PacketPosition,
    {
        match item {
            Coproduct::Inl(item) => <P::FrameSources as SupplyFrameSources<T, L, V, S, H>>::supply(
                lineage, now, item, packet,
            ),
            Coproduct::Inr(rest) => Ps::supply(lineage, now, rest, packet),
        }
    }
}
