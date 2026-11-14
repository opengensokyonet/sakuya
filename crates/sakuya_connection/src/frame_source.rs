//! Frame sources: what writes the planned content into a packet and takes
//! back what comes of it, and how the parts' frame sources make up the
//! sets each kind of packet carries.
//!
//! A frame source ([`FrameSource`]) gets one planned item at a time, with
//! an open packet of its class, and hands back what it holds afterwards;
//! each frame it writes leaves a summary in the packet's record, which
//! comes back to it when the packet is delivered or lost. Then it may
//! publish intents again through the publisher it is lent
//! ([`PublishIntent`]).
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

use sakuya_recovery::packet_number_space::PacketNumberSpaceKind;
use sakuya_wire::parts::{CNil, Coproduct, HCons, HNil};

use crate::{
    clock::{ConnectionChoices, InstantOf},
    send_strategy::{FrameSourceSet, PlannedPacketKind, SendIntentPart},
    take::Lineage,
    write::{
        ClassOfSource, FlightClassType, OpenPacket, PacketPosition, PacketWriting, SummaryOf,
        Supplied,
    },
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
    /// What it publishes when a frame of it is acknowledged or declared
    /// lost: intents sent and forgotten, with no ticket to keep;
    /// [`NoIntent`] when it publishes nothing.
    type Intent;

    /// Write content for `item` into `packet` and hand back what it holds
    /// afterwards.
    ///
    /// It is called only when the item's least room fits. Having written
    /// nothing, it has already updated or withdrawn the intent, so that the
    /// plan does not give it the same item again.
    fn supply<W, P>(
        &mut self,
        item: Self::Item<'_>,
        packet: OpenPacket<W, Self::Class, P>,
    ) -> Supplied<W, Self::Class, P>
    where
        W: PacketWriting,
        SummaryOf<W>: From<Self::Summary>,
        P: PacketPosition;

    /// The packet of `space` that a frame of `summary` was written into was
    /// acknowledged; `publish` takes what it publishes again.
    fn delivered<Pb, Idx>(
        &mut self,
        publish: &mut Pb,
        space: PacketNumberSpaceKind,
        summary: Self::Summary,
    ) where
        Pb: PublishIntent<Self::Intent, Idx>;

    /// The packet of `space` that a frame of `summary` was written into was
    /// declared lost, or its send result is unknown, or its link path ended
    /// before it was settled; `publish` takes what it publishes again.
    /// `summary` stays in the packet's record while it is kept, for a late
    /// acknowledgment.
    fn lost<Pb, Idx>(
        &mut self,
        publish: &mut Pb,
        space: PacketNumberSpaceKind,
        summary: &Self::Summary,
    ) where
        Pb: PublishIntent<Self::Intent, Idx>;
}

/// `Pb: PublishIntent<J, Idx>`: what a frame source is lent when its frames
/// come back takes intents `J`, sent and forgotten.
///
/// `Idx` is the place of `J` in the composition's sum of intents; the
/// compiler infers it.
pub trait PublishIntent<J, Idx> {
    /// Publish `intent`.
    fn publish(&mut self, intent: J);
}

/// The intents of a frame source that publishes nothing when its frames
/// come back: there are none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoIntent {}

/// The place of [`NoIntent`] in any sum of intents: there is none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nowhere {}

/// Anything takes the intents there are none of.
impl<Pb: ?Sized> PublishIntent<NoIntent, Nowhere> for Pb {
    fn publish(&mut self, intent: NoIntent) {
        match intent {}
    }
}

// ---- kinds of frame sources ----

/// A kind of frame source, as a type: what a part lists for each of its
/// frame sources. It gives the types of the source's items, summaries and
/// intents, apart from where the source is.
///
/// `I` in the summary is the type of instants of the composition's
/// choices, so that a summary can hold a deadline.
pub trait FrameSourceKind {
    /// One planned item of the source.
    type Item<'a>;
    /// The summary of one frame of the source.
    type Summary<I>;
    /// What the source publishes when its frames come back.
    type Intent;
}

/// How a frame source of this kind is found in a lineage: implemented by
/// the marker type of the kind.
///
/// `T` is the choices, `L` the composition's list of parts, `V` the list
/// of the lineage and `H` what the impl infers the positions of what it
/// finds by.
pub trait FindFrameSource<T: ConnectionChoices, L, V, H>: FrameSourceKind {
    /// The source, borrowing what it is made of from the lineage.
    type Source<'l, 'r>: for<'a> FrameSource<
            Item<'a> = Self::Item<'a>,
            Summary = Self::Summary<InstantOf<T>>,
            Intent = Self::Intent,
        >
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
/// summary of every kind; `Hs` holds the positions of each kind's impl.
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
        W::Attempt: sakuya_recovery::send_journals::PacketSendAttempt<Summary = S>,
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
        W::Attempt: sakuya_recovery::send_journals::PacketSendAttempt<Summary = S>,
        P: PacketPosition,
    {
        match item {}
    }
}

impl<T, L, V, S, K, Ks, H, Hs> SupplyFrameSources<T, L, V, S, HCons<H, Hs>> for HCons<K, Ks>
where
    T: ConnectionChoices,
    K: FindFrameSource<T, L, V, H>,
    Ks: SupplyFrameSources<T, L, V, S, Hs>,
    S: From<K::Summary<InstantOf<T>>>,
{
    fn supply<W, P>(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        item: Self::Items<'_>,
        packet: OpenPacket<W, ClassOfSource, P>,
    ) -> Supplied<W, ClassOfSource, P>
    where
        W: PacketWriting,
        W::Attempt: sakuya_recovery::send_journals::PacketSendAttempt<Summary = S>,
        P: PacketPosition,
    {
        match item {
            Coproduct::Inl(item) => K::find(lineage, now)
                .supply(item, packet.into_source_class())
                .into_class_of_source(),
            Coproduct::Inr(rest) => Ks::supply(lineage, now, rest, packet),
        }
    }
}

/// Handing a summary back to the frame source of its kind: implemented for
/// every list of kinds that implement [`FindFrameSource`], with a publisher
/// `Pb` that takes what each publishes.
///
/// `Hs` holds, for each kind, the positions of its impl and the place of
/// its intents.
pub trait FeedFrameSources<T: ConnectionChoices, L, V, Pb, Hs>: FrameSourceKinds {
    /// The packet of `space` that the frame of `summary` was written into
    /// was acknowledged; see [`FrameSource::delivered`].
    fn delivered(
        lineage: &mut Lineage<'_, V>,
        publish: &mut Pb,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: Self::Summaries<InstantOf<T>>,
    );

    /// The packet of `space` that the frame of `summary` was written into
    /// was declared lost; see [`FrameSource::lost`].
    fn lost(
        lineage: &mut Lineage<'_, V>,
        publish: &mut Pb,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: &Self::Summaries<InstantOf<T>>,
    );
}

impl<T: ConnectionChoices, L, V, Pb> FeedFrameSources<T, L, V, Pb, HNil> for HNil {
    fn delivered(
        _: &mut Lineage<'_, V>,
        _: &mut Pb,
        _: InstantOf<T>,
        _: PacketNumberSpaceKind,
        summary: CNil,
    ) {
        match summary {}
    }

    fn lost(
        _: &mut Lineage<'_, V>,
        _: &mut Pb,
        _: InstantOf<T>,
        _: PacketNumberSpaceKind,
        summary: &CNil,
    ) {
        match *summary {}
    }
}

impl<T, L, V, Pb, K, Ks, H, Idx, Hs> FeedFrameSources<T, L, V, Pb, HCons<(H, Idx), Hs>>
    for HCons<K, Ks>
where
    T: ConnectionChoices,
    K: FindFrameSource<T, L, V, H>,
    Ks: FeedFrameSources<T, L, V, Pb, Hs>,
    Pb: PublishIntent<K::Intent, Idx>,
{
    fn delivered(
        lineage: &mut Lineage<'_, V>,
        publish: &mut Pb,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: Self::Summaries<InstantOf<T>>,
    ) {
        match summary {
            Coproduct::Inl(summary) => {
                K::find(lineage, now).delivered::<Pb, Idx>(publish, space, summary);
            }
            Coproduct::Inr(rest) => Ks::delivered(lineage, publish, now, space, rest),
        }
    }

    fn lost(
        lineage: &mut Lineage<'_, V>,
        publish: &mut Pb,
        now: InstantOf<T>,
        space: PacketNumberSpaceKind,
        summary: &Self::Summaries<InstantOf<T>>,
    ) {
        match summary {
            Coproduct::Inl(summary) => {
                K::find(lineage, now).lost::<Pb, Idx>(publish, space, summary);
            }
            Coproduct::Inr(rest) => Ks::lost(lineage, publish, now, space, rest),
        }
    }
}

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
    /// [`PlannedPacketKind::SettlingResponse`] as a type.
    SettlingResponsePacket => SettlingResponse;
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
        W::Attempt: sakuya_recovery::send_journals::PacketSendAttempt<Summary = S>,
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
        W::Attempt: sakuya_recovery::send_journals::PacketSendAttempt<Summary = S>,
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
        W::Attempt: sakuya_recovery::send_journals::PacketSendAttempt<Summary = S>,
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
