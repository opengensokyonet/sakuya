//! Frame sources: what writes the planned content into a packet, and how
//! the parts' frame sources make up the sets each kind of packet carries.
//!
//! A frame source ([`FrameSource`]) gets one planned item at a time, with
//! an open packet of its class, and hands back what it holds afterwards.
//! Each part says, for each kind of packet ([`PacketKind`]), which of its
//! intents that packet may carry and as what item ([`FrameSourcePart`]);
//! the set of a composition is the sum of its parts' ([`PartsFrameSources`]),
//! with a part that has nothing for a kind of packet giving no items. The
//! filling hands an item to the part it belongs to ([`FrameSourceDispatch`],
//! summed over the list by [`PartsFrameSourceDispatch`]); the part finds the
//! frame source in the view it is given and sets the packet's class to that
//! source's.

use core::marker::PhantomData;

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

/// What writes one kind of content into packets.
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
/// item. Implemented by the marker type of the part; a part with nothing
/// for `K` gives an item type without values and no items.
pub trait FrameSourcePart<K: PacketKind>: SendIntentPart {
    /// One item: one intent of one of the part's frame sources that `K`
    /// may carry, borrowed.
    type Item<'a>;

    /// The item for `intent`, if `K` may carry it.
    fn item(intent: &Self::SendIntents) -> Option<Self::Item<'_>>;

    /// The frame source of `item`.
    fn source(item: &Self::Item<'_>) -> Self::FrameSourceId;
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
    type Item<'a> = Coproduct<P::Item<'a>, <PartsFrameSources<K, Ps> as FrameSourceSet>::Item<'a>>;

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

/// Handing an item of one part to its frame source: implemented by the
/// marker type of the part, for packets of kind `K`.
///
/// `T` is the choices, `V` the list of the lineage the sending call finds
/// the frame sources in, `S` the summary of the composition's send
/// attempts, and `H` what the impl infers the positions of what it takes
/// by.
pub trait FrameSourceDispatch<T: ConnectionChoices, K: PacketKind, V, S, H>:
    FrameSourcePart<K>
{
    /// Give `item` to its frame source in `lineage` at `now`, setting the
    /// packet's class to that source's, and hand back what the source
    /// handed back.
    fn supply<W, P>(
        lineage: &mut Lineage<'_, V>,
        now: InstantOf<T>,
        item: Self::Item<'_>,
        packet: OpenPacket<W, ClassOfSource, P>,
    ) -> Supplied<W, ClassOfSource, P>
    where
        W: PacketWriting,
        W::Attempt: sakuya_recovery::send_journals::PacketSendAttempt<Summary = S>,
        P: PacketPosition;
}

/// Handing an item of a list of parts to the part it belongs to.
///
/// It is implemented for every list whose parts implement
/// [`FrameSourceDispatch`]; `Hs` holds the positions of each part's impl.
pub trait PartsFrameSourceDispatch<T: ConnectionChoices, K: PacketKind, V, S, Hs>: Sized
where
    PartsFrameSources<K, Self>: FrameSourceSet,
{
    /// Give `item` to the part it belongs to.
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

impl<T: ConnectionChoices, K: PacketKind, V, S> PartsFrameSourceDispatch<T, K, V, S, HNil>
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

impl<T: ConnectionChoices, K: PacketKind, V, S, P, Ps, H, Hs>
    PartsFrameSourceDispatch<T, K, V, S, HCons<H, Hs>> for HCons<P, Ps>
where
    P: FrameSourceDispatch<T, K, V, S, H>,
    Ps: PartsFrameSourceDispatch<T, K, V, S, Hs>,
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
            Coproduct::Inl(item) => P::supply(lineage, now, item, packet),
            Coproduct::Inr(rest) => Ps::supply(lineage, now, rest, packet),
        }
    }
}
