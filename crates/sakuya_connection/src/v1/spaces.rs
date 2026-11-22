//! What a logical path keeps for each packet number space: its packet
//! number state, its receive journals, its ACK obligation and its send
//! journals.
//!
//! Each is one component of [`PacketNumberSpaces`]: the value for a space
//! does not know which space it is. A space exists until its keys are
//! discarded, so a logical path built after the Initial or Handshake keys
//! are discarded has no such space.
//!
//! The send journals record each packet sent with the feedback summaries
//! of its frames, until it is acknowledged, or declared lost and its
//! retention ended.

use crate::v1::common_choices::V1Choices;
use crate::v1::state_choices::{StateChoices, StateHostChoices};
use core::time::Duration;

use sakuya_recovery_v1::{
    ack_obligation::AckObligation,
    loss::LossThresholds,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaceState, PacketNumberSpaces},
    receive_journals::ReceiveJournals,
};
use sakuya_wire::parts::Selector;
use sakuya_wire_v1::encryption_level::EncryptionLevel;
use sakuya_wire_v1::parameters::ParametersOf;
use sakuya_wire_v1::transport_parameters::{
    TransportParameterSlots, TransportParameterSpace, integer::MaxAckDelay,
};

use crate::v1::AckObligationOf;
use crate::{
    call::CallBundle,
    clock::InstantOf,
    component::{
        ArgsOf, Build, DataComponent, LineageOf, ParentsOf, PassiveDataComponent, RequestOf,
    },
    component_event::Happened,
    feedback::{FeedbackSummariesOf, FeedbackSummaryOf},
    layer,
    others::OtherNodes,
    share::{LineageLists, LineagePartList, LinkPathIdentifierOf},
    take::{GetAt, Lineage},
};

use super::{
    Choices,
    component_events::AckPendingChanged,
    first_flight::FirstFlightStart,
    keys::{HandshakeKeys, InitialKeys},
    parameters::{LocalTransportParameters, PeerTransportParameters},
};

/// The ACK obligations of a logical path, of the type the choices `T`
/// give.
pub type AckObligationsOf<T> = PacketNumberSpaces<AckObligationOf<T>>;

/// Where the ACK obligations are among a logical path's components.
#[derive(Debug)]
pub struct ChosenAckObligation;

/// The send journals of a logical path, of the type the choices `T` give,
/// for the summaries and the link paths of the list of parts `L`.
pub type SendJournalsOf<T, L> = PacketNumberSpaces<
    <<T as V1Choices>::Host as StateHostChoices<T>>::SendJournals<
        FeedbackSummaryOf<T, L>,
        LinkPathIdentifierOf<T, L>,
    >,
>;

/// Where the send journals are among a logical path's components.
#[derive(Debug)]
pub struct ChosenSendJournals;

/// The `max_ack_delay` a peer assumes when the parameter is absent (RFC
/// 9000 §18.2): 25 ms.
pub const DEFAULT_MAX_ACK_DELAY: Duration = Duration::from_millis(25);

/// A value for each space whose keys are not discarded in the connection
/// above: the Application Data space always.
pub(super) fn live_spaces<T, V, Ii, Ih, X>(
    parents: &Lineage<'_, V>,
    mut make: impl FnMut(PacketNumberSpaceKind) -> X,
) -> PacketNumberSpaces<X>
where
    T: StateChoices,
    V: GetAt<InitialKeys<T::Crypto>, Ii> + GetAt<HandshakeKeys<T::Crypto>, Ih>,
{
    let initial = !matches!(
        parents.get::<InitialKeys<T::Crypto>, Ii>(),
        InitialKeys::Discarded
    );
    let handshake = !matches!(
        parents.get::<HandshakeKeys<T::Crypto>, Ih>(),
        HandshakeKeys::Discarded
    );
    PacketNumberSpaces {
        initial: initial.then(|| make(PacketNumberSpaceKind::Initial)),
        handshake: handshake.then(|| make(PacketNumberSpaceKind::Handshake)),
        application_data: make(PacketNumberSpaceKind::ApplicationData),
    }
}

/// The `max_ack_delay` among version 1's transport parameters: its default
/// when absent.
fn max_ack_delay<S: Selector<Option<MaxAckDelay>, I>, I>(slots: &S) -> Duration {
    slots
        .get()
        .as_ref()
        .map_or(DEFAULT_MAX_ACK_DELAY, |delay: &MaxAckDelay| {
            Duration::from_millis(delay.get().get())
        })
}

/// The peer's `max_ack_delay` once its transport parameters are known: its
/// default when absent; `None` while they are not known.
///
/// Remembered parameters do not count: a client does not use a remembered
/// `max_ack_delay` (RFC 9000 §7.4.1).
pub(super) fn peer_max_ack_delay<L, I>(
    peer: &PeerTransportParameters<TransportParameterSlots<L>>,
) -> Option<Duration>
where
    L: ParametersOf<TransportParameterSpace>,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, I>,
{
    peer.known().map(max_ack_delay)
}

// ---- the packet number state ----

/// Each space starts with nothing acknowledged and nothing marked.
impl<T: StateChoices, L, Ii, Ih> Build<T, L, layer::LogicalPath, (Ii, Ih)>
    for PacketNumberSpaces<PacketNumberSpaceState>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<InitialKeys<T::Crypto>, Ii> + GetAt<HandshakeKeys<T::Crypto>, Ih>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        live_spaces::<T, _, Ii, Ih, _>(parents, |_| PacketNumberSpaceState::new())
    }
}
impl PassiveDataComponent for PacketNumberSpaces<PacketNumberSpaceState> {}

// ---- the receive journals ----

/// Each space starts with nothing received; the Initial space of the
/// first logical path starts with what reading the first flight before the
/// connection was made received in it.
impl<T: Choices, L, Ii, Ih, If> Build<T, L, layer::LogicalPath, (Ii, Ih, If)>
    for PacketNumberSpaces<ReceiveJournals<InstantOf<T>>>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<FirstFlightStart<T>, If>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        let mut read = parents
            .get_mut::<FirstFlightStart<T>, If>()
            .take_initial_journals();
        live_spaces::<T, _, Ii, Ih, _>(parents, |space| match space {
            PacketNumberSpaceKind::Initial => read.take().unwrap_or_default(),
            PacketNumberSpaceKind::Handshake | PacketNumberSpaceKind::ApplicationData => {
                ReceiveJournals::new()
            }
        })
    }
}
impl<I> PassiveDataComponent for PacketNumberSpaces<ReceiveJournals<I>> {}

// ---- the ACK obligations ----

/// The Initial and Handshake spaces acknowledge at once (RFC 9000
/// §13.2.1). The Application Data space may delay by this side's
/// `max_ack_delay` less the precision of the clock's timers, and not below
/// zero: a timer that fires late still sends the ACK frame within the
/// delay announced (§18.2). The Initial space of the first logical path
/// starts with what reading the first flight before the connection was
/// made left it owing.
impl<T, L, X, Ii, Ih, Il, It, Is, If>
    Build<T, L, layer::LogicalPath, (ChosenAckObligation, (Ii, Ih, If), Il, It, Is)>
    for PacketNumberSpaces<X>
where
    T: Choices<Host: StateHostChoices<T, AckObligation = X>>,
    X: AckObligation<InstantOf<T>>,
    L: LineagePartList<T>,
    TransportParameterSlots: Selector<Option<MaxAckDelay>, Is>,
    for<'v> <L as LineageLists<'v, T>>::Connection: GetAt<InitialKeys<T::Crypto>, Ii>
        + GetAt<HandshakeKeys<T::Crypto>, Ih>
        + GetAt<FirstFlightStart<T>, If>
        + GetAt<LocalTransportParameters<crate::v1::Part>, Il>
        + GetAt<LossThresholds, It>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        let mut read = parents
            .get_mut::<FirstFlightStart<T>, If>()
            .take_initial_ack_obligation();
        let local = parents.get::<LocalTransportParameters<crate::v1::Part>, Il>();
        let announced = local
            .sent()
            .or(local.configured())
            .map_or(DEFAULT_MAX_ACK_DELAY, max_ack_delay);
        let early = parents.get::<LossThresholds, It>().clock_granularity();
        let delay = announced.saturating_sub(early);
        live_spaces::<T, _, Ii, Ih, _>(parents, |space| match space {
            PacketNumberSpaceKind::Initial => read.take().unwrap_or_else(|| X::new(None)),
            PacketNumberSpaceKind::Handshake => X::new(None),
            PacketNumberSpaceKind::ApplicationData => X::new(Some(delay)),
        })
    }
}

/// The deadline is the earliest a space's ACK frame is due by, which the
/// calls change. When it comes, each space whose instant came is due now,
/// and the ACK frames to send changed.
impl<T, L, X, I> DataComponent<T, L, layer::LogicalPath, (ChosenAckObligation, I)>
    for PacketNumberSpaces<X>
where
    T: StateChoices<Host: StateHostChoices<T, AckObligation = X>>,
    X: AckObligation<InstantOf<T>> + 'static,
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::LogicalPath: GetAt<PacketNumberSpaces<X>, I>,
{
    const DEADLINE: bool = true;
    fn deadline<'v>(lineage: &LineageOf<'v, T, L, layer::LogicalPath>) -> Option<InstantOf<T>> {
        lineage
            .get::<PacketNumberSpaces<X>, I>()
            .iter()
            .filter_map(|(_, obligation)| obligation.due().deadline())
            .min()
    }
    fn expire<'v, B: CallBundle>(
        mut lineage: LineageOf<'v, T, L, layer::LogicalPath>,
        _: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        for (_, obligation) in lineage.get_mut::<PacketNumberSpaces<X>, I>().iter_mut() {
            obligation.on_deadline(now);
        }
        lineage.publish(Happened::<AckPendingChanged>::new());
        None
    }
}

// ---- the send journals ----

/// Each space starts with nothing sent.
///
/// The positions are one tuple: the packet number states and the receive
/// journals are built with two and three positions, and a tuple of the
/// same length would overlap theirs.
impl<T, L, X, Ii, Ih> Build<T, L, layer::LogicalPath, ((ChosenSendJournals, Ii, Ih),)>
    for PacketNumberSpaces<X>
where
    T: StateChoices<
        Host: StateHostChoices<
            T,
            SendJournals<FeedbackSummaryOf<T, L>, LinkPathIdentifierOf<T, L>> = X,
        >,
    >,
    X: Default,
    L: LineagePartList<T> + FeedbackSummariesOf,
    for<'v> <L as LineageLists<'v, T>>::Connection:
        GetAt<InitialKeys<T::Crypto>, Ii> + GetAt<HandshakeKeys<T::Crypto>, Ih>,
{
    fn build<'v>(
        parents: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        live_spaces::<T, _, Ii, Ih, _>(parents, |_| X::default())
    }
}

/// They have no deadline and read nothing: what lies past its retention is
/// dropped when an ACK frame or a loss detection of the space looks at
/// them anyway (RFC 9002 §6.1 keeps no record of lost packets; these are
/// kept only to recognize late acknowledgments).
impl<T, L, X> DataComponent<T, L, layer::LogicalPath, ChosenSendJournals> for PacketNumberSpaces<X>
where
    T: StateChoices<
        Host: StateHostChoices<
            T,
            SendJournals<FeedbackSummaryOf<T, L>, LinkPathIdentifierOf<T, L>> = X,
        >,
    >,
    L: LineagePartList<T> + FeedbackSummariesOf,
{
}

/// The packet number space of the packets of `level`.
pub(super) fn space_of(level: EncryptionLevel) -> PacketNumberSpaceKind {
    match level {
        EncryptionLevel::Initial => PacketNumberSpaceKind::Initial,
        EncryptionLevel::Handshake => PacketNumberSpaceKind::Handshake,
        EncryptionLevel::ZeroRtt | EncryptionLevel::OneRtt => {
            PacketNumberSpaceKind::ApplicationData
        }
    }
}
