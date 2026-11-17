//! Transport parameters in a connection: the peer's, and each part's own,
//! the error of a failure of reading the peer's, and the checks of version
//! 1 on the connection IDs the peer's state (RFC 9000 §7.3).
//!
//! A server that resumes a connection settles each part's own parameters
//! against those the ticket remembers
//! ([`ResumeLocalTransportParameters`]): each part's policy
//! ([`ResumedParametersPolicy`]) picks one of the three ways RFC 9000
//! §7.4.1 allows, and the part holds to the rules of its parameters that
//! 0-RTT relies on.

use core::{convert::Infallible, fmt, marker::PhantomData, ops::Add};

use bytes::Bytes;
use sakuya_tls::extension::alpn::ProtocolName;
use sakuya_wire::{
    connection_id::ConnectionId,
    parameters::{ParameterList, ParametersOf, ParametersPart, codec::ReadParametersError},
    parts::{CoprodInjector, HCons, HNil, PartsError, Selector},
    v1::transport_parameters::{
        TransportParameterSlots, TransportParameterSpace,
        codec::{ReadTransportParametersError, read_remembered_transport_parameters},
        connection_id::{
            InitialSourceConnectionId, OriginalDestinationConnectionId, RetrySourceConnectionId,
        },
        integer::{
            ActiveConnectionIdLimit, InitialMaxData, InitialMaxStreamDataBidiLocal,
            InitialMaxStreamDataBidiRemote, InitialMaxStreamDataUni, InitialMaxStreamsBidi,
            InitialMaxStreamsUni,
        },
    },
};
use snafu::{Snafu, ensure};

use super::{
    error::{ConnectionError, V1ConnectionErrorOf},
    receive::v1_error,
};
use crate::{
    error::{ConnectionErrorOf, TransportParameterValueErrorsOf},
    take::{GetAt, Lineage},
};

/// The peer's transport parameters: one component of the connection node,
/// read by whoever uses them.
///
/// `S` is the slots of the transport parameter types of the parts of the
/// connection. Values are written only after every part has checked its
/// own, so whatever reads them reads checked parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTransportParameters<S> {
    /// Not known yet.
    NotYet,
    /// A client that offers 0-RTT: the slots remembered from the earlier
    /// connection, only those whose parameters 0-RTT must remember (RFC
    /// 9000 §7.4.1); they govern 0-RTT packets only.
    Remembered(S),
    /// The parameters the peer sent in this handshake.
    Known(S),
}

impl<S> PeerTransportParameters<S> {
    /// The slots, remembered or known, if there are any.
    pub fn slots(&self) -> Option<&S> {
        match self {
            Self::NotYet => None,
            Self::Remembered(slots) | Self::Known(slots) => Some(slots),
        }
    }

    /// The slots the peer sent in this handshake, once they are known.
    pub fn known(&self) -> Option<&S> {
        match self {
            Self::Known(slots) => Some(slots),
            Self::NotYet | Self::Remembered(_) => None,
        }
    }

    /// Remember the slots of an earlier connection, as a client that offers
    /// 0-RTT does before the peer's parameters are known.
    pub fn remember(&mut self, slots: S) {
        debug_assert!(
            matches!(self, Self::NotYet),
            "remembering parameters over known ones"
        );
        *self = Self::Remembered(slots);
    }

    /// Set the parameters the peer sent in this handshake.
    pub fn set_known(&mut self, slots: S) {
        debug_assert!(
            !matches!(self, Self::Known(_)),
            "the peer's parameters are known twice"
        );
        *self = Self::Known(slots);
    }
}

/// The transport parameters a part sends: one configuration component of
/// that part in the connection node.
///
/// `P` is the part's own transport parameters. They are given when the
/// connection is made and stay as they were sent for the rest of the
/// connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalTransportParameters<P> {
    /// As configured; the handshake has not sent them yet, and a server
    /// may still settle them by the application protocol it selects and by
    /// whether it resumes.
    Configured(P),
    /// As sent; they no longer change.
    Sent(P),
}

impl<P> LocalTransportParameters<P> {
    /// The parameters as sent, once they are.
    pub fn sent(&self) -> Option<&P> {
        match self {
            Self::Sent(parameters) => Some(parameters),
            Self::Configured(_) => None,
        }
    }

    /// The parameters as configured, while they are not sent.
    pub fn configured(&self) -> Option<&P> {
        match self {
            Self::Configured(parameters) => Some(parameters),
            Self::Sent(_) => None,
        }
    }

    /// The configured parameters become what `settle` makes of them, as a
    /// server that resumes settles them; they are not sent yet. Parameters
    /// already sent stay as they were.
    pub(crate) fn settle_configured(&mut self, settle: impl FnOnce(&P) -> P) {
        if let Self::Configured(configured) = self {
            *configured = settle(configured);
        }
    }

    /// The parameters are sent as `settle` makes them from the configured
    /// ones; they no longer change.
    pub fn send_with(&mut self, settle: impl FnOnce(&P) -> P) {
        match self {
            Self::Configured(configured) => {
                let sent = settle(configured);
                *self = Self::Sent(sent);
            }
            Self::Sent(_) => debug_assert!(false, "transport parameters are sent twice"),
        }
    }
}

/// The place of a part's transport parameters among the components of the
/// connection node: [`InNode`] for a part that defines parameters, at the
/// position `I`, which the compiler infers.
#[derive(Debug)]
pub enum InNode<I> {
    #[doc(hidden)]
    _Never(PhantomData<I>, Infallible),
}

/// The place of the transport parameters of a part that defines none: there
/// is no component.
#[derive(Debug)]
pub enum NoParameters {}

/// A part's share of the transport parameters this side sends: its slots,
/// sent from its own [`LocalTransportParameters`] in the connection node,
/// whose components are `V`. `I` is where they are, [`InNode`] or
/// [`NoParameters`]; the compiler infers it.
///
/// It is implemented for every part: one that defines parameters keeps
/// them in the connection node, one that defines none has none to send.
pub trait SendLocalTransportParametersPart<V, I>: ParametersPart<TransportParameterSpace> {
    /// The part's slots as sent: those configured the first time, as they
    /// were sent afterwards.
    fn send_local(lineage: &mut Lineage<'_, V>) -> PartSlots<Self>;
}

/// The slots of the transport parameter types of the part `P` alone.
pub type PartSlots<P> =
    <<P as ParametersPart<TransportParameterSpace>>::Parameters as ParameterList<
        TransportParameterSpace,
    >>::Slots;

/// A part that defines parameters sends those it keeps, as configured the
/// first time.
impl<P, V, I> SendLocalTransportParametersPart<V, InNode<I>> for P
where
    P: ParametersPart<TransportParameterSpace>,
    PartSlots<P>: Clone,
    V: GetAt<LocalTransportParameters<PartSlots<P>>, I>,
{
    fn send_local(lineage: &mut Lineage<'_, V>) -> PartSlots<P> {
        let local = lineage.get_mut::<LocalTransportParameters<PartSlots<P>>, I>();
        if local.sent().is_none() {
            local.send_with(Clone::clone);
        }
        // invariant: sent just above when it was not
        local.sent().expect("the parameters are sent").clone()
    }
}

/// A part that defines no parameters has none to send.
impl<P, V> SendLocalTransportParametersPart<V, NoParameters> for P
where
    P: ParametersPart<TransportParameterSpace, Parameters = HNil>,
{
    fn send_local(_: &mut Lineage<'_, V>) -> PartSlots<P> {
        HNil
    }
}

/// The transport parameters this side sends, of a list of parts: each
/// part's slots ([`SendLocalTransportParametersPart`]), joined in the order
/// of the parts. `Is` holds the place of each part's; the compiler infers
/// it.
///
/// A part settles its own before they are joined: version 1 settles its
/// connection IDs as its advancing call sends them; the others send theirs
/// as configured.
pub trait SendLocalTransportParameters<V, Is>: ParametersOf<TransportParameterSpace> {
    /// The slots of every part, as sent.
    fn send_local(lineage: &mut Lineage<'_, V>) -> TransportParameterSlots<Self>;
}

impl<V> SendLocalTransportParameters<V, HNil> for HNil {
    fn send_local(_: &mut Lineage<'_, V>) -> HNil {
        HNil
    }
}

impl<P, Ps, V, I, Is> SendLocalTransportParameters<V, HCons<I, Is>> for HCons<P, Ps>
where
    P: SendLocalTransportParametersPart<V, I>,
    Ps: SendLocalTransportParameters<V, Is>,
    HCons<P, Ps>: ParametersOf<TransportParameterSpace>,
    PartSlots<P>: Add<TransportParameterSlots<Ps>, Output = TransportParameterSlots<HCons<P, Ps>>>,
{
    fn send_local(lineage: &mut Lineage<'_, V>) -> TransportParameterSlots<Self> {
        let own = P::send_local(lineage);
        own + Ps::send_local(lineage)
    }
}

// ---- resumption ----

/// What a part's [`ResumedParametersPolicy`] picks for the parameters a
/// server sends on a connection it resumes: the three ways RFC 9000 §7.4.1
/// allows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumedParametersDecision {
    /// Reject 0-RTT; the part sends its parameters as configured.
    Reject,
    /// Accept 0-RTT and send the values remembered: each parameter the
    /// ticket remembers as remembered, the others as configured.
    UseRemembered,
    /// Accept 0-RTT and send the parameters as configured. When one of
    /// them is lower than the remembered value of a limit 0-RTT relies on,
    /// which RFC 9000 §7.4.1 forbids, the part rejects 0-RTT instead.
    UseConfigured,
}

/// What decides, for one part and a connection a server resumes, how the
/// part's own transport parameters `P` go: its slots
/// ([`PartSlots`]).
///
/// It only picks; the part holds to the rules of its parameters: a pick of
/// the configured values that lowers a limit 0-RTT relies on rejects 0-RTT,
/// so that a policy cannot break the protocol. When any part rejects, the
/// connection rejects 0-RTT. It is asked only when the client resumes with
/// a ticket.
///
/// Its type is the part's choice, and its value is in the connection node,
/// from what the connection was made with. It sees neither the other parts'
/// parameters nor the ticket's age, the peer's address or whether a Retry
/// came first: a type that implements the policies of several parts
/// coordinates them, and one that holds a handle to outside state sees the
/// load.
pub trait ResumedParametersPolicy<P> {
    /// Pick for `remembered`, the part's parameters as the ticket remembers
    /// them (only those 0-RTT remembers), `configured`, as they are
    /// configured now, and `application_protocol`, the one selected for
    /// this connection.
    fn decide(
        &mut self,
        remembered: &P,
        configured: &P,
        application_protocol: Option<&ProtocolName<Bytes>>,
    ) -> ResumedParametersDecision;
}

/// The policy that always sends the parameters as configured
/// ([`ResumedParametersDecision::UseConfigured`]): 0-RTT is accepted while
/// they lower no limit 0-RTT relies on.
#[derive(Clone, Copy, Debug, Default)]
pub struct UseConfiguredParameters;

impl<P> ResumedParametersPolicy<P> for UseConfiguredParameters {
    fn decide(
        &mut self,
        _: &P,
        _: &P,
        _: Option<&ProtocolName<Bytes>>,
    ) -> ResumedParametersDecision {
        ResumedParametersDecision::UseConfigured
    }
}

/// A part's [`ResumedParametersPolicy`] `Pol` in the connection node: one
/// configuration component of each part that defines transport parameters,
/// made from the part's `Args`. `S` is the part's slots ([`PartSlots`]),
/// which tells the parts' components apart.
pub struct PartResumedParametersPolicy<S, Pol> {
    policy: Pol,
    slots: PhantomData<fn() -> S>,
}

impl<S, Pol> PartResumedParametersPolicy<S, Pol> {
    /// The component that holds `policy`.
    pub fn new(policy: Pol) -> Self {
        Self {
            policy,
            slots: PhantomData,
        }
    }

    /// The policy.
    #[cfg(test)]
    pub(crate) fn policy(&self) -> &Pol {
        &self.policy
    }
}

impl<S, Pol: fmt::Debug> fmt::Debug for PartResumedParametersPolicy<S, Pol> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PartResumedParametersPolicy")
            .field(&self.policy)
            .finish()
    }
}

/// A part's share of settling this side's transport parameters for a
/// connection a server resumes, from its own
/// [`LocalTransportParameters`] and [`PartResumedParametersPolicy`] in the
/// connection node, whose components are `V`. `I` is where they are,
/// [`InNode`] or [`NoParameters`]; the compiler infers it.
///
/// A part that defines parameters implements it with the rules of its
/// parameters that 0-RTT relies on; one that defines none accepts at once.
pub trait ResumeLocalTransportParametersPart<V, I>:
    ParametersPart<TransportParameterSpace>
{
    /// Settle the part's configured parameters for the resumption, before
    /// they are sent: read the part's own from `remembered`, the whole
    /// encoding of the parameters this side sent on the connection the
    /// ticket came from (the other parts' are ignored), let the policy pick
    /// with `application_protocol`, the one selected, and hold to the
    /// part's rules. Return whether the part accepts 0-RTT.
    ///
    /// Remembered parameters that do not read reject 0-RTT. Parameters sent
    /// already stay as they were, and reject it.
    fn resume_local(
        lineage: &mut Lineage<'_, V>,
        remembered: &Bytes,
        application_protocol: Option<&ProtocolName<Bytes>>,
    ) -> bool;
}

/// A part that defines no parameters has nothing to settle, and accepts.
impl<P, V> ResumeLocalTransportParametersPart<V, NoParameters> for P
where
    P: ParametersPart<TransportParameterSpace, Parameters = HNil>,
{
    fn resume_local(_: &mut Lineage<'_, V>, _: &Bytes, _: Option<&ProtocolName<Bytes>>) -> bool {
        true
    }
}

/// Settling this side's transport parameters for a connection a server
/// resumes, of a list of parts: each part's
/// ([`ResumeLocalTransportParametersPart`]), in the order of the parts.
/// `Is` holds the place of each part's; the compiler infers it.
///
/// The connection accepts 0-RTT when every part accepts. Every part settles
/// its own even when another rejects: a part whose policy picked the
/// remembered values sends them all the same, and they are valid values to
/// send.
pub trait ResumeLocalTransportParameters<V, Is>: ParametersOf<TransportParameterSpace> {
    /// Settle every part's configured parameters, as
    /// [`ResumeLocalTransportParametersPart::resume_local`] says; return
    /// whether every part accepts 0-RTT.
    fn resume_local(
        lineage: &mut Lineage<'_, V>,
        remembered: &Bytes,
        application_protocol: Option<&ProtocolName<Bytes>>,
    ) -> bool;
}

impl<V> ResumeLocalTransportParameters<V, HNil> for HNil {
    fn resume_local(_: &mut Lineage<'_, V>, _: &Bytes, _: Option<&ProtocolName<Bytes>>) -> bool {
        true
    }
}

impl<P, Ps, V, I, Is> ResumeLocalTransportParameters<V, HCons<I, Is>> for HCons<P, Ps>
where
    P: ResumeLocalTransportParametersPart<V, I>,
    Ps: ResumeLocalTransportParameters<V, Is>,
    HCons<P, Ps>: ParametersOf<TransportParameterSpace>,
{
    fn resume_local(
        lineage: &mut Lineage<'_, V>,
        remembered: &Bytes,
        application_protocol: Option<&ProtocolName<Bytes>>,
    ) -> bool {
        let own = P::resume_local(lineage, remembered, application_protocol);
        // every part settles its own, whatever the others decide
        let rest = Ps::resume_local(lineage, remembered, application_protocol);
        own && rest
    }
}

/// Slots that take, slot by slot, the parameter of other slots of the same
/// types where those hold one.
pub(crate) trait OverlaySlots {
    /// Each slot of `over` that holds a parameter replaces this one's.
    fn overlay(&mut self, over: &Self);
}

impl OverlaySlots for HNil {
    fn overlay(&mut self, _: &HNil) {}
}

impl<H: Clone, T: OverlaySlots> OverlaySlots for HCons<Option<H>, T> {
    fn overlay(&mut self, over: &Self) {
        if let Some(parameter) = &over.head {
            self.head = Some(parameter.clone());
        }
        self.tail.overlay(&over.tail);
    }
}

/// What the part `P` settles its configured parameters to on a resumption,
/// and whether it accepts 0-RTT, from `remembered`, its parameters as the
/// ticket remembers them (`None` when they do not read), `configured` and
/// what `policy` picks for `application_protocol`. `limits_kept` tells
/// whether parameters sent keep the rules of the part's parameters that
/// 0-RTT relies on against the remembered ones.
pub(crate) fn settle_resumed<S, Pol>(
    remembered: Option<&S>,
    configured: &S,
    policy: &mut Pol,
    application_protocol: Option<&ProtocolName<Bytes>>,
    limits_kept: impl FnOnce(&S, &S) -> bool,
) -> (S, bool)
where
    S: Clone + OverlaySlots,
    Pol: ResumedParametersPolicy<S>,
{
    let Some(remembered) = remembered else {
        return (configured.clone(), false);
    };
    match policy.decide(remembered, configured, application_protocol) {
        ResumedParametersDecision::Reject => (configured.clone(), false),
        ResumedParametersDecision::UseRemembered => {
            let mut sent = configured.clone();
            sent.overlay(remembered);
            (sent, true)
        }
        ResumedParametersDecision::UseConfigured => {
            let kept = limits_kept(remembered, configured);
            (configured.clone(), kept)
        }
    }
}

/// [`ResumeLocalTransportParametersPart::resume_local`] for the part `P`,
/// whose configured parameters are at `I` and whose policy `Pol` is at
/// `Ip` among the components `V`, with the rules `limits_kept` of its
/// parameters ([`settle_resumed`]).
pub(crate) fn resume_part<P, V, I, Ip, Pol>(
    lineage: &mut Lineage<'_, V>,
    remembered: &Bytes,
    application_protocol: Option<&ProtocolName<Bytes>>,
    limits_kept: impl FnOnce(&PartSlots<P>, &PartSlots<P>) -> bool,
) -> bool
where
    P: ParametersPart<TransportParameterSpace>,
    HCons<P, HNil>: ParametersOf<
            TransportParameterSpace,
            Parameters = <P as ParametersPart<TransportParameterSpace>>::Parameters,
        >,
    PartSlots<P>: Clone + OverlaySlots,
    V: GetAt<LocalTransportParameters<PartSlots<P>>, I>
        + GetAt<PartResumedParametersPolicy<PartSlots<P>, Pol>, Ip>,
    Pol: ResumedParametersPolicy<PartSlots<P>>,
{
    let Some(configured) = lineage
        .get::<LocalTransportParameters<PartSlots<P>>, I>()
        .configured()
        .cloned()
    else {
        return false;
    };
    // the part's own alone: the other parts' parameters are unknown to the
    // list, and dropped
    let mut source = remembered.clone();
    let remembered =
        read_remembered_transport_parameters::<HCons<P, HNil>, _>(&mut source, PhantomData).ok();
    let policy = &mut lineage
        .get_mut::<PartResumedParametersPolicy<PartSlots<P>, Pol>, Ip>()
        .policy;
    let (settled, accepted) = settle_resumed(
        remembered.as_ref(),
        &configured,
        policy,
        application_protocol,
        limits_kept,
    );
    lineage
        .get_mut::<LocalTransportParameters<PartSlots<P>>, I>()
        .settle_configured(|_| settled);
    accepted
}

/// Whether a limit `sent` is not lower than `remembered`, each its type's
/// default when absent.
pub(crate) fn not_lowered<P: Copy + Default + Ord>(remembered: Option<P>, sent: Option<P>) -> bool {
    sent.unwrap_or_default() >= remembered.unwrap_or_default()
}

/// Whether version 1's parameters `sent` lower none of the seven limits
/// 0-RTT relies on below the `remembered` ones: `active_connection_id_limit`,
/// `initial_max_data`, the three `initial_max_stream_data_*` and the two
/// `initial_max_streams_*`, each its default when absent, 2 for the first
/// and 0 for the others (RFC 9000 §7.4.1, MUST NOT; §18.2).
pub(crate) fn v1_limits_kept(
    remembered: &TransportParameterSlots,
    sent: &TransportParameterSlots,
) -> bool {
    fn kept<P: Copy + Default + Ord, I>(
        remembered: &TransportParameterSlots,
        sent: &TransportParameterSlots,
    ) -> bool
    where
        TransportParameterSlots: Selector<Option<P>, I>,
    {
        not_lowered(
            *Selector::<Option<P>, I>::get(remembered),
            *Selector::<Option<P>, I>::get(sent),
        )
    }
    kept::<ActiveConnectionIdLimit, _>(remembered, sent)
        && kept::<InitialMaxData, _>(remembered, sent)
        && kept::<InitialMaxStreamDataBidiLocal, _>(remembered, sent)
        && kept::<InitialMaxStreamDataBidiRemote, _>(remembered, sent)
        && kept::<InitialMaxStreamDataUni, _>(remembered, sent)
        && kept::<InitialMaxStreamsBidi, _>(remembered, sent)
        && kept::<InitialMaxStreamsUni, _>(remembered, sent)
}

/// Version 1 holds to the seven limits 0-RTT relies on: sending the
/// configured parameters, it accepts 0-RTT only when none of
/// `active_connection_id_limit`, `initial_max_data`, the three
/// `initial_max_stream_data_*` and the two `initial_max_streams_*` is
/// lower than the one remembered, each its default when absent (RFC 9000
/// §7.4.1). Its connection IDs are not among the parameters 0-RTT
/// remembers; they are filled in when the parameters are sent.
impl<V, I, Ip, Pol> ResumeLocalTransportParametersPart<V, InNode<(I, Ip, Pol)>> for super::Part
where
    V: GetAt<LocalTransportParameters<TransportParameterSlots>, I>
        + GetAt<PartResumedParametersPolicy<TransportParameterSlots, Pol>, Ip>,
    Pol: ResumedParametersPolicy<TransportParameterSlots>,
{
    fn resume_local(
        lineage: &mut Lineage<'_, V>,
        remembered: &Bytes,
        application_protocol: Option<&ProtocolName<Bytes>>,
    ) -> bool {
        resume_part::<Self, V, I, Ip, Pol>(
            lineage,
            remembered,
            application_protocol,
            v1_limits_kept,
        )
    }
}

/// How the peer's transport parameters, once read, fail the checks of
/// version 1 on the connection IDs: each closes the connection with
/// TRANSPORT_PARAMETER_ERROR (RFC 9000 §7.3).
///
/// Failures of reading them are not here: one of the encoding, or of the
/// value of a parameter of version 1, is
/// [`ConnectionError::ReadTransportParameters`], and one of the value of a
/// parameter of another part is that part's error
/// ([`TransportParameterValueErrorPart`](crate::error::TransportParameterValueErrorPart)).
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum PeerTransportParametersError {
    /// The peer sent no `initial_source_connection_id`.
    #[snafu(display("initial_source_connection_id absent"))]
    InitialSourceConnectionIdAbsent,
    /// The peer's `initial_source_connection_id` is not the Source
    /// Connection ID of the first Initial packet that opened from it.
    #[snafu(display("initial_source_connection_id {received:?} is not the peer's"))]
    InitialSourceConnectionIdMismatch {
        /// The connection ID it states.
        received: ConnectionId,
    },
    /// The server sent no `original_destination_connection_id`.
    #[snafu(display("original_destination_connection_id absent"))]
    OriginalDestinationConnectionIdAbsent,
    /// The server's `original_destination_connection_id` is not the
    /// Destination Connection ID of the client's first Initial packet.
    #[snafu(display("original_destination_connection_id {received:?} is not the client's"))]
    OriginalDestinationConnectionIdMismatch {
        /// The connection ID it states.
        received: ConnectionId,
    },
    /// The server sent a `retry_source_connection_id`, though the client
    /// received no Retry.
    #[snafu(display("retry_source_connection_id {received:?} without a Retry"))]
    RetrySourceConnectionIdWithoutRetry {
        /// The connection ID it states.
        received: ConnectionId,
    },
    /// The client received a Retry, and the server sent no
    /// `retry_source_connection_id`.
    #[snafu(display("retry_source_connection_id absent after a Retry"))]
    RetrySourceConnectionIdAbsent,
    /// The server's `retry_source_connection_id` is not the Source
    /// Connection ID of the Retry the client received.
    #[snafu(display("retry_source_connection_id {received:?} is not the Retry's"))]
    RetrySourceConnectionIdMismatch {
        /// The connection ID it states.
        received: ConnectionId,
    },
}

/// The connection's error for the peer's transport parameters that could
/// not be read into the slots of the parts `L`: version 1's for a failure
/// of the encoding as a whole, the error of the part whose type claims the
/// parameter for a value that breaks a rule of the type.
pub(super) fn read_transport_parameters_error<L, Iv>(
    error: ReadTransportParametersError<L>,
) -> ConnectionErrorOf<L>
where
    L: TransportParameterValueErrorsOf,
    L::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
{
    let source = match error {
        ReadParametersError::Id { source } => ReadParametersError::Id { source },
        ReadParametersError::Length { id, source } => ReadParametersError::Length { id, source },
        ReadParametersError::Value { id, source } => ReadParametersError::Value { id, source },
        ReadParametersError::Duplicate { source } => ReadParametersError::Duplicate { source },
        ReadParametersError::NotAdmitted { source } => ReadParametersError::NotAdmitted { source },
        ReadParametersError::InvalidValue {
            id,
            source: PartsError(source),
        } => return PartsError(L::value_error(id, source)),
    };
    v1_error::<L, Iv>(ConnectionError::ReadTransportParameters { source })
}

/// Check that the peer's `initial_source_connection_id` among `slots`
/// states `chosen`, the Source Connection ID of the first Initial packet
/// that opened from it; `None` when none opened, which none matches.
pub(super) fn check_initial_source<S, I>(
    slots: &S,
    chosen: Option<ConnectionId>,
) -> Result<(), PeerTransportParametersError>
where
    S: Selector<Option<InitialSourceConnectionId>, I>,
{
    let received = Selector::<Option<InitialSourceConnectionId>, I>::get(slots)
        .ok_or(PeerTransportParametersError::InitialSourceConnectionIdAbsent)?
        .get();
    ensure!(
        Some(received) == chosen,
        InitialSourceConnectionIdMismatchSnafu { received }
    );
    Ok(())
}

/// Check, as a client, that the server's `original_destination_connection_id`
/// among `slots` states `original`, the Destination Connection ID of the
/// client's first Initial packet, and that its `retry_source_connection_id`
/// states `retry_source`, the Source Connection ID of the Retry the client
/// received: absent when it received none (RFC 9000 §7.3).
pub(super) fn check_server_destination<S, Io, Ir>(
    slots: &S,
    original: ConnectionId,
    retry_source: Option<ConnectionId>,
) -> Result<(), PeerTransportParametersError>
where
    S: Selector<Option<OriginalDestinationConnectionId>, Io>
        + Selector<Option<RetrySourceConnectionId>, Ir>,
{
    let received = Selector::<Option<OriginalDestinationConnectionId>, Io>::get(slots)
        .ok_or(PeerTransportParametersError::OriginalDestinationConnectionIdAbsent)?
        .get();
    ensure!(
        received == original,
        OriginalDestinationConnectionIdMismatchSnafu { received }
    );
    let stated = Selector::<Option<RetrySourceConnectionId>, Ir>::get(slots).map(|id| id.get());
    match (retry_source, stated) {
        (None, None) => Ok(()),
        (None, Some(received)) => RetrySourceConnectionIdWithoutRetrySnafu { received }.fail(),
        (Some(_), None) => Err(PeerTransportParametersError::RetrySourceConnectionIdAbsent),
        (Some(retry), Some(received)) => {
            ensure!(
                received == retry,
                RetrySourceConnectionIdMismatchSnafu { received }
            );
            Ok(())
        }
    }
}

/// What the tests of each part's settling on resumption share.
#[cfg(test)]
pub(crate) mod resume_tests {
    use bytes::Bytes;
    use sakuya_wire::{
        parameters::ParametersPart,
        parts::HList,
        v1::{
            role::Role,
            transport_parameters::{TransportParameterSpace, codec::write_transport_parameters},
        },
    };

    use super::{
        InNode, LocalTransportParameters, PartResumedParametersPolicy, PartSlots,
        ResumeLocalTransportParametersPart, ResumedParametersDecision, ResumedParametersPolicy,
    };
    use crate::take::{Lineage, TakenPositions};

    /// A policy that picks `0`, and keeps what it was asked with.
    #[derive(Debug, Clone)]
    pub(crate) struct Picks<S>(
        pub(crate) ResumedParametersDecision,
        pub(crate) Option<(S, S)>,
    );

    impl<S: Clone> ResumedParametersPolicy<S> for Picks<S> {
        fn decide(
            &mut self,
            remembered: &S,
            configured: &S,
            _: Option<&sakuya_tls::extension::alpn::ProtocolName<Bytes>>,
        ) -> ResumedParametersDecision {
            self.1 = Some((remembered.clone(), configured.clone()));
            self.0
        }
    }

    /// The parameters `slots` of the part `P` alone, as a server sent them.
    pub(crate) fn encoded<P>(slots: PartSlots<P>) -> Bytes
    where
        P: ParametersPart<TransportParameterSpace>,
        HList![P]: sakuya_wire::parameters::ParametersOf<
                TransportParameterSpace,
                Parameters = <P as ParametersPart<TransportParameterSpace>>::Parameters,
            >,
    {
        let mut parameters =
            sakuya_wire::v1::transport_parameters::TransportParameters::<Bytes, HList![P]>::new();
        parameters.known = slots;
        let mut encoded = Vec::new();
        write_transport_parameters(&mut encoded, parameters, Role::Server)
            .expect("valid parameters");
        Bytes::from(encoded)
    }

    /// What the part `P`, configured with `configured` and picking
    /// `decision`, settles on against `remembered`: whether it accepts,
    /// what it is to send, and what its policy was asked with.
    #[allow(clippy::type_complexity)] // the outcome of a settling
    pub(crate) fn resume<P, I>(
        configured: PartSlots<P>,
        decision: ResumedParametersDecision,
        remembered: &Bytes,
    ) -> (bool, PartSlots<P>, Option<(PartSlots<P>, PartSlots<P>)>)
    where
        P: ParametersPart<TransportParameterSpace>,
        PartSlots<P>: Clone,
        for<'a> P: ResumeLocalTransportParametersPart<
                HList![
                    &'a mut LocalTransportParameters<PartSlots<P>>,
                    &'a mut PartResumedParametersPolicy<PartSlots<P>, Picks<PartSlots<P>>>
                ],
                InNode<I>,
            >,
    {
        let mut local = LocalTransportParameters::Configured(configured);
        let mut policy = PartResumedParametersPolicy::new(Picks(decision, None));
        let mut taken = TakenPositions::default();
        let accepted = {
            let mut lineage = Lineage::new(frunk_core::hlist![&mut local, &mut policy], &mut taken);
            P::resume_local(&mut lineage, remembered, None)
        };
        let settled = local.configured().expect("still configured").clone();
        (accepted, settled, policy.policy().1.clone())
    }
}

#[cfg(test)]
mod tests {
    use core::marker::PhantomData;

    use bytes::{Buf, BufMut};
    use sakuya_wire::{
        parameters::{KeyedParameter, ParametersPart, TrailingBytesError, ValueSource},
        parts::{Coprod, Coproduct, HList},
        v1::{
            role::Role,
            transport_error::TransportErrorCode,
            transport_parameters::{
                RememberedForZeroRtt, SentBy, TransportParameterAttributes,
                TransportParameterSpace, TransportParameters, codec::read_transport_parameters,
                integer::AckDelayExponent,
            },
        },
        var_int::VarInt,
    };

    use super::*;
    use crate::{
        error::{ConnectionErrorPart, TransportParameterValueErrorPart},
        v1::{
            Part,
            close::TransportClose,
            streams::resets::{StreamResets, StreamResetsPart},
        },
    };

    fn id(byte: u8) -> ConnectionId {
        ConnectionId::new(&[byte; 8]).unwrap()
    }

    /// The ID of the parameter of the extension of the tests.
    const EXTENSION_ID: u32 = 0x2a;

    /// The parameter of the extension of the tests: its value is empty.
    struct Flag;

    impl KeyedParameter for Flag {
        type Space = TransportParameterSpace;
        type ValueError = TrailingBytesError;

        const ID: VarInt = VarInt::from_u32(EXTENSION_ID);
        const ATTRIBUTES: TransportParameterAttributes = TransportParameterAttributes {
            sent_by: SentBy::Either,
            remembered_for_zero_rtt: RememberedForZeroRtt::Prohibited,
        };

        fn read_value<D: Buf>(_: &mut ValueSource<D>) -> Result<Self, TrailingBytesError> {
            Ok(Self)
        }

        fn value_len(&self) -> usize {
            0
        }

        fn write_value<B: BufMut>(&self, _: &mut B) {}
    }

    /// An extension with a transport parameter of its own, after version 1.
    struct Extension;

    /// The extension's error: the value of its parameter broke the rule of
    /// its type.
    #[derive(Debug)]
    struct ExtensionValueError {
        id: VarInt,
        #[expect(dead_code, reason = "the tests match the ID only")]
        source: PartsError<Coprod![TrailingBytesError]>,
    }

    impl<L> ConnectionErrorPart<L> for Extension {
        type ConnectionError = ExtensionValueError;
    }

    impl StreamResetsPart for Extension {
        type Fold<Prev: StreamResets> = Prev;
    }

    impl ParametersPart<TransportParameterSpace> for Extension {
        type Parameters = HList![Flag];
    }

    impl<L> TransportParameterValueErrorPart<Coprod![TrailingBytesError], L> for Extension {
        fn value_error(
            id: VarInt,
            source: PartsError<Coprod![TrailingBytesError]>,
        ) -> ExtensionValueError {
            ExtensionValueError { id, source }
        }
    }

    /// The connection's error for `encoding`, sent by a server, read for
    /// the parts `L`.
    fn read_error<L, Iv>(encoding: &[u8]) -> ConnectionErrorOf<L>
    where
        L: TransportParameterValueErrorsOf,
        L::ConnectionErrors: CoprodInjector<V1ConnectionErrorOf<L>, Iv>,
    {
        let mut source = encoding;
        match read_transport_parameters(&mut source, Role::Server, PhantomData::<L>) {
            Ok(_) => panic!("the transport parameters were read"),
            Err(error) => read_transport_parameters_error::<L, Iv>(error),
        }
    }

    /// The read failure in version 1's error, which closes with
    /// TRANSPORT_PARAMETER_ERROR.
    fn v1_read_failure<Rest>(
        error: PartsError<Coproduct<ConnectionError, Rest>>,
    ) -> ReadTransportParametersError {
        let PartsError(Coproduct::Inl(error)) = error else {
            panic!("not version 1's error");
        };
        assert_eq!(error.code(), TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
        match error {
            ConnectionError::ReadTransportParameters { source } => source,
            other => panic!("not a read failure: {other:?}"),
        }
    }

    type V1Alone = HList![Part];
    type WithExtension = HList![Part, Extension];

    #[test]
    fn a_read_failure_of_version_1_alone_is_its_error() {
        // max_idle_timeout twice
        let error = read_error::<V1Alone, _>(&[0x01, 0x01, 0x05, 0x01, 0x01, 0x05]);
        assert!(matches!(
            v1_read_failure(error),
            ReadParametersError::Duplicate { source } if source.id() == VarInt::from_u32(0x01)
        ));
        // a Length of 4 with one byte after it
        let error = read_error::<V1Alone, _>(&[0x01, 0x04, 0x05]);
        let failure = v1_read_failure(error);
        assert!(matches!(failure, ReadParametersError::Value { .. }));
        assert!(failure.is_incomplete());
        // ack_delay_exponent 21
        let error = read_error::<V1Alone, _>(&[0x0a, 0x01, 0x15]);
        let failure = v1_read_failure(error);
        assert!(failure.value_error::<AckDelayExponent>().is_some());
    }

    #[test]
    fn the_value_of_another_parts_parameter_is_that_parts_error() {
        let error = read_error::<WithExtension, _>(&[EXTENSION_ID as u8, 0x01, 0x00]);
        assert!(matches!(
            error,
            PartsError(Coproduct::Inr(Coproduct::Inl(ExtensionValueError { id, .. })))
                if id == VarInt::from_u32(EXTENSION_ID)
        ));
        // the value of a parameter of version 1 stays version 1's
        let error = read_error::<WithExtension, _>(&[0x0a, 0x01, 0x15]);
        assert!(
            v1_read_failure(error)
                .value_error::<AckDelayExponent>()
                .is_some()
        );
        // the extension's parameter twice is a failure of the encoding
        let error =
            read_error::<WithExtension, _>(&[EXTENSION_ID as u8, 0x00, EXTENSION_ID as u8, 0x00]);
        assert!(matches!(
            v1_read_failure(error),
            ReadParametersError::Duplicate { source }
                if source.id() == VarInt::from_u32(EXTENSION_ID)
        ));
    }

    #[test]
    fn the_initial_source_connection_id_states_the_peers() {
        let mut parameters = TransportParameters::<&[u8]>::new();
        assert!(matches!(
            check_initial_source::<_, _>(&parameters.known, Some(id(1))),
            Err(PeerTransportParametersError::InitialSourceConnectionIdAbsent)
        ));
        parameters.set(InitialSourceConnectionId::new(id(2)));
        assert!(matches!(
            check_initial_source::<_, _>(&parameters.known, Some(id(1))),
            Err(PeerTransportParametersError::InitialSourceConnectionIdMismatch { received })
                if received == id(2)
        ));
        assert!(matches!(
            check_initial_source::<_, _>(&parameters.known, None),
            Err(PeerTransportParametersError::InitialSourceConnectionIdMismatch { .. })
        ));
        assert!(check_initial_source::<_, _>(&parameters.known, Some(id(2))).is_ok());
    }

    #[test]
    fn a_server_states_the_clients_first_destination_and_no_retry() {
        let mut parameters = TransportParameters::<&[u8]>::new();
        assert!(matches!(
            check_server_destination::<_, _, _>(&parameters.known, id(1), None),
            Err(PeerTransportParametersError::OriginalDestinationConnectionIdAbsent)
        ));
        parameters.set(OriginalDestinationConnectionId::new(id(2)));
        assert!(matches!(
            check_server_destination::<_, _, _>(&parameters.known, id(1), None),
            Err(PeerTransportParametersError::OriginalDestinationConnectionIdMismatch { received })
                if received == id(2)
        ));
        assert!(check_server_destination::<_, _, _>(&parameters.known, id(2), None).is_ok());
        parameters.set(RetrySourceConnectionId::new(id(3)));
        assert!(matches!(
            check_server_destination::<_, _, _>(&parameters.known, id(2), None),
            Err(PeerTransportParametersError::RetrySourceConnectionIdWithoutRetry { received })
                if received == id(3)
        ));
    }

    #[test]
    fn after_a_retry_a_server_states_the_retrys_source() {
        let mut parameters = TransportParameters::<&[u8]>::new();
        parameters.set(OriginalDestinationConnectionId::new(id(2)));
        assert!(matches!(
            check_server_destination::<_, _, _>(&parameters.known, id(2), Some(id(3))),
            Err(PeerTransportParametersError::RetrySourceConnectionIdAbsent)
        ));
        parameters.set(RetrySourceConnectionId::new(id(4)));
        assert!(matches!(
            check_server_destination::<_, _, _>(&parameters.known, id(2), Some(id(3))),
            Err(PeerTransportParametersError::RetrySourceConnectionIdMismatch { received })
                if received == id(4)
        ));
        assert!(check_server_destination::<_, _, _>(&parameters.known, id(2), Some(id(4))).is_ok());
    }

    mod resumption {
        use bytes::Bytes;
        use sakuya_wire::{
            v1::{
                stream_count::StreamCount,
                transport_parameters::{
                    TransportParameters,
                    integer::{
                        ActiveConnectionIdLimit, InitialMaxData, InitialMaxStreamDataBidiLocal,
                        InitialMaxStreamDataBidiRemote, InitialMaxStreamDataUni,
                        InitialMaxStreamsBidi, InitialMaxStreamsUni, MaxAckDelay, MaxIdleTimeout,
                    },
                },
            },
            var_int::VarInt,
        };

        use super::super::{
            ResumedParametersDecision, TransportParameterSlots, resume_tests::*, v1_limits_kept,
        };
        use crate::v1::Part;

        /// Version 1's parameters with each of the seven limits 0-RTT
        /// relies on at `value`, 2 more for `active_connection_id_limit`.
        fn limits(value: u32) -> TransportParameters<Bytes> {
            let mut parameters = TransportParameters::<Bytes>::new();
            parameters.set(ActiveConnectionIdLimit::new(VarInt::from_u32(value + 2)).unwrap());
            parameters.set(InitialMaxData::new(VarInt::from_u32(value)));
            parameters.set(InitialMaxStreamDataBidiLocal::new(VarInt::from_u32(value)));
            parameters.set(InitialMaxStreamDataBidiRemote::new(VarInt::from_u32(value)));
            parameters.set(InitialMaxStreamDataUni::new(VarInt::from_u32(value)));
            parameters.set(InitialMaxStreamsBidi::new(
                StreamCount::new(u64::from(value)).unwrap(),
            ));
            parameters.set(InitialMaxStreamsUni::new(
                StreamCount::new(u64::from(value)).unwrap(),
            ));
            parameters
        }

        /// Each of the seven, lowered by one below `limits(10)`.
        fn each_lowered() -> Vec<TransportParameterSlots> {
            let lowered: [fn(&mut TransportParameters<Bytes>); 7] = [
                |p| {
                    p.set(ActiveConnectionIdLimit::new(VarInt::from_u32(11)).unwrap());
                },
                |p| {
                    p.set(InitialMaxData::new(VarInt::from_u32(9)));
                },
                |p| {
                    p.set(InitialMaxStreamDataBidiLocal::new(VarInt::from_u32(9)));
                },
                |p| {
                    p.set(InitialMaxStreamDataBidiRemote::new(VarInt::from_u32(9)));
                },
                |p| {
                    p.set(InitialMaxStreamDataUni::new(VarInt::from_u32(9)));
                },
                |p| {
                    p.set(InitialMaxStreamsBidi::new(StreamCount::new(9).unwrap()));
                },
                |p| {
                    p.set(InitialMaxStreamsUni::new(StreamCount::new(9).unwrap()));
                },
            ];
            lowered
                .into_iter()
                .map(|lower| {
                    let mut parameters = limits(10);
                    lower(&mut parameters);
                    parameters.known
                })
                .collect()
        }

        #[test]
        fn configured_values_that_lower_a_limit_reject_0_rtt() {
            let remembered = encoded::<Part>(limits(10).known);
            for configured in each_lowered() {
                let (accepted, settled, _) = resume::<Part, _>(
                    configured,
                    ResumedParametersDecision::UseConfigured,
                    &remembered,
                );
                assert!(!accepted);
                // the configured values are sent all the same
                assert_eq!(settled, configured);
            }
        }

        #[test]
        fn configured_values_that_lower_no_limit_accept_0_rtt() {
            let remembered = encoded::<Part>(limits(10).known);
            for configured in [limits(10).known, limits(20).known] {
                let (accepted, settled, _) = resume::<Part, _>(
                    configured,
                    ResumedParametersDecision::UseConfigured,
                    &remembered,
                );
                assert!(accepted);
                assert_eq!(settled, configured);
            }
        }

        #[test]
        fn absent_limits_are_their_defaults() {
            let none = TransportParameters::<Bytes>::new().known;
            // nothing remembered: 2 and 0, which nothing lowers
            assert!(v1_limits_kept(&none, &none));
            let mut two = TransportParameters::<Bytes>::new();
            two.set(ActiveConnectionIdLimit::new(VarInt::from_u32(2)).unwrap());
            two.set(InitialMaxData::new(VarInt::from_u32(0)));
            assert!(v1_limits_kept(&two.known, &none));
            assert!(v1_limits_kept(&none, &two.known));
            // a remembered limit above the default is lowered by its absence
            assert!(!v1_limits_kept(&limits(10).known, &none));
        }

        #[test]
        fn the_remembered_values_are_sent_over_those_configured() {
            let mut remembered = limits(10);
            // not remembered for 0-RTT: dropped when the ticket is read
            remembered.set(MaxAckDelay::new(VarInt::from_u32(40)).unwrap());
            let mut configured = limits(5);
            configured.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
            configured.set(MaxAckDelay::new(VarInt::from_u32(20)).unwrap());
            let (accepted, settled, asked) = resume::<Part, _>(
                configured.known,
                ResumedParametersDecision::UseRemembered,
                &encoded::<Part>(remembered.known),
            );
            assert!(accepted);
            let mut expected = limits(10);
            expected.set(MaxIdleTimeout::new(VarInt::from_u32(30_000)));
            expected.set(MaxAckDelay::new(VarInt::from_u32(20)).unwrap());
            assert_eq!(settled, expected.known);
            // the policy saw the remembered values 0-RTT keeps, and those
            // configured
            let (seen_remembered, seen_configured) = asked.expect("asked");
            assert_eq!(seen_remembered, limits(10).known);
            assert_eq!(seen_configured, configured.known);
        }

        #[test]
        fn a_policy_that_rejects_sends_the_configured_values() {
            let configured = limits(20).known;
            let (accepted, settled, _) = resume::<Part, _>(
                configured,
                ResumedParametersDecision::Reject,
                &encoded::<Part>(limits(10).known),
            );
            assert!(!accepted);
            assert_eq!(settled, configured);
        }

        #[test]
        fn remembered_parameters_that_do_not_read_reject_0_rtt() {
            let configured = limits(20).known;
            // max_idle_timeout twice
            let broken = Bytes::from_static(&[0x01, 0x01, 0x05, 0x01, 0x01, 0x05]);
            for decision in [
                ResumedParametersDecision::UseConfigured,
                ResumedParametersDecision::UseRemembered,
            ] {
                let (accepted, settled, asked) = resume::<Part, _>(configured, decision, &broken);
                assert!(!accepted);
                assert_eq!(settled, configured);
                assert!(asked.is_none(), "the policy is not asked");
            }
        }

        #[test]
        fn the_parameters_of_other_parts_are_ignored() {
            let mut encoding = encoded::<Part>(limits(10).known).to_vec();
            // a parameter no type of version 1 claims
            encoding.extend_from_slice(&[0x2a, 0x00]);
            let (accepted, _, asked) = resume::<Part, _>(
                limits(10).known,
                ResumedParametersDecision::UseConfigured,
                &Bytes::from(encoding),
            );
            assert!(accepted);
            assert_eq!(asked.expect("asked").0, limits(10).known);
        }
    }
}
