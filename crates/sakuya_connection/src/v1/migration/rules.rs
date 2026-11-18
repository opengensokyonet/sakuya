//! The fixed part of connection migration: what it does with the answers of
//! the migration policy, as the [parent module](super) says.
//!
//! [`ConnectionMigration`] decides from the link paths' states alone: each
//! of its rules takes the states of the link paths involved and returns what
//! changes ([`MigrationStep`], [`FailedValidation`]). [`MigrationRules`]
//! reads those states out of a lend of a logical path, applies the result
//! there (roles, and when the link paths entered them) and gives the
//! changes of structure that follow as [`MigrationRequest`]s, for the
//! caller to hand to the driver in order.
//!
//! Path validation calls the two rules of its results: a link path
//! validated ([`MigrationRules::validated`]), with the RTT of its
//! challenge when the response came back over it, and a path validation
//! that gave up ([`MigrationRules::validation_failed`]). When the active
//! link path's validation sets the instant it gives up at, the fallback in
//! `Settling` keeps at least until then ([`hold_fallback`]).
use core::time::Duration;

use frunk_core::hlist_pat;
use sakuya_link::{Link, LinkId};
use sakuya_recovery::{
    packet_number_space::PacketNumberSpaceKind, pto::probe_timeout, rtt::RttEstimator,
};
use sakuya_wire::{
    connection_id::ConnectionId,
    parameters::ParametersOf,
    parts::{HList, Selector},
    v1::transport_parameters::{
        TransportParameterSlots, TransportParameterSpace,
        disable_active_migration::DisableActiveMigration, integer::MaxAckDelay,
    },
};

use super::{
    ConnectionMigration, LinkPathAdmission, LinkPathAdmissionContext, LinkPathFacts,
    LinkPathMigration, MigrationPolicy, PeerMovedContext, SettlingContext, SwitchRecovery,
    SwitchTiming,
};
use crate::{
    call::CallBundle,
    clock::{CheckedAdd, ConnectionChoices, InstantOf, LinkIdOf},
    component::{ArgsOf, Build, DataComponent, LineageOf, ParentsOf, RequestOf},
    component_event::{EventSubscriptions, Happened, NodeStarted, TriggeredEvents},
    layer::{self, NodeKey},
    others::OtherNodes,
    request::StructureRequest,
    role::LinkPathRole,
    share::{FlatMut, LineageLists, LineagePartList, NodeData},
    take::{GetAt, ReadEach, TakeEach},
    v1::{
        Choices, LinkPathRoleReads, MigrationPolicyOf,
        amplification::{AddressValidation, AntiAmplification},
        component_events::LinkPathRoleChanged,
        connection_ids::{ConnectionIdsOf, LineageConnectionIdEvents, LocalConnectionIdUsedByPeer},
        link::LinkFacts,
        parameters::LocalTransportParameters,
        recovery::RttOf,
        spaces::{DEFAULT_MAX_ACK_DELAY, peer_max_ack_delay},
    },
};

/// This side's end of the links of the choices `T`.
type LocalOf<T> = <<T as ConnectionChoices>::Link as Link>::Local;
/// The peer's end of the links of the choices `T`.
type PeerOf<T> = <<T as ConnectionChoices>::Link as Link>::Peer;

/// The connection migration of a logical path of the choices `T`.
pub type ConnectionMigrationOf<T> =
    ConnectionMigration<MigrationPolicyOf<T>, LocalOf<T>, PeerOf<T>>;

/// What connection migration keeps in a link path of the choices `T`.
pub type LinkPathMigrationOf<T> = LinkPathMigration<LocalOf<T>, PeerOf<T>, InstantOf<T>>;

/// What the rules of connection migration are told of one link path.
#[derive(Debug, Clone, Copy)]
pub struct LinkPathState<'a, Lo, P, I> {
    /// Its logical link.
    pub link: &'a LinkId<Lo, P>,
    /// Its role.
    pub role: LinkPathRole<I>,
    /// Whether the address of its logical link is validated.
    pub validation: AddressValidation,
    /// Its probe timeout when it has a recovery layer; `None` without one.
    pub pto: Option<Duration>,
}

impl<Lo, P, I> LinkPathState<'_, Lo, P, I> {
    fn validated(&self) -> bool {
        self.validation == AddressValidation::Validated
    }
}

/// A change of the active link path: to `to`, the former active one taking
/// the role `from` gives it, with the recovery layer `layer` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Switch<Lo, P, I> {
    /// The logical link of the link path that becomes active.
    pub to: LinkId<Lo, P>,
    /// The logical link of the former active link path and its role from
    /// now on; `None` when there was none.
    pub from: Option<(LinkId<Lo, P>, LinkPathRole<I>)>,
    /// The recovery layer of the link path that becomes active.
    pub layer: SwitchLayer,
}

/// The recovery layer a link path that becomes active gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchLayer {
    /// The one it has: it was `Settling`.
    Keep,
    /// The former active link path's, moved by value.
    Move,
    /// A new one, which starts with `initial_rtt` as its RTT when given
    /// (RFC 9002 §6.2.2).
    New {
        /// The time from a PATH_CHALLENGE to its PATH_RESPONSE.
        initial_rtt: Option<Duration>,
    },
}

/// What a processed packet or a validation changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationStep<Lo, P, I> {
    /// Nothing.
    Stay,
    /// The switch to the link path waits for its validation, with the
    /// recovery layer the policy chose.
    Await(SwitchRecovery<Lo, P>),
    /// The active link path changes.
    Switch(Switch<Lo, P, I>),
}

/// What a path validation that gave up changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailedValidation<Lo, P, I> {
    /// The link path ends: no switch involves it, or one only waited for
    /// it.
    End(LinkId<Lo, P>),
    /// The active link path, whose validation failed, gives way to the
    /// fallback and ends (RFC 9000 §9.3.2).
    Revert {
        /// The switch back to the fallback.
        switch: Switch<Lo, P, I>,
        /// The logical link of the failed link path.
        end: LinkId<Lo, P>,
    },
    /// The active link path failed and no validated address is left to
    /// revert to: the connection closes silently, discarding its state
    /// without sending (RFC 9000 §9.3.2).
    NoFallback,
}

impl<M, Lo: Clone, P: Clone> ConnectionMigration<M, Lo, P> {
    /// The policy's admission of a link path for a packet from
    /// `cx.link`: `None` to drop the datagram's packets; otherwise the
    /// logical links of the link paths to end first, which are among
    /// `cx.link_paths` and neither the active one nor the fallback.
    pub fn admit<I: Copy>(
        &mut self,
        cx: &LinkPathAdmissionContext<'_, Lo, P, I>,
    ) -> Option<Vec<LinkId<Lo, P>>>
    where
        M: MigrationPolicy<Lo, P, I>,
    {
        let LinkPathAdmission::Accept { mut end } = self.policy.admit(cx) else {
            return None;
        };
        end.retain(|link| {
            cx.link_paths.iter().any(|facts| {
                facts.link == *link
                    && !matches!(facts.role, LinkPathRole::Active)
                    && !facts.fallback
            })
        });
        end.dedup();
        Some(end)
    }

    /// A packet was processed on `arrival`; it is the non-probing packet of
    /// the highest number in its space when `moves`. `active` is the active
    /// link path, unless `arrival` is or none is; `awaits` says whether a
    /// switch to `arrival` already waits for its validation.
    pub fn on_processed<I: Copy + CheckedAdd>(
        &mut self,
        arrival: &LinkPathState<'_, Lo, P, I>,
        awaits: bool,
        active: Option<&LinkPathState<'_, Lo, P, I>>,
        moves: bool,
        peer_switched_local_id: bool,
        now: I,
    ) -> MigrationStep<Lo, P, I>
    where
        M: MigrationPolicy<Lo, P, I>,
    {
        if !moves
            || !matches!(
                arrival.role,
                LinkPathRole::Candidate | LinkPathRole::Settling(_)
            )
        {
            return MigrationStep::Stay;
        }
        let recovery = if arrival.validated() {
            // back to a validated address: the change the layer moved by,
            // the other way, if it was from here to the active one
            match (self.moved.take(), active) {
                (Some(moved), Some(active)) if moved.is(arrival.link, active.link) => {
                    SwitchRecovery::Move(moved.reversed())
                }
                _ => SwitchRecovery::New,
            }
        } else if awaits {
            return MigrationStep::Stay;
        } else if let Some(active) = active {
            let decision = self.policy.on_peer_moved(&PeerMovedContext {
                from: active.link,
                to: arrival.link,
                peer_switched_local_id,
                now,
            });
            if decision.timing == SwitchTiming::AfterValidation {
                return MigrationStep::Await(decision.recovery);
            }
            decision.recovery
        } else {
            // with no active link path, nothing else is there to send on
            SwitchRecovery::New
        };
        MigrationStep::Switch(self.switch(arrival, active, recovery, None, now))
    }

    /// The link path `validated` was validated; `awaiting` is the switch to
    /// it that waited for this, if one did, and `initial_rtt` the time from
    /// its PATH_CHALLENGE to the response, when the response came back over
    /// it. `active` is the active link path, unless `validated` is.
    pub fn on_validated<I: Copy + CheckedAdd>(
        &mut self,
        validated: &LinkPathState<'_, Lo, P, I>,
        awaiting: Option<SwitchRecovery<Lo, P>>,
        active: Option<&LinkPathState<'_, Lo, P, I>>,
        initial_rtt: Option<Duration>,
        now: I,
    ) -> MigrationStep<Lo, P, I>
    where
        M: MigrationPolicy<Lo, P, I>,
    {
        if matches!(validated.role, LinkPathRole::Active) {
            // the active link path is validated: nothing to revert to
            self.fallback = None;
            return MigrationStep::Stay;
        }
        let Some(recovery) = awaiting else {
            return MigrationStep::Stay;
        };
        let state = LinkPathState {
            validation: AddressValidation::Validated,
            ..*validated
        };
        MigrationStep::Switch(self.switch(&state, active, recovery, initial_rtt, now))
    }

    /// The path validation of `failed` gave up. `active` is the active link
    /// path, unless `failed` is; `fallback` is the fallback, when there is
    /// one.
    pub fn on_validation_failed<I: Copy + CheckedAdd>(
        &mut self,
        failed: &LinkPathState<'_, Lo, P, I>,
        fallback: Option<&LinkPathState<'_, Lo, P, I>>,
        now: I,
    ) -> FailedValidation<Lo, P, I>
    where
        M: MigrationPolicy<Lo, P, I>,
    {
        if !matches!(failed.role, LinkPathRole::Active) {
            return FailedValidation::End(failed.link.clone());
        }
        let Some(fallback) = fallback else {
            return FailedValidation::NoFallback;
        };
        let recovery = match self.moved.take() {
            Some(moved) if moved.is(fallback.link, failed.link) => {
                SwitchRecovery::Move(moved.reversed())
            }
            _ => SwitchRecovery::New,
        };
        let switch = self.switch(fallback, Some(failed), recovery, None, now);
        FailedValidation::Revert {
            switch,
            end: failed.link.clone(),
        }
    }

    /// The switch of the active link path from `from` to `to` with
    /// `recovery`, as the [parent module](super) says; the fallback and the
    /// change the layer moved by follow it.
    fn switch<I: Copy + CheckedAdd>(
        &mut self,
        to: &LinkPathState<'_, Lo, P, I>,
        from: Option<&LinkPathState<'_, Lo, P, I>>,
        recovery: SwitchRecovery<Lo, P>,
        initial_rtt: Option<Duration>,
        now: I,
    ) -> Switch<Lo, P, I>
    where
        M: MigrationPolicy<Lo, P, I>,
    {
        let has_layer = to.pto.is_some();
        let (layer, moved) = match recovery {
            _ if has_layer => (SwitchLayer::Keep, None),
            SwitchRecovery::Move(change)
                if from.is_some_and(|from| from.pto.is_some() && change.is(from.link, to.link)) =>
            {
                (SwitchLayer::Move, Some(change))
            }
            SwitchRecovery::Move(_) | SwitchRecovery::New => {
                (SwitchLayer::New { initial_rtt }, None)
            }
        };
        if to.validated() {
            self.fallback = None;
        } else if let Some(from) = from.filter(|from| from.validated()) {
            self.fallback = Some(from.link.clone());
        }
        self.moved = moved;
        let from = from.map(|from| {
            let role = match from.pto {
                Some(pto) if layer != SwitchLayer::Move => {
                    let settling = self.policy.settling_for(&SettlingContext { pto });
                    // an end past what the instant type represents is none:
                    // the link path settles until now
                    LinkPathRole::Settling(now.checked_add(settling).unwrap_or(now))
                }
                _ => LinkPathRole::Candidate,
            };
            (from.link.clone(), role)
        });
        Switch {
            to: to.link.clone(),
            from,
            layer,
        }
    }
}

/// When the fallback, `role`, is `Settling`, it keeps at least until
/// `until`, the instant the path validation of the active link path gives
/// up at, so that a failure still has it to revert to (RFC 9000 §9.3.2).
/// What happened, when the end moved.
#[must_use = "what happened is to be published in the lend"]
pub fn hold_fallback<I: Copy + Ord>(
    role: &mut LinkPathRole<I>,
    until: I,
) -> Option<Happened<LinkPathRoleChanged>> {
    match role {
        LinkPathRole::Settling(end) if *end < until => {
            *end = until;
            Some(Happened::new())
        }
        _ => None,
    }
}

/// A change of structure that connection migration asks for, of a link
/// path of the logical path it acts in; `Id` is the identity of a logical
/// link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationRequest<Id> {
    /// Move the recovery layer of the link path over `from` to the one over
    /// `to`.
    MoveRecovery {
        /// The link path's logical link it is on.
        from: Id,
        /// The link path's logical link it goes to.
        to: Id,
    },
    /// Build the recovery layer of the link path over `link`.
    AddRecovery {
        /// The link path's logical link.
        link: Id,
        /// What its RTT starts with, when it is measured.
        initial_rtt: Option<Duration>,
    },
    /// End the link path over `link`.
    EndLinkPath {
        /// The link path's logical link.
        link: Id,
    },
}

impl<Lo, P> MigrationRequest<LinkId<Lo, P>> {
    /// The request of the tree's structure, for the logical path `path`.
    pub fn into_structure<K, Lk: Link<Local = Lo, Peer = P>>(
        self,
        path: K,
    ) -> StructureRequest<K, Lk> {
        match self {
            Self::MoveRecovery { from, to } => StructureRequest::MoveRecovery { path, from, to },
            Self::AddRecovery { link, initial_rtt } => StructureRequest::AddRecovery {
                args: layer::RecoveryArgs {
                    path,
                    link,
                    initial_rtt,
                },
            },
            Self::EndLinkPath { link } => StructureRequest::EndLinkPath { path, link },
        }
    }
}

/// A link path admitted for a packet from a new logical link: the link
/// paths to end before it is built, and whether the packet is sent to
/// another of this side's connection IDs than the peer last used on the
/// active link path. `Id` is the identity of a logical link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmittedLinkPath<Id> {
    /// The logical links of the link paths to end first.
    pub end: Vec<Id>,
    /// Whether the peer switched to another of this side's connection IDs.
    pub peer_switched_local_id: bool,
}

/// What the rules of connection migration read of a link path of a lend.
struct Gathered<T: Choices> {
    link: LinkIdOf<T>,
    role: LinkPathRole<InstantOf<T>>,
    since: Option<InstantOf<T>>,
    awaits: bool,
    used: Option<ConnectionId>,
    validation: AddressValidation,
    pto: Option<Duration>,
}

impl<T: Choices> Gathered<T> {
    fn state(&self) -> LinkPathState<'_, LocalOf<T>, PeerOf<T>, InstantOf<T>> {
        LinkPathState {
            link: &self.link,
            role: self.role,
            validation: self.validation,
            pto: self.pto,
        }
    }
}

/// `L: MigrationRules<T, H>`: the rules of connection migration, applied in
/// a lend of a logical path of the composition's list of parts `L`, the
/// migration policy and its records in the logical path, the roles and
/// records of its link paths, the facts of their logical links and their
/// recovery layers read there. What they change of structure is added to
/// `requests`, in order.
///
/// `H` holds the positions of what they take.
pub trait MigrationRules<T: Choices, H>: LineagePartList<T> + Sized {
    /// A packet sent to `destination` arrived over `link`, which has no
    /// link path in the logical path; it opened and is no duplicate. `None`
    /// to drop the datagram's packets.
    fn admit<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, Self, layer::LogicalPath>,
        others: &mut OtherNodes<'v, T, Self, B>,
        link: &LinkIdOf<T>,
        destination: &ConnectionId,
        now: InstantOf<T>,
    ) -> Option<AdmittedLinkPath<LinkIdOf<T>>>;

    /// A packet sent to `destination` was processed on the link path over
    /// `link`; it is the non-probing packet of the highest number in its
    /// space when `moves`. The local connection ID strategy hears that the
    /// peer switched to `destination` when it did on this link path, or,
    /// on its first packet, from the active one; the active link path
    /// follows the packet as the migration policy says.
    fn processed<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, Self, layer::LogicalPath>,
        others: &mut OtherNodes<'v, T, Self, B>,
        link: &LinkIdOf<T>,
        destination: &ConnectionId,
        moves: bool,
        now: InstantOf<T>,
        requests: &mut Vec<MigrationRequest<LinkIdOf<T>>>,
    );

    /// The link path over `link` was validated; `initial_rtt` is the time
    /// from its PATH_CHALLENGE to the response, when the response came back
    /// over it. A switch that waited for it is made.
    fn validated<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, Self, layer::LogicalPath>,
        others: &mut OtherNodes<'v, T, Self, B>,
        link: &LinkIdOf<T>,
        initial_rtt: Option<Duration>,
        now: InstantOf<T>,
        requests: &mut Vec<MigrationRequest<LinkIdOf<T>>>,
    );

    /// The path validation of the link path over `link` gave up: a link
    /// path that is not active ends, and the active one reverts to the
    /// fallback and ends. `false` when the active one failed with no
    /// fallback: the connection is to close silently (RFC 9000 §9.3.2).
    fn validation_failed<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, Self, layer::LogicalPath>,
        others: &mut OtherNodes<'v, T, Self, B>,
        link: &LinkIdOf<T>,
        now: InstantOf<T>,
        requests: &mut Vec<MigrationRequest<LinkIdOf<T>>>,
    ) -> bool;
}

/// What the rules change of a link path: its role, its record of
/// migration and the local connection ID the peer last used on it.
type LinkPathTakes<T> = HList![
    LinkPathRole<InstantOf<T>>,
    LinkPathMigrationOf<T>,
    LocalConnectionIdUsedByPeer
];

impl<T, L, Imig, Ilt, Ida, Icid, Hc, Iv, Ima, Ir, Ilm, Icu, Ix, Ian, Irt>
    MigrationRules<
        T,
        (
            (Imig, Ilt, Ida, Icid, Hc, Iv, Ima),
            (Ir, Ilm, Icu, Ix, Ian, Irt),
        ),
    > for L
where
    T: Choices,
    L: LineagePartList<T> + ParametersOf<TransportParameterSpace>,
    MigrationPolicyOf<T>: MigrationPolicy<LocalOf<T>, PeerOf<T>, InstantOf<T>>,
    TransportParameterSlots: Selector<Option<DisableActiveMigration>, Ida>,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<ConnectionMigrationOf<T>, Imig>
        + GetAt<LocalTransportParameters<TransportParameterSlots>, Ilt>
        + GetAt<ConnectionIdsOf<T>, Icid>
        + ReadEach<LinkPathRoleReads<T, L>, Iv>
        + LineageConnectionIdEvents<T, L, Hc>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out: GetAt<LinkPathRole<InstantOf<T>>, Ir>
        + GetAt<LinkPathMigrationOf<T>, Ilm>
        + GetAt<LocalConnectionIdUsedByPeer, Icu>
        + TakeEach<'s, LinkPathTakes<T>, Ix>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification, LinkFacts], Ian>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Irt>,
{
    fn admit<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, L, layer::LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        link: &LinkIdOf<T>,
        destination: &ConnectionId,
        now: InstantOf<T>,
    ) -> Option<AdmittedLinkPath<LinkIdOf<T>>> {
        let gathered = gather::<T, L, B, Iv, Ima, Ir, Ilm, Icu, Ian, Irt>(lineage, others);
        let fallback = lineage
            .get::<ConnectionMigrationOf<T>, Imig>()
            .fallback()
            .cloned();
        let facts: Vec<_> = gathered
            .iter()
            .map(|each| LinkPathFacts {
                link: each.link.clone(),
                role: each.role,
                since: each.since.unwrap_or(now),
                validation: each.validation,
                fallback: fallback.as_ref() == Some(&each.link),
            })
            .collect();
        let disabled = lineage
            .get::<LocalTransportParameters<TransportParameterSlots>, Ilt>()
            .sent()
            .is_some_and(|slots| {
                Selector::<Option<DisableActiveMigration>, Ida>::get(slots).is_some()
            });
        let active_used = gathered
            .iter()
            .find(|each| each.role == LinkPathRole::Active)
            .and_then(|each| each.used);
        let peer_switched_local_id =
            !zero_length::<T, L, Icid>(lineage) && active_used != Some(*destination);
        let cx = LinkPathAdmissionContext {
            link,
            link_paths: &facts,
            local_disabled_active_migration: disabled,
            peer_switched_local_id,
            now,
        };
        let end = lineage
            .get_mut::<ConnectionMigrationOf<T>, Imig>()
            .admit(&cx)?;
        Some(AdmittedLinkPath {
            end,
            peer_switched_local_id,
        })
    }

    fn processed<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, L, layer::LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        link: &LinkIdOf<T>,
        destination: &ConnectionId,
        moves: bool,
        now: InstantOf<T>,
        requests: &mut Vec<MigrationRequest<LinkIdOf<T>>>,
    ) {
        let NodeKey::LogicalPath(path) = others.here().clone() else {
            unreachable!("a logical path's lend carries its key")
        };
        // nearly every packet comes with the connection ID its link path saw
        // last and either does not move the peer or arrives on the active
        // link path: nothing changes, and the link paths are not gathered
        let zero = zero_length::<T, L, Icid>(lineage);
        if let Some(hlist_pat![role, _, used]) =
            others.link_path::<LinkPathTakes<T>, Ix>(&path, link)
        {
            let same_id = zero || used.get() == Some(*destination);
            let may_switch = matches!(*role, LinkPathRole::Candidate | LinkPathRole::Settling(_));
            if same_id && !(moves && may_switch) {
                return;
            }
        }
        let mut gathered = gather::<T, L, B, Iv, Ima, Ir, Ilm, Icu, Ian, Irt>(lineage, others);
        let Some(arrival) = gathered.iter().position(|each| each.link == *link) else {
            return;
        };
        let active = gathered
            .iter()
            .position(|each| each.role == LinkPathRole::Active);
        if !zero_length::<T, L, Icid>(lineage) && gathered[arrival].used != Some(*destination) {
            // a new link path's first packet is compared with the active one
            let previous = gathered[arrival]
                .used
                .or_else(|| active.and_then(|active| gathered[active].used));
            if let Some(hlist_pat![_, _, mut used]) =
                others.link_path::<LinkPathTakes<T>, Ix>(&path, link)
            {
                used.set(*destination);
            }
            gathered[arrival].used = Some(*destination);
            if previous != Some(*destination) {
                LineageConnectionIdEvents::<T, L, Hc>::used_by_peer(lineage, destination, link);
            }
        }
        let active = active.filter(|active| *active != arrival);
        let peer_switched_local_id = !zero_length::<T, L, Icid>(lineage)
            && active.is_none_or(|active| gathered[active].used != gathered[arrival].used);
        let arrival_state = gathered[arrival].state();
        let active_state = active.map(|active| gathered[active].state());
        let step = lineage
            .get_mut::<ConnectionMigrationOf<T>, Imig>()
            .on_processed(
                &arrival_state,
                gathered[arrival].awaits,
                active_state.as_ref(),
                moves,
                peer_switched_local_id,
                now,
            );
        apply_step::<T, L, B, Ix>(others, &path, link, step, now, requests);
    }

    fn validated<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, L, layer::LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        link: &LinkIdOf<T>,
        initial_rtt: Option<Duration>,
        now: InstantOf<T>,
        requests: &mut Vec<MigrationRequest<LinkIdOf<T>>>,
    ) {
        let NodeKey::LogicalPath(path) = others.here().clone() else {
            unreachable!("a logical path's lend carries its key")
        };
        let gathered = gather::<T, L, B, Iv, Ima, Ir, Ilm, Icu, Ian, Irt>(lineage, others);
        let Some(validated) = gathered.iter().position(|each| each.link == *link) else {
            return;
        };
        let active = gathered
            .iter()
            .position(|each| each.role == LinkPathRole::Active)
            .filter(|active| *active != validated);
        let awaiting = others
            .link_path::<LinkPathTakes<T>, Ix>(&path, link)
            .and_then(|taken| {
                let hlist_pat![_, mut migration, _] = taken;
                migration.take_awaiting()
            });
        let validated_state = gathered[validated].state();
        let active_state = active.map(|active| gathered[active].state());
        let step = lineage
            .get_mut::<ConnectionMigrationOf<T>, Imig>()
            .on_validated(
                &validated_state,
                awaiting,
                active_state.as_ref(),
                initial_rtt,
                now,
            );
        apply_step::<T, L, B, Ix>(others, &path, link, step, now, requests);
    }

    fn validation_failed<'v, B: CallBundle>(
        lineage: &mut LineageOf<'v, T, L, layer::LogicalPath>,
        others: &mut OtherNodes<'v, T, L, B>,
        link: &LinkIdOf<T>,
        now: InstantOf<T>,
        requests: &mut Vec<MigrationRequest<LinkIdOf<T>>>,
    ) -> bool {
        let NodeKey::LogicalPath(path) = others.here().clone() else {
            unreachable!("a logical path's lend carries its key")
        };
        let gathered = gather::<T, L, B, Iv, Ima, Ir, Ilm, Icu, Ian, Irt>(lineage, others);
        let Some(failed) = gathered.iter().find(|each| each.link == *link) else {
            return true;
        };
        let fallback = lineage
            .get::<ConnectionMigrationOf<T>, Imig>()
            .fallback()
            .and_then(|fallback| gathered.iter().find(|each| each.link == *fallback))
            .map(Gathered::state);
        let failed_state = failed.state();
        let outcome = lineage
            .get_mut::<ConnectionMigrationOf<T>, Imig>()
            .on_validation_failed(&failed_state, fallback.as_ref(), now);
        match outcome {
            FailedValidation::End(link) => {
                requests.push(MigrationRequest::EndLinkPath { link });
                true
            }
            FailedValidation::Revert { switch, end } => {
                apply_switch::<T, L, B, Ix>(others, &path, switch, now, requests);
                requests.push(MigrationRequest::EndLinkPath { link: end });
                true
            }
            FailedValidation::NoFallback => false,
        }
    }
}

/// Whether this side's connection IDs on the logical path of `lineage` are
/// zero-length: the peer then never switches between them.
fn zero_length<T, L, Icid>(lineage: &LineageOf<'_, T, L, layer::LogicalPath>) -> bool
where
    T: Choices,
    L: LineagePartList<T>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<ConnectionIdsOf<T>, Icid>,
{
    lineage.get::<ConnectionIdsOf<T>, Icid>().local() == ConnectionId::EMPTY
}

/// What the rules read of each link path of the logical path of a lend.
#[allow(clippy::type_complexity)] // the positions of what it reads
fn gather<'v, T, L, B, Iv, Ima, Ir, Ilm, Icu, Ian, Irt>(
    lineage: &LineageOf<'v, T, L, layer::LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
) -> Vec<Gathered<T>>
where
    T: Choices,
    L: LineagePartList<T> + ParametersOf<TransportParameterSpace>,
    B: CallBundle,
    TransportParameterSlots<L>: Selector<Option<MaxAckDelay>, Ima>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: ReadEach<LinkPathRoleReads<T, L>, Iv>,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out: GetAt<LinkPathRole<InstantOf<T>>, Ir>
        + GetAt<LinkPathMigrationOf<T>, Ilm>
        + GetAt<LocalConnectionIdUsedByPeer, Icu>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![AntiAmplification, LinkFacts], Ian>,
    for<'s> NodeData<T, L, layer::Recovery>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Recovery> as FlatMut<'s>>::Out: GetAt<RttOf<T, L>, Irt>,
{
    let NodeKey::LogicalPath(path) = others.here().clone() else {
        unreachable!("a logical path's lend carries its key")
    };
    let link_of = |key: &crate::layer::NodeKeyOf<T, L>| -> Option<LinkIdOf<T>> {
        match key {
            NodeKey::LinkPath(each, link) | NodeKey::Recovery(each, link) if *each == path => {
                Some(link.clone())
            }
            _ => None,
        }
    };
    let mut gathered: Vec<Gathered<T>> = Vec::new();
    others.each_link_path_read::<LinkPathRole<InstantOf<T>>, Ir>(|key, role| {
        if let Some(link) = link_of(key) {
            gathered.push(Gathered {
                link,
                role: *role,
                since: None,
                awaits: false,
                used: None,
                validation: AddressValidation::NotValidated,
                pto: None,
            });
        }
    });
    let find = |key: &crate::layer::NodeKeyOf<T, L>, gathered: &mut Vec<Gathered<T>>| {
        let link = link_of(key)?;
        gathered.iter_mut().position(|each| each.link == link)
    };
    others.each_link_path_read::<LinkPathMigrationOf<T>, Ilm>(|key, migration| {
        if let Some(at) = find(key, &mut gathered) {
            gathered[at].since = migration.since();
            gathered[at].awaits = migration.awaits_validation();
        }
    });
    others.each_link_path_read::<LocalConnectionIdUsedByPeer, Icu>(|key, used| {
        if let Some(at) = find(key, &mut gathered) {
            gathered[at].used = used.get();
        }
    });
    let hlist_pat![peer, thresholds, _] = lineage.read_each::<LinkPathRoleReads<T, L>, Iv>();
    let max_ack_delay = peer_max_ack_delay::<L, Ima>(peer).unwrap_or(DEFAULT_MAX_ACK_DELAY);
    let granularity = thresholds.granularity();
    others.each_recovery_read::<RttOf<T, L>, Irt>(|key, rtt| {
        if let (Some(at), Some(rtt)) = (find(key, &mut gathered), rtt) {
            gathered[at].pto = Some(probe_timeout(
                &rtt.estimate(),
                granularity,
                PacketNumberSpaceKind::ApplicationData,
                max_ack_delay,
                0,
            ));
        }
    });
    for each in &mut gathered {
        if let Some(hlist_pat![_, facts]) =
            others.link_entry::<HList![AntiAmplification, LinkFacts], Ian>(&each.link)
        {
            each.validation = facts.validation;
        }
    }
    gathered
}

/// Apply `step`, of the link path over `link` of the logical path `path`.
fn apply_step<T, L, B, Ix>(
    others: &mut OtherNodes<'_, T, L, B>,
    path: &crate::share::PathKey<L>,
    link: &LinkIdOf<T>,
    step: MigrationStep<LocalOf<T>, PeerOf<T>, InstantOf<T>>,
    now: InstantOf<T>,
    requests: &mut Vec<MigrationRequest<LinkIdOf<T>>>,
) where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, LinkPathTakes<T>, Ix>,
{
    match step {
        MigrationStep::Stay => {}
        MigrationStep::Await(recovery) => {
            if let Some(hlist_pat![_, mut migration, _]) =
                others.link_path::<LinkPathTakes<T>, Ix>(path, link)
            {
                migration.await_validation(recovery);
            }
        }
        MigrationStep::Switch(switch) => {
            apply_switch::<T, L, B, Ix>(others, path, switch, now, requests);
        }
    }
}

/// Apply `switch` in the logical path `path`: each link path takes its
/// role, entered at `now`, and the recovery layer follows.
fn apply_switch<T, L, B, Ix>(
    others: &mut OtherNodes<'_, T, L, B>,
    path: &crate::share::PathKey<L>,
    switch: Switch<LocalOf<T>, PeerOf<T>, InstantOf<T>>,
    now: InstantOf<T>,
    requests: &mut Vec<MigrationRequest<LinkIdOf<T>>>,
) where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, LinkPathTakes<T>, Ix>,
{
    let Switch { to, from, layer } = switch;
    enter::<T, L, B, Ix>(others, path, &to, LinkPathRole::Active, now);
    if let Some((from, role)) = &from {
        enter::<T, L, B, Ix>(others, path, from, *role, now);
    }
    match (layer, from) {
        (SwitchLayer::Keep, _) => {}
        (SwitchLayer::Move, Some((from, _))) => {
            requests.push(MigrationRequest::MoveRecovery { from, to });
        }
        // invariant: a layer moves only from the former active link path
        (SwitchLayer::Move, None) => unreachable!("a layer moves from a link path"),
        (SwitchLayer::New { initial_rtt }, _) => {
            requests.push(MigrationRequest::AddRecovery {
                link: to,
                initial_rtt,
            });
        }
    }
}

/// The link path over `link` of the logical path `path` enters `role` at
/// `now`; the change is published at the link path.
fn enter<T, L, B, Ix>(
    others: &mut OtherNodes<'_, T, L, B>,
    path: &crate::share::PathKey<L>,
    link: &LinkIdOf<T>,
    role: LinkPathRole<InstantOf<T>>,
    now: InstantOf<T>,
) where
    T: Choices,
    L: LineagePartList<T>,
    B: CallBundle,
    for<'s> NodeData<T, L, layer::LinkPath>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkPath> as FlatMut<'s>>::Out:
        TakeEach<'s, LinkPathTakes<T>, Ix>,
{
    {
        let Some(hlist_pat![mut current, mut migration, _]) =
            others.link_path::<LinkPathTakes<T>, Ix>(path, link)
        else {
            return;
        };
        *current = role;
        migration.entered_role(now);
    }
    others.publish_at(
        &NodeKey::LinkPath(path.clone(), link.clone()),
        Happened::<LinkPathRoleChanged>::new(),
    );
}

// ---- the components ----

/// A logical path starts with its migration policy as it defaults, no
/// fallback and no recovery layer moved.
impl<T: Choices, L> Build<T, L, layer::LogicalPath, ()> for ConnectionMigrationOf<T>
where
    L: LineagePartList<T>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LogicalPath>,
        _: &mut ArgsOf<T, L, layer::LogicalPath>,
    ) -> Self {
        Self::default()
    }
}
impl<M, Lo, P> crate::component::PassiveDataComponent for ConnectionMigration<M, Lo, P> {}

/// A link path is in its role from when it starts, and nothing waits for
/// its validation. When it ends, its logical path's migration forgets it.
impl<T: Choices, L, I> Build<T, L, layer::LinkPath, (I,)> for LinkPathMigrationOf<T>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::LinkPathParents: GetAt<ConnectionMigrationOf<T>, I>,
{
    fn build<'v>(
        _: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        _: &mut ArgsOf<T, L, layer::LinkPath>,
    ) -> Self {
        Self::default()
    }

    fn end<'v, B: CallBundle>(
        self,
        parents: &mut ParentsOf<'v, T, L, layer::LinkPath>,
        others: &mut OtherNodes<'v, T, L, B>,
    ) {
        let NodeKey::LinkPath(_, link) = others.here() else {
            unreachable!("a link path's end carries its key")
        };
        parents
            .get_mut::<ConnectionMigrationOf<T>, I>()
            .link_path_ended(link);
    }
}

/// It subscribes to its link path started, which it notes the instant of.
impl<T: Choices, L, I> DataComponent<T, L, layer::LinkPath, (I,)> for LinkPathMigrationOf<T>
where
    L: LineagePartList<T>,
    for<'v> <L as LineageLists<'v, T>>::LinkPath: GetAt<LinkPathMigrationOf<T>, I>,
{
    fn subscribes(out: &mut EventSubscriptions) {
        out.add::<NodeStarted<layer::LinkPath>>();
    }

    fn on_events<'v, B: CallBundle>(
        _: TriggeredEvents<'_>,
        mut lineage: LineageOf<'v, T, L, layer::LinkPath>,
        _: &mut OtherNodes<'v, T, L, B>,
        now: InstantOf<T>,
    ) -> Option<RequestOf<T, L>> {
        lineage.get_mut::<LinkPathMigrationOf<T>, I>().started(now);
        None
    }
}
