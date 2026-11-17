//! A client's handling of a Retry packet (RFC 9000 §17.2.5).
//!
//! A server that wants the client's address validated before it keeps any
//! state answers the client's first Initial packet with a Retry packet: a
//! token and a connection ID to send to. The client:
//!
//! 1. checks that the Retry is valid ([`check_retry`]): the first one, from
//!    a server it has received no other packet from, with a token, from a
//!    connection ID other than the one it sent to, and with an integrity
//!    tag that verifies (RFC 9000 §17.2.5.1, §17.2.5.2; RFC 9001 §5.8). An
//!    invalid Retry is dropped;
//! 2. asks its [`ClientRetryPolicy`] whether to go on ([`RetryDecision`]):
//!    giving up ends the connection without sending anything, for
//!    [`CloseReason::RetryAbandoned`](sakuya_stream::connection::CloseReason::RetryAbandoned);
//! 3. going on, derives the Initial keys from the Retry's Source Connection
//!    ID ([`retry_initial_keys`]), sends to that connection ID, puts the
//!    token in every Initial packet it sends from then on, and sends the
//!    same ClientHello again: the packets it sent are handed back as lost,
//!    and the recovery state of the link path starts over, as made anew by
//!    the recovery factory (RFC 9002 §6.3), with the interval from the
//!    first Initial packet to the Retry as its initial RTT. Packet numbers
//!    go on (RFC 9000 §17.2.5.3).

use core::{ops::Range, time::Duration};

use bytes::Bytes;
use frunk_core::hlist_pat;
use sakuya_packet_protection::{
    backend::CryptoBackend,
    initial::{INITIAL_AEAD, InitialSecrets},
    retry::{VerifyRetryIntegrityError, verify_retry_integrity_tag},
};
use sakuya_recovery::{
    factory::RecoveryFactory,
    loss_detection::LossDetectionState,
    packet_number_space::{PacketNumberSpaceKind, PacketNumberSpaces},
    send_journals::{SendJournals as _, SentPacketState},
};
use sakuya_wire::{
    connection_id::ConnectionId,
    v1::header::{LongPacket, TypeFields},
};
use snafu::Snafu;

use super::{
    Choices,
    feedback::CoreLentFeedback,
    keys::{DirectionKeys, LevelKeys},
    link::LinkClone,
    pto::ProbeTimeout,
    recovery::{CongestionPartOf, LinkPathCongestionState, PmtuOf, RecoveryFactoryOf, RttOf},
    send::SendTypes,
    send_planning::IntakePublishOutcome,
    spaces::SendJournalsOf,
    streams::send::StreamIntent,
};
use crate::v1::SendParametersOf;
use crate::{
    call::CallBundle,
    clock::{InstantOf, LinkIdOf},
    component::LineageOf,
    error::ConnectionErrorsOf,
    feedback::FeedbackSummariesOf,
    frame_source::{EstablishedSourceComponentsOf, EstablishedSourceComponentsOfParts},
    layer::{self, LogicalPath, NodeKey},
    others::OtherNodes,
    send_strategy::AnyActiveLinkPath,
    share::{FlatMut, LineageLists, LineagePartList, NodeData},
    take::{GetAt, TakeEach},
};
use sakuya_wire::parts::HList;

/// A valid Retry, as the client's [`ClientRetryPolicy`] sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceivedRetry {
    source: ConnectionId,
    token_len: usize,
    since_first_initial: Option<Duration>,
}

impl ReceivedRetry {
    /// The Retry for a policy to judge: its Source Connection ID, the length
    /// of its token, and how long ago the client's first Initial packet was
    /// sent, when that is known.
    pub const fn new(
        source: ConnectionId,
        token_len: usize,
        since_first_initial: Option<Duration>,
    ) -> Self {
        Self {
            source,
            token_len,
            since_first_initial,
        }
    }

    /// The Retry's Source Connection ID, which the client would send to.
    pub const fn source(&self) -> ConnectionId {
        self.source
    }

    /// The length of the Retry's token, which every later Initial packet
    /// would carry.
    pub const fn token_len(&self) -> usize {
        self.token_len
    }

    /// How long ago the client's first Initial packet was sent: about one
    /// round trip to the server. `None` when no record of it is left.
    pub const fn since_first_initial(&self) -> Option<Duration> {
        self.since_first_initial
    }
}

/// What a client does with a valid Retry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryDecision {
    /// Go on with the connection attempt: send the ClientHello again to the
    /// Retry's connection ID, with its token.
    Continue,
    /// Give the connection attempt up: nothing is sent, and the connection
    /// ends for [`CloseReason::RetryAbandoned`](sakuya_stream::connection::CloseReason::RetryAbandoned).
    Abandon,
}

/// What decides, as a client, whether to go on after a valid Retry.
///
/// The protocol does not require a client to go on (RFC 9000 §17.2.5);
/// the decision is made at once, while the Retry is handled.
pub trait ClientRetryPolicy {
    /// Decide about `retry`.
    fn decide(&mut self, retry: &ReceivedRetry) -> RetryDecision;
}

/// Always goes on after a Retry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ContinueOnRetry;

impl ClientRetryPolicy for ContinueOnRetry {
    fn decide(&mut self, _: &ReceivedRetry) -> RetryDecision {
        RetryDecision::Continue
    }
}

/// A Retry that passed [`check_retry`]: what the client goes on with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidRetry {
    source: ConnectionId,
    token: Bytes,
}

impl ValidRetry {
    /// The Retry's Source Connection ID: the client sends to it, and derives
    /// its Initial keys from it.
    pub const fn source(&self) -> ConnectionId {
        self.source
    }

    /// The Retry's token, which every later Initial packet carries; never
    /// empty.
    pub fn token(&self) -> &Bytes {
        &self.token
    }

    /// The Retry for the policy to judge, with how long ago the first
    /// Initial packet was sent.
    pub fn received(&self, since_first_initial: Option<Duration>) -> ReceivedRetry {
        ReceivedRetry::new(self.source, self.token.len(), since_first_initial)
    }

    /// The token, taken out.
    pub fn into_token(self) -> Bytes {
        self.token
    }
}

/// Why a client dropped a Retry packet.
#[derive(Debug, Snafu)]
pub enum RetryDropReason {
    /// The client has already processed a packet from the server, an
    /// Initial or a Retry (RFC 9000 §17.2.5.2).
    #[snafu(display("a packet from the server was already processed"))]
    AfterServerPacket,
    /// The Retry Token is empty (RFC 9000 §17.2.5.2).
    #[snafu(display("the Retry Token is empty"))]
    EmptyToken,
    /// The Source Connection ID is the Destination Connection ID of the
    /// client's first Initial packet (RFC 9000 §17.2.5.1).
    #[snafu(display("the Source Connection ID is the one the client sent to"))]
    SourceIsFirstDestination,
    /// The Retry Integrity Tag does not verify (RFC 9000 §17.2.5.2, RFC
    /// 9001 §5.8).
    #[snafu(display("the Retry Integrity Tag does not verify"))]
    IntegrityTag {
        /// The failure.
        source: VerifyRetryIntegrityError,
    },
}

/// Check, as a client, the Retry packet `packet`, whose bytes are
/// `packet_bytes`, against `first_destination`, the Destination Connection
/// ID of the client's first Initial packet. `answered` is whether the
/// client has already processed an Initial or a Retry packet from the
/// server. `backend` computes the integrity tag.
///
/// # Errors
///
/// The [`RetryDropReason`] the Retry is dropped for.
pub fn check_retry<B: CryptoBackend>(
    backend: &B,
    packet: &LongPacket<Range<usize>>,
    packet_bytes: &[u8],
    first_destination: &ConnectionId,
    answered: bool,
) -> Result<ValidRetry, RetryDropReason> {
    if answered {
        return Err(RetryDropReason::AfterServerPacket);
    }
    let TypeFields::Retry { token, .. } = packet.fields() else {
        unreachable!("a Retry packet has the fields of one")
    };
    if token.is_empty() {
        return Err(RetryDropReason::EmptyToken);
    }
    if packet.scid() == first_destination {
        return Err(RetryDropReason::SourceIsFirstDestination);
    }
    verify_retry_integrity_tag(backend, first_destination, packet_bytes)
        .map_err(|source| RetryDropReason::IntegrityTag { source })?;
    Ok(ValidRetry {
        source: *packet.scid(),
        token: token.clone(),
    })
}

/// The client's Initial keys after a Retry whose Source Connection ID is
/// `source` (RFC 9001 §5.2): the client sends with the client secret and
/// receives with the server secret.
pub fn retry_initial_keys<B: CryptoBackend>(backend: &B, source: &ConnectionId) -> LevelKeys<B> {
    let secrets = InitialSecrets::derive(backend, source);
    LevelKeys {
        send: DirectionKeys::derive(backend, INITIAL_AEAD, &secrets.client),
        receive: DirectionKeys::derive(backend, INITIAL_AEAD, &secrets.server),
    }
}

/// What starting over the recovery state takes from a link path's
/// recovery layer, with the loss detection states of the controller's `S`
/// and `Ls`.
pub(super) type RestartRecoveryTakes<T, L, S, Ls> = HList![
    RttOf<T, L>,
    CongestionPartOf<T, L>,
    PmtuOf<T, L>,
    LinkPathCongestionState<InstantOf<T>>,
    PacketNumberSpaces<LossDetectionState<InstantOf<T>, S, Ls>>,
    ProbeTimeout<InstantOf<T>>
];

/// Start the recovery state of the link path over `link` over at `now`,
/// as a client does once it goes on after a Retry (RFC 9002 §6.3), in the
/// lend of its logical path, `lineage` and `others`.
///
/// What the link path sent and has not seen settled leaves the send
/// journals, in every space, and the summaries of its frames go back to
/// their frame sources as lost, as when a link path ends: the ClientHello
/// is sent again. Its recovery layer is then as if built anew: the recovery
/// factory makes the RTT estimate, the stored part of congestion control
/// and the probing policy again, with the interval from the earliest of
/// those packets to `now` as the initial RTT (RFC 9002 §6.3, MAY), and
/// nothing is in flight, no loss is pending and the probe timeout has no
/// backoff. Packet numbers go on (RFC 9000 §17.2.5.3).
///
/// `go_on` decides in between, given the lineage and that interval, `None`
/// when nothing was left to measure it from: the recovery layer is made
/// anew only when it says so, and what `restart_recovery` returns. A
/// client that gives up ends the connection, so what was taken from the
/// journals is not missed.
///
/// The positions: `Ij` of the send journals, `If` of the recovery factory,
/// `Il` of the link's clone in an entry, `Ik` of what this takes from a
/// recovery layer, `Hf` of the frame sources fed back and `Is` of the
/// frame sources in an established layer.
pub(super) fn restart_recovery<'v, T, L, B, S, Ls, Ij, If, Il, Ik, Hf, Is>(
    lineage: &mut LineageOf<'v, T, L, LogicalPath>,
    others: &mut OtherNodes<'v, T, L, B>,
    link: &LinkIdOf<T>,
    now: InstantOf<T>,
    go_on: impl FnOnce(&mut LineageOf<'v, T, L, LogicalPath>, Option<Duration>) -> bool,
) -> bool
where
    T: Choices,
    L: LineagePartList<T>
        + FeedbackSummariesOf
        + ConnectionErrorsOf
        + EstablishedSourceComponentsOf<T, L>,
    B: CallBundle,
    SendTypes<T, L>: IntakePublishOutcome<StreamIntent<SendParametersOf<T>>, AnyActiveLinkPath>,
    S: 'static,
    Ls: 'static,
    RecoveryFactoryOf<T, L>: RecoveryFactory<T::Link>,
    for<'x> <L as LineageLists<'x, T>>::LogicalPath: GetAt<SendJournalsOf<T, L>, Ij>
        + GetAt<RecoveryFactoryOf<T, L>, If>
        + CoreLentFeedback<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>,
    for<'s> NodeData<T, L, layer::LinkEntry>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::LinkEntry> as FlatMut<'s>>::Out:
        TakeEach<'s, HList![LinkClone<T::Link>], Il>,
    for<'x> NodeData<T, L, layer::Recovery>: FlatMut<'x>,
    for<'x> <NodeData<T, L, layer::Recovery> as FlatMut<'x>>::Out:
        TakeEach<'x, RestartRecoveryTakes<T, L, S, Ls>, Ik>,
    for<'s> NodeData<T, L, layer::Established>: FlatMut<'s>,
    for<'s> <NodeData<T, L, layer::Established> as FlatMut<'s>>::Out:
        TakeEach<'s, EstablishedSourceComponentsOfParts<T, L>, Is>,
{
    let NodeKey::LogicalPath(path) = others.here().clone() else {
        unreachable!("a logical path's lend carries its key")
    };
    let identifier = L::link_path_identifier(&path, link);
    let mut earliest: Option<InstantOf<T>> = None;
    let mut established =
        others.borrow_established_optional::<EstablishedSourceComponentsOfParts<T, L>, Is>();
    for space in PacketNumberSpaceKind::ALL {
        let Some(journals) = lineage.get_mut::<SendJournalsOf<T, L>, Ij>().get_mut(space) else {
            continue;
        };
        let unsettled: Vec<_> = journals.take_link_path(&identifier).collect();
        for record in &unsettled {
            if let SentPacketState::Sent(at) = record.state {
                earliest = Some(earliest.map_or(at, |e| e.min(at)));
            }
        }
        CoreLentFeedback::<T, L, EstablishedSourceComponentsOfParts<T, L>, Hf>::lost_each(
            lineage,
            &mut established,
            now,
            space,
            unsettled
                .iter()
                .filter(|record| !record.content_handed_back)
                .flat_map(|record| &record.summaries),
        );
    }
    drop(established);
    let initial_rtt = earliest.map(|at| now - at).filter(|rtt| !rtt.is_zero());
    if !go_on(lineage, initial_rtt) {
        return false;
    }
    let Some(hlist_pat![clone]) = others.link_entry::<HList![LinkClone<T::Link>], Il>(link) else {
        return true;
    };
    let clone = clone.0.clone();
    let factory = lineage.get_mut::<RecoveryFactoryOf<T, L>, If>();
    others.with_recovery_at::<RestartRecoveryTakes<T, L, S, Ls>, Ik, _>(
        &path,
        link,
        |hlist_pat![rtt, part, pmtu, state, detections, pto], _| {
            let (new_rtt, new_part, new_pmtu) = factory.create(&clone, initial_rtt);
            *rtt = new_rtt;
            *part = new_part;
            *pmtu = new_pmtu;
            *state = LinkPathCongestionState::new();
            for (_, detection) in detections.iter_mut() {
                *detection = LossDetectionState::new();
            }
            *pto = ProbeTimeout::new();
        },
    );
    true
}

#[cfg(test)]
mod tests;
