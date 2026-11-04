//! The datagram router: first-round classification, lookup and delivery

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use sakuya_link::LinkId;
use sakuya_wire::connection_id::{ConnectionId, NonEmptyCid, StatelessResetToken};
use sakuya_wire::header::v1::LongPacketType;
use sakuya_wire::header::v1::codec::ReadLongPacketHostExt as _;
use sakuya_wire::header::{
    HeaderForm,
    codec::{
        ReadLongHeaderHostExt as _, ReadShortHeaderHostExt as _, ReadVersionNegotiationHostExt as _,
    },
};
use sakuya_wire::version::Version;
use smallvec::SmallVec;

use super::acceptance::{
    InitialAcceptance, InitialDatagramReceiver, InitialReceiverFactory, ReflowHandoff,
    ReflowProvider, UnclaimedWork,
};
use super::datagram::{LinkIdentity, ReceivedDatagram};
use super::index::{FrozenEntries, Lookup, OfferedRouteHistory, Recheck, RouteIndex};
use super::interpretation::{FirstPacketInterpretation, RecognizedInitial};
use super::recognizer::ConnectionIdRecognizer;
use super::reset::{StatelessResetDetector, StatelessResetTarget};
use crate::claim::delivery::ExclusiveDatagram;
use crate::claim::erased::ErasedDatagramDeliverer;
use crate::claim::finish::{ReleaseUnclaimed, UnclaimedHandoff};
use crate::claim::group::prepare_claim;
use crate::claim::route_match::DatagramRouteMatchInfo;
use crate::claim::shared::DatagramFinishPolicy;

/// Handles datagrams of a version this side does not support.
///
/// Only the version-independent fields of such a datagram can be read, so it
/// is never routed by version 1 rules. A version service may, for example,
/// answer with Version Negotiation where the role and the protocol allow it.
/// Version Negotiation packets themselves (version 0) are not unsupported
/// versions; they go to the existing client entries.
pub trait VersionService<Payload, Link> {
    /// Takes over a datagram whose first packet has the non-zero `version`.
    fn unsupported_version(&self, version: Version, datagram: ReceivedDatagram<Payload, Link>);
}

/// No version service: datagrams of unsupported versions are released.
impl<Payload, Link> VersionService<Payload, Link> for () {
    fn unsupported_version(&self, _version: Version, _datagram: ReceivedDatagram<Payload, Link>) {}
}

pub(super) mod sealed {
    use std::sync::Arc;

    use super::super::acceptance::UnclaimedWork;
    use super::super::datagram::ReceivedDatagram;
    use super::super::index::{FrozenEntries, RouteIndex};
    use super::super::interpretation::RecognizedInitial;
    use crate::claim::finish::UnclaimedHandoff;
    use crate::claim::shared::DatagramFinishPolicy;

    /// The routing decisions that depend on Initial acceptance.
    pub trait AcceptanceMode<Payload, Link, Target: ?Sized> {
        /// What takes over an acceptable Initial that every candidate left.
        type Handoff: UnclaimedHandoff<ReceivedDatagram<Payload, Link>>;

        /// The finish policy of a first-round supported Initial.
        fn first_round(
            &self,
            initial: &RecognizedInitial,
            datagram: &ReceivedDatagram<Payload, Link>,
            frozen: &FrozenEntries<Target>,
        ) -> DatagramFinishPolicy<Self::Handoff>;

        /// Runs one reflow round.
        fn resume(&self, index: &Arc<RouteIndex<Target>>, work: UnclaimedWork<Payload, Link>);
    }
}

/// Whether and how a router accepts new Initial receivers.
///
/// It is implemented by `()`, which never creates a receiver and releases
/// every unclaimed datagram, and by [`InitialAcceptance`]. The mode decides
/// the [handoff](crate::claim::deliverer::DatagramDeliverer::Handoff) that the
/// deliverers of the routing domain name:
///
/// | Mode | Handoff |
/// | --- | --- |
/// | `()` | [`ReleaseUnclaimed`] |
/// | `InitialAcceptance<Factory, Provider>` | [`ReflowHandoff<Provider>`](ReflowHandoff) |
///
/// Neither mode requires `Send`: a routing domain used on one thread accepts
/// new Initials with local deliverers, datagrams and providers, and a domain
/// shared between threads is `Send` because its parts are.
pub trait InitialAcceptanceMode<Payload, Link, Target: ?Sized>:
    sealed::AcceptanceMode<Payload, Link, Target>
{
}

impl<Payload, Link, Target: ?Sized, Mode> InitialAcceptanceMode<Payload, Link, Target> for Mode where
    Mode: sealed::AcceptanceMode<Payload, Link, Target>
{
}

/// No acceptance: every Initial is offered to the existing entries only.
impl<Payload, Link, Target: ?Sized> sealed::AcceptanceMode<Payload, Link, Target> for () {
    type Handoff = ReleaseUnclaimed;

    fn first_round(
        &self,
        _initial: &RecognizedInitial,
        _datagram: &ReceivedDatagram<Payload, Link>,
        _frozen: &FrozenEntries<Target>,
    ) -> DatagramFinishPolicy<ReleaseUnclaimed> {
        DatagramFinishPolicy::LastTakes
    }

    fn resume(&self, _index: &Arc<RouteIndex<Target>>, work: UnclaimedWork<Payload, Link>) {
        drop(work);
    }
}

impl<Payload, Link, Target, Factory, Provider> sealed::AcceptanceMode<Payload, Link, Target>
    for InitialAcceptance<Factory, Provider>
where
    Payload: AsRef<[u8]>,
    Target:
        ?Sized + ErasedDatagramDeliverer<ReceivedDatagram<Payload, Link>, ReflowHandoff<Provider>>,
    Factory: InitialReceiverFactory<Payload, Link, Target>,
    Provider: ReflowProvider<Payload, Link>,
{
    type Handoff = ReflowHandoff<Provider>;

    fn first_round(
        &self,
        initial: &RecognizedInitial,
        datagram: &ReceivedDatagram<Payload, Link>,
        frozen: &FrozenEntries<Target>,
    ) -> DatagramFinishPolicy<ReflowHandoff<Provider>> {
        if !self.factory().admits(initial, datagram) {
            return DatagramFinishPolicy::LastTakes;
        }
        let mut offered = OfferedRouteHistory::new();
        for (entry, _, interpretation) in frozen {
            offered.record(entry, *interpretation);
        }
        DatagramFinishPolicy::OnUnclaimed(ReflowHandoff::new(
            self.provider(),
            offered,
            initial.clone(),
        ))
    }

    fn resume(&self, index: &Arc<RouteIndex<Target>>, work: UnclaimedWork<Payload, Link>) {
        let (datagram, mut offered, initial) = work.into_parts();
        // Prepared outside the index; the recheck only moves it in.
        let prepared = self.factory().prepare(&initial);
        match index.recheck_initial(&initial, &mut offered, prepared) {
            Recheck::Offer { fresh, unused } => {
                drop(unused);
                let handoff = ReflowHandoff::new(self.provider(), offered, initial);
                dispatch(datagram, DatagramFinishPolicy::OnUnclaimed(handoff), fresh);
            }
            Recheck::Published {
                registration,
                receiver,
            } => {
                receiver.receive_first(registration, ExclusiveDatagram::new(datagram), initial);
            }
            Recheck::Release => drop(datagram),
        }
    }
}

/// Routes received datagrams of one routing domain to its route entries.
///
/// A router combines the [`RouteIndex`] of the domain with the components the
/// domain is configured with: the short header [`ConnectionIdRecognizer`],
/// a [`StatelessResetDetector`], a [`VersionService`] and the
/// [acceptance](InitialAcceptanceMode) of new Initial receivers. The last three
/// default to `()`, which means "not provided". `Target` is the erased
/// deliverer type of the domain, whose handoff the acceptance mode decides.
/// The router has no runtime, task spawner or polling loop of its own:
/// [`route`](Self::route) and [`resume`](Self::resume) do their work on the
/// caller's stack and return.
pub struct DatagramRouter<
    Payload,
    Link,
    Target: ?Sized,
    Recognizer,
    Reset = (),
    Versions = (),
    Acceptance = (),
> {
    index: Arc<RouteIndex<Target>>,
    recognizer: Recognizer,
    reset: Reset,
    versions: Versions,
    acceptance: Acceptance,
    datagram: PhantomData<fn(ReceivedDatagram<Payload, Link>)>,
}

impl<Payload, Link, Target: ?Sized, Recognizer> DatagramRouter<Payload, Link, Target, Recognizer> {
    /// Routes into `index`, reading short headers with `recognizer`, without
    /// stateless reset detection, version service or Initial acceptance.
    pub fn new(index: Arc<RouteIndex<Target>>, recognizer: Recognizer) -> Self {
        Self {
            index,
            recognizer,
            reset: (),
            versions: (),
            acceptance: (),
            datagram: PhantomData,
        }
    }
}

impl<Payload, Link, Target: ?Sized, Recognizer, Reset, Versions, Acceptance>
    DatagramRouter<Payload, Link, Target, Recognizer, Reset, Versions, Acceptance>
{
    /// Checks every datagram with `reset` before ordinary routing.
    pub fn with_stateless_reset<Detector>(
        self,
        reset: Detector,
    ) -> DatagramRouter<Payload, Link, Target, Recognizer, Detector, Versions, Acceptance> {
        DatagramRouter {
            index: self.index,
            recognizer: self.recognizer,
            reset,
            versions: self.versions,
            acceptance: self.acceptance,
            datagram: PhantomData,
        }
    }

    /// Hands datagrams of unsupported versions to `versions`.
    pub fn with_version_service<Service>(
        self,
        versions: Service,
    ) -> DatagramRouter<Payload, Link, Target, Recognizer, Reset, Service, Acceptance> {
        DatagramRouter {
            index: self.index,
            recognizer: self.recognizer,
            reset: self.reset,
            versions,
            acceptance: self.acceptance,
            datagram: PhantomData,
        }
    }

    /// Accepts new Initial receivers with `acceptance`.
    pub fn with_initial_acceptance<Factory, Provider>(
        self,
        acceptance: InitialAcceptance<Factory, Provider>,
    ) -> DatagramRouter<
        Payload,
        Link,
        Target,
        Recognizer,
        Reset,
        Versions,
        InitialAcceptance<Factory, Provider>,
    > {
        DatagramRouter {
            index: self.index,
            recognizer: self.recognizer,
            reset: self.reset,
            versions: self.versions,
            acceptance,
            datagram: PhantomData,
        }
    }

    /// The index of the routing domain, for registering route entries.
    pub fn index(&self) -> &Arc<RouteIndex<Target>> {
        &self.index
    }
}

impl<Payload, Link, Target, Recognizer, Reset, Versions, Acceptance>
    DatagramRouter<Payload, Link, Target, Recognizer, Reset, Versions, Acceptance>
where
    Payload: AsRef<[u8]>,
    Link: LinkIdentity,
    Target: ?Sized + ErasedDatagramDeliverer<ReceivedDatagram<Payload, Link>, Acceptance::Handoff>,
    Recognizer: ConnectionIdRecognizer,
    Reset: StatelessResetDetector,
    Versions: VersionService<Payload, Link>,
    Acceptance: InitialAcceptanceMode<Payload, Link, Target>,
{
    /// Routes one datagram as it arrived from its link.
    ///
    /// The datagram is first checked for a received stateless reset; a hit
    /// releases it and runs the target. Otherwise its first packet is
    /// classified, every lookup completes while this call still owns the
    /// datagram, the complete set of candidates is frozen, and only then is
    /// each candidate delivered:
    ///
    /// | First packet | Looked up | When no candidate is left |
    /// | --- | --- | --- |
    /// | Fields needed for lookup not readable | nothing | released; later bytes are not searched for another packet |
    /// | Supported Initial the domain may accept | local and Initial associations, or the zero-length one of the link binding; on-unclaimed | reflow, then a recheck that may publish a new receiver |
    /// | Supported Initial otherwise | the same entries; last takes | released |
    /// | Supported 0-RTT | local and Initial associations, or the zero-length one; last takes | released |
    /// | Supported Handshake or Retry | the local association, or the zero-length one; last takes | released |
    /// | Short header | every interpretation the recognizer yields; last takes | released |
    /// | Version Negotiation | the local association of its destination connection ID, or the zero-length one; last takes | released |
    /// | Unsupported non-zero version | nothing | handed to the version service |
    ///
    /// Entries registered after the set was frozen do not join this round.
    /// The call returns once every candidate was delivered; it does not wait
    /// for the competition. Deliverers that attempt or consume on the spot run
    /// that work on this call stack.
    pub fn route(&self, datagram: ReceivedDatagram<Payload, Link>) {
        let bytes = datagram.payload().as_ref();
        let link = datagram.link().link_id();
        let reset = bytes
            .last_chunk::<{ StatelessResetToken::LEN }>()
            .and_then(|tail| self.reset.detect(&StatelessResetToken::new(*tail), link));
        if let Some(target) = reset {
            drop(datagram);
            target.stateless_reset_received();
            return;
        }
        match classify(bytes, link, &self.recognizer) {
            Classification::Release => drop(datagram),
            Classification::Unsupported(version) => {
                self.versions.unsupported_version(version, datagram);
            }
            Classification::Route(queries) => {
                let frozen = self.freeze(&queries);
                dispatch(datagram, DatagramFinishPolicy::LastTakes, frozen);
            }
            Classification::RouteInitial { queries, initial } => {
                let frozen = self.freeze(&queries);
                let finish = self.acceptance.first_round(&initial, &datagram, &frozen);
                dispatch(datagram, finish, frozen);
            }
        }
    }

    /// Runs the next round for work a reflow provider took over.
    ///
    /// Call it after the call that handed the work off has returned, never
    /// from inside [`ReflowProvider::hand_off`]. It prepares a new receiver
    /// first, then rechecks the Initial's key within one entry access, as
    /// described in the [`acceptance`](super#accepting-new-initials) section,
    /// and delivers outside the index. A router without acceptance releases
    /// the work.
    pub fn resume(&self, work: UnclaimedWork<Payload, Link>) {
        self.acceptance.resume(&self.index, work);
    }

    /// Completes every lookup of one round.
    fn freeze(&self, queries: &Queries) -> FrozenEntries<Target> {
        let mut frozen = FrozenEntries::new();
        for (lookup, interpretation) in queries {
            self.index.collect(lookup, *interpretation, &mut frozen);
        }
        frozen
    }
}

impl<Payload, Link, Target: ?Sized, Recognizer, Reset, Versions, Acceptance> fmt::Debug
    for DatagramRouter<Payload, Link, Target, Recognizer, Reset, Versions, Acceptance>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatagramRouter")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// Builds the candidate set of one round and delivers it.
fn dispatch<Payload, Link, Handoff, Target>(
    datagram: ReceivedDatagram<Payload, Link>,
    finish: DatagramFinishPolicy<Handoff>,
    frozen: FrozenEntries<Target>,
) where
    Handoff: UnclaimedHandoff<ReceivedDatagram<Payload, Link>>,
    Target: ?Sized + ErasedDatagramDeliverer<ReceivedDatagram<Payload, Link>, Handoff>,
{
    let entries = frozen
        .into_iter()
        .map(|(entry, association, interpretation)| {
            (
                Arc::clone(entry.deliverer()),
                DatagramRouteMatchInfo::new(association, interpretation),
            )
        });
    prepare_claim(datagram, finish, entries).dispatch();
}

/// The lookups a first packet calls for.
type Queries = SmallVec<[(Lookup, FirstPacketInterpretation); 4]>;

enum Classification {
    /// The fields needed for lookup cannot be read safely.
    Release,
    /// A long header of an unsupported, non-zero version.
    Unsupported(Version),
    /// Look these up.
    Route(Queries),
    /// A supported Initial: look these up, and keep what was recognized.
    RouteInitial {
        queries: Queries,
        initial: RecognizedInitial,
    },
}

fn classify(
    bytes: &[u8],
    link: &LinkId,
    recognizer: &impl ConnectionIdRecognizer,
) -> Classification {
    let Some(&first) = bytes.first() else {
        return Classification::Release;
    };
    let binding = link.binding_id();
    let by_dcid = |dcid: ConnectionId, interpretation, with_initial: bool| {
        let mut queries = Queries::new();
        let lookup = match NonEmptyCid::new(dcid) {
            Ok(cid) if with_initial => Lookup::LocalAndInitial(cid),
            Ok(cid) => Lookup::Local(cid),
            Err(_) => Lookup::Zero(binding.clone()),
        };
        queries.push((lookup, interpretation));
        queries
    };
    match HeaderForm::of(first) {
        HeaderForm::Short => {
            let mut queries = Queries::new();
            for dcid_len in recognizer.short_dcid_lengths(bytes, link) {
                let mut input = bytes;
                let Ok(short) = input.sync_read_short_header_unpin(u8::from(dcid_len)) else {
                    continue;
                };
                let Ok(dcid) = ConnectionId::try_from(*short.dcid()) else {
                    continue;
                };
                let interpretation = FirstPacketInterpretation::Short { dcid_len };
                if queries.iter().any(|(_, seen)| *seen == interpretation) {
                    continue;
                }
                queries.extend(by_dcid(dcid, interpretation, false));
            }
            Classification::Route(queries)
        }
        HeaderForm::Long => {
            let mut input = bytes;
            let Ok(long) = input.sync_read_long_header_unpin() else {
                return Classification::Release;
            };
            let version = long.version();
            if version == Version::NEGOTIATION {
                let Ok(packet) = input.sync_read_version_negotiation_unpin(long) else {
                    return Classification::Release;
                };
                let Ok(dcid) = ConnectionId::try_from(*packet.dcid()) else {
                    return Classification::Release;
                };
                return Classification::Route(by_dcid(
                    dcid,
                    FirstPacketInterpretation::VersionNegotiation,
                    false,
                ));
            }
            if version != Version::V1 {
                return Classification::Unsupported(version);
            }
            let Ok(packet) = input.sync_read_long_packet_unpin(long) else {
                return Classification::Release;
            };
            let packet_type = packet.packet_type();
            let interpretation = FirstPacketInterpretation::Long {
                version,
                packet_type,
            };
            let dcid = *packet.dcid();
            match packet_type {
                LongPacketType::Initial => Classification::RouteInitial {
                    queries: by_dcid(dcid, interpretation, true),
                    initial: RecognizedInitial::new(version, dcid, *packet.scid(), binding.clone()),
                },
                LongPacketType::ZeroRtt => {
                    Classification::Route(by_dcid(dcid, interpretation, true))
                }
                LongPacketType::Handshake | LongPacketType::Retry => {
                    Classification::Route(by_dcid(dcid, interpretation, false))
                }
            }
        }
    }
}
