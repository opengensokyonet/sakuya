//! The datagram router: first-round classification, lookup and delivery

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

use sakuya_link::LinkId;
use sakuya_wire::connection_id::{ConnectionId, NonEmptyCid};
use sakuya_wire::header::v1::{self, LongPacketType};
use sakuya_wire::header::{HeaderForm, LongHeader, ShortHeader, VersionNegotiation};
use smallvec::SmallVec;

use super::index::{FrozenEntries, OfferedRouteHistory, Recheck};
use super::{
    ConnectionIdRecognizer, FirstPacketInterpretation, InitialAcceptance, InitialDatagramReceiver,
    InitialReceiverFactory, LinkIdentity, MatchAssociation, ReceivedDatagram, RecognizedInitial,
    ReflowProvider, RouteIndex, STATELESS_RESET_TOKEN_LEN, StatelessResetDetector,
    StatelessResetTarget, UnclaimedWork,
};
use crate::claim::group::prepare_claim;
use crate::claim::shared::{DatagramFinishPolicy, UnclaimedHandoff};
use crate::claim::{DatagramRouteMatchInfo, ErasedDatagramDeliverer, ExclusiveDatagram};

/// Handles datagrams of a version this side does not support.
///
/// Only the version-independent fields of such a datagram can be read, so it
/// is never routed by version 1 rules. A version service may, for example,
/// answer with Version Negotiation where the role and the protocol allow it.
/// Version Negotiation packets themselves (version 0) are not unsupported
/// versions; they go to the existing client entries.
pub trait VersionService<Payload, Link> {
    /// Takes over a datagram whose first packet has the non-zero `version`.
    fn unsupported_version(&self, version: u32, datagram: ReceivedDatagram<Payload, Link>);
}

/// No version service: datagrams of unsupported versions are released.
impl<Payload, Link> VersionService<Payload, Link> for () {
    fn unsupported_version(&self, _version: u32, _datagram: ReceivedDatagram<Payload, Link>) {}
}

pub(super) mod sealed {
    use std::sync::Arc;

    use super::super::index::FrozenEntries;
    use super::super::{ReceivedDatagram, RecognizedInitial, RouteIndex, UnclaimedWork};
    use crate::claim::shared::DatagramFinishPolicy;

    /// The routing decisions that depend on Initial acceptance.
    pub trait AcceptanceMode<Payload, Link, Target: ?Sized> {
        /// The finish policy of a first-round supported Initial.
        fn first_round(
            &self,
            initial: &RecognizedInitial,
            datagram: &ReceivedDatagram<Payload, Link>,
            frozen: &FrozenEntries<Target>,
        ) -> DatagramFinishPolicy<ReceivedDatagram<Payload, Link>>;

        /// Runs one reflow round.
        fn resume(
            &self,
            index: &Arc<RouteIndex<Target>>,
            work: UnclaimedWork<Payload, Link, Target>,
        );
    }
}

/// Whether and how a router accepts new Initial receivers.
///
/// It is implemented by `()`, which never creates a receiver, and by
/// [`InitialAcceptance`] when the routing domain's deliverers, datagrams and
/// reflow provider can cross threads, as reflow requires.
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
    fn first_round(
        &self,
        _initial: &RecognizedInitial,
        _datagram: &ReceivedDatagram<Payload, Link>,
        _frozen: &FrozenEntries<Target>,
    ) -> DatagramFinishPolicy<ReceivedDatagram<Payload, Link>> {
        DatagramFinishPolicy::LastTakes
    }

    fn resume(&self, _index: &Arc<RouteIndex<Target>>, work: UnclaimedWork<Payload, Link, Target>) {
        drop(work);
    }
}

/// The handoff of one reflow round: it moves the datagram, with its history
/// and Initial context, to the provider.
fn handoff<Payload, Link, Target, Provider>(
    provider: &Arc<Provider>,
    offered: OfferedRouteHistory<Target>,
    initial: RecognizedInitial,
) -> UnclaimedHandoff<ReceivedDatagram<Payload, Link>>
where
    Payload: 'static,
    Link: 'static,
    Target: ?Sized + Send + Sync + 'static,
    Provider: ReflowProvider<Payload, Link, Target> + Send + Sync + 'static,
{
    let provider = Arc::clone(provider);
    Box::new(move |datagram| provider.hand_off(UnclaimedWork::new(datagram, offered, initial)))
}

impl<Payload, Link, Target, Factory, Provider> sealed::AcceptanceMode<Payload, Link, Target>
    for InitialAcceptance<Factory, Provider>
where
    Payload: AsRef<[u8]> + 'static,
    Link: 'static,
    Target:
        ?Sized + ErasedDatagramDeliverer<ReceivedDatagram<Payload, Link>> + Send + Sync + 'static,
    Factory: InitialReceiverFactory<Payload, Link, Target>,
    Provider: ReflowProvider<Payload, Link, Target> + Send + Sync + 'static,
{
    fn first_round(
        &self,
        initial: &RecognizedInitial,
        datagram: &ReceivedDatagram<Payload, Link>,
        frozen: &FrozenEntries<Target>,
    ) -> DatagramFinishPolicy<ReceivedDatagram<Payload, Link>> {
        if !self.factory().admits(initial, datagram) {
            return DatagramFinishPolicy::LastTakes;
        }
        let mut offered = OfferedRouteHistory::new();
        for (entry, _, interpretation) in frozen {
            offered.record(entry, *interpretation);
        }
        DatagramFinishPolicy::OnUnclaimed(handoff(self.provider(), offered, initial.clone()))
    }

    fn resume(&self, index: &Arc<RouteIndex<Target>>, work: UnclaimedWork<Payload, Link, Target>) {
        let (datagram, mut offered, initial) = work.into_parts();
        // Prepared outside the index; the recheck only moves it in.
        let (mut deliverer, receiver) = match self.factory().prepare(&initial) {
            Some(prepared) => {
                let (deliverer, receiver) = prepared.into_parts();
                (Some(deliverer), Some(receiver))
            }
            None => (None, None),
        };
        match index.recheck_initial(&initial, &mut offered, &mut deliverer) {
            Recheck::Offer(fresh) => {
                drop((deliverer, receiver));
                let handoff = handoff(self.provider(), offered, initial);
                dispatch(datagram, DatagramFinishPolicy::OnUnclaimed(handoff), fresh);
            }
            Recheck::Published(registration) => {
                let receiver = receiver.expect("a deliverer was published only with its receiver");
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
/// default to `()`, which means "not provided". It has no runtime, task
/// spawner or polling loop of its own: [`route`](Self::route) and
/// [`resume`](Self::resume) do their work on the caller's stack and return.
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
    Target: ?Sized + ErasedDatagramDeliverer<ReceivedDatagram<Payload, Link>>,
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
    /// for the competition. Deliverers that consume on the spot run their
    /// factory and judgment on this call stack.
    pub fn route(&self, datagram: ReceivedDatagram<Payload, Link>) {
        let bytes = datagram.payload().as_ref();
        let link = datagram.link().link_id();
        let reset = bytes
            .last_chunk::<STATELESS_RESET_TOKEN_LEN>()
            .and_then(|tail| self.reset.detect(tail, link));
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
            Classification::Route { queries, initial } => {
                let mut frozen = FrozenEntries::new();
                for (association, interpretation) in &queries {
                    self.index
                        .collect(association, *interpretation, &mut frozen);
                }
                let finish = match &initial {
                    Some(initial) => self.acceptance.first_round(initial, &datagram, &frozen),
                    None => DatagramFinishPolicy::LastTakes,
                };
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
    pub fn resume(&self, work: UnclaimedWork<Payload, Link, Target>) {
        self.acceptance.resume(&self.index, work);
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
fn dispatch<Payload, Link, Target>(
    datagram: ReceivedDatagram<Payload, Link>,
    finish: DatagramFinishPolicy<ReceivedDatagram<Payload, Link>>,
    frozen: FrozenEntries<Target>,
) where
    Target: ?Sized + ErasedDatagramDeliverer<ReceivedDatagram<Payload, Link>>,
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
type Queries = SmallVec<[(MatchAssociation, FirstPacketInterpretation); 4]>;

#[expect(
    clippy::large_enum_variant,
    reason = "a classification lives only within one route call"
)]
enum Classification {
    /// The fields needed for lookup cannot be read safely.
    Release,
    /// A long header of an unsupported, non-zero version.
    Unsupported(u32),
    /// Look these up; a supported Initial also records what was recognized.
    Route {
        queries: Queries,
        initial: Option<RecognizedInitial>,
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
        match NonEmptyCid::new(dcid) {
            Some(cid) => {
                queries.push((MatchAssociation::LocalCid(cid), interpretation));
                if with_initial {
                    queries.push((MatchAssociation::InitialDcid(cid), interpretation));
                }
            }
            None => queries.push((MatchAssociation::ZeroCid(binding.clone()), interpretation)),
        }
        queries
    };
    match HeaderForm::of(first) {
        HeaderForm::Short => {
            let mut queries = Queries::new();
            for dcid_len in recognizer.short_dcid_lengths(bytes, link) {
                let Ok(short) = ShortHeader::parse(bytes, dcid_len) else {
                    continue;
                };
                let (Ok(dcid), Ok(dcid_len)) =
                    (ConnectionId::new(short.dcid()), u8::try_from(dcid_len))
                else {
                    continue;
                };
                let interpretation = FirstPacketInterpretation::Short { dcid_len };
                if queries.iter().any(|(_, seen)| *seen == interpretation) {
                    continue;
                }
                queries.extend(by_dcid(dcid, interpretation, false));
            }
            Classification::Route {
                queries,
                initial: None,
            }
        }
        HeaderForm::Long => {
            let Ok(long) = LongHeader::parse(bytes) else {
                return Classification::Release;
            };
            match long.version() {
                VersionNegotiation::VERSION => {
                    let Ok(packet) = VersionNegotiation::try_from(long) else {
                        return Classification::Release;
                    };
                    let Ok(dcid) = ConnectionId::new(packet.dcid()) else {
                        return Classification::Release;
                    };
                    Classification::Route {
                        queries: by_dcid(
                            dcid,
                            FirstPacketInterpretation::VersionNegotiation,
                            false,
                        ),
                        initial: None,
                    }
                }
                v1::VERSION => {
                    let Ok(packet) = v1::LongPacket::try_from(long) else {
                        return Classification::Release;
                    };
                    let packet_type = packet.packet_type();
                    let interpretation = FirstPacketInterpretation::Long {
                        version: v1::VERSION,
                        packet_type,
                    };
                    let dcid = *packet.dcid();
                    let with_initial = matches!(
                        packet_type,
                        LongPacketType::Initial | LongPacketType::ZeroRtt
                    );
                    let initial = (packet_type == LongPacketType::Initial).then(|| {
                        RecognizedInitial::new(v1::VERSION, dcid, *packet.scid(), binding.clone())
                    });
                    Classification::Route {
                        queries: by_dcid(dcid, interpretation, with_initial),
                        initial,
                    }
                }
                version => Classification::Unsupported(version),
            }
        }
    }
}
